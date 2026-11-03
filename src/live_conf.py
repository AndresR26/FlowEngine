from scapy.all import *
import numpy as np
import os, csv, threading, sys, time, math, hashlib
from collections import defaultdict, deque, Counter
from datetime import datetime
import platform
import joblib
import sklearn
import sklearn.ensemble # Fuerza la inclusión de Random Forest
# NUEVO: pandas se usa para alinear las features del flujo con las que espera el
# modelo de IA (modelo_rf_ids.joblib) antes de predecir. Si no está disponible, el
# modo manual (etiquetado por teclado) sigue funcionando igual que siempre.
try:
    import pandas as pd
except Exception:
    pd = None

# =========================
# FORZAR COMPATIBILIDAD NPCAP EN WINDOWS
# =========================
if platform.system().lower() == "windows":
    conf.use_npcap = True

# =========================
# IMPORTS SEGUROS
# =========================
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except:
    HTTPRequest = HTTPResponse = None

try:
    from scapy.layers.dns import DNS
except:
    DNS = None

try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Auth, Dot11Deauth, Dot11ProbeReq
except:
    Dot11 = Dot11Beacon = Dot11Auth = Dot11Deauth = Dot11ProbeReq = None

# ========================= CONFIG
CONFIG = {
    "csv_file": "live_resultado.csv",
    "min_packets": 5,
    "time_window": 60,
    "flow_timeout": 30,     # NUEVO: seg. de inactividad antes de forzar el cierre de un flujo
    "active_gap": 1.0,      # NUEVO: hueco (seg) que separa una racha "activa" de un periodo "idle"
    "save_pcap": True,      # NUEVO: guarda también el tráfico crudo en un .pcap junto al CSV
    "pcap_file": "captura.pcap",  # NUEVO
}

# ========================= VARIABLES GLOBALES
CURRENT_LABEL = "normal"
STOP_FLAG = False
LABEL_LOG = []  # NUEVO: [(timestamp_unix, etiqueta), ...] para poder auditar/re-etiquetar después

# NUEVO: modo de etiquetado -- "manual" (por teclado, el de siempre) o "modelo" (un
# RandomForest ya entrenado predice la etiqueta de cada flujo automáticamente)
MODO_ETIQUETADO = "manual"
MODELO_IDS = None            # NUEVO: objeto del modelo cargado (joblib.load)
MODEL_FEATURE_NAMES = None   # NUEVO: caché del orden de columnas que el modelo espera

# NUEVO: valores GREASE de TLS (RFC 8701) -- se excluyen del cálculo de JA3
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# ========================= HILO DE ETIQUETADO DINÁMICO
def input_listener(analyzer=None):
    """Escucha la entrada del teclado para cambiar la etiqueta o detener.
    NUEVO: registra cada cambio con su timestamp exacto en LABEL_LOG, y le pide al
    analyzer que cierre (flush) los flujos activos en ese instante para que ninguno
    arrastre la etiqueta anterior más allá de lo que realmente ocurrió.
    NUEVO: en modo 'modelo' (etiquetado automático por IA) ya no tiene sentido cambiar
    la etiqueta a mano, así que cualquier texto que no sea stop/salir se ignora."""
    global CURRENT_LABEL, STOP_FLAG
    while not STOP_FLAG:
        try:
            new_label = input("").strip()
            if new_label.lower() in ["stop", "salir", "exit", "quit"]:
                STOP_FLAG = True
                print("\n[!] Deteniendo captura... (espera a que pase el siguiente paquete o presiona Ctrl+C)")
                break
            elif new_label:
                if MODO_ETIQUETADO == "modelo":
                    print("[i] Etiquetado automático (IA) activo: cada flujo se etiqueta solo con el modelo. "
                          "Escribe 'stop' o 'salir' para detener la captura.")
                    continue
                CURRENT_LABEL = new_label.lower()
                LABEL_LOG.append((time.time(), CURRENT_LABEL))
                print(f"\n[+] Etiqueta cambiada a: '{CURRENT_LABEL}'")
                if analyzer:
                    n = analyzer.flush_all_active()
                    print(f"[*] {n} flujo(s) en curso se cerraron con la etiqueta anterior.")
                else:
                    print(f"[*] Los flujos activos previos terminarán con su etiqueta original.")
        except EOFError:
            break

# ========================= INTERFAZ AUTOMÁTICA
def get_active_interface():
    """Obtiene la interfaz de red con la ruta predeterminada."""
    try:
        return conf.route.route("0.0.0.0")[0]
    except Exception:
        return None

# ========================= CARPETA DEL PROGRAMA (NUEVO)
def _ruta_base_programa():
    """Carpeta donde vive el programa, tanto si corre como script .py como si está
    empaquetado en un .exe. Se usa para guardar capturas por defecto y, sobre todo,
    para buscar el modelo de IA (modelo_rf_ids.joblib) junto al programa."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# ========================= NOMBRES DE ARCHIVO PERSONALIZABLES (NUEVO)
def _sanitizar_nombre_archivo(nombre, default, extension):
    """Limpia un nombre de archivo dado por el usuario: si viene vacío usa el valor por
    defecto, descarta cualquier ruta/carpeta incluida (para no escribir fuera de la
    carpeta elegida), quita caracteres inválidos en Windows y se asegura de que termine
    en la extensión correcta. Separa manualmente por '/' y '\\' -- así el resultado es
    el mismo sin importar en qué sistema operativo corra esto (os.path.basename por sí
    solo se comporta distinto en Windows que en Linux/Mac)."""
    nombre = (nombre or "").strip()
    if not nombre:
        return default
    nombre = nombre.replace("\\", "/").split("/")[-1]
    for ch in '\\/:*?"<>|':
        nombre = nombre.replace(ch, "_")
    if not nombre.lower().endswith(extension):
        nombre += extension
    return nombre

def _ruta_disponible(ruta):
    """Si el archivo ya existe y no se puede borrar (bloqueado por Excel, un antivirus,
    OneDrive, etc.), devuelve una ruta alterna con sufijo de hora en vez de fallar al
    iniciar o, peor, mezclar datos de una sesión vieja con la nueva."""
    if not os.path.exists(ruta):
        return ruta
    try:
        os.remove(ruta)
        return ruta
    except Exception:
        carpeta, nombre = os.path.split(ruta)
        raiz, ext = os.path.splitext(nombre)
        alterna = os.path.join(carpeta, f"{raiz}_{datetime.now().strftime('%H%M%S')}{ext}")
        print(f"[!] '{nombre}' está en uso (¿abierto en Excel/otro programa?). Se usará '{os.path.basename(alterna)}' en su lugar.")
        return alterna
# ========================= remoto (NUEVO)
def capturar_remoto(duracion, ruta_guardado, id_captura, nombre_pcap):
    """
    Ejecuta una captura automática por un tiempo determinado sin requerir consola.
    MODIFICADO: Fuerza el uso del modelo de IA para el etiquetado remoto.
    """
    # 1. Se añaden las variables globales del modelo
    global STOP_FLAG, CURRENT_LABEL, MODO_ETIQUETADO, MODELO_IDS
    STOP_FLAG = False
    CURRENT_LABEL = "" 

    # 2. CARGAR MODELO Y FORZAR MODO IA
    modelo, ruta_modelo = cargar_modelo_ids()
    if modelo is None:
        print(f"[-] ERROR CRÍTICO: No se encontró el modelo IA en la ruta: {ruta_modelo}")
        print("[-] Abortando captura remota. Asegúrate de enviar 'modelo_rf_ids.joblib' al agente.")
        return None
    
    MODELO_IDS = modelo
    MODO_ETIQUETADO = "modelo"
    print(f"[+] Modo IA activado para captura remota. Modelo cargado correctamente.")

    # Asegurar que el CSV y el PCAP tengan nombres emparejados
    nombre_csv = nombre_pcap.replace('.pcap', '.csv')
    
    # Instanciar el Analyzer original
    analyzer = Analyzer(output_dir=ruta_guardado, csv_file=nombre_csv, pcap_file=nombre_pcap)

    # Hilo temporizador que detiene la captura automáticamente
    def auto_stop():
        import time
        time.sleep(duracion)
        global STOP_FLAG
        STOP_FLAG = True

    import threading
    threading.Thread(target=auto_stop, daemon=True).start()

    # Hilo de limpieza de flujos
    threading.Thread(target=analyzer._reaper_loop, daemon=True).start()

    iface = get_active_interface()
    
    def should_stop(pkt):
        return STOP_FLAG

    # Ejecutar sniffer
    try:
        sniff(iface=iface, prn=analyzer.process, store=False, stop_filter=should_stop)
    except Exception as e:
        print(f"[-] Error en captura nativa: {e}")
    finally:
        STOP_FLAG = True
        # Forzar vaciado de los flujos activos al terminar
        with analyzer.lock:
            for fid, flow in list(analyzer.flows.items()):
                rev = (fid[1], fid[0], fid[3], fid[2], fid[4])
                analyzer._flush(fid, rev, flow)
        
        # Cerrar el PCAP de forma segura
        if analyzer.pcap_writer is not None:
            try:
                analyzer.pcap_writer.close()
            except Exception:
                pass
        
        # 3. Restaurar el entorno al finalizar
        MODO_ETIQUETADO = "manual"
        MODELO_IDS = None

    return analyzer.csv_path

# ========================= MODELO DE IA (ETIQUETADO AUTOMÁTICO) -- NUEVO
def cargar_modelo_ids(nombre_archivo="modelo_rf_ids.joblib"):
    """Busca 'modelo_rf_ids.joblib' en la misma carpeta donde vive el programa (junto
    al .py o al .exe) y lo carga con joblib. Devuelve (modelo, ruta_buscada); si el
    archivo no existe o no se puede cargar, modelo es None (la ruta se devuelve igual
    para poder informar al usuario dónde se buscó)."""
    ruta = os.path.join(_ruta_base_programa(), nombre_archivo)
    if not os.path.exists(ruta):
        return None, ruta
    try:
        import joblib
        modelo = joblib.load(ruta)
        return modelo, ruta
    except Exception as e:
        print(f"[!] No se pudo cargar el modelo '{nombre_archivo}': {e}")
        return None, ruta

def _predecir_etiqueta(modelo, data):
    """Arma el vector de features en el mismo orden que el modelo espera
    (modelo.feature_names_in_, expuesto por scikit-learn cuando el modelo se entrenó
    con un DataFrame de pandas) a partir de la fila ya calculada por Flow.compute(), y
    devuelve la etiqueta predicha como texto.

    IMPORTANTE: esto asume que los nombres de columna usados al entrenar el modelo
    coinciden con los nombres de columna que genera este script (p. ej. 'Flow Duration',
    'Src Bytes', 'SYN Count', ...). Si el modelo se entrenó con otros nombres, otro
    orden, o con columnas categóricas codificadas (one-hot/label encoding), hay que
    ajustar este mapeo a mano. Cualquier feature que el modelo espere y no exista en el
    flujo actual, o que llegue como texto (IP, servicio, etc.), se rellena con 0 en vez
    de hacer fallar la predicción."""
    global MODEL_FEATURE_NAMES
    if pd is None:
        return "sin_pandas"
    try:
        if MODEL_FEATURE_NAMES is None:
            MODEL_FEATURE_NAMES = list(getattr(modelo, "feature_names_in_", []))
        if not MODEL_FEATURE_NAMES:
            print("[!] El modelo no expone 'feature_names_in_'; no se puede alinear el orden de las columnas automáticamente.")
            return "sin_prediccion"

        fila = {}
        for col in MODEL_FEATURE_NAMES:
            valor = data.get(col, 0)
            if valor is None or isinstance(valor, str):
                valor = 0
            fila[col] = valor

        X = pd.DataFrame([fila], columns=MODEL_FEATURE_NAMES)
        pred = modelo.predict(X)[0]
        return str(pred)
    except Exception as e:
        print(f"[!] Error al predecir con el modelo: {e}")
        return "error_prediccion"

# ========================= ENTROPÍA DE SHANNON (NUEVO)
def _entropia(data: bytes) -> float:
    """Entropía de Shannon del payload (bits/byte, 0-8). Valores altos (~7-8) sugieren
    contenido cifrado/comprimido/empaquetado; valores bajos, texto plano o datos repetitivos."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

# ========================= TLS CLIENTHELLO: SNI + JA3 (AMPLIADO)
def analizar_tls_clienthello(payload: bytes):
    """Parsea un TLS ClientHello y devuelve SNI + los campos necesarios para JA3
    (versión, cipher suites, extensiones, curvas elípticas, formatos de punto).
    Devuelve None si el payload no es un ClientHello válido."""
    try:
        if len(payload) < 43: return None
        idx = 0
        if payload[idx] != 0x16: return None
        idx += 5
        if payload[idx] != 0x01: return None
        idx += 4
        tls_version = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + 32
        session_id_len = payload[idx]
        idx += 1 + session_id_len
        cipher_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        ciphers = [int.from_bytes(payload[idx+i:idx+i+2], "big") for i in range(0, cipher_len, 2)]
        idx += cipher_len
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return {"sni": None, "tls_version": tls_version, "ciphers": ciphers,
                    "extensions": [], "curves": [], "point_formats": []}
        ext_total = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        end = idx + ext_total

        sni, extensions, curves, point_formats = None, [], [], []

        while idx + 4 <= end and idx + 4 <= len(payload):
            ext_type = int.from_bytes(payload[idx:idx+2], "big")
            ext_len  = int.from_bytes(payload[idx+2:idx+4], "big")
            data0 = idx + 4
            extensions.append(ext_type)

            if ext_type == 0x0000:  # server_name (SNI)
                name_start = data0 + 5
                name_len   = int.from_bytes(payload[data0+3:data0+5], "big")
                sni = payload[name_start:name_start+name_len].decode("utf-8", errors="ignore")
            elif ext_type == 0x000a and data0 + 2 <= len(payload):  # supported_groups (curvas elípticas)
                l = int.from_bytes(payload[data0:data0+2], "big")
                raw = payload[data0+2:data0+2+l]
                curves = [int.from_bytes(raw[i:i+2], "big") for i in range(0, len(raw) - 1, 2)]
            elif ext_type == 0x000b and data0 + 1 <= len(payload):  # ec_point_formats
                l = payload[data0]
                point_formats = list(payload[data0+1:data0+1+l])

            idx = data0 + ext_len

        return {"sni": sni, "tls_version": tls_version, "ciphers": ciphers,
                "extensions": extensions, "curves": curves, "point_formats": point_formats}
    except Exception:
        return None

def calcular_ja3(tls_info: dict):
    """JA3 = MD5('TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats'),
    ignorando los valores GREASE, según el estándar original de Salesforce (2017).
    Validado contra los vectores de prueba oficiales y la implementación de referencia."""
    if not tls_info:
        return None
    ciphers = [c for c in tls_info.get("ciphers", []) if c not in GREASE_VALUES]
    exts    = [e for e in tls_info.get("extensions", []) if e not in GREASE_VALUES]
    curves  = [c for c in tls_info.get("curves", []) if c not in GREASE_VALUES]
    pfmts   = tls_info.get("point_formats", [])
    ja3_str = "{},{},{},{},{}".format(
        tls_info.get("tls_version", 0),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in pfmts),
    )
    return hashlib.md5(ja3_str.encode()).hexdigest()

# ========================= DETECCIÓN DE PROTOCOLOS Y SERVICIOS
def detectar_protocolo(pkt):
    if Dot11 and pkt.haslayer(Dot11):
        if pkt.haslayer(Dot11Beacon): return "802.11_Beacon"
        if pkt.haslayer(Dot11Auth): return "802.11_Auth"
        if pkt.haslayer(Dot11Deauth): return "802.11_Deauth"
        if pkt.haslayer(Dot11ProbeReq): return "802.11_ProbeReq"
        return "802.11_Other"

    if pkt.haslayer(ARP):  return "ARP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(TCP):  return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(IP):   return "IP"
    return "OTHER"

def detectar_service_y_payload(pkt):
    """Detecta el servicio de un paquete y extrae metadatos enriquecidos: SNI/JA3/versión TLS,
    nombre/tipo/rcode de consulta DNS, método/host/URI/user-agent/status de HTTP, y entropía
    del payload. Devuelve un diccionario; los campos no aplicables quedan en None (para no
    confundirlos con un 0 real en el CSV)."""
    info = {
        "service": "unknown", "sni": None, "ja3": None, "tls_version": None,
        "dns_qname": None, "dns_qtype": None, "dns_rcode": None, "dns_ancount": None,
        "http_method": None, "http_host": None, "http_uri": None,
        "http_ua": None, "http_status": None, "http_len": None,
        "entropy": None,
    }

    if DNS and pkt.haslayer(DNS):
        info["service"] = "dns"
        dns = pkt[DNS]
        try:
            if dns.qd is not None:
                info["dns_qname"] = dns.qd.qname.decode(errors="ignore").rstrip(".")
                info["dns_qtype"] = int(dns.qd.qtype)
        except Exception:
            pass
        if dns.qr == 1:  # rcode/ancount solo tienen sentido en la respuesta, no en la consulta
            try:
                info["dns_rcode"] = int(dns.rcode)
                info["dns_ancount"] = int(dns.ancount) if dns.ancount is not None else 0
            except Exception:
                pass
        return info

    if HTTPRequest and pkt.haslayer(HTTPRequest):
        info["service"] = "http"
        req = pkt[HTTPRequest]
        try:
            info["http_method"] = req.Method.decode(errors="ignore") if req.Method else None
            info["http_host"]   = req.Host.decode(errors="ignore") if req.Host else None
            info["http_uri"]    = req.Path.decode(errors="ignore") if req.Path else None
            info["http_ua"]     = req.User_Agent.decode(errors="ignore") if req.User_Agent else None
        except Exception:
            pass
        return info

    if HTTPResponse and pkt.haslayer(HTTPResponse):
        info["service"] = "http"
        resp = pkt[HTTPResponse]
        try:
            info["http_status"] = int(resp.Status_Code) if resp.Status_Code else None
        except Exception:
            pass
        try:
            info["http_len"] = int(resp.Content_Length) if resp.Content_Length else None
        except Exception:
            pass
        return info

    port_map = {
        80: "http", 443: "https", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 110: "pop3", 143: "imap",
        53: "dns", 123: "ntp", 137: "netbios", 138: "netbios",
        139: "smb", 445: "smb", 3389: "rdp",
        3306: "mysql", 1433: "mssql", 5432: "postgresql",
        1900: "ssdp", 1883: "mqtt"
    }

    if pkt.haslayer(TCP):
        port = min(pkt[TCP].sport, pkt[TCP].dport)
        raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
        if raw:
            info["entropy"] = _entropia(raw)
            tls_info = analizar_tls_clienthello(raw)
            if tls_info:
                info["sni"] = tls_info["sni"]
                info["tls_version"] = tls_info["tls_version"]
                info["ja3"] = calcular_ja3(tls_info)

        is_tls = (port == 443) or (len(raw) > 0 and raw[0] == 0x16)
        info["service"] = port_map.get(port, "https" if is_tls else "other")
        return info

    if pkt.haslayer(UDP):
        port = min(pkt[UDP].sport, pkt[UDP].dport)
        raw = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
        if raw:
            info["entropy"] = _entropia(raw)
        info["service"] = port_map.get(port, "other")
        return info

    return info

# ========================= FLOW
class Flow:
    def __init__(self, fid):
        self.fid = fid
        self.fwd_sizes, self.bwd_sizes = [], []
        self.fwd_times, self.bwd_times = [], []
        self.fwd_ttl,   self.bwd_ttl   = [], []
        self.states, self.services, self.sni_list = [], [], []
        self.start = self.end = self.last_seen = None

        self.syn_time = self.synack_time = self.ack_time = None
        self.syn_cnt = self.fin_cnt = self.rst_cnt = self.psh_cnt = self.ack_cnt = 0

        # NUEVO: flags extendidas y firma de escaneo
        self.urg_cnt = self.ece_cnt = self.cwr_cnt = 0
        self.fwd_psh_cnt = self.bwd_psh_cnt = 0
        self.fwd_urg_cnt = self.bwd_urg_cnt = 0
        self.flag_signature = "none"
        self.fin_fwd = self.fin_bwd = False  # cierre "limpio" (FIN en ambos sentidos)

        # NUEVO: ventana TCP / retransmisiones
        self.fwd_win_init, self.bwd_win_init = None, None
        self.zero_win_cnt = 0
        self.fwd_seen_seq, self.bwd_seen_seq = set(), set()
        self.fwd_retrans = self.bwd_retrans = 0

        # NUEVO: fragmentación IP
        self.frag_cnt = self.df_cnt = 0

        # NUEVO: enriquecimiento de protocolo
        self.ja3_list, self.tls_version_list = [], []
        self.dns_qname_list, self.dns_qtype_list = [], []
        self.dns_rcode_list, self.dns_ancount_list = [], []
        self.http_method_list, self.http_host_list, self.http_uri_list = [], [], []
        self.http_ua_list, self.http_status_list, self.http_len_list = [], [], []
        self.icmp_type_list, self.icmp_code_list = [], []
        self.entropy_list = []

        self.flow_label = CURRENT_LABEL

    def add(self, pkt, direction):
        t = float(pkt.time)
        size = len(pkt)
        if self.start is None: self.start = t
        self.end = t
        self.last_seen = t  # NUEVO: para el timeout de inactividad

        ttl = pkt[IP].ttl if pkt.haslayer(IP) else 0

        if direction == "FWD":
            self.fwd_sizes.append(size)
            self.fwd_times.append(t)
            self.fwd_ttl.append(ttl)
        else:
            self.bwd_sizes.append(size)
            self.bwd_times.append(t)
            self.bwd_ttl.append(ttl)

        # NUEVO: fragmentación IP
        if pkt.haslayer(IP):
            ipl = pkt[IP]
            if ipl.flags.MF or ipl.frag > 0:
                self.frag_cnt += 1
            if ipl.flags.DF:
                self.df_cnt += 1

        # NUEVO: ICMP type/code
        if pkt.haslayer(ICMP):
            self.icmp_type_list.append(pkt[ICMP].type)
            self.icmp_code_list.append(pkt[ICMP].code)

        info = detectar_service_y_payload(pkt)
        self.services.append(info["service"])
        if info["sni"]: self.sni_list.append(info["sni"])
        if info["ja3"]: self.ja3_list.append(info["ja3"])
        if info["tls_version"] is not None: self.tls_version_list.append(info["tls_version"])
        if info["dns_qname"] is not None:
            self.dns_qname_list.append(info["dns_qname"])
            self.dns_qtype_list.append(info["dns_qtype"])
        if info["dns_rcode"] is not None:
            self.dns_rcode_list.append(info["dns_rcode"])
            self.dns_ancount_list.append(info["dns_ancount"])
        if info["http_method"] is not None:
            self.http_method_list.append(info["http_method"])
            self.http_host_list.append(info["http_host"])
            self.http_uri_list.append(info["http_uri"])
            self.http_ua_list.append(info["http_ua"])
        if info["http_status"] is not None:
            self.http_status_list.append(info["http_status"])
            self.http_len_list.append(info["http_len"])
        if info["entropy"] is not None:
            self.entropy_list.append(info["entropy"])

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            f = int(tcp.flags)
            if f & 0x02: self.syn_cnt += 1
            if f & 0x01: self.fin_cnt += 1
            if f & 0x04: self.rst_cnt += 1
            if f & 0x08:
                self.psh_cnt += 1
                if direction == "FWD": self.fwd_psh_cnt += 1
                else: self.bwd_psh_cnt += 1
            if f & 0x10: self.ack_cnt += 1
            if f & 0x20:  # NUEVO: URG
                self.urg_cnt += 1
                if direction == "FWD": self.fwd_urg_cnt += 1
                else: self.bwd_urg_cnt += 1
            if f & 0x40: self.ece_cnt += 1  # NUEVO
            if f & 0x80: self.cwr_cnt += 1  # NUEVO

            # NUEVO: firma de escaneo (NULL / XMAS / FIN) -- ver "core" = FIN,SYN,RST,PSH,ACK,URG
            core = f & 0x3F
            if core == 0x00: self.flag_signature = "null_scan"
            elif core == 0x29: self.flag_signature = "xmas_scan"
            elif core == 0x01 and self.flag_signature == "none": self.flag_signature = "fin_scan"

            # NUEVO: ventana TCP / zero window
            if tcp.window == 0: self.zero_win_cnt += 1
            if direction == "FWD" and self.fwd_win_init is None: self.fwd_win_init = tcp.window
            if direction == "BWD" and self.bwd_win_init is None: self.bwd_win_init = tcp.window

            # NUEVO: retransmisiones (heurística: mismo seq ya visto + trae payload)
            has_payload = len(bytes(tcp.payload)) > 0
            if direction == "FWD":
                if has_payload and tcp.seq in self.fwd_seen_seq: self.fwd_retrans += 1
                self.fwd_seen_seq.add(tcp.seq)
            else:
                if has_payload and tcp.seq in self.bwd_seen_seq: self.bwd_retrans += 1
                self.bwd_seen_seq.add(tcp.seq)

            if f & 0x01:  # NUEVO: FIN por dirección, para is_terminal()
                if direction == "FWD": self.fin_fwd = True
                else: self.fin_bwd = True

            if (f & 0x3F) == 0x02:
                self.syn_time = t
                self.states.append("S0")
            elif (f & 0x12) == 0x12:
                self.synack_time = t
                self.states.append("S1")
            elif (f & 0x11) == 0x11:
                self.states.append("FIN")
            elif f & 0x04:
                self.states.append("RST")
            elif f & 0x10:
                self.ack_time = t
                self.states.append("EST")
            elif f & 0x01:
                self.states.append("FIN")

    def is_terminal(self):
        """NUEVO: True si el flujo llegó a un cierre 'natural' (RST, o FIN visto en ambos
        sentidos). Se usa para cerrar flujos cortos que nunca llegarían a min_packets."""
        return self.rst_cnt > 0 or (self.fin_fwd and self.fin_bwd)

    def _jitter(self, times):
        return float(np.std(np.diff(times))) if len(times) > 1 else 0

    def _iat(self, times):
        return float(np.mean(np.diff(times))) if len(times) > 1 else 0

    def _iat_min(self, times):  # NUEVO
        return float(np.min(np.diff(times))) if len(times) > 1 else 0

    def _iat_max(self, times):  # NUEVO
        return float(np.max(np.diff(times))) if len(times) > 1 else 0

    def _active_idle(self, gap_threshold=None):
        """NUEVO: separa los timestamps del flujo en rachas 'activas' (paquetes con huecos
        <= gap_threshold entre sí) y calcula la duración media de las rachas y de los huecos
        'idle' entre ellas. Útil para patrones tipo slowloris (ráfagas + silencios)."""
        gap_threshold = gap_threshold or CONFIG["active_gap"]
        times = sorted(self.fwd_times + self.bwd_times)
        if len(times) < 2:
            return 0.0, 0.0
        actives, idles = [], []
        burst_start = prev = times[0]
        for t in times[1:]:
            gap = t - prev
            if gap > gap_threshold:
                actives.append(prev - burst_start)
                idles.append(gap)
                burst_start = t
            prev = t
        actives.append(prev - burst_start)
        active_mean = float(np.mean(actives)) if actives else 0.0
        idle_mean = float(np.mean(idles)) if idles else 0.0
        return active_mean, idle_mean

    def compute(self, stats):
        src, dst, sport, dport, proto = self.fid
        duration = max(self.end - self.start, 1e-6)

        sum_fwd, sum_bwd = sum(self.fwd_sizes), sum(self.bwd_sizes)
        total_packets = len(self.fwd_sizes) + len(self.bwd_sizes)
        total_bytes   = sum_fwd + sum_bwd

        if proto in ["UDP", "ICMP"]:
            state = "CON" if len(self.bwd_sizes) > 0 else "INT"
        else:
            state = max(set(self.states), key=self.states.count) if self.states else "NONE"

        service = max(set(self.services), key=self.services.count) if self.services else "unknown"

        synack = (self.synack_time - self.syn_time) if self.syn_time and self.synack_time else 0
        tcprtt = (self.ack_time - self.syn_time) if self.syn_time and self.ack_time else synack
        sni_final = self.sni_list[0] if self.sni_list else ""

        bytes_per_packet = total_bytes / total_packets if total_packets > 0 else 0
        size_diff = abs(sum_fwd - sum_bwd)

        all_sizes = self.fwd_sizes + self.bwd_sizes
        pkt_size_var = float(np.var(all_sizes)) if len(all_sizes) > 1 else 0.0
        pkt_size_mean = float(np.mean(all_sizes)) if all_sizes else 0.0

        payload_sizes = [s for s in self.fwd_sizes if s > 60]
        first_payload_size = payload_sizes[0] if payload_sizes else 0

        byte_ratio = (sum_fwd / sum_bwd) if sum_bwd > 0 else float(sum_fwd)

        # NUEVO: tamaño de paquete por dirección (antes solo había una media/varianza combinada)
        fwd_min = min(self.fwd_sizes) if self.fwd_sizes else 0
        fwd_max = max(self.fwd_sizes) if self.fwd_sizes else 0
        fwd_mean = float(np.mean(self.fwd_sizes)) if self.fwd_sizes else 0.0
        fwd_std  = float(np.std(self.fwd_sizes)) if len(self.fwd_sizes) > 1 else 0.0
        bwd_min = min(self.bwd_sizes) if self.bwd_sizes else 0
        bwd_max = max(self.bwd_sizes) if self.bwd_sizes else 0
        bwd_mean = float(np.mean(self.bwd_sizes)) if self.bwd_sizes else 0.0
        bwd_std  = float(np.std(self.bwd_sizes)) if len(self.bwd_sizes) > 1 else 0.0

        active_mean, idle_mean = self._active_idle()

        ttl_src_var = float(np.var(self.fwd_ttl)) if len(self.fwd_ttl) > 1 else 0.0
        ttl_dst_var = float(np.var(self.bwd_ttl)) if len(self.bwd_ttl) > 1 else 0.0

        payload_entropy_mean = float(np.mean(self.entropy_list)) if self.entropy_list else 0.0

        ja3_final = self.ja3_list[0] if self.ja3_list else None
        tls_version_final = self.tls_version_list[0] if self.tls_version_list else None

        dns_qname_final = self.dns_qname_list[0] if self.dns_qname_list else None
        dns_qtype_final = self.dns_qtype_list[0] if self.dns_qtype_list else None
        dns_rcode_final = self.dns_rcode_list[0] if self.dns_rcode_list else None
        dns_ancount_final = self.dns_ancount_list[0] if self.dns_ancount_list else None
        dns_qname_len = len(dns_qname_final) if dns_qname_final else None
        dns_qname_entropy = _entropia(dns_qname_final.encode()) if dns_qname_final else None

        http_method_final = self.http_method_list[0] if self.http_method_list else None
        http_host_final   = self.http_host_list[0] if self.http_host_list else None
        http_uri_final    = self.http_uri_list[0] if self.http_uri_list else None
        http_ua_final     = self.http_ua_list[0] if self.http_ua_list else None
        http_status_final = self.http_status_list[0] if self.http_status_list else None
        http_len_final    = self.http_len_list[0] if self.http_len_list else None

        # Primer valor visto (no voto mayoritario): en un echo request+reply hay empate
        # 50/50 entre el type del request y el de la respuesta, y lo más útil es saber
        # qué inició el flujo.
        icmp_type_final = self.icmp_type_list[0] if self.icmp_type_list else None
        icmp_code_final = self.icmp_code_list[0] if self.icmp_code_list else None

        now = self.end
        while stats["events"] and now - stats["events"][0][0] > CONFIG["time_window"]:
            _, s, d, srv = stats["events"].popleft()
            stats["src"][s] -= 1
            stats["dst"][d] -= 1
            stats["srv_src"][(s, srv)] -= 1
            stats["srv_dst"][(d, srv)] -= 1

        start_clock = datetime.fromtimestamp(self.start).strftime('%H:%M:%S.%f')
        end_clock   = datetime.fromtimestamp(self.end).strftime('%H:%M:%S.%f')

        return {
            "Start Time":       start_clock,
            "End Time":         end_clock,
            "Source IP":        src,
            "Destination IP":   dst,
            "Source Port":      sport,
            "Destination Port": dport,
            "Protocol":         proto,
            "State":            state,
            "Service":          service,
            "SNI":              sni_final,
            "Flow Duration":    duration,
            "Src Bytes":        sum_fwd,
            "Dst Bytes":        sum_bwd,
            "Src Packets":      len(self.fwd_sizes),
            "Dst Packets":      len(self.bwd_sizes),
            "Flow Bytes/s":     total_bytes / duration,
            "Flow Packets/s":   total_packets / duration,
            "Src Load":         sum_fwd / duration,
            "Dst Load":         sum_bwd / duration,
            "Src TTL":          int(np.mean(self.fwd_ttl)) if self.fwd_ttl else 0,
            "Dst TTL":          int(np.mean(self.bwd_ttl)) if self.bwd_ttl else 0,
            "Sjit":             self._jitter(self.fwd_times),
            "Djit":             self._jitter(self.bwd_times),
            "Sintpkt":          self._iat(self.fwd_times),
            "Dintpkt":          self._iat(self.bwd_times),
            "tcprtt":           tcprtt,
            "synack":           synack,
            "ct_srv_src":       stats["srv_src"][(src, service)],
            "ct_srv_dst":       stats["srv_dst"][(dst, service)],
            "ct_dst_ltm":       stats["dst"][dst],
            "ct_src_ltm":       stats["src"][src],
            "Bytes Per Pkt":    bytes_per_packet,
            "Size Diff":        size_diff,
            "SYN Count":        self.syn_cnt,
            "ACK Count":        self.ack_cnt,
            "FIN Count":        self.fin_cnt,
            "RST Count":        self.rst_cnt,
            "PSH Count":        self.psh_cnt,
            "Pkt Size Mean":    pkt_size_mean,
            "Pkt Size Var":     pkt_size_var,
            "First Pkt Size":   first_payload_size,
            "Byte Ratio":       byte_ratio,

            # NUEVO: flags extendidas y firma de escaneo
            "URG Count":        self.urg_cnt,
            "ECE Count":        self.ece_cnt,
            "CWR Count":        self.cwr_cnt,
            "Fwd PSH Count":    self.fwd_psh_cnt,
            "Bwd PSH Count":    self.bwd_psh_cnt,
            "Fwd URG Count":    self.fwd_urg_cnt,
            "Bwd URG Count":    self.bwd_urg_cnt,
            "Flag Signature":   self.flag_signature,

            # NUEVO: tamaño de paquete por dirección
            "Fwd Pkt Len Min":  fwd_min,
            "Fwd Pkt Len Max":  fwd_max,
            "Fwd Pkt Len Mean": fwd_mean,
            "Fwd Pkt Len Std":  fwd_std,
            "Bwd Pkt Len Min":  bwd_min,
            "Bwd Pkt Len Max":  bwd_max,
            "Bwd Pkt Len Mean": bwd_mean,
            "Bwd Pkt Len Std":  bwd_std,

            # NUEVO: IAT min/max por dirección
            "Fwd IAT Min":      self._iat_min(self.fwd_times),
            "Fwd IAT Max":      self._iat_max(self.fwd_times),
            "Bwd IAT Min":      self._iat_min(self.bwd_times),
            "Bwd IAT Max":      self._iat_max(self.bwd_times),

            # NUEVO: ventana TCP / retransmisiones
            "Init Fwd Win":      self.fwd_win_init,
            "Init Bwd Win":      self.bwd_win_init,
            "Zero Window Count": self.zero_win_cnt,
            "Fwd Retrans":       self.fwd_retrans,
            "Bwd Retrans":       self.bwd_retrans,

            # NUEVO: fragmentación / TTL / entropía / active-idle
            "Frag Count":           self.frag_cnt,
            "DF Count":             self.df_cnt,
            "Src TTL Var":          ttl_src_var,
            "Dst TTL Var":          ttl_dst_var,
            "Payload Entropy Mean": payload_entropy_mean,
            "Active Mean":          active_mean,
            "Idle Mean":            idle_mean,

            # NUEVO: ICMP
            "ICMP Type": icmp_type_final,
            "ICMP Code": icmp_code_final,

            # NUEVO: DNS
            "DNS Qname":         dns_qname_final,
            "DNS Qtype":         dns_qtype_final,
            "DNS Rcode":         dns_rcode_final,
            "DNS Ancount":       dns_ancount_final,
            "DNS Qname Len":     dns_qname_len,
            "DNS Qname Entropy": dns_qname_entropy,

            # NUEVO: HTTP
            "HTTP Method":         http_method_final,
            "HTTP Host":           http_host_final,
            "HTTP URI":            http_uri_final,
            "HTTP User-Agent":     http_ua_final,
            "HTTP Status":         http_status_final,
            "HTTP Content-Length": http_len_final,

            # NUEVO: TLS
            "TLS Version": tls_version_final,
            "JA3":          ja3_final,

            "Label":            self.flow_label
        }

# ========================= ANALYZER
class Analyzer:
    def __init__(self, output_dir, csv_file=None, pcap_file=None):
        self.flows = {}
        self.lock = threading.Lock()  # NUEVO: protege self.flows (sniff, reaper e input_listener corren en hilos distintos)
        self.stats = {
            "events":  deque(),
            "src":     defaultdict(int),
            "dst":     defaultdict(int),
            "srv_src": defaultdict(int),
            "srv_dst": defaultdict(int)
        }

        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir

        # NUEVO: nombre de archivo elegible por el usuario (antes fijo: live_resultado.csv)
        csv_file = _sanitizar_nombre_archivo(csv_file, CONFIG["csv_file"], ".csv")
        self.csv_path = _ruta_disponible(os.path.join(output_dir, csv_file))
        self.init = False

        # NUEVO: pcap crudo en paralelo al CSV, también con nombre elegible. Si algún día
        # se descubre un bug en una feature, o se quiere agregar una nueva, se puede
        # re-derivar el CSV desde aquí sin repetir la generación de tráfico (a menudo lo
        # más caro de reproducir).
        self.pcap_path = None
        self.pcap_writer = None
        if CONFIG.get("save_pcap", True):
            pcap_file = _sanitizar_nombre_archivo(pcap_file, CONFIG["pcap_file"], ".pcap")
            self.pcap_path = _ruta_disponible(os.path.join(output_dir, pcap_file))
            try:
                # sync=True fuerza escritura a disco en cada paquete: un poco más lento,
                # pero no se pierde nada si el proceso se cierra de forma abrupta.
                self.pcap_writer = PcapWriter(self.pcap_path, append=False, sync=True)
            except Exception as e:
                print(f"[!] No se pudo crear el .pcap ({e}); la captura seguirá solo con el CSV.")
                self.pcap_writer = None

    def get_id(self, pkt):
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif Dot11 and pkt.haslayer(Dot11):
            src, dst = pkt.addr2 or "None", pkt.addr1 or "None"
        elif pkt.haslayer(Ether):
            src, dst = pkt[Ether].src, pkt[Ether].dst
        else:
            return None

        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            # NUEVO: ICMP no tiene puertos. Usamos el id del echo (idéntico en el
            # request y su reply) como pseudo-puerto simétrico, para no fusionar
            # sesiones ICMP distintas (varios pings, un barrido) entre el mismo par de IPs.
            icmp_id = getattr(pkt[ICMP], "id", None)
            sport = dport = icmp_id if icmp_id is not None else 0
        else:
            sport = dport = 0

        proto = detectar_protocolo(pkt)
        return (src, dst, sport, dport, proto)

    def _flush(self, fid, rev, flow):
        """NUEVO (antes en línea dentro de process): calcula las features del flujo y lo
        guarda en el CSV. Debe llamarse con self.lock ya adquirido. Comprueba membresía
        primero para no guardar el mismo flujo dos veces si dos hilos deciden cerrarlo
        casi al mismo tiempo (ej. reap_idle y un cambio de etiqueta simultáneos)."""
        if fid not in self.flows and rev not in self.flows:
            return
        data = flow.compute(self.stats)
        t = flow.end

        # NUEVO: en modo 'modelo', la etiqueta ya no viene de CURRENT_LABEL sino de la
        # predicción del modelo IDS sobre las features recién calculadas del flujo.
        if MODO_ETIQUETADO == "modelo" and MODELO_IDS is not None:
            data["Label"] = _predecir_etiqueta(MODELO_IDS, data)

        if data["Source IP"] != "None" and data["Destination IP"] != "None":
            self.stats["events"].append((t, data["Source IP"], data["Destination IP"], data["Service"]))
            self.stats["src"][data["Source IP"]] += 1
            self.stats["dst"][data["Destination IP"]] += 1
            self.stats["srv_src"][(data["Source IP"], data["Service"])] += 1
            self.stats["srv_dst"][(data["Destination IP"], data["Service"])] += 1

        self.save(data)
        self.flows.pop(fid, None)
        self.flows.pop(rev, None)

    def process(self, pkt):
        if self.pcap_writer is not None:
            # NUEVO: se guarda SIEMPRE, incluso si el procesamiento de flujos de abajo
            # falla -- el pcap es el respaldo crudo, independiente de bugs en las features.
            try:
                self.pcap_writer.write(pkt)
            except Exception:
                pass
        try:
            fid = self.get_id(pkt)
            if not fid: return
            rev = (fid[1], fid[0], fid[3], fid[2], fid[4])

            with self.lock:
                flow = self.flows.get(fid) or self.flows.get(rev)
                if flow is None:
                    flow = Flow(fid)
                    self.flows[fid] = flow
                flow.add(pkt, "FWD" if fid in self.flows else "BWD")

                umbral = len(flow.fwd_sizes) + len(flow.bwd_sizes) >= CONFIG["min_packets"]
                # NUEVO: cierre inmediato por RST/FIN, además del umbral de paquetes.
                # Antes, un flujo que nunca llegaba a min_packets (ej. un escaneo SYN de
                # 2-3 paquetes) jamás se guardaba en el CSV.
                if flow.is_terminal() or umbral:
                    self._flush(fid, rev, flow)
        except Exception:
            pass

    def reap_idle(self):
        """NUEVO: cierra flujos inactivos por más de CONFIG['flow_timeout'] segundos.
        Se llama periódicamente desde un hilo aparte para no perder flujos cortos que
        nunca reciben más tráfico (una consulta DNS aislada, un ping, un puerto filtrado)."""
        now = time.time()
        with self.lock:
            stale = [(fid, fl) for fid, fl in self.flows.items()
                     if now - fl.last_seen > CONFIG["flow_timeout"]]
            for fid, flow in stale:
                rev = (fid[1], fid[0], fid[3], fid[2], fid[4])
                self._flush(fid, rev, flow)

    def flush_all_active(self):
        """NUEVO: cierra TODOS los flujos activos ahora mismo. Se llama cuando cambia la
        etiqueta en vivo, para que ningún flujo en curso arrastre una etiqueta
        desactualizada más allá del instante real del cambio."""
        with self.lock:
            n = len(self.flows)
            for fid, flow in list(self.flows.items()):
                rev = (fid[1], fid[0], fid[3], fid[2], fid[4])
                self._flush(fid, rev, flow)
        return n

    def save(self, data, intentos=5, espera=0.2):
        """NUEVO: reintenta si el archivo está momentáneamente bloqueado (antivirus,
        indexación de Windows, OneDrive, o el propio CSV abierto en Excel) en vez de
        propagar la excepción. Si tras varios intentos sigue sin poder escribir, la fila
        se guarda en un CSV de respaldo para no perderla."""
        for intento in range(intentos):
            try:
                with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=data.keys())
                    if not self.init:
                        writer.writeheader()
                        self.init = True
                    writer.writerow(data)
                return
            except (PermissionError, OSError) as e:
                if intento < intentos - 1:
                    time.sleep(espera)
                else:
                    self._guardar_respaldo(data, e)

    def _guardar_respaldo(self, data, error):
        """NUEVO: si el CSV principal no se pudo escribir tras varios intentos, la fila
        se guarda aquí para no perderla -- se puede unir al resto después a mano."""
        backup_path = os.path.join(self.output_dir, "filas_no_guardadas.csv")
        try:
            existe = os.path.exists(backup_path)
            with open(backup_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data.keys())
                if not existe:
                    writer.writeheader()
                writer.writerow(data)
            print(f"[!] No se pudo escribir en {os.path.basename(self.csv_path)} ({error}). "
                  f"Fila guardada en {os.path.basename(backup_path)} -- únela después con el resto.")
        except Exception:
            print(f"[!] ERROR: se perdió una fila de datos ({error}). "
                  f"Revisa si otro programa (Excel, antivirus) tiene el CSV abierto.")

    def save_label_log(self):
        """NUEVO: vuelca LABEL_LOG (timestamp exacto de cada cambio de etiqueta) a un CSV
        aparte, para poder auditar o re-etiquetar flujos en post-procesamiento en vez de
        confiar solo en la sincronización en vivo."""
        if not LABEL_LOG:
            return
        path = os.path.join(self.output_dir, "labels_log.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_unix", "timestamp_legible", "label"])
            for ts, label in LABEL_LOG:
                legible = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                writer.writerow([ts, legible, label])
        print(f"[+] Log de etiquetas (con timestamp) guardado en: {path}")

    def _reaper_loop(self):
        while not STOP_FLAG:
            time.sleep(5)
            try:
                self.reap_idle()
            except Exception as e:
                # NUEVO: antes, cualquier excepción aquí mataba el hilo para el resto de
                # la sesión y el timeout de flujos inactivos dejaba de funcionar sin aviso.
                print(f"[!] Error en el hilo de limpieza de flujos inactivos: {e}")

    def run(self):
        global STOP_FLAG, CURRENT_LABEL
        STOP_FLAG = False
        CURRENT_LABEL = "normal"  # NUEVO: si run() se llama de nuevo desde el menú en el mismo proceso, no arrastra la última etiqueta usada
        LABEL_LOG.clear()  # por si run() se invoca varias veces en el mismo proceso (menú)
        LABEL_LOG.append((time.time(), CURRENT_LABEL))  # marca el estado inicial

        t = threading.Thread(target=input_listener, args=(self,), daemon=True)
        t.start()

        reaper = threading.Thread(target=self._reaper_loop, daemon=True)  # NUEVO
        reaper.start()

        iface = get_active_interface()
        print(f"\n🚀 LIVE - Interfaz activa: {iface if iface else 'Predeterminada de Scapy'}")
        if MODO_ETIQUETADO == "modelo":
            print(f"[*] Etiquetado automático (IA) activo -- cada flujo se etiqueta con el modelo cargado.")
            print(f"[*] Escribe 'stop' o 'salir' para detener.")
        else:
            print(f"[*] Escribe una etiqueta (Ej: 'dos') y presiona Enter. Escribe 'stop' o 'salir' para detener.")
            print(f"[*] Etiqueta actual: '{CURRENT_LABEL}'")

        def should_stop(pkt):
            return STOP_FLAG

        try:
            sniff(iface=iface, prn=self.process, store=False, stop_filter=should_stop)
        except OSError as e:
            error_msg = str(e).lower()
            if "winpcap is not installed" in error_msg or "layer 2" in error_msg:
                print("\n" + "="*60)
                print("🚨 ERROR CRÍTICO DE RED: SCAPY NO DETECTA NPCAP 🚨")
                print("="*60)
                print("Esto ocurre habitualmente en máquinas nuevas por dos razones:")
                print("1. El programa instaló Npcap HOY pero Scapy necesita que REINICIES la aplicación.")
                print("   -> SOLUCIÓN: Cierra la consola/ejecutable y vuelve a abrirlo.")
                print("\n2. Npcap se instaló sin compatibilidad de API.")
                print("   -> SOLUCIÓN: Desinstala Npcap, vuelve a instalarlo desde la USB y")
                print("      ASEGÚRATE de marcar la casilla 'Install Npcap in WinPcap API-compatible Mode'.")
                print("="*60 + "\n")
            else:
                print(f"\n[!] Ocurrió un error inesperado al iniciar la captura: {e}")
        except KeyboardInterrupt:
            print("\n[!] Captura detenida manualmente (Ctrl+C).")
        finally:
            STOP_FLAG = True
            # NUEVO: flush final -- ya no se pierden los flujos que quedaron activos al detener
            with self.lock:
                pendientes = len(self.flows)
                for fid, flow in list(self.flows.items()):
                    rev = (fid[1], fid[0], fid[3], fid[2], fid[4])
                    self._flush(fid, rev, flow)
            if pendientes:
                print(f"[+] {pendientes} flujo(s) activo(s) se guardaron al cerrar (antes se perdían).")
            self.save_label_log()
            if self.pcap_writer is not None:  # NUEVO
                try:
                    self.pcap_writer.close()
                    print(f"[+] Tráfico crudo guardado en: {self.pcap_path}")
                except Exception:
                    pass
            print("[+] Regresando al menú principal...\n")

# ========================= RUN (Exposición para el menú)
def run():
    print("\n======================================")
    print("    CONFIGURACIÓN DE CAPTURA EN VIVO  ")
    print("======================================")
    print("[*] ¿Dónde deseas guardar los archivos generados (CSV, pcap, log de etiquetas)?")
    print("[*] (Presiona ENTER sin escribir nada para guardarlos en la carpeta actual)")

    ruta = input("\n[?] Ruta de guardado: ").strip()

    # Si el usuario presiona Enter, creamos una carpeta "Capturas" donde esté el .exe
    if not ruta:
        ruta = os.path.join(_ruta_base_programa(), "Capturas")

    # NUEVO: nombre de archivo personalizable para el CSV y el pcap
    nombre_csv = input(f"[?] Nombre del archivo CSV (ENTER = '{CONFIG['csv_file']}'): ").strip()
    nombre_pcap = input(f"[?] Nombre del archivo PCAP (ENTER = '{CONFIG['pcap_file']}'): ").strip()
    csv_file = _sanitizar_nombre_archivo(nombre_csv, CONFIG["csv_file"], ".csv")
    pcap_file = _sanitizar_nombre_archivo(nombre_pcap, CONFIG["pcap_file"], ".pcap")

    try:
        os.makedirs(ruta, exist_ok=True)
        print(f"\n[+] Los datos se guardarán en: {ruta}")
        print(f"[+] CSV:  {csv_file}")
        print(f"[+] PCAP: {pcap_file}")
    except Exception as e:
        print(f"[-] Error al intentar acceder/crear la ruta: {e}")
        return

    Analyzer(output_dir=ruta, csv_file=csv_file, pcap_file=pcap_file).run()

# ========================= RUN CON MODELO IA (NUEVO -- Exposición para el menú)
def run_ia():
    """Igual que run(), pero en lugar de etiquetar a mano por teclado, cada flujo se
    etiqueta automáticamente con la predicción de un modelo IDS (modelo_rf_ids.joblib)
    ya entrenado. El modelo se busca en la misma carpeta donde vive el programa (junto
    al .py o al .exe), nunca se pide su ruta por teclado."""
    global MODO_ETIQUETADO, MODELO_IDS, MODEL_FEATURE_NAMES

    print("\n======================================")
    print("  CAPTURA EN VIVO CON MODELO (IA)      ")
    print("======================================")

    modelo, ruta_modelo = cargar_modelo_ids()
    if modelo is None:
        print(f"[-] No se encontró (o no se pudo cargar) el modelo en: {ruta_modelo}")
        print("[-] Coloca 'modelo_rf_ids.joblib' en la misma carpeta que el programa e inténtalo de nuevo.")
        return
    print(f"[+] Modelo cargado desde: {ruta_modelo}")

    MODELO_IDS = modelo
    MODO_ETIQUETADO = "modelo"
    MODEL_FEATURE_NAMES = None  # se recalcula para este modelo

    print("[*] ¿Dónde deseas guardar los archivos generados (CSV, pcap, log)?")
    print("[*] (Presiona ENTER sin escribir nada para guardarlos en la carpeta actual)")
    ruta = input("\n[?] Ruta de guardado: ").strip()

    if not ruta:
        ruta = os.path.join(_ruta_base_programa(), "Capturas")

    nombre_csv = input(f"[?] Nombre del archivo CSV (ENTER = '{CONFIG['csv_file']}'): ").strip()
    nombre_pcap = input(f"[?] Nombre del archivo PCAP (ENTER = '{CONFIG['pcap_file']}'): ").strip()
    csv_file = _sanitizar_nombre_archivo(nombre_csv, CONFIG["csv_file"], ".csv")
    pcap_file = _sanitizar_nombre_archivo(nombre_pcap, CONFIG["pcap_file"], ".pcap")

    try:
        os.makedirs(ruta, exist_ok=True)
        print(f"\n[+] Los datos se guardarán en: {ruta}")
        print(f"[+] CSV:  {csv_file}")
        print(f"[+] PCAP: {pcap_file}")
    except Exception as e:
        print(f"[-] Error al intentar acceder/crear la ruta: {e}")
        MODO_ETIQUETADO = "manual"
        MODELO_IDS = None
        return

    try:
        Analyzer(output_dir=ruta, csv_file=csv_file, pcap_file=pcap_file).run()
    finally:
        # NUEVO: al terminar se vuelve al modo manual por defecto, para no afectar la
        # opción de captura en vivo normal del menú (run()) si se usa después.
        MODO_ETIQUETADO = "manual"
        MODELO_IDS = None

if __name__ == "__main__":
    run()
