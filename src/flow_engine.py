import os
import sys
import subprocess
import shutil
import platform
import time
import argparse
import warnings

warnings.filterwarnings("ignore", message=".*TLS cipher suite not usable.*")
warnings.filterwarnings("ignore", message=".*Unknown cipher suite.*")

# Instalador de librerías Python (se ejecuta primero)
import importlib.util

def instalar_dependencias_python():
    # Si el script está compilado como ejecutable (.exe), no intentar usar pip
    if getattr(sys, 'frozen', False):
        return

    dependencias = {
        "scapy": "scapy", 
        "numpy": "numpy", 
        "pandas": "pandas", 
        "cryptography": "cryptography",
        "scikit-learn": "scikit-learn",
        "joblib": "joblib"
    }
        # pyftpdlib eliminado ya que ahora usamos Sockets TCP nativos
    
    for modulo, paquete in dependencias.items():
        if importlib.util.find_spec(modulo) is None:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", paquete], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                print(f"[-] Advertencia: No se pudo instalar '{paquete}' automáticamente.")

# Importación de módulos del proyecto
import live_conf
import pcap_conf
import advanced_dataset_filters
import red_distribuida

def check_and_install_tools():
    system_os = platform.system().lower()
    print(f"\n[*] Iniciando GENERADOR...")
    print(f"[*] Sistema operativo detectado: {system_os.capitalize()}")

    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    # ==========================================
    # LÓGICA PARA WINDOWS 
    # ==========================================
    if system_os == "windows":
        npcap_path = r"C:\Windows\System32\Npcap"
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        
        npcap_installer = os.path.join(base_path, "npcap-1.88.exe")
        nmap_installer = os.path.join(base_path, "nmap-7.99-setup.exe")

        if not os.path.exists(npcap_path):
            print("[-] Npcap no detectado. Es vital para capturar tráfico.")
            if os.path.exists(npcap_installer):
                print(f"[+] Iniciando instalador: {os.path.basename(npcap_installer)}")
                subprocess.run([npcap_installer], shell=True)
            else:
                print(f"[!] ERROR: No se encontró '{os.path.basename(npcap_installer)}' junto a este programa.")
                time.sleep(3)
        else:
            print("[+] Npcap detectado y listo.")

        if not os.path.exists(nmap_path):
            print("[-] Nmap no detectado.")
            if os.path.exists(nmap_installer):
                print(f"[+] Iniciando instalador: {os.path.basename(nmap_installer)}")
                subprocess.run([nmap_installer], shell=True)
            else:
                print(f"[!] ADVERTENCIA: No se encontró '{os.path.basename(nmap_installer)}'.")
        else:
            print("[+] Nmap detectado y listo.")

    # ==========================================
    # LÓGICA PARA LINUX
    # ==========================================
    elif system_os == "linux":
        if os.geteuid() != 0:
            print("[!] ADVERTENCIA CRÍTICA: En Linux necesitas permisos de root.")
            print("[!] Cierra esto y ejecuta: sudo ./FlowEngine")
            sys.exit(1)
            
        if not shutil.which("nmap") or not shutil.which("tcpdump"):
            print("[-] Herramientas nativas (Nmap/tcpdump) no detectadas.")
            print("[*] Intentando instalar vía 'apt'...")
            try:
                subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["apt-get", "install", "-y", "nmap", "tcpdump"], check=True)
                print("[+] Herramientas instaladas correctamente.")
            except subprocess.CalledProcessError:
                print("[!] Falló la instalación automática. Instálalas manualmente.")
        else:
            print("[+] Herramientas de red nativas listas.")

    print("[+] Verificación de sistema completada.\n")
    time.sleep(1)

MODULES = {
    "1": live_conf,
    "2": pcap_conf,
    "3": advanced_dataset_filters
}

director_red = red_distribuida.DirectorRed()

def preparar_red_distribuida():
    """Restaura el servidor TCP local en el PC Director para recibir reportes."""
    global director_red
    director_red = red_distribuida.DirectorRed()
    director_red.iniciar_receptor_reportes()

def ejecutar_modo_captura_remota():
    import argparse
    import time
    parser = argparse.ArgumentParser(description="Modo Captura Remota FlowEngine")
    parser.add_argument("--captura-remota", action="store_true")
    parser.add_argument("--duracion", type=int, default=60)
    parser.add_argument("--id", dest="id_captura", default="sin_id")
    parser.add_argument("--director-ip", dest="ip_destino", required=True) 
    
    args, _ = parser.parse_known_args()

    print("======================================")
    print("     FLOW ENGINE -- CAPTURA REMOTA")
    print("======================================")
    print(f"[*] ID Captura   : {args.id_captura}")
    print(f"[*] Duración     : {args.duracion}s")
    print(f"[*] IP Director  : {args.ip_destino}")
    print("======================================")

    # Vuelve a utilizar director_ip en lugar de ip_pico
    red_distribuida.ejecutar_captura_y_reportar(
        funcion_captura=live_conf.capturar_remoto,
        carpeta_capturas=red_distribuida.CARPETA_CAPTURAS_REMOTAS,
        director_ip=args.ip_destino, 
        duracion=args.duracion,
        id_captura=args.id_captura,
    )
    
    print("\n[*] Captura remota finalizada exitosamente.")
    time.sleep(3)
def menu_principal():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("======================================")
        print("         🛡️ GENERADOR DATASET 🛡️         ")
        print("======================================")
        print("1. Iniciar Captura en Vivo (Manual)")
        print("2. Iniciar Captura en Vivo (Automática con IA)")
        print("3. Procesar Archivos PCAP")
        print("4. Aplicar Filtros Avanzados (Dataset)")
        print("5. Programar Captura Remota")
        print("6. Captura Instantánea Remota")
        print("0. Salir")
        print("======================================")
        
        opcion = input("\n[?] Selecciona una opción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            try: live_conf.run() 
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        elif opcion == "2":
            try: live_conf.run_ia() 
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        elif opcion == "3":
            try: pcap_conf.run() 
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        elif opcion == "4":
            try: advanced_dataset_filters.run() 
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        elif opcion == "5":
            try: red_distribuida.menu_programar_captura(director_red)
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        elif opcion == "6":
            try: red_distribuida.menu_captura_instantanea(director_red)
            except Exception as e: print(f"\n[!] Error: {e}")
            input("\n[!] Presiona ENTER para volver al menú...")
        else:
            time.sleep(1)

if __name__ == "__main__":
    if "--captura-remota" in sys.argv:
        ejecutar_modo_captura_remota()
    else:
        check_and_install_tools()
        preparar_red_distribuida()
        menu_principal()
