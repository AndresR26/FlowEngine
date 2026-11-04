import os
import subprocess
import sys
import shutil
import platform

def verificar_pyinstaller():
    try:
        import PyInstaller
        print("[+] PyInstaller detectado.")
    except ImportError:
        print("[-] PyInstaller no encontrado. Instalando...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def limpiar_directorios():
    for carpeta in ["build", "dist"]:
        if os.path.exists(carpeta):
            shutil.rmtree(carpeta)
            print(f"[*] Carpeta vieja '{carpeta}' eliminada.")
            
    # Limpiar archivos .spec residuales
    for spec in ["FlowEngine.spec", "SensorAgente.spec", "Detector de intrusiones.spec"]:
        if os.path.exists(spec):
            os.remove(spec)

def compilar_flow_engine():
    print(f"\n[*] Compilando Flow Engine (Main/Director)... Por favor espera.")
    comando = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        "--name", "FlowEngine", 
        "flow_engine.py"
    ]
    subprocess.run(comando, check=True)
    print("[+] FlowEngine compilado exitosamente.")

def compilar_agente():
    print(f"\n[*] Compilando Agente Persistente (Sensor)... Por favor espera.")
    comando = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        "--noconsole",
        "--name", "SensorAgente",
        "agente_persistente.py"
    ]
    subprocess.run(comando, check=True)
    print("[+] SensorAgente compilado exitosamente.")

def construir_todo():
    system_os = platform.system().lower()
    
    print("==========================================")
    print("   🛠️  CONSTRUCTOR DE LABORATORIO IDS 🛠️")
    print(f"   OS Detectado: {system_os.upper()}")
    print("==========================================\n")

    verificar_pyinstaller()
    limpiar_directorios()

    try:
        if os.path.exists("flow_engine.py"):
            compilar_flow_engine()
        else:
            print("[!] ADVERTENCIA: No se encontró 'flow_engine.py'.")

        if os.path.exists("agente_persistente.py"):
            compilar_agente()
        else:
            print("[!] ADVERTENCIA: No se encontró 'agente_persistente.py'.")
            
        print("\n==========================================")
        print("  ✅ COMPILACIÓN EXITOSA ✅")
        print("==========================================")
        
        if system_os == "windows":
            print("[!] Ejecutables creados en la carpeta 'dist/':")
            print("    -> FlowEngine.exe")
            print("    -> SensorAgente.exe")
        else:
            print("[!] Binarios creados en la carpeta 'dist/'.")
            print("[!] Recuerda darles permisos de ejecución (chmod +x).")

    except subprocess.CalledProcessError:
        print("\n[!] ERROR FATAL: Ocurrió un problema en la compilación de PyInstaller.")
        sys.exit(1)

if __name__ == "__main__":
    construir_todo()
