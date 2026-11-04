import socket
import subprocess
import sys
import os
import threading
import json
import logging
import time  # <-- IMPORTANTE PARA EL TEMPORIZADOR

# ========================================================================
# 1. RESOLUCIÓN DEL DIRECTORIO BASE
# ========================================================================
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.chdir(BASE_DIR)

# ========================================================================
# 2. CONFIGURACIÓN DE LOGS Y CONSTANTES
# ========================================================================
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "sensor_agente.log"),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

PUERTO_TCP_COMANDOS = 50050
PUERTO_UDP_DESCUBRIMIENTO = 51500
def _cargar_token_red(por_defecto="MI_TOKEN_SECRETO_123"):
    """Token compartido de la red Director/Agentes. Orden de búsqueda:
    1) variable de entorno FLOWENGINE_TOKEN, 2) archivo 'token_red.txt' junto al
    programa (.py o .exe), 3) valor por defecto (solo para pruebas: es público)."""
    token = os.environ.get("FLOWENGINE_TOKEN", "").strip()
    if token:
        return token
    base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    ruta = os.path.join(base, "token_red.txt")
    try:
        with open(ruta, encoding="utf-8") as f:
            token = f.read().strip()
        if token:
            return token
    except OSError:
        pass
    return por_defecto

TOKEN_RED = _cargar_token_red()

def iniciar_motor_captura(duracion, ip_director, id_captura):
    """Lanza FlowEngine asegurando compatibilidad si es EXE o PY."""
    if getattr(sys, 'frozen', False):
        # CORREGIDO: en Linux el binario compilado no lleva extensión .exe
        nombre_binario = "FlowEngine.exe" if os.name == "nt" else "FlowEngine"
        ruta_motor = os.path.join(BASE_DIR, nombre_binario)
        comando = [ruta_motor, "--captura-remota", "--duracion", str(duracion), "--director-ip", ip_director, "--id", id_captura]
    else:
        ruta_motor = os.path.join(BASE_DIR, "flow_engine.py")
        comando = [sys.executable, ruta_motor, "--captura-remota", "--duracion", str(duracion), "--director-ip", ip_director, "--id", id_captura]

    if not os.path.exists(ruta_motor):
        logging.error(f"¡ERROR CRÍTICO! No se encontró el motor de captura en: {ruta_motor}")
        return

    logging.info(f"Ejecutando motor: {' '.join(comando)}")
    try:
        subprocess.Popen(comando)
    except Exception as e:
        logging.error(f"Error al lanzar el motor de captura: {e}")

def cuenta_regresiva_captura(delay, duracion, ip_director, id_captura):
    """Espera el tiempo programado y luego ejecuta la captura."""
    logging.info(f"Cuenta regresiva iniciada: Esperando {delay} segundos...")
    time.sleep(delay)
    logging.info("Tiempo de espera finalizado. Iniciando captura programada.")
    iniciar_motor_captura(duracion, ip_director, id_captura)

# ========================================================================
# 3. MÓDULO UDP: DESCUBRIMIENTO
# ========================================================================
def escuchar_descubrimiento_udp():
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    try:
        sock_udp.bind(('0.0.0.0', PUERTO_UDP_DESCUBRIMIENTO))
        logging.info(f"[*] Hilo UDP activo en el puerto {PUERTO_UDP_DESCUBRIMIENTO}")
        while True:
            datos, addr = sock_udp.recvfrom(1024)
            try:
                paquete = json.loads(datos.decode('utf-8').strip())
                if paquete.get("token") == TOKEN_RED and paquete.get("accion") == "ping":
                    respuesta = json.dumps({"estado": "activo", "hostname": socket.gethostname(), "puerto_tcp": PUERTO_TCP_COMANDOS})
                    sock_udp.sendto(respuesta.encode('utf-8'), addr)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logging.critical(f"Fallo UDP: {e}")
    finally:
        sock_udp.close()

# ========================================================================
# 4. MÓDULO TCP: RECEPCIÓN DE COMANDOS
# ========================================================================
def manejar_conexion(conn, addr):
    try:
        datos = conn.recv(1024).decode('utf-8')
        if not datos: return
        comando_recibido = json.loads(datos)
        
        if comando_recibido.get("token") != TOKEN_RED:
            return

        accion = comando_recibido.get("accion")
        duracion = comando_recibido.get("duracion", 60)
        ip_director = comando_recibido.get("director_ip", addr[0]) 
        id_captura = comando_recibido.get("id_captura", "remota")

        if accion == "capturar":
            logging.info(f"Orden Inmediata: ID '{id_captura}', {duracion}s")
            iniciar_motor_captura(duracion, ip_director, id_captura)
            respuesta = json.dumps({"estado": "ok", "mensaje": "Captura iniciada en el sensor"})
            conn.send(respuesta.encode('utf-8'))
            
        elif accion == "capturar_programada":
            # CORREGIDO: el Director envía "retraso_segundos"; antes se leía "delay_segundos"
            # y toda captura programada arrancaba a los 60 s por defecto.
            delay = comando_recibido.get("retraso_segundos", comando_recibido.get("delay_segundos", 60))
            try:
                delay = max(0, int(delay))
            except (TypeError, ValueError):
                delay = 60
            logging.info(f"Orden Programada: ID '{id_captura}', {duracion}s, ESPERA de {delay}s")
            
            # Lanzamos un hilo separado para que cuente el tiempo sin bloquear el servidor
            hilo_timer = threading.Thread(target=cuenta_regresiva_captura, args=(delay, duracion, ip_director, id_captura), daemon=True)
            hilo_timer.start()
            
            respuesta = json.dumps({"estado": "ok", "mensaje": f"Captura programada para iniciar en {delay} segundos."})
            conn.send(respuesta.encode('utf-8'))
            
    except Exception as e:
        logging.error(f"Error conexión {addr[0]}: {e}")
    finally:
        conn.close()

def iniciar_servidor_tcp():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    try:
        servidor.bind(('0.0.0.0', PUERTO_TCP_COMANDOS))
        servidor.listen(5)
        logging.info(f"=== Agente Iniciado (TCP Puerto {PUERTO_TCP_COMANDOS}) ===")
        while True:
            conn, addr = servidor.accept()
            threading.Thread(target=manejar_conexion, args=(conn, addr)).start()
    except Exception as e:
        logging.critical(f"Fallo TCP: {e}")
    finally:
        servidor.close()

if __name__ == "__main__":
    threading.Thread(target=escuchar_descubrimiento_udp, daemon=True).start()
    iniciar_servidor_tcp()
