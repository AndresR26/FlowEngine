import socket
import json
import threading
import time
import os
import struct
import datetime
import sys
import re

PUERTO_UDP_DESCUBRIMIENTO = 51500
PUERTO_TCP_RECEPCION_REPORTES = 51502
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
CARPETA_CAPTURAS_REMOTAS = "capturas_remotas"

def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _recibir_exacto(conn, n):
    """Lee exactamente n bytes del socket (recv() puede devolver menos)."""
    datos = b""
    while len(datos) < n:
        chunk = conn.recv(n - len(datos))
        if not chunk:
            break
        datos += chunk
    return datos


def _nombre_seguro(nombre):
    """Deja solo el nombre de archivo (sin carpetas) y quita caracteres inválidos."""
    nombre = str(nombre or "captura.csv").replace("\\", "/").split("/")[-1]
    nombre = re.sub(r'[<>:"|?*\x00-\x1f]', "_", nombre).strip(" .")
    return nombre or "captura.csv"


class DirectorRed:
    def __init__(self):
        self.ip_director = obtener_ip_local()
        if not os.path.exists(CARPETA_CAPTURAS_REMOTAS):
            os.makedirs(CARPETA_CAPTURAS_REMOTAS)

    def descubrir_agentes(self, tiempo_espera=3):
        agentes_encontrados = []
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock_udp.settimeout(tiempo_espera)
        
        mensaje_ping = json.dumps({"accion": "ping", "token": TOKEN_RED}).encode('utf-8')
        print(f"\n[*] Buscando agentes en la red (UDP Broadcast Puerto {PUERTO_UDP_DESCUBRIMIENTO})...")
        
        try:
            sock_udp.sendto(mensaje_ping, ('255.255.255.255', PUERTO_UDP_DESCUBRIMIENTO))
            while True:
                try:
                    datos, addr = sock_udp.recvfrom(1024)
                    respuesta = json.loads(datos.decode('utf-8'))
                    if respuesta.get("estado") == "activo":
                        agentes_encontrados.append({
                            "ip": addr[0],
                            "hostname": respuesta.get("hostname", "Desconocido"),
                            "puerto_tcp": respuesta.get("puerto_tcp", 50050)
                        })
                except socket.timeout:
                    break
                except json.JSONDecodeError:
                    pass
        finally:
            sock_udp.close()
        return agentes_encontrados

    def enviar_orden_captura(self, agente, duracion, id_captura, delay_segundos=0, fecha_str=""):
        comando = {
            "accion": "capturar_programada" if delay_segundos > 0 else "capturar",
            "token": TOKEN_RED,
            "duracion": duracion,
            "director_ip": self.ip_director,
            "id_captura": id_captura
        }
        
        if delay_segundos > 0:
            comando["retraso_segundos"] = delay_segundos
            comando["fecha_ejecucion"] = fecha_str

        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.settimeout(10) 
        
        try:
            sock_tcp.connect((agente['ip'], agente['puerto_tcp']))
            sock_tcp.send(json.dumps(comando).encode('utf-8'))
            respuesta_raw = sock_tcp.recv(1024).decode('utf-8')
            
            if respuesta_raw:
                if delay_segundos > 0:
                    print(f"[+] Orden enviada a {agente['hostname']}. Ejecución programada para: {fecha_str}")
                else:
                    print(f"[+] Orden de captura instantánea enviada exitosamente a {agente['hostname']}.")
                    
        except Exception as e:
            print(f"[!] Fallo de conexión con {agente['ip']}: {e}")
        finally:
            sock_tcp.close()

    def iniciar_receptor_reportes(self):
        """Servidor TCP para recibir los archivos procesados por los agentes."""
        def escuchar():
            servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                servidor.bind(('0.0.0.0', PUERTO_TCP_RECEPCION_REPORTES))
                servidor.listen(10)
                print(f"\n[*] Receptor TCP activo en el puerto {PUERTO_TCP_RECEPCION_REPORTES}...")
                while True:
                    conn, addr = servidor.accept()
                    threading.Thread(target=self.manejar_recepcion_archivo, args=(conn, addr)).start()
            except Exception as e:
                pass
            finally:
                servidor.close()
        threading.Thread(target=escuchar, daemon=True).start()

    def manejar_recepcion_archivo(self, conn, addr):
        try:
            raw_metadata_len = _recibir_exacto(conn, 4)
            if len(raw_metadata_len) < 4: return
            metadata_len = struct.unpack('>I', raw_metadata_len)[0]
            if metadata_len > 64 * 1024:
                print(f"[-] Metadatos inválidos recibidos de {addr[0]}; conexión descartada.")
                return
            metadata = json.loads(_recibir_exacto(conn, metadata_len).decode('utf-8'))

            # CORREGIDO: solo se aceptan archivos de agentes con el token de la red
            if metadata.get("token") != TOKEN_RED:
                print(f"[-] Archivo rechazado de {addr[0]}: token inválido.")
                return

            # CORREGIDO: el nombre llega del cliente; se limpia para no escribir fuera de la carpeta
            nombre_final = f"{addr[0]}_{_nombre_seguro(metadata.get('nombre_archivo'))}"
            ruta = os.path.join(CARPETA_CAPTURAS_REMOTAS, nombre_final)
            bytes_recibidos, tamano = 0, int(metadata.get("tamano", 0))

            with open(ruta, 'wb') as f:
                while bytes_recibidos < tamano:
                    chunk = conn.recv(min(tamano - bytes_recibidos, 4096))
                    if not chunk: break
                    f.write(chunk)
                    bytes_recibidos += len(chunk)
            if bytes_recibidos < tamano:
                print(f"[-] Transferencia incompleta desde {addr[0]} ({bytes_recibidos}/{tamano} bytes): {ruta}")
            else:
                print(f"\n[+] Archivo recibido exitosamente de {addr[0]}: {ruta}")
        except Exception as e:
            print(f"[-] Error recibiendo archivo: {e}")
        finally:
            conn.close()


def menu_captura_instantanea(director_red):
    print("\n======================================")
    print("      CAPTURA INSTANTÁNEA REMOTA      ")
    print("======================================")
    agentes = director_red.descubrir_agentes()
    
    if not agentes:
        print("[-] No se detectaron agentes en la red.")
        return
        
    print(f"\n[+] Se encontraron {len(agentes)} agentes activos.")
    for i, ag in enumerate(agentes):
        print(f"    {i+1}. {ag['hostname']} ({ag['ip']})")
        
    try:
        duracion = int(input("\n[?] Duración de la captura en segundos (ej. 60): ") or "60")
    except ValueError:
        duracion = 60
    id_cap = input("[?] ID de la captura (ej. prueba_01): ") or "prueba_01"
    
    print("\n[*] Enviando órdenes...")
    for agente in agentes:
        director_red.enviar_orden_captura(agente, duracion, id_cap, delay_segundos=0)


def menu_programar_captura(director_red):
    print("\n--- PROGRAMAR CAPTURA REMOTA ---")
    agentes = director_red.descubrir_agentes()
    if not agentes: return
    
    while True:
        print("\n[!] IMPORTANTE: Usa reloj de 24 horas (Ej: para 8:30 PM escribe 20:30)")
        fecha_input = input("[?] Fecha y hora de inicio (YYYY-MM-DD HH:MM): ")
        try:
            fecha_objetivo = datetime.datetime.strptime(fecha_input, "%Y-%m-%d %H:%M")
            ahora = datetime.datetime.now()
            delay_segundos = int((fecha_objetivo - ahora).total_seconds())
            
            if delay_segundos <= 0:
                print(f"[-] La fecha/hora ingresada ({fecha_objetivo}) es anterior a la hora actual del sistema ({ahora.strftime('%Y-%m-%d %H:%M')}).")
                print("[-] Asegúrate de estar usando el formato de 24 horas si es de tarde/noche.")
                continue
            break
        except ValueError:
            print("[-] Formato inválido. Asegúrate de usar el formato YYYY-MM-DD HH:MM (Ej: 2026-09-02 21:15).")

    duracion = int(input("[?] Duración (s): ") or "60")
    id_cap = input("[?] ID de captura: ") or "prog_01"
    
    for agente in agentes:
        director_red.enviar_orden_captura(agente, duracion, id_cap, delay_segundos, fecha_input)


def ejecutar_captura_y_reportar(funcion_captura, carpeta_capturas, director_ip, duracion, id_captura):
    """Ejecutado por el agente: captura y envía el archivo al PC Director."""
    print(f"[*] Iniciando captura nativa IA por {duracion}s...")
    nombre_pcap = f"remoto_{id_captura}_{int(time.time())}.pcap"
    
    try:
        archivo_generado = funcion_captura(duracion, carpeta_capturas, id_captura, nombre_pcap) 
    except Exception as e:
        print(f"[-] Error en captura local: {e}")
        return

    if not archivo_generado or not os.path.exists(archivo_generado): return

    nombre_archivo = os.path.basename(archivo_generado)
    tamano_archivo = os.path.getsize(archivo_generado)
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((director_ip, PUERTO_TCP_RECEPCION_REPORTES))
        
        metadata = json.dumps({"nombre_archivo": nombre_archivo, "tamano": tamano_archivo,
                               "token": TOKEN_RED}).encode('utf-8')
        sock.sendall(struct.pack('>I', len(metadata)))
        sock.sendall(metadata)
        
        with open(archivo_generado, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk: break
                sock.sendall(chunk)
                
        print("[+] CSV transferido exitosamente vía TCP al Director.")
    except Exception as e:
        print(f"[!] Falló la transferencia TCP: {e}")
    finally:
        if sock is not None:
            sock.close()
