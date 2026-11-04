# Manual de Usuario — FlowEngine

> **English version:** [../en/user_manual.md](../en/user_manual.md)

Esta guía explica, paso a paso y sin tecnicismos, cómo usar **FlowEngine** una vez que ya tienes los programas compilados (`FlowEngine.exe` y `SensorAgente.exe`).

---

## Contenido

1. [¿Qué hace este programa?](#1-qué-hace-este-programa)
2. [Antes de empezar](#2-antes-de-empezar)
3. [Abrir el programa por primera vez](#3-abrir-el-programa-por-primera-vez)
4. [El menú principal](#4-el-menú-principal)
5. [Opción 1 — Captura en vivo (manual)](#5-opción-1--captura-en-vivo-manual)
6. [Opción 2 — Captura en vivo con IA](#6-opción-2--captura-en-vivo-con-ia)
7. [Opción 3 — Procesar un archivo PCAP](#7-opción-3--procesar-un-archivo-pcap)
8. [Opción 4 — Filtrar el dataset](#8-opción-4--filtrar-el-dataset)
9. [Capturar desde varios computadores (opciones 5 y 6)](#9-capturar-desde-varios-computadores-opciones-5-y-6)
10. [¿Dónde quedan mis archivos?](#10-dónde-quedan-mis-archivos)
11. [Problemas frecuentes](#11-problemas-frecuentes)
12. [Glosario](#12-glosario)

---

## 1. ¿Qué hace este programa?

FlowEngine **observa el tráfico de tu red** (las "conversaciones" entre computadores) y lo guarda en una **tabla de Excel (CSV)**. Cada fila de la tabla es una conversación y tiene una **etiqueta** que dice qué tipo de tráfico era (por ejemplo `normal` o `ataque`).

Esa tabla sirve para entrenar o probar una inteligencia artificial que detecta ataques.

Puedes:
- ✅ Grabar el tráfico **en este momento** y etiquetarlo tú mismo.
- ✅ Dejar que la **IA lo etiquete sola**.
- ✅ Convertir una **grabación antigua** (archivo `.pcap`) en tabla.
- ✅ **Filtrar** la tabla para quedarte solo con lo que te interesa.
- ✅ Ordenar a **otros computadores** de la red que graben al mismo tiempo y te envíen sus tablas.

---

## 2. Antes de empezar

### En el computador principal (Director)

Pon estos archivos **juntos en la misma carpeta**:

| Archivo | ¿Obligatorio? | Para qué |
|---|---|---|
| `FlowEngine.exe` | ✅ Sí | El programa |
| `npcap-1.88.exe` | ✅ Sí (si no tienes Npcap) | Permite "escuchar" la red |
| `modelo_rf_ids.joblib` | Solo para la opción 2 | El "cerebro" de la IA |
| `nmap-7.99-setup.exe` | Opcional | Herramienta de red adicional |
| `token_red.txt` | Recomendado | La "contraseña" que comparten el Director y los Agentes (ver §9.1) |

### En cada computador que va a grabar a distancia (Agente)

| Archivo | ¿Obligatorio? |
|---|---|
| `SensorAgente.exe` | ✅ Sí |
| `FlowEngine.exe` | ✅ Sí |
| `modelo_rf_ids.joblib` | ✅ Sí |
| `npcap-1.88.exe` | ✅ Sí (si no tienes Npcap) |
| `token_red.txt` | Recomendado (el mismo del Director) |

> 💡 Todos los computadores deben estar conectados **a la misma red** (el mismo router o WiFi).

---

## 3. Abrir el programa por primera vez

### En Windows

1. Haz **clic derecho** sobre `FlowEngine.exe`.
2. Elige **"Ejecutar como administrador"** y acepta el aviso.
3. Si es la primera vez, se abrirá el instalador de **Npcap**:
   - Pulsa **"I Agree"**.
   - ⚠️ **Marca la casilla "Install Npcap in WinPcap API-compatible Mode"**.
   - Pulsa **Install** y luego **Finish**.
4. **Cierra FlowEngine y vuelve a abrirlo** (como administrador). Esto solo se hace una vez.

### En Linux

Abre una terminal en la carpeta del programa y escribe:

```bash
chmod +x FlowEngine
sudo ./FlowEngine
```

El programa instalará solo lo que le falte.

Si todo está bien verás:

```text
[*] Iniciando GENERADOR...
[*] Sistema operativo detectado: Windows
[+] Npcap detectado y listo.
[+] Nmap detectado y listo.
[+] Verificación de sistema completada.
```

---

## 4. El menú principal

```text
======================================
         GENERADOR DATASET
======================================
1. Iniciar Captura en Vivo (Manual)
2. Iniciar Captura en Vivo (Automática con IA)
3. Procesar Archivos PCAP
4. Aplicar Filtros Avanzados (Dataset)
5. Programar Captura Remota
6. Captura Instantánea Remota
0. Salir
======================================
[?] Selecciona una opción:
```

**Escribe el número** de lo que quieres hacer y pulsa **Enter**.
Al terminar cualquier opción, pulsa **Enter** para volver a este menú.

| Quiero… | Opción |
|---|---|
| Grabar tráfico y ponerle yo las etiquetas | **1** |
| Grabar tráfico y que la IA ponga las etiquetas | **2** |
| Convertir una grabación `.pcap` en tabla | **3** |
| Limpiar o filtrar una tabla | **4** |
| Que otros PCs graben a una hora concreta | **5** |
| Que otros PCs graben ya mismo | **6** |
| Cerrar el programa | **0** |

---

## 5. Opción 1 — Captura en vivo (manual)

Úsala cuando tú sabes qué tipo de tráfico está pasando en cada momento (por ejemplo, durante una prueba de laboratorio).

**Paso 1.** Escribe `1` y pulsa Enter.

**Paso 2.** El programa te pregunta tres cosas. Si pulsas **Enter sin escribir nada**, usa la opción por defecto:

| Pregunta | Qué escribir | Si pulsas Enter |
|---|---|---|
| `Ruta de guardado` | Una carpeta, por ejemplo `C:\Datos\Prueba1` | Carpeta `Capturas` junto al programa |
| `Nombre del archivo CSV` | Ej. `lunes_mañana` | `live_resultado.csv` |
| `Nombre del archivo PCAP` | Ej. `lunes_mañana` | `captura.pcap` |

**Paso 3.** La grabación empieza. La etiqueta inicial es **`normal`**:

```text
    LIVE - Interfaz activa: Wi-Fi
[*] Escribe una etiqueta (Ej: 'dos') y presiona Enter. Escribe 'stop' o 'salir' para detener.
[*] Etiqueta actual: 'normal'
```

**Paso 4.** Cuando cambie el tipo de tráfico, **escribe la nueva etiqueta y pulsa Enter**. Por ejemplo, al iniciar un ataque de prueba escribe `dos`; cuando termine, escribe `normal`.

```text
dos
[+] Etiqueta cambiada a: 'dos'
[*] 12 flujo(s) en curso se cerraron con la etiqueta anterior.
```

> 💡 Usa siempre las **mismas palabras** para el mismo tipo de tráfico (todo en minúsculas): `normal`, `dos`, `escaneo`, `fuerza_bruta`…

**Paso 5.** Para terminar escribe **`stop`** (o `salir`) y pulsa Enter. También puedes pulsar **Ctrl + C**.

```text
[+] Tráfico crudo guardado en: C:\...\Capturas\captura.pcap
[+] Log de etiquetas (con timestamp) guardado en: C:\...\Capturas\labels_log.csv
[+] Regresando al menú principal...
```

---

## 6. Opción 2 — Captura en vivo con IA

Igual que la opción 1, pero **no tienes que escribir etiquetas**: la IA decide sola qué es cada conversación.

1. Comprueba que `modelo_rf_ids.joblib` está **en la misma carpeta** que `FlowEngine.exe`.
2. Escribe `2` y pulsa Enter.
3. Debe aparecer: `[+] Modelo cargado desde: ...`
4. Responde las mismas tres preguntas de la opción 1 (o pulsa Enter).
5. Deja que grabe. Para terminar escribe **`stop`** y pulsa Enter.

> Si escribes otra palabra durante la captura, el programa te recordará que la IA está etiquetando sola.

---

## 7. Opción 3 — Procesar un archivo PCAP

Úsala si ya tienes una grabación de red (de Wireshark, tcpdump, etc.).

1. Escribe `3` y pulsa Enter.
2. Se abre una ventana: **elige tu archivo** `.pcap` o `.pcapng`.
3. Se abre otra ventana: **elige la carpeta** donde guardar la tabla.
4. Escribe un nombre para la tabla o pulsa Enter (se llamará `pcap_resultado1.csv`).
5. Espera. Verás el avance cada 10 000 paquetes:

```text
[*] Paquetes procesados: 10000
[*] Paquetes procesados: 20000
```

> La tabla que sale de un PCAP **no trae columna `Label`** (no hay nadie etiquetando). Puedes añadirla después en Excel, o con la opción 4 → *Crear variable* (por ejemplo nombre `Label`, expresión `'normal'`).

---

## 8. Opción 4 — Filtrar el dataset

Sirve para quedarte solo con las filas que te interesan o crear columnas nuevas.

1. Escribe `4` y pulsa Enter.
2. Se abre una ventana: **elige tu archivo CSV**.
3. Verás un pequeño menú:

```text
==========================
1 Ver columnas
2 Crear variable
3 Aplicar filtro
4 Guardar dataset
5 Salir
==========================
```

### 1 · Ver columnas
Muestra los nombres de todas las columnas. Úsalo para saber cómo se escriben.

### 3 · Aplicar filtro
Escribe la condición. Ejemplos listos para copiar:

| Quiero quedarme con… | Escribe |
|---|---|
| Solo tráfico TCP | `tcp` |
| Solo tráfico UDP | `udp` |
| Lo que usa el puerto 80 (web), de ida o de vuelta | `tcp.port == 80` |
| Lo que sale de un equipo | `ip.src == '192.168.1.10'` |
| Lo que llega a un equipo | `ip.dst == '192.168.1.20'` |
| Solo filas etiquetadas "dos" | `Label == 'dos'` |
| TCP con paquetes grandes | `tcp && \`Pkt Size Mean\` > 500` |
| HTTP o HTTPS | `tcp.port == 80 \|\| tcp.port == 443` |
| Consultas DNS | `udp.port == 53` |

> ⚠️ Si el nombre de la columna tiene **espacios**, escríbelo entre acentos graves: `` `Src Bytes` ``.
> Los textos van entre comillas simples: `'192.168.1.10'`.

Puedes aplicar varios filtros seguidos; cada uno se suma al anterior.

### 2 · Crear variable
Crea una columna nueva a partir de otras. Ejemplo:
- Nombre: `bytes_por_segundo_origen`
- Expresión: `` `Src Bytes` / `Flow Duration` ``

### 4 · Guardar dataset
Guarda el resultado como **`dataset_filtrado_avanzado.csv`** en la misma carpeta del archivo original.

### 5 · Salir
Vuelve al menú principal. **Si no guardaste (opción 4), los cambios se pierden.**

---

## 9. Capturar desde varios computadores (opciones 5 y 6)

Con esto, desde **un solo PC (Director)** puedes ordenar a **otros PCs (Agentes)** que graben su tráfico. Cuando terminan, te envían su tabla automáticamente.

### 9.1 Preparar cada Agente (solo una vez)

**Primero, la "contraseña" de la red (token).** El Director y los Agentes solo se obedecen entre sí si comparten la misma palabra secreta:

1. Crea un archivo de texto llamado **`token_red.txt`**.
2. Escribe dentro una palabra secreta, por ejemplo `LabRedes-2026-xK9`, y guárdalo.
3. Copia **ese mismo archivo** junto a `FlowEngine.exe` en el Director y junto a `SensorAgente.exe` en cada Agente.

> Si no creas el archivo, el programa usa una contraseña por defecto que es pública. Sirve para pruebas, pero no en una red compartida.

**Después, en cada Agente:**

1. Copia `SensorAgente.exe`, `FlowEngine.exe`, `modelo_rf_ids.joblib` (y `npcap-1.88.exe`) en una carpeta del agente.
2. Abre **una vez** `FlowEngine.exe` como administrador para que instale Npcap, y ciérralo.
3. Haz clic derecho en **`SensorAgente.exe` → Ejecutar como administrador**.
   - No se abre ninguna ventana: **es normal**, trabaja en segundo plano.
   - Para comprobar que está activo, búscalo en el **Administrador de tareas** (Ctrl + Shift + Esc).
4. Si Windows pregunta por el **Firewall**, pulsa **"Permitir acceso"** (redes privadas).

### 9.2 Captura instantánea (opción 6)

En el **Director**:

1. Escribe `6` y pulsa Enter.
2. El programa busca agentes (tarda unos 3 segundos):

```text
[+] Se encontraron 2 agentes activos.
 1. PC-LAB-01 (192.168.1.21)
 2. PC-LAB-02 (192.168.1.22)
```

3. Escribe cuántos **segundos** debe durar la grabación (Enter = 60).
4. Escribe un **nombre** para la captura, por ejemplo `prueba_01` (Enter = `prueba_01`).
5. Listo: todos los agentes empiezan a grabar. Cuando terminen verás:

```text
[+] Archivo recibido exitosamente de 192.168.1.21: capturas_remotas\192.168.1.21_remoto_prueba_01_...csv
```

> ⚠️ **No cierres FlowEngine en el Director** hasta recibir todos los archivos.

### 9.3 Captura programada (opción 5)

Igual que la anterior, pero eliges **cuándo** empezar.

1. Escribe `5` y pulsa Enter.
2. Escribe la fecha y hora con este formato exacto, **en horario de 24 horas**:

```text
AAAA-MM-DD HH:MM        →   2026-11-03 20:30   (8:30 de la noche)
```

3. Escribe la duración en segundos y un nombre.

> 💡 Los agentes empiezan a la hora elegida según el **reloj del Director**. Comprueba que todos los PCs tengan la hora bien puesta.
> No cierres FlowEngine en el Director hasta que lleguen los archivos.

---

## 10. ¿Dónde quedan mis archivos?

| Archivo | Qué es | Dónde |
|---|---|---|
| `*.csv` | **La tabla** con las conversaciones y sus etiquetas. Ábrela con Excel. | La carpeta que elegiste (o `Capturas`) |
| `*.pcap` | La **grabación original** del tráfico. Se abre con Wireshark. | Misma carpeta |
| `labels_log.csv` | El **historial** de cuándo cambiaste cada etiqueta | Misma carpeta |
| `filas_no_guardadas.csv` | Filas que no se pudieron guardar porque la tabla estaba abierta en Excel | Misma carpeta (solo si pasó) |
| `dataset_filtrado_avanzado.csv` | La tabla después de filtrar (opción 4) | Junto al CSV original |
| `capturas_remotas\` | Las tablas que enviaron los agentes | En el Director, junto a `FlowEngine.exe` |

> 💡 **No abras la tabla en Excel mientras se está grabando.** Si lo haces, el programa guarda las filas en otro archivo para no perderlas.

---

## 11. Problemas frecuentes

**❓ Sale "ERROR CRÍTICO DE RED: SCAPY NO DETECTA NPCAP".**
➡️ Cierra el programa y ábrelo de nuevo como administrador. Si sigue igual, desinstala Npcap e instálalo otra vez **marcando "WinPcap API-compatible Mode"**.

**❓ Dice "No se detectaron agentes en la red".**
➡️ Revisa que:
- `SensorAgente.exe` esté abierto en el agente (Administrador de tareas).
- Los dos PCs estén en la **misma red**.
- El firewall del agente permita el programa (o pide a quien administra la red que abra los puertos UDP 51500 y TCP 50050).

**❓ Encontró los agentes pero nunca llega el archivo.**
➡️ El firewall del **Director** debe permitir FlowEngine (puerto TCP 51502). No cierres FlowEngine mientras esperas.

**❓ Dice "No se encontró el modelo IA".**
➡️ Copia `modelo_rf_ids.joblib` en la **misma carpeta** que `FlowEngine.exe` (y en la del agente).

**❓ La columna `Label` dice `error_prediccion`.**
➡️ El modelo no es compatible con esta versión. Pide un modelo entrenado con tablas creadas por FlowEngine.

**❓ Aparece "'archivo' está en uso".**
➡️ La tabla está abierta en Excel. Ciérrala. El programa usará un nombre nuevo automáticamente.

**❓ Al programar una captura dice que la fecha es anterior a la actual.**
➡️ Usa horario de **24 horas**: las 8:30 de la noche son `20:30`.

**❓ Aparece "Archivo rechazado … token inválido".**
➡️ El Agente y el Director tienen contraseñas distintas. Copia el mismo `token_red.txt` en todos los equipos y reinicia `SensorAgente.exe`.

**❓ ¿Cómo apago el agente?**
➡️ Administrador de tareas → busca `SensorAgente.exe` → **Finalizar tarea**.

---

## 12. Glosario

| Palabra | Significado sencillo |
|---|---|
| **Tráfico de red** | Toda la información que los computadores se envían entre sí |
| **Paquete** | Un pedacito de esa información |
| **Flujo** | Una "conversación" entre dos equipos (muchos paquetes juntos) |
| **Etiqueta (Label)** | La palabra que dice qué tipo de tráfico es: `normal`, `dos`… |
| **Dataset / CSV** | La tabla con todos los flujos; se abre con Excel |
| **PCAP** | Archivo con la grabación original del tráfico |
| **IA / modelo** | Programa entrenado que pone las etiquetas solo |
| **Director** | El PC desde el que das las órdenes |
| **Agente / Sensor** | Los PCs que graban cuando el Director lo pide |
| **Npcap** | Programa de Windows que permite escuchar la red |
| **Token** | Contraseña compartida entre el Director y los Agentes (`token_red.txt`) |

---

> 🔒 **Uso responsable:** graba tráfico solo en redes propias o donde tengas permiso.
