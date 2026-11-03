# User Manual — FlowEngine

> **Versión en español:** [../es/manual_usuario.md](../es/manual_usuario.md)

This guide explains, step by step and without jargon, how to use **FlowEngine** once you already have the compiled programs (`FlowEngine.exe` and `SensorAgente.exe`).

> The program's menus and messages are in Spanish. This guide shows them exactly as they appear, with an English explanation next to them.

---

## Contents

1. [What does this program do?](#1-what-does-this-program-do)
2. [Before you start](#2-before-you-start)
3. [Opening the program for the first time](#3-opening-the-program-for-the-first-time)
4. [The main menu](#4-the-main-menu)
5. [Option 1 — Live capture (manual)](#5-option-1--live-capture-manual)
6. [Option 2 — Live capture with AI](#6-option-2--live-capture-with-ai)
7. [Option 3 — Process a PCAP file](#7-option-3--process-a-pcap-file)
8. [Option 4 — Filter the dataset](#8-option-4--filter-the-dataset)
9. [Capturing from several computers (options 5 and 6)](#9-capturing-from-several-computers-options-5-and-6)
10. [Where are my files?](#10-where-are-my-files)
11. [Common problems](#11-common-problems)
12. [Glossary](#12-glossary)

---

## 1. What does this program do?

FlowEngine **watches your network traffic** (the "conversations" between computers) and saves it as a **spreadsheet table (CSV)**. Each row is one conversation and has a **label** saying what kind of traffic it was (for example `normal` or `attack`).

That table is used to train or test an artificial intelligence that detects attacks.

You can:
- ✅ Record traffic **right now** and label it yourself.
- ✅ Let the **AI label it** automatically.
- ✅ Turn an **old recording** (`.pcap` file) into a table.
- ✅ **Filter** the table to keep only what you need.
- ✅ Tell **other computers** on the network to record at the same time and send you their tables.

---

## 2. Before you start

### On the main computer (Director)

Put these files **together in the same folder**:

| File | Required? | What for |
|---|---|---|
| `FlowEngine.exe` | ✅ Yes | The program |
| `npcap-1.88.exe` | ✅ Yes (if Npcap is not installed) | Lets the PC "listen" to the network |
| `modelo_rf_ids.joblib` | Only for option 2 | The AI's "brain" |
| `nmap-7.99-setup.exe` | Optional | Extra network tool |
| `token_red.txt` | Recommended | The "password" shared by Director and Agents (see §9.1) |

### On each computer that will record remotely (Agent)

| File | Required? |
|---|---|
| `SensorAgente.exe` | ✅ Yes |
| `FlowEngine.exe` | ✅ Yes |
| `modelo_rf_ids.joblib` | ✅ Yes |
| `npcap-1.88.exe` | ✅ Yes (if Npcap is not installed) |
| `token_red.txt` | Recommended (same as the Director's) |

> 💡 All computers must be connected **to the same network** (same router or Wi-Fi).

---

## 3. Opening the program for the first time

### On Windows

1. **Right-click** `FlowEngine.exe`.
2. Choose **"Run as administrator"** and accept the prompt.
3. The first time, the **Npcap** installer opens:
   - Click **"I Agree"**.
   - ⚠️ **Tick "Install Npcap in WinPcap API-compatible Mode"**.
   - Click **Install**, then **Finish**.
4. **Close FlowEngine and open it again** (as administrator). You only do this once.

### On Linux

Open a terminal in the program folder and type:

```bash
chmod +x FlowEngine
sudo ./FlowEngine
```

The program installs anything it is missing.

If everything is fine you will see:

```text
[*] Iniciando GENERADOR...                      ← Starting
[*] Sistema operativo detectado: Windows        ← OS detected
[+] Npcap detectado y listo.                    ← Npcap ready
[+] Nmap detectado y listo.                     ← Nmap ready
[+] Verificación de sistema completada.         ← System check done
```

---

## 4. The main menu

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

**Type the number** of what you want and press **Enter**.
When any option finishes, press **Enter** to return to this menu.

| I want to… | Option |
|---|---|
| Record traffic and label it myself | **1** |
| Record traffic and let the AI label it | **2** |
| Turn a `.pcap` recording into a table | **3** |
| Clean or filter a table | **4** |
| Make other PCs record at a set time | **5** |
| Make other PCs record right now | **6** |
| Close the program | **0** |

---

## 5. Option 1 — Live capture (manual)

Use it when you know what kind of traffic is happening at each moment (for example, during a lab test).

**Step 1.** Type `1` and press Enter.

**Step 2.** The program asks three things. Pressing **Enter without typing** uses the default:

| Question | What to type | If you just press Enter |
|---|---|---|
| `Ruta de guardado` (save folder) | A folder, e.g. `C:\Data\Test1` | `Capturas` folder next to the program |
| `Nombre del archivo CSV` (CSV name) | e.g. `monday_morning` | `live_resultado.csv` |
| `Nombre del archivo PCAP` (PCAP name) | e.g. `monday_morning` | `captura.pcap` |

**Step 3.** Recording starts. The initial label is **`normal`**:

```text
    LIVE - Interfaz activa: Wi-Fi
[*] Escribe una etiqueta (Ej: 'dos') y presiona Enter. Escribe 'stop' o 'salir' para detener.
[*] Etiqueta actual: 'normal'
```
*(Type a label and press Enter. Type 'stop' or 'salir' to finish. Current label: 'normal')*

**Step 4.** When the type of traffic changes, **type the new label and press Enter**. For example, type `dos` when a test attack starts and `normal` when it ends.

```text
dos
[+] Etiqueta cambiada a: 'dos'
[*] 12 flujo(s) en curso se cerraron con la etiqueta anterior.
```

> 💡 Always use the **same words** for the same kind of traffic (lowercase): `normal`, `dos`, `scan`, `brute_force`…

**Step 5.** To finish, type **`stop`** (or `salir`) and press Enter. You can also press **Ctrl + C**.

```text
[+] Tráfico crudo guardado en: C:\...\Capturas\captura.pcap
[+] Log de etiquetas (con timestamp) guardado en: C:\...\Capturas\labels_log.csv
[+] Regresando al menú principal...
```

---

## 6. Option 2 — Live capture with AI

Same as option 1, but **you don't type labels**: the AI decides what each conversation is.

1. Make sure `modelo_rf_ids.joblib` is **in the same folder** as `FlowEngine.exe`.
2. Type `2` and press Enter.
3. You should see: `[+] Modelo cargado desde: ...` (model loaded).
4. Answer the same three questions as option 1 (or press Enter).
5. Let it record. To finish, type **`stop`** and press Enter.

> If you type any other word during the capture, the program reminds you that the AI is labelling automatically.

---

## 7. Option 3 — Process a PCAP file

Use it if you already have a network recording (from Wireshark, tcpdump, etc.).

1. Type `3` and press Enter.
2. A window opens: **pick your** `.pcap` or `.pcapng` **file**.
3. Another window opens: **pick the folder** to save the table in.
4. Type a name for the table or press Enter (it will be called `pcap_resultado1.csv`).
5. Wait. Progress is shown every 10,000 packets:

```text
[*] Paquetes procesados: 10000
[*] Paquetes procesados: 20000
```

> A table made from a PCAP **has no `Label` column** (nobody is labelling). Add it later in Excel, or with option 4 → *Create variable* (e.g. name `Label`, expression `'normal'`).

---

## 8. Option 4 — Filter the dataset

Use it to keep only the rows you care about or to create new columns.

1. Type `4` and press Enter.
2. A window opens: **pick your CSV file**.
3. You will see a small menu:

```text
==========================
1 Ver columnas        ← Show columns
2 Crear variable      ← Create variable
3 Aplicar filtro      ← Apply filter
4 Guardar dataset     ← Save dataset
5 Salir               ← Exit
==========================
```

### 1 · Show columns
Lists every column name. Use it to check exact spelling.

### 3 · Apply filter
Type the condition. Ready-to-copy examples:

| I want to keep… | Type |
|---|---|
| TCP traffic only | `tcp` |
| UDP traffic only | `udp` |
| Traffic using port 80 (web), either direction | `tcp.port == 80` |
| Traffic sent by one machine | `ip.src == '192.168.1.10'` |
| Traffic received by one machine | `ip.dst == '192.168.1.20'` |
| Rows labelled "dos" only | `Label == 'dos'` |
| TCP with large packets | `tcp && \`Pkt Size Mean\` > 500` |
| HTTP or HTTPS | `tcp.port == 80 \|\| tcp.port == 443` |
| DNS queries | `udp.port == 53` |

> ⚠️ If a column name has **spaces**, wrap it in backticks: `` `Src Bytes` ``.
> Text values go in single quotes: `'192.168.1.10'`.

You can apply several filters in a row; each one narrows the previous result.

### 2 · Create variable
Creates a new column from others. Example:
- Name: `src_bytes_per_second`
- Expression: `` `Src Bytes` / `Flow Duration` ``

### 4 · Save dataset
Saves the result as **`dataset_filtrado_avanzado.csv`** in the same folder as the original file.

### 5 · Exit
Back to the main menu. **If you didn't save (option 4), changes are lost.**

---

## 9. Capturing from several computers (options 5 and 6)

From **one PC (Director)** you can tell **other PCs (Agents)** to record their traffic. When they finish, they send their table to you automatically.

### 9.1 Set up each Agent (once)

**First, the network "password" (token).** The Director and Agents only obey each other if they share the same secret word:

1. Create a text file named **`token_red.txt`**.
2. Type a secret word inside, e.g. `LabNet-2026-xK9`, and save it.
3. Copy **that same file** next to `FlowEngine.exe` on the Director and next to `SensorAgente.exe` on every Agent.

> Without the file, the program uses a public default password. Fine for testing, not for a shared network.

**Then, on each Agent:**

1. Copy `SensorAgente.exe`, `FlowEngine.exe`, `modelo_rf_ids.joblib` (and `npcap-1.88.exe`) into a folder on the agent.
2. Open `FlowEngine.exe` as administrator **once** so it installs Npcap, then close it.
3. Right-click **`SensorAgente.exe` → Run as administrator**.
   - No window appears: **that's normal**, it works in the background.
   - To check it is running, look for it in **Task Manager** (Ctrl + Shift + Esc).
4. If Windows asks about the **Firewall**, click **"Allow access"** (private networks).

### 9.2 Instant capture (option 6)

On the **Director**:

1. Type `6` and press Enter.
2. The program looks for agents (about 3 seconds):

```text
[+] Se encontraron 2 agentes activos.        ← 2 active agents found
 1. PC-LAB-01 (192.168.1.21)
 2. PC-LAB-02 (192.168.1.22)
```

3. Type how many **seconds** to record (Enter = 60).
4. Type a **name** for the capture, e.g. `test_01` (Enter = `prueba_01`).
5. Done: all agents start recording. When they finish you will see:

```text
[+] Archivo recibido exitosamente de 192.168.1.21: capturas_remotas\192.168.1.21_remoto_test_01_...csv
```
*(File received successfully from …)*

> ⚠️ **Don't close FlowEngine on the Director** until all files have arrived.

### 9.3 Scheduled capture (option 5)

Same as above, but you choose **when** it starts.

1. Type `5` and press Enter.
2. Type the date and time in this exact format, **using 24-hour time**:

```text
YYYY-MM-DD HH:MM        →   2026-11-03 20:30   (8:30 PM)
```

3. Type the duration in seconds and a name.

> 💡 Agents start at the chosen time according to the **Director's clock**. Make sure every PC has the correct time.
> Don't close FlowEngine on the Director until the files arrive.

---

## 10. Where are my files?

| File | What it is | Where |
|---|---|---|
| `*.csv` | **The table** with conversations and labels. Open it in Excel. | The folder you chose (or `Capturas`) |
| `*.pcap` | The **original recording**. Open it with Wireshark. | Same folder |
| `labels_log.csv` | **History** of when you changed each label | Same folder |
| `filas_no_guardadas.csv` | Rows that couldn't be saved because the table was open in Excel | Same folder (only if it happened) |
| `dataset_filtrado_avanzado.csv` | The table after filtering (option 4) | Next to the original CSV |
| `capturas_remotas\` | Tables sent by the agents | On the Director, next to `FlowEngine.exe` |

> 💡 **Don't open the table in Excel while recording.** If you do, the program saves rows in a separate file so nothing is lost.

---

## 11. Common problems

**❓ "ERROR CRÍTICO DE RED: SCAPY NO DETECTA NPCAP" appears.**
➡️ Close the program and reopen it as administrator. If it persists, uninstall Npcap and reinstall it **ticking "WinPcap API-compatible Mode"**.

**❓ It says "No se detectaron agentes en la red" (no agents found).**
➡️ Check that:
- `SensorAgente.exe` is running on the agent (Task Manager).
- Both PCs are on the **same network**.
- The agent's firewall allows the program (or ask your network admin to open UDP 51500 and TCP 50050).

**❓ Agents are found but the file never arrives.**
➡️ The **Director's** firewall must allow FlowEngine (TCP port 51502). Don't close FlowEngine while waiting.

**❓ It says "No se encontró el modelo IA" (AI model not found).**
➡️ Copy `modelo_rf_ids.joblib` into the **same folder** as `FlowEngine.exe` (and on the agent).

**❓ The `Label` column says `error_prediccion`.**
➡️ The model is not compatible with this version. Use a model trained on tables produced by FlowEngine.

**❓ "'file' está en uso" (file in use) appears.**
➡️ The table is open in Excel. Close it. The program switches to a new name automatically.

**❓ When scheduling, it says the date is earlier than now.**
➡️ Use **24-hour time**: 8:30 PM is `20:30`.

**❓ "Archivo rechazado … token inválido" (file rejected, invalid token) appears.**
➡️ Agent and Director have different passwords. Copy the same `token_red.txt` to every machine and restart `SensorAgente.exe`.

**❓ How do I stop the agent?**
➡️ Task Manager → find `SensorAgente.exe` → **End task**.

---

## 12. Glossary

| Term | Plain meaning |
|---|---|
| **Network traffic** | All the information computers send to each other |
| **Packet** | A small piece of that information |
| **Flow** | A "conversation" between two machines (many packets together) |
| **Label** | The word that says what type of traffic it is: `normal`, `dos`… |
| **Dataset / CSV** | The table with all flows; opens in Excel |
| **PCAP** | File with the original traffic recording |
| **AI / model** | Trained program that labels automatically |
| **Director** | The PC you give orders from |
| **Agent / Sensor** | The PCs that record when the Director asks |
| **Npcap** | Windows program that lets the PC listen to the network |
| **Token** | Password shared by Director and Agents (`token_red.txt`) |

---

> 🔒 **Responsible use:** only record traffic on networks you own or have permission to monitor.
