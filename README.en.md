# FlowEngine — IDS Dataset Generator

[🇪🇸 Español](README.md) · 🇬🇧 English

Python tool that **captures network traffic, turns it into flows with 90+ features and labels them** (manually or with a Random Forest model), built to train and evaluate **Intrusion Detection Systems (IDS)**. Includes a **distributed** mode to capture from several LAN machines at once, the model training script and the lab's attack-traffic generator.

![Network architecture](docs/img/topologia_red_en.png)

## Features

- **Live capture** with Scapy (Windows with Npcap, Linux as root).
- **Live manual labelling**: type the label while capturing; every change is logged with its exact timestamp.
- **Automatic AI labelling** (`modelo_rf_ids.joblib`, scikit-learn) plus the script to train it.
- **Processing of existing PCAP/PCAPNG files**.
- **Wireshark-style filters** (`tcp.port == 80`, `ip.src == '…'`, `&&`, `||`) and derived variables.
- **Distributed capture** Director → Agents (immediate or scheduled) with automatic CSV upload, protected by a token.
- Timing, size, TCP flag, TLS (SNI, **JA3**), DNS, HTTP, entropy and UNSW-NB15-style context features.
- **232,515 labelled lab flows** (normal, dos, portscan, bruteforce, fuzzer, beaconing, injection).

## Quick start

```bash
git clone https://github.com/<your-user>/FlowEngine.git
cd FlowEngine
pip install -r requirements.txt

cd src
python flow_engine.py          # Windows: Administrator console · Linux: sudo
python compilar.py             # builds FlowEngine.exe and SensorAgente.exe in src/dist/
```

Train the model on the datasets (download them from the Release first, see [datasets/](datasets/README.md)):

```bash
python training/entrenar_modelo.py --datos datasets --salida training/modelo_salida
```

## Documentation

| Document | English | Español | PDF |
|---|---|---|---|
| Technical manual (includes network architecture) | [technical_manual.md](docs/en/technical_manual.md) | [manual_tecnico.md](docs/es/manual_tecnico.md) | [EN](docs/pdf/Technical_Manual_FlowEngine_EN.pdf) · [ES](docs/pdf/Manual_Tecnico_FlowEngine_ES.pdf) |
| User manual | [user_manual.md](docs/en/user_manual.md) | [manual_usuario.md](docs/es/manual_usuario.md) | [EN](docs/pdf/User_Manual_FlowEngine_EN.pdf) · [ES](docs/pdf/Manual_Usuario_FlowEngine_ES.pdf) |
| Network architecture | [Technical manual §5](docs/en/technical_manual.md#5-network-architecture) | [Manual técnico §5](docs/es/manual_tecnico.md#5-arquitectura-de-red) | |

## Repository layout

```text
FlowEngine/
├── src/            Main program (flow_engine, live_conf, pcap_conf, filters, network, agent, build)
├── training/       entrenar_modelo.py → modelo_rf_ids.joblib
├── tools/          etiquetar_con_ground_truth.py · generar_diagramas.py · build_pdfs.sh
├── lab/            lab_attacks.sh — attack traffic for the isolated lab
├── legacy/         Earlier versions no longer used
├── datasets/       README with statistics (CSV/PCAP files go to Releases)
├── models/         README (the .joblib goes to Releases)
├── installers/     README with Npcap and Nmap links
└── docs/           ES/EN manuals, diagrams (img/) and PDFs
```

## Network ports

| Port | Protocol | Listening machine | Purpose |
|---|---|---|---|
| 51500 | UDP | Agent | Discovery (broadcast) |
| 50050 | TCP | Agent | Capture orders |
| 51502 | TCP | Director | CSV reception |

Set the same token on every machine with a `token_red.txt` file next to the program or the `FLOWENGINE_TOKEN` variable (see [technical manual §5.2](docs/en/technical_manual.md#52-ports-and-protocols)).

## Large files (GitHub Releases)

GitHub does not accept files over 100 MB inside a repository, so these are published as **Release** assets (up to 2 GB each):

| Asset | Content |
|---|---|
| `FlowEngine_datasets_csv.zip` | 12 labelled CSVs (≈10 MB zipped) |
| `*.pcap` | Raw lab traffic (≈1.6 GB) |
| `modelo_rf_ids.joblib` | Trained model |
| `FlowEngine.exe`, `SensorAgente.exe` | Compiled executables (optional) |

## Responsible use

This software and `lab/lab_attacks.sh` are meant for **labs and networks you own or are authorised to test**. Capturing third-party traffic or launching attacks without permission may be illegal.

## License

[MIT](LICENSE)
