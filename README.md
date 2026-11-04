# datasets/

🇪🇸 Datasets generados con FlowEngine en un laboratorio aislado y usados para entrenar el modelo. Los archivos **no se guardan dentro del repositorio** (pesan ~88 MB los CSV y ~1,6 GB los PCAP); están publicados en **Zenodo**: [10.5281/zenodo.23932954](https://doi.org/10.5281/zenodo.23932954).
🇬🇧 Datasets generated with FlowEngine in an isolated lab and used to train the model. The files are **not stored in the repository** (~88 MB of CSV and ~1.6 GB of PCAP); they are published on **Zenodo**: [10.5281/zenodo.23932954](https://doi.org/10.5281/zenodo.23932954).

Para usarlos / To use them: descarga los CSV de Zenodo y descomprímelos aquí / download the CSVs from Zenodo and unzip them here:

```bash
python training/entrenar_modelo.py --datos datasets --salida training/modelo_salida
```

## Laboratorio / Lab

| Rol / Role | IP |
|---|---|
| Servidor víctima / Victim server (DVWA, FTP, SSH, HTTP) | 192.168.1.10 |
| Cliente legítimo / Legitimate client | 192.168.1.20 |
| Atacante / Attacker (Kali, [`lab/lab_attacks.sh`](../lab/lab_attacks.sh)) | 192.168.1.30 |
| Sensor FlowEngine (puerto espejo / mirror port) | 192.168.1.40 |

Todo el tráfico es de la red privada del laboratorio: no hay IPs públicas ni dominios de terceros en los CSV.
All traffic belongs to the private lab network: the CSVs contain no public IPs or third-party domains.

## CSV (91 columnas / columns, 232,515 flujos en bruto / raw flows)

- **91 columnas / columns:** identificación (IPs, puertos, protocolo, horas, servicio…), **64 características numéricas** que usa el modelo y `Label`. / identification fields, **64 numeric features** used by the model, and `Label`.
- **232,515** filas en bruto / raw rows → **223,763** utilizables para entrenar (`training/entrenar_modelo.py`): el script elimina las filas duplicadas (en estos CSV no hay ninguna) y las 8,752 filas con valores nulos o infinitos en las características. / usable for training: the script removes duplicate rows (there are none in these CSVs) and the 8,752 rows with null or infinite feature values.

| Archivo / File | Flujos / Flows | Etiquetas / Labels | Tamaño / Size |
|---|---:|---|---:|
| `ataque beacon-normal.csv` | 17,926 | normal 13,057 · beaconing 4,869 | 7.2 MB |
| `bruteforce.csv` | 9,227 | normal 4,790 · bruteforce 4,437 | 3.7 MB |
| `bruteforce2.csv` | 16,667 | bruteforce 8,656 · normal 8,011 | 6.6 MB |
| `dos.csv` | 40,859 | dos 23,203 · normal 17,656 | 14.6 MB |
| `fuzzer.csv` | 8,703 | normal 4,812 · fuzzer 3,891 | 3.5 MB |
| `live_resultado.csv` | 22,874 | normal 18,304 · portscan 4,570 | 9.8 MB |
| `normal-http.csv` ⚠️ | 17,581 | dos 9,072 · normal 8,509 | 7.1 MB |
| `portscan.csv` | 51,687 | portscan 27,644 · normal 24,043 | 20.1 MB |
| `prueba de fuego.csv` | 24,010 | normal 10,710 · dos 4,633 · fuzzer 4,406 · beaconing 4,261 | 9.6 MB |
| `tcpsyn.csv` | 5,563 | normal 4,534 · dos 1,029 | 2.2 MB |
| `webattack.csv` | 9,926 | normal 6,154 · injection 3,772 | 3.9 MB |
| `webfuzzer.csv` | 7,492 | normal 4,387 · fuzzer 3,105 | 3.0 MB |

⚠️ `normal-http.csv`: el nombre sugiere solo tráfico normal, pero el 52 % de las filas está etiquetado `dos`. Conviene confirmar si es correcto antes de publicarlo. / The name suggests normal traffic only, but 52 % of rows are labelled `dos`. Confirm this is intended before publishing.

Columnas: ver el diccionario de datos en el [manual técnico §8](../docs/es/manual_tecnico.md#8-diccionario-de-datos-del-csv). / Columns: see the data dictionary in the [technical manual §8](../docs/en/technical_manual.md#8-csv-data-dictionary).

## PCAP (tráfico crudo / raw traffic)

| Archivo / File | Tamaño / Size |
|---|---:|
| `beacon-normal.pcap` | 120 MB |
| `bruteforce.pcap` | 111 MB |
| `bruteforce (2).pcap` | 61 MB |
| `captura.pcap` | 147 MB |
| `dos.pcap` | 109 MB |
| `fuzzer.pcap` | 57 MB |
| `http.pcap` | 105 MB |
| `portscan.pcap` | 290 MB |
| `prueba de fuego.pcap` | 419 MB |
| `tcpsyn.pcap` | 37 MB |
| `webattack.pcap` | 66 MB |
| `webfz.pcap` | 50 MB |

Disponibles en Zenodo / Available on Zenodo: [10.5281/zenodo.23932954](https://doi.org/10.5281/zenodo.23932954).
