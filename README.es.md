# Reproducibilidad

🇪🇸 Español · [🇬🇧 English](README.md)

Scripts que reconstruyen todas las cifras y figuras de datos de los dos artículos sobre Flow Engine
(la auditoría de etiquetas, el dataset corregido, los resultados del Random Forest y la comparación
con CICFlowMeter) a partir de los archivos publicados en Zenodo.

## Datos

Descarga los 12 archivos PCAP y los 12 archivos CSV de
[FlowEngine Datasets](https://doi.org/10.5281/zenodo.23932954) en una misma carpeta, sin cambiar
sus nombres. Esa carpeta es `DATA` en los comandos. `WORK` es cualquier carpeta de salida vacía.

## Entorno

```bash
pip install -r requirements.txt
```

El paso 2 necesita libpcap y tcpdump, que cicflowmeter (a través de Scapy) usa para leer y filtrar los PCAP: en Linux `sudo apt-get install libpcap0.8 tcpdump`; en Windows, Npcap.

Los resultados de los artículos se obtuvieron con Python 3.13, Scapy 2.8.0, scikit-learn 1.9.1
y cicflowmeter 0.5.0 en una máquina virtual con dos núcleos de un Intel Xeon a 2,10 GHz y 8 GB
de memoria. Los tiempos de procesamiento dependen del equipo; todas las demás cifras son
deterministas (semilla 42).

## Pasos

| Paso | Comando | Salida en `WORK` | Tiempo |
|---|---|---|---|
| 1 | `python 01_extract_flowengine.py --data DATA --work WORK --src ../src` | `fe/*_fe.csv`, `fe/times.tsv` | ≈ 8 min |
| 2 | `python 02_extract_cicflowmeter.py --data DATA --work WORK` | `cic/*_cic.csv`, `cic/times.tsv` | ≈ 11 min |
| 3 | `python 03_prepare_datasets.py --data DATA --work WORK` | `label_audit.csv`, `fe_all.pkl`, `cic_all.pkl`, `attack_windows.csv` | ≈ 1 min |
| 4 | `python 04_results.py --data DATA --work WORK` | `results.json`, `latency_*.npy` | ≈ 20 min |
| 5 | `python 05_figures.py --data DATA --work WORK` | `figures/en/*.png`, `figures/es/*.png` | < 1 min |

## Qué significa cada resultado

- `label_audit.csv`: registros por etiqueta de ataque escritos durante la captura y cuántos de
  ellos tienen al atacante (192.168.1.30) como origen o destino.
- `fe_all.pkl`, columna `Y`: etiqueta corregida. Un registro que no toca al atacante es
  `Normal`; uno que lo toca conserva `DoS` o `PortScan`; cualquier otro que lo toque se
  excluye (`EXCL`).
- `results.json`:
  - `ablation_*`: etiquetas originales con partición estratificada 80/20, con las 64
    características y sin puertos ni contadores de contexto (`ct_*`).
  - `fe_cv`, `cic_cv`: validación cruzada estratificada de cinco particiones sobre los datos
    corregidos; Flow Engine con 58 características y CICFlowMeter con 77.
  - `fe_holdout`, `cic_holdout`: entrenado con nueve capturas y probado con `prueba de fuego`,
    `tcpsyn` y `bruteforce (2)`.
  - `p_normal_flagged`, `q_attack_flagged`, `trigger_*`: tasas por registro en las capturas
    reservadas y simulación del disparador por origen (14 registros marcados entre los últimos 20).
  - `time_*`, `records_*`, `latency`: tiempo de procesamiento, registros por herramienta y tiempo
    desde el primer paquete de una conexión TCP hasta su primer registro en Flow Engine y hasta
    su final.
