# Reproducibility

[🇪🇸 Español](README.es.md) · 🇬🇧 English

Scripts that rebuild every number and data figure of the two papers on Flow Engine
(the label audit, the corrected dataset, the Random Forest results and the comparison
with CICFlowMeter) from the files published in Zenodo.

## Data

Download the 12 PCAP files and the 12 CSV files of
[FlowEngine Datasets](https://doi.org/10.5281/zenodo.23932954) into one folder, keeping
their original names. That folder is `DATA` below. `WORK` is any empty output folder.

## Environment

```bash
pip install -r requirements.txt
```

Step 2 needs libpcap and tcpdump, which cicflowmeter (through Scapy) uses to read and filter the PCAP files: on Linux `sudo apt-get install libpcap0.8 tcpdump`; on Windows, Npcap.

Results in the papers were produced with Python 3.13, Scapy 2.8.0, scikit-learn 1.9.1
and cicflowmeter 0.5.0 on a virtual machine with two cores of an Intel Xeon at 2.10 GHz
and 8 GB of memory. Processing times depend on the machine; every other number is
deterministic (seed 42).

## Steps

| Step | Command | Output in `WORK` | Time |
|---|---|---|---|
| 1 | `python 01_extract_flowengine.py --data DATA --work WORK --src ../src` | `fe/*_fe.csv`, `fe/times.tsv` | ≈ 8 min |
| 2 | `python 02_extract_cicflowmeter.py --data DATA --work WORK` | `cic/*_cic.csv`, `cic/times.tsv` | ≈ 11 min |
| 3 | `python 03_prepare_datasets.py --data DATA --work WORK` | `label_audit.csv`, `fe_all.pkl`, `cic_all.pkl`, `attack_windows.csv` | ≈ 1 min |
| 4 | `python 04_results.py --data DATA --work WORK` | `results.json`, `latency_*.npy` | ≈ 20 min |
| 5 | `python 05_figures.py --data DATA --work WORK` | `figures/en/*.png`, `figures/es/*.png` | < 1 min |

## What each result means

- `label_audit.csv`: records per attack label written during capture and how many of
  them have the attacker (192.168.1.30) as source or destination.
- `fe_all.pkl`, column `Y`: corrected label. A record that does not touch the attacker is
  `Normal`; a record that touches it keeps `DoS` or `PortScan`; any other record that
  touches it is excluded (`EXCL`).
- `results.json`:
  - `ablation_*`: original labels on a stratified 80/20 split, with all 64 features and
    without ports and context counters (`ct_*`).
  - `fe_cv`, `cic_cv`: five-fold stratified cross-validation on the corrected data,
    Flow Engine with 58 features and CICFlowMeter with 77.
  - `fe_holdout`, `cic_holdout`: trained on nine captures, tested on `prueba de fuego`,
    `tcpsyn` and `bruteforce (2)`.
  - `p_normal_flagged`, `q_attack_flagged`, `trigger_*`: per-record rates on the held-out
    captures and replay of the per-source trigger (14 flagged records among the last 20).
  - `time_*`, `records_*`, `latency`: processing time, records per tool and time from the
    first packet of a TCP connection to its first Flow Engine record and to its end.
