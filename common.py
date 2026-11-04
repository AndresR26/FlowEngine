"""Shared settings for the reproducibility scripts.

Every script takes --data (folder with the Zenodo files: 12 PCAP + 12 CSV)
and --work (folder where intermediate files and results are written).
"""
import argparse
import os

ATTACKER = '192.168.1.30'
CLASSES = ['Normal', 'DoS', 'PortScan']

# Random Forest hyperparameters selected once for the model deployed in Flow Engine
RF_PARAMS = dict(n_estimators=100, criterion='gini', max_depth=25, min_samples_split=10,
                 min_samples_leaf=2, max_features='sqrt', class_weight='balanced',
                 random_state=42, n_jobs=-1)

# Columns that describe where/when a record happened rather than what it did
IDENTIFIERS = ['Source Port', 'Destination Port', 'ct_dst_ltm', 'ct_src_ltm', 'ct_srv_dst', 'ct_srv_src']
NOT_FEATURES = ['Flow ID', 'Source IP', 'Src IP', 'Destination IP', 'Dst IP', 'Timestamp',
                'SimillarHTTP', 'Unnamed: 0', 'id', 'ID']
LABEL_MAP = {'normal': 'Normal', 'dos': 'DoS', 'portscan': 'PortScan', 'bruteforce': 'BruteForce'}

# PCAP file (without extension) -> CSV labeled during that capture
PAIRS = {
    'beacon-normal': 'ataque beacon-normal.csv',
    'bruteforce (2)': 'bruteforce.csv',
    'bruteforce': 'bruteforce2.csv',
    'captura': 'live_resultado.csv',
    'dos': 'dos.csv',
    'fuzzer': 'fuzzer.csv',
    'http': 'normal-http.csv',
    'portscan': 'portscan.csv',
    'prueba de fuego': 'prueba de fuego.csv',
    'tcpsyn': 'tcpsyn.csv',
    'webattack': 'webattack.csv',
    'webfz': 'webfuzzer.csv',
}
# Captures held out from training (mixed scenario, SYN flood, brute force)
HOLDOUT_PCAPS = ['prueba de fuego', 'tcpsyn', 'bruteforce (2)']
HOLDOUT_CSVS = [PAIRS[p] for p in HOLDOUT_PCAPS]


def stem(pcap_name):
    """File-system friendly name used for intermediate outputs."""
    return pcap_name.replace(' ', '_')


def args(extra=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True, help='folder with the Zenodo PCAP and CSV files')
    ap.add_argument('--work', required=True, help='output folder')
    for a, kw in (extra or []):
        ap.add_argument(a, **kw)
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    return a
