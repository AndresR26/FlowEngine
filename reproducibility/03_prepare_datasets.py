"""Build the analysis tables.

1. Loads the 12 CSV files labeled during capture, removes duplicates and keeps the
   64 numeric features of the deployed model (WORK/fe_all.pkl).
2. Audits the labels: records per attack label and records that touch the attacker
   (WORK/label_audit.csv).
3. Applies the corrected labeling rule (Eq 12 in article A):
     Normal   if the record does not touch 192.168.1.30
     y        if it touches the attacker and y is DoS or PortScan
     excluded otherwise
4. Labels the CICFlowMeter flows with the same rule, taking the attack windows from
   the Flow Engine label log (WORK/cic_all.pkl, WORK/attack_windows.csv).

Usage:
  python 03_prepare_datasets.py --data DATA --work WORK
"""
import glob
import json
import os

import numpy as np
import pandas as pd

from common import ATTACKER, LABEL_MAP, NOT_FEATURES, PAIRS, args, stem

a = args()
here = os.path.dirname(os.path.abspath(__file__))
feats = json.load(open(os.path.join(here, 'features_model.json')))

# ---------- Flow Engine CSV files ----------
dfs = []
for f in sorted(PAIRS.values()):
    d = pd.read_csv(os.path.join(a.data, f), low_memory=False)
    d.columns = [c.strip() for c in d.columns]
    d['Label'] = d['Label'].astype(str).str.strip().map(lambda x: LABEL_MAP.get(x.lower(), x))
    d['__file'] = f
    dfs.append(d)
common = set(dfs[0].columns)
for d in dfs[1:]:
    common &= set(d.columns)
df = pd.concat([d[sorted(common)] for d in dfs], ignore_index=True)
print('rows read:', len(df))
df = df.drop_duplicates(subset=[c for c in df.columns if c != '__file']).reset_index(drop=True)
X = df.drop(columns=[c for c in NOT_FEATURES + ['Label', '__file'] if c in df.columns])
X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
X = X.drop(columns=X.columns[X.isna().mean() > 0.5])
ok = X.notna().all(axis=1)
assert sorted(X.columns) == sorted(feats), set(X.columns) ^ set(feats)
df = df[ok].reset_index(drop=True)
print('unique rows with complete features:', len(df), '| features:', len(feats))

touch = (df['Source IP'] == ATTACKER) | (df['Destination IP'] == ATTACKER)

# Label audit over every row written during capture (before removing duplicates)
raw = pd.concat(dfs, ignore_index=True)
rtouch = (raw['Source IP'] == ATTACKER) | (raw['Destination IP'] == ATTACKER)
att = raw[raw.Label != 'Normal']
audit = pd.DataFrame({'records': att.Label.value_counts(),
                      'touch_attacker': att[rtouch[att.index]].Label.value_counts()}).fillna(0).astype(int)
audit['share'] = (audit.touch_attacker / audit.records).round(4)
audit.loc['Total'] = [audit.records.sum(), audit.touch_attacker.sum(), round(audit.touch_attacker.sum() / audit.records.sum(), 4)]
audit.to_csv(os.path.join(a.work, 'label_audit.csv'))
print(audit)

df['Y'] = np.where(~touch, 'Normal', np.where(df.Label.isin(['DoS', 'PortScan']), df.Label, 'EXCL'))
df.to_pickle(os.path.join(a.work, 'fe_all.pkl'))
print('corrected labels:', df.Y.value_counts().to_dict())

# ---------- CICFlowMeter flows ----------
def seconds(s):
    return pd.to_timedelta(s).dt.total_seconds()

out, windows = [], []
for cap, fe_csv in PAIRS.items():
    f = pd.read_csv(os.path.join(a.data, fe_csv), low_memory=False, usecols=['Start Time', 'End Time', 'Label'])
    f['s'], f['e'] = seconds(f['Start Time']), seconds(f['End Time'])
    f = f.sort_values('s')
    f['lab'] = f.Label.astype(str).str.lower().map(lambda x: LABEL_MAP.get(x, x))
    seg_id = (f.lab != f.lab.shift()).cumsum()
    segs = f.groupby(seg_id).agg(lab=('lab', 'first'), s=('s', 'min'), e=('e', 'max'), n=('lab', 'size'))
    segs = segs[segs.lab != 'Normal']
    windows += [(cap, r.lab, r.s, r.e, r.n) for r in segs.itertuples()]
    c = pd.read_csv(os.path.join(a.work, 'cic', f'{stem(cap)}_cic.csv'))
    t = pd.to_datetime(c.timestamp)
    c['tod'] = t.dt.hour * 3600 + t.dt.minute * 60 + t.dt.second
    ctouch = (c.src_ip == ATTACKER) | (c.dst_ip == ATTACKER)
    lab = np.array(['Normal'] * len(c), dtype=object)
    for r in segs.itertuples():
        inwin = (c.tod >= np.floor(r.s) - 1) & (c.tod <= r.e)
        lab[(inwin & ctouch).values] = r.lab
    c['LabelR'] = lab
    c['Y'] = np.where(~ctouch, 'Normal', np.where(c.LabelR.isin(['DoS', 'PortScan']), c.LabelR, 'EXCL'))
    c['__file'] = cap
    out.append(c)
cic = pd.concat(out, ignore_index=True)
cic.to_pickle(os.path.join(a.work, 'cic_all.pkl'))
pd.DataFrame(windows, columns=['capture', 'label', 'start_s', 'end_s', 'n_fe_records']).to_csv(
    os.path.join(a.work, 'attack_windows.csv'), index=False)
print('CICFlowMeter labels:', cic.Y.value_counts().to_dict())
