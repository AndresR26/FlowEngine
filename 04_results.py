"""Compute every number reported in the papers and write WORK/results.json.

- Ablation with the original labels (stratified 80/20 split, seed 42): all 64
  features versus without ports and context counters.
- Corrected labels: five-fold stratified cross-validation and held-out captures,
  for Flow Engine (58 features) and CICFlowMeter (77 features).
- False alarms per held-out capture, feature importances, per-source trigger replay
  (m = 20, k = 14), processing time, records per tool and first-record latency.

Usage:
  python 04_results.py --data DATA --work WORK
"""
import glob
import json
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedKFold, train_test_split

from common import (ATTACKER, CLASSES, HOLDOUT_CSVS, HOLDOUT_PCAPS, IDENTIFIERS, PAIRS, RF_PARAMS,
                    args, stem)

a = args()
here = os.path.dirname(os.path.abspath(__file__))
feats = json.load(open(os.path.join(here, 'features_model.json')))
clean = [f for f in feats if f not in IDENTIFIERS]
R = {}
f32 = lambda X: X.astype(np.float32)  # noqa: E731

# ---------- ablation with the original labels ----------
fe = pd.read_pickle(os.path.join(a.work, 'fe_all.pkl'))
tr, te = train_test_split(fe.index, test_size=0.2, random_state=42, stratify=fe.Label)
for name, cols in [('orig_all_features', feats), ('orig_no_identifiers', clean)]:
    m = RandomForestClassifier(**RF_PARAMS).fit(f32(fe.loc[tr, cols]), fe.loc[tr, 'Label'])
    yp = m.predict(f32(fe.loc[te, cols]))
    R['ablation_' + name] = dict(acc=accuracy_score(fe.loc[te, 'Label'], yp),
                                 bacc=balanced_accuracy_score(fe.loc[te, 'Label'], yp))
    print(name, R['ablation_' + name])

# ---------- corrected datasets ----------
R['fe_excluded'] = fe[fe.Y == 'EXCL'].Label.value_counts().to_dict()
fe = fe[fe.Y != 'EXCL'].reset_index(drop=True)
R['fe_counts'] = fe.Y.value_counts().to_dict()

c = pd.read_pickle(os.path.join(a.work, 'cic_all.pkl'))
c = c[c.Y != 'EXCL'].reset_index(drop=True)
drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'tod', 'LabelR', '__file', 'Y']
CX = c.drop(columns=drop).select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
CX = CX.loc[:, CX.isna().mean() <= 0.5]
ok = CX.notna().all(axis=1)
c, CX = c[ok].reset_index(drop=True), CX[ok].reset_index(drop=True)
R['cic_counts'] = c.Y.value_counts().to_dict()
R['n_features'] = dict(flowengine=len(clean), cicflowmeter=int(CX.shape[1]))


def metrics(yt, yp):
    p, r, f, s = precision_recall_fscore_support(yt, yp, labels=CLASSES, zero_division=0)
    present = [l for l in CLASSES if l in set(yt)]
    return dict(acc=accuracy_score(yt, yp), bacc=balanced_accuracy_score(yt, yp),
                f1m=f1_score(yt, yp, labels=present, average='macro'),
                per={l: dict(p=float(p[i]), r=float(r[i]), f1=float(f[i]), n=int(s[i])) for i, l in enumerate(CLASSES)})


def cross_validation(X, y):
    out, cm = [], np.zeros((3, 3), int)
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=42).split(X, y):
        m = RandomForestClassifier(**RF_PARAMS).fit(f32(X.iloc[tr]), y.iloc[tr])
        yp = m.predict(f32(X.iloc[te]))
        out.append(metrics(y.iloc[te], yp))
        cm += confusion_matrix(y.iloc[te], yp, labels=CLASSES)
    agg = {k: (float(np.mean([o[k] for o in out])), float(np.std([o[k] for o in out]))) for k in ['acc', 'bacc', 'f1m']}
    agg['per'] = {l: {k: (float(np.mean([o['per'][l][k] for o in out])), float(np.std([o['per'][l][k] for o in out])))
                      for k in ['p', 'r', 'f1']} for l in CLASSES}
    agg['cm'] = cm.tolist()
    return agg


def held_out(X, y, files, held):
    trm = ~files.isin(held)
    m = RandomForestClassifier(**RF_PARAMS).fit(f32(X[trm]), y[trm])
    yp = m.predict(f32(X[~trm]))
    r = metrics(y[~trm], yp)
    r['cm'] = confusion_matrix(y[~trm], yp, labels=CLASSES).tolist()
    r['n_train'], r['n_test'] = int(trm.sum()), int((~trm).sum())
    return r, yp, ~trm


R['fe_cv'] = cross_validation(fe[clean], fe.Y)
R['fe_cv_with_identifiers'] = cross_validation(fe[feats], fe.Y)
R['cic_cv'] = cross_validation(CX, c.Y)
R['fe_holdout'], yp_fe, te_fe = held_out(fe[clean], fe.Y, fe['__file'], HOLDOUT_CSVS)
R['cic_holdout'], yp_cic, te_cic = held_out(CX, c.Y, c['__file'], HOLDOUT_PCAPS)
for k in ['fe_cv', 'cic_cv', 'fe_cv_with_identifiers']:
    print(k, 'bacc', R[k]['bacc'])
print('holdout bacc FE', R['fe_holdout']['bacc'], 'CIC', R['cic_holdout']['bacc'])

t = fe[te_fe].copy()
t['pred'] = yp_fe
R['fe_holdout_false_alarms'] = {f: float((g[g.Y == 'Normal'].pred != 'Normal').mean()) for f, g in t.groupby('__file')}

R['fe_importance'] = pd.Series(RandomForestClassifier(**RF_PARAMS).fit(f32(fe[clean]), fe.Y).feature_importances_,
                               index=clean).sort_values(ascending=False).head(12).round(4).to_dict()
R['cic_importance'] = pd.Series(RandomForestClassifier(**RF_PARAMS).fit(f32(CX), c.Y).feature_importances_,
                                index=CX.columns).sort_values(ascending=False).head(12).round(4).to_dict()

# ---------- per-source trigger replay on the held-out captures ----------
t['t'] = pd.to_timedelta(t['End Time']).dt.total_seconds()
t = t.sort_values(['__file', 't'])
t['flag'] = (t.pred != 'Normal').astype(int)
normal = t[(t['Source IP'] != ATTACKER) & (t['Destination IP'] != ATTACKER)]
attack = t[(t['Source IP'] == ATTACKER) | (t['Destination IP'] == ATTACKER)]
R['p_normal_flagged'], R['q_attack_flagged'] = float(normal.flag.mean()), float(attack.flag.mean())


def triggers(frame, m=20, k=14):
    res = {}
    for (f, src), g in frame.groupby(['__file', 'Source IP']):
        if len(g) < m:
            continue
        on = g.flag.rolling(m).sum() >= k
        res[f'{f}|{src}'] = dict(records=int(len(g)), triggers=int((on & ~on.shift(1, fill_value=False)).sum()))
    return res


R['trigger_by_source'] = triggers(t)
R['trigger_normal_only'] = sum(v['triggers'] for v in triggers(normal).values())

# ---------- processing time, records and latency ----------
def read_times(path):
    return {l.split('\t')[0]: float(l.split('\t')[1]) for l in open(path) if l.strip()}


R['time_flowengine'] = read_times(os.path.join(a.work, 'fe', 'times.tsv'))
R['time_cicflowmeter'] = read_times(os.path.join(a.work, 'cic', 'times.tsv'))
R['packets'] = {l.split('\t')[0]: int(l.split('\t')[2]) for l in open(os.path.join(a.work, 'fe', 'times.tsv')) if l.strip()}
R['records_flowengine'] = {cap: sum(1 for _ in open(os.path.join(a.work, 'fe', f'{stem(cap)}_fe.csv'))) - 1 for cap in PAIRS}
R['records_cicflowmeter'] = {cap: sum(1 for _ in open(os.path.join(a.work, 'cic', f'{stem(cap)}_cic.csv'))) - 1 for cap in PAIRS}

parts = []
for cap in PAIRS:
    d = pd.read_csv(os.path.join(a.work, 'fe', f'{stem(cap)}_fe.csv'), low_memory=False,
                    usecols=['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Start Time', 'End Time'])
    d['cap'] = cap
    parts.append(d)
d = pd.concat(parts, ignore_index=True)
d = d[d.Protocol == 'TCP'].copy()
d['s'] = pd.to_timedelta(d['Start Time']).dt.total_seconds()
d['e'] = pd.to_timedelta(d['End Time']).dt.total_seconds()
e1 = d['Source IP'].astype(str) + ':' + d['Source Port'].astype(str)
e2 = d['Destination IP'].astype(str) + ':' + d['Destination Port'].astype(str)
d['conn'] = np.where(e1 < e2, e1 + '|' + e2, e2 + '|' + e1)  # bidirectional TCP connection
g = d.sort_values(['s', 'e']).groupby(['cap', 'conn']).agg(n=('s', 'size'), s0=('s', 'first'), e1=('e', 'first'), emax=('e', 'max'))
g = g[g.n >= 2]
first, whole = (g.e1 - g.s0).values, (g.emax - g.s0).values
np.save(os.path.join(a.work, 'latency_first.npy'), first)
np.save(os.path.join(a.work, 'latency_whole.npy'), whole)
q = (50, 90, 99, 100)
R['latency'] = dict(connections=int(len(g)), first_record=[float(np.percentile(first, x)) for x in q],
                    whole_connection=[float(np.percentile(whole, x)) for x in q], percentiles=list(q))

json.dump(R, open(os.path.join(a.work, 'results.json'), 'w'), indent=1, default=str)
print('written', os.path.join(a.work, 'results.json'))
