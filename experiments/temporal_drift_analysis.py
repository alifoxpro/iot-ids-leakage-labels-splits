# -*- coding: utf-8 -*-
"""
temporal_drift_analysis.py
==========================
Step 2: why do the cleaned minority classes (e.g. Recon, Mirai) collapse under the
temporal split? Hypothesis: the genuine attack traffic changes over time (different
phases, ports or targets), so the last 15% of a capture differs from the first 70%.

For every capture group, after removing background flows (rules R1|R2|R3), flows are
ordered by time and compared between the training period (first 70%) and the test
period (last 15%) - exactly the periods of the per-sub-attack temporal split:
  * time span of each period
  * protocol mix and top destination ports; overlap of the top-20 port sets (Jaccard)
  * share of test-period flows whose source / destination IP also occurs in training
  * adversarial-validation AUC: a small XGBoost tries to tell training-period from
    test-period flows using the 81 model features (3-fold CV). 0.5 = no drift,
    1.0 = the two periods are completely different.
Groups with fewer than 60 cleaned flows are reported but not scored.

Output: results_2026_03_03/split_pilot/temporal_drift.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\temporal_drift_analysis.py
"""
import json, sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold, cross_val_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, FEATS, OUT, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
PROTO = {0: 'proto0', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
MAX_PER_PERIOD = 50_000


def periods(g):
    g = g.sort_values('ts', kind='stable')
    a, b = int(0.70 * len(g)), int(0.85 * len(g))
    return g.iloc[:a], g.iloc[b:]


def top_ports(s, k):
    return s.value_counts().head(k)


MIN_PERIOD = 100          # AUC only when both periods have at least this many flows
REPEATS = 5               # repeated 3-fold CV (different fold seeds) -> mean and sd


def drift_auc(tr, te):
    """Mean and sd of the 3-fold CV ROC-AUC over REPEATS fold seeds."""
    rng = np.random.default_rng(SEED)
    tr = tr.iloc[rng.permutation(len(tr))[:MAX_PER_PERIOD]]
    te = te.iloc[rng.permutation(len(te))[:MAX_PER_PERIOD]]
    X = np.vstack([tr[FEATS].to_numpy(np.float32), te[FEATS].to_numpy(np.float32)])
    y = np.r_[np.zeros(len(tr)), np.ones(len(te))]
    clf = xgb.XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.2, tree_method='hist',
                            random_state=SEED, eval_metric='logloss',
                            scale_pos_weight=len(tr) / max(len(te), 1))
    v = [cross_val_score(clf, X, y, scoring='roc_auc',
                         cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED + k)).mean()
         for k in range(REPEATS)]
    return float(np.mean(v)), float(np.std(v))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--cleaning', choices=['all', 'r1'], default='all',
                    help='all: R1|R2|R3 removed (original analysis); r1: main condition of the paper')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    df = get_flagged()
    bg = df['r1_external'] if a.cleaning == 'r1' else (df['r1_external'] | df['r2_service'] | df['r3_benign_pair'])
    clean = df[~bg]
    res = {}
    print(f'\n{"class / capture group":38s} {"flows":>8s} {"train period":>27s} {"test period":>27s} '
          f'{"port J":>7s} {"srcIP seen":>10s} {"dstIP seen":>10s} {"drift AUC":>9s}')
    for (c, s), g in clean.groupby(['y', 'sub'], sort=True):
        name = f'{CLASSES[c]} / {s}' if s != CLASSES[c] else CLASSES[c]
        tr, te = periods(g)
        span = lambda p: f'{p["ts"].min():%m-%d %H:%M}..{p["ts"].max():%m-%d %H:%M}' if len(p) else '-'
        pj = np.nan
        if len(tr) and len(te):
            A = set(top_ports(tr['Dst Port'], 20).index); B = set(top_ports(te['Dst Port'], 20).index)
            pj = len(A & B) / len(A | B)
        src_seen = float(te['Src IP'].isin(set(tr['Src IP'])).mean()) if len(te) else np.nan
        dst_seen = float(te['Dst IP'].isin(set(tr['Dst IP'])).mean()) if len(te) else np.nan
        auc, auc_sd = drift_auc(tr, te) if min(len(tr), len(te)) >= MIN_PERIOD else (np.nan, np.nan)
        proto = lambda p: {PROTO.get(int(k), str(k)): round(float(v), 3)
                           for k, v in p['Protocol'].value_counts(normalize=True).head(3).items()}
        res[name] = {
            'flows_clean': int(len(g)), 'n_train_period': int(len(tr)), 'n_test_period': int(len(te)), 'train_span': span(tr), 'test_span': span(te),
            'protocol_train': proto(tr), 'protocol_test': proto(te),
            'top_dst_ports_train': {int(k): int(v) for k, v in top_ports(tr['Dst Port'], 5).items()},
            'top_dst_ports_test': {int(k): int(v) for k, v in top_ports(te['Dst Port'], 5).items()},
            'top20_port_jaccard': None if np.isnan(pj) else round(pj, 3),
            'test_src_ip_seen_in_train': None if np.isnan(src_seen) else round(src_seen, 3),
            'test_dst_ip_seen_in_train': None if np.isnan(dst_seen) else round(dst_seen, 3),
            'drift_auc': None if np.isnan(auc) else round(auc, 3),
            'drift_auc_sd': None if np.isnan(auc_sd) else round(auc_sd, 3),
        }
        f = lambda v: f'{v:.2f}' if isinstance(v, float) and not np.isnan(v) else '  -'
        print(f'{name:38s} {len(g):>8,} {span(tr):>27s} {span(te):>27s} {f(pj):>7s} '
              f'{f(src_seen):>10s} {f(dst_seen):>10s} {f(auc):>9s}', flush=True)

    print('\n=== top destination ports, training period -> test period ===')
    for name, r in res.items():
        tp = ', '.join(f'{p}:{n}' for p, n in r['top_dst_ports_train'].items())
        sp = ', '.join(f'{p}:{n}' for p, n in r['top_dst_ports_test'].items())
        print(f'\n{name}\n   train: {tp}\n   test : {sp}\n   protocol {r["protocol_train"]} -> {r["protocol_test"]}')

    fn = OUT / ('temporal_drift.json' if a.cleaning == 'all' else 'temporal_drift_r1.json')
    json.dump(res, open(fn, 'w'), indent=2, default=str)
    print('\n[DONE]', fn)


if __name__ == '__main__':
    main()
