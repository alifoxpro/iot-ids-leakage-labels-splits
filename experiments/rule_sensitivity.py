# -*- coding: utf-8 -*-
"""
rule_sensitivity.py
===================
Step 1: does the label-noise conclusion depend on one particular cleaning rule?
The same class-weighted XGBoost is trained under seven cleaning variants, each with
  A  random stratified split
  D  temporal split inside each sub-attack (every sub-attack seen in training)

Variants (background flows are dropped from attack classes; Benign is never touched):
  none            no cleaning
  R1              external endpoint only
  R2              service ports only
  R3              IP pair seen in Benign only
  R1+R3           without the service-port rule
  all             R1 or R2 or R3                       (relabel_background.py)
  all, floods-R2  as 'all' but R2 is not applied to DOS/DDOS (their flood traffic
                  may legitimately target port 53 and similar ports)

Output: results_2026_03_03/split_pilot/rule_sensitivity.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\rule_sensitivity.py
"""
import json, sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, FEATS, OUT, SEED, fit_eval  # noqa: E402
from temporal_split_by_subattack import subattack_temporal_idx  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
FLOODS = {CLASSES.index('DOS'), CLASSES.index('DDOS')}


def variants(df):
    r1, r2, r3 = (df[c].to_numpy() for c in ('r1_external', 'r2_service', 'r3_benign_pair'))
    flood = df['y'].isin(FLOODS).to_numpy()
    return {
        'none': np.zeros(len(df), bool),
        'R1': r1, 'R2': r2, 'R3': r3,
        'R1+R3': r1 | r3,
        'all': r1 | r2 | r3,
        'all, floods-R2': r1 | r3 | (r2 & ~flood),
    }


def evaluate(df, name):
    df = df.reset_index(drop=True)
    X, y = df[FEATS].to_numpy(np.float32), df['y'].to_numpy()
    tr, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
    tr, _ = train_test_split(tr, test_size=0.15 / 0.85, stratify=y[tr], random_state=SEED)
    a, _ = fit_eval(X[tr], y[tr], X[te], y[te], f'{name:15s} A random')
    tr, _, te = subattack_temporal_idx(df)
    d, _ = fit_eval(X[tr], y[tr], X[te], y[te], f'{name:15s} D temporal')
    counts = {c: int((y == i).sum()) for i, c in enumerate(CLASSES)}
    return {'A_random': a, 'D_temporal_subattack': d, 'class_counts': counts}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df = get_flagged()
    res = {}
    for name, drop in variants(df).items():
        print(f'\n--- variant: {name}  (drops {drop.mean():.1%} of all flows)')
        res[name] = evaluate(df[~drop], name)
        res[name]['dropped_fraction'] = round(float(drop.mean()), 4)

    print('\n=== macro-F1 / balanced accuracy per cleaning variant ===')
    print(f'  {"variant":16s} {"dropped":>8s}   {"random":>15s}   {"temporal":>15s}')
    for n, r in res.items():
        a, d = r['A_random'], r['D_temporal_subattack']
        print(f'  {n:16s} {r["dropped_fraction"]:>8.1%}   {a["macro_f1"]:.3f} / {a["balanced_accuracy"]:.3f}'
              f'   {d["macro_f1"]:.3f} / {d["balanced_accuracy"]:.3f}')

    print('\n=== per-class F1, random split ===')
    print('  ' + f'{"variant":16s}' + ''.join(f'{c[:9]:>10s}' for c in CLASSES))
    for n, r in res.items():
        print('  ' + f'{n:16s}' + ''.join(f'{r["A_random"]["per_class_f1"][c]:>10.3f}' for c in CLASSES))
    print('\n=== per-class F1, temporal split ===')
    print('  ' + f'{"variant":16s}' + ''.join(f'{c[:9]:>10s}' for c in CLASSES))
    for n, r in res.items():
        print('  ' + f'{n:16s}' + ''.join(f'{r["D_temporal_subattack"]["per_class_f1"][c]:>10.3f}' for c in CLASSES))
    print('\n=== flows kept per class ===')
    print('  ' + f'{"variant":16s}' + ''.join(f'{c[:9]:>10s}' for c in CLASSES))
    for n, r in res.items():
        print('  ' + f'{n:16s}' + ''.join(f'{r["class_counts"][c]:>10,}' for c in CLASSES))

    json.dump(res, open(OUT / 'rule_sensitivity.json', 'w'), indent=2, default=str)
    print('\n[DONE]', OUT / 'rule_sensitivity.json')


if __name__ == '__main__':
    main()
