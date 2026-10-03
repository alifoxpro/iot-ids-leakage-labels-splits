# -*- coding: utf-8 -*-
"""
identifier_leakage.py
=====================
Can the near-perfect published accuracy on CIC IoT-DIAD 2024 be reached when the
identifier columns of the flow files are used as features?

Hossain (2025) describes 84 features and Ghosh et al. (2025) 85 features - the total column
counts of the CICFlowMeter files, which include Flow ID, IP addresses, ports, protocol and
timestamp - and both label-encode categorical columns. Neither paper states that the
identifier columns were removed. This script adds five of the seven identifier columns
(Flow ID and source port are not in the cache) to the 81 flow features and trains the
class-weighted XGBoost of the paper on the same sample:

  split     random stratified 80/20 (as in both papers)  |  temporal (main protocol)
  features  F0: 81 flow features
            F1: + destination port and protocol (numeric)
            F2: + source and destination IP address, label-encoded in LEXICOGRAPHIC order
                (pd.factorize(sort=True)); the first version encoded addresses in order of first
                appearance, and because the rows are ordered by class and time that code itself
                carried the class - results of that version are kept in identifier_leakage/
            F3: + timestamp (seconds since the first flow of the sample, float32: about 1 s resolution)
            F4: F1 + F2 + F3 (five identifiers)
  labels    raw folder labels
XGBoost runs on the CPU here (the GPU ran out of memory with the extra columns); on the same
inputs this changes macro-F1 by about 0.001 relative to the GPU runs of tree_protocol_study.py.
Output: results_2026_03_03/identifier_leakage_v2/<split>_<set>.json (one condition per process)
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\identifier_leakage.py
"""
import gc, json, sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import NEEDED, metrics, prepare, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'identifier_leakage_v2'
IDS = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol']


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ids = get_flagged(columns=IDS + ['ts'])                 # pass 1: identifiers -> integers
    ident = pd.DataFrame({
        'dst_port': ids['Dst Port'].astype(np.float32).to_numpy(),
        'protocol': ids['Protocol'].astype(np.float32).to_numpy(),
        'src_ip': pd.factorize(ids['Src IP'], sort=True)[0].astype(np.float32),     # class-independent codes
        'dst_ip': pd.factorize(ids['Dst IP'], sort=True)[0].astype(np.float32),
    })
    t = pd.to_datetime(ids['ts']).astype('int64') // 10**9
    ident['ts'] = (t - t.min()).astype(np.float32).to_numpy()                    # relative seconds
    del ids; gc.collect()
    raw = get_flagged(columns=NEEDED)                        # pass 2: features, same row order
    X, meta, _ = prepare(raw)
    del raw; gc.collect()
    y = meta['y'].to_numpy(); sub = meta['sub'].astype(str).to_numpy()
    sets = {'F0 flow features': [], 'F1 +port,protocol': ['dst_port', 'protocol'],
            'F2 +IP addresses': ['src_ip', 'dst_ip'], 'F3 +timestamp': ['ts'],
            'F4 +all identifiers': ['dst_port', 'protocol', 'src_ip', 'dst_ip', 'ts']}
    idx = np.arange(len(y))
    split_idx = {'random 80/20': train_test_split(idx, test_size=0.2, stratify=y, random_state=SEED),
                 'temporal': (lambda t: (t[0], t[2]))(splits(meta, 'temporal'))}
    only = sys.argv[1:]                                     # optional: "<split>|<feature set>" to run one condition
    for sname, (tr, te) in split_idx.items():
        for fname, cols in sets.items():
            fn = OUT / f"{sname.split()[0]}_{fname.split()[0]}.json"
            if fn.exists() or (only and f'{sname}|{fname}' not in only):
                continue
            Xtr = X[tr] if not cols else np.hstack([X[tr], ident[cols].to_numpy(np.float32)[tr]])
            clf = make('XGBoost'); clf.set_params(device='cpu', n_jobs=4)
            clf.fit(Xtr, y[tr], sample_weight=compute_sample_weight('balanced', y[tr]))
            del Xtr; gc.collect()
            Xte = X[te] if not cols else np.hstack([X[te], ident[cols].to_numpy(np.float32)[te]])
            p = clf.predict(Xte)
            r = metrics(y[te], p, sub[te])
            r.update({'split': sname, 'features': fname, 'n_features': int(Xte.shape[1])})
            json.dump(r, open(fn, 'w'), indent=1)
            print(f'{sname:13s} {fname:22s} acc={r["accuracy"]:.4f}  bal-acc={r["balanced_accuracy"]:.4f}  '
                  f'macro-F1={r["macro_f1"]:.4f}', flush=True)
            del Xte, clf; gc.collect()
            return                                          # one condition per process (memory)
    print('[DONE] all conditions', flush=True)


if __name__ == '__main__':
    main()
