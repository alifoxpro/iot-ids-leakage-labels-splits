# -*- coding: utf-8 -*-
"""
diagnose_icmp_confusion.py
==========================
Why are DDOS ICMP Flood / ICMP Fragmentation detected at only ~15% recall even
under the random split? Two checks on the same data as the split pilot:

  1. Confusion per sub-attack: where the model sends each sub-attack
     (random split, class-weighted XGBoost, same settings as the pilot).
  2. Cross-class duplicates: flows whose 76 raw features are *identical* to a flow
     of another class. Duplicates are removed only within a class, so identical
     feature vectors can carry different labels, which no classifier can separate.

The loaded data are cached to results_2026_03_03/split_pilot/pilot_data.parquet so
later split experiments start in seconds instead of re-reading ~10 GB of CSV.
Output: results_2026_03_03/split_pilot/icmp_diagnosis.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\diagnose_icmp_confusion.py
"""
import json, sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pilot_temporal_split import CLASSES, FEATS, OUT, RAW, SEED, fit_eval, load  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
CACHE = OUT / 'pilot_data.parquet'


def get_data():
    if CACHE.exists():
        print(f'[1] loading cached data {CACHE.name}')
        return pd.read_parquet(CACHE)
    print('[1] loading CSVs (first run; will be cached)')
    df = load()
    df.to_parquet(CACHE, index=False)
    return df


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df = get_data()
    X, y = df[FEATS].to_numpy(np.float32), df['y'].to_numpy()
    sub = df['sub'].to_numpy()
    res = {}

    # ---------------- 1. confusion per sub-attack (random split) ----------------
    print('[2] random split + XGBoost')
    tr, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
    tr, _ = train_test_split(tr, test_size=0.15 / 0.85, stratify=y[tr], random_state=SEED)
    _, p = fit_eval(X[tr], y[tr], X[te], y[te], 'A random')
    conf = {}
    print('\n=== where each sub-attack goes (random split; share of its test flows) ===')
    for c, s in sorted(set(zip(y[te], sub[te]))):
        m = (y[te] == c) & (sub[te] == s)
        dist = pd.Series(p[m]).map(dict(enumerate(CLASSES))).value_counts(normalize=True)
        conf[f'{CLASSES[c]} / {s}'] = dist.round(4).to_dict()
        top = ', '.join(f'{k} {v:.2f}' for k, v in dist.head(3).items())
        print(f'  {CLASSES[c]:10s} / {s:24s} n={m.sum():>7,}  ->  {top}')
    res['confusion_per_subattack_random'] = conf

    # ---------------- 2. cross-class duplicates ----------------
    print('\n[3] cross-class identical feature vectors (76 raw features)')
    key = pd.util.hash_pandas_object(df[RAW].fillna(-1.2345e30), index=False).to_numpy()
    k = pd.DataFrame({'key': key, 'y': y, 'sub': sub})
    n_cls = k.groupby('key')['y'].nunique()
    shared = set(n_cls.index[n_cls > 1])
    k['shared'] = k['key'].isin(shared)
    dup = {}
    print('  share of flows whose exact feature vector also appears in ANOTHER class:')
    for (c, s), g in k.groupby(['y', 'sub']):
        frac = float(g['shared'].mean())
        others = k[k['key'].isin(set(g.loc[g['shared'], 'key'])) & (k['y'] != c)]['y']
        with_ = others.map(dict(enumerate(CLASSES))).value_counts().head(3).to_dict()
        dup[f'{CLASSES[c]} / {s}'] = {'n': int(len(g)), 'shared_fraction': round(frac, 4),
                                     'shared_with': {a: int(b) for a, b in with_.items()}}
        print(f'  {CLASSES[c]:10s} / {s:24s} {frac:6.1%}   shared with: {with_ if with_ else "-"}')
    res['cross_class_duplicates'] = dup
    res['total_flows_in_ambiguous_vectors'] = int(k['shared'].sum())

    # ---------------- 3. what the ICMP flows look like ----------------
    print('\n[4] ICMP sub-attacks: typical flow shape (medians)')
    cols = ['Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Packet Length Max',
            'Flow Packets/s', 'Fwd Header Length']
    cols = [c for c in cols if c in df.columns]
    grp = df[df['sub'].isin(['DDOS ICMP FLOOD', 'DDOS ICMP Fragmentation'])].groupby('sub')[cols].median()
    ref = df[df['y'].isin([CLASSES.index('Benign'), CLASSES.index('Recon'), CLASSES.index('Mirai')])] \
        .groupby('y')[cols].median().rename(index=dict(enumerate(CLASSES)))
    shape = pd.concat([grp, ref])
    print(shape.round(1).to_string())
    res['median_profiles'] = shape.round(3).to_dict(orient='index')

    json.dump(res, open(OUT / 'icmp_diagnosis.json', 'w'), indent=2, default=str)
    print('\n[DONE]', OUT / 'icmp_diagnosis.json')


if __name__ == '__main__':
    main()
