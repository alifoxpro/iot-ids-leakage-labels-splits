# -*- coding: utf-8 -*-
"""
temporal_split_by_subattack.py
==============================
Step 2 of the split-design study. The pilot (pilot_temporal_split.py) showed a
large drop from a random split to a per-class temporal split. Because DDOS, DOS,
Spoofing and Web-Based consist of several sub-attacks captured at different times,
part of that drop may come from sub-attacks that are absent from training rather
than from time itself. This script separates the two effects.

Same data, same model (class-weighted XGBoost) as the pilot, three splits:
  A  random stratified 70/15/15 split                        (paper protocol)
  B  per-class temporal split                                 (pilot design)
  D  per-sub-attack temporal split: inside each of the 16 capture groups
     (sub-folder, or the class itself when it has none) flows are ordered by
     Timestamp; first 70% train, next 15% validation, last 15% test.
     Every sub-attack is present in training, so only the time gap remains.

Reading the result:
  A -> D  = effect of testing on later traffic of already-seen attacks (pure time)
  D -> B  = extra effect of sub-attacks that appear only in the test period

Output: results_2026_03_03/split_pilot/subattack_results.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\temporal_split_by_subattack.py
"""
import json, sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pilot_temporal_split import CLASSES, FEATS, OUT, SEED, fit_eval, load, temporal_idx  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')


def subattack_temporal_idx(df):
    """70/15/15 by time inside every capture group (class + sub-folder)."""
    tr, va, te = [], [], []
    for _, g in df.groupby(['y', 'sub'], sort=True):
        idx = g.sort_values('ts', kind='stable').index.to_numpy()
        a, b = int(0.70 * len(idx)), int(0.85 * len(idx))
        tr += list(idx[:a]); va += list(idx[a:b]); te += list(idx[b:])
    return np.array(tr), np.array(va), np.array(te)


def per_group_recall(df, te, pred):
    """Recall of the true class, reported separately for each sub-attack in the test set."""
    out = {}
    sub = df['sub'].to_numpy()[te]
    yte = df['y'].to_numpy()[te]
    for (c, s) in sorted(set(zip(yte, sub))):
        m = (yte == c) & (sub == s)
        recall = float((pred[m] == c).mean())
        out[f'{CLASSES[c]} / {s}'] = {'n_test': int(m.sum()), 'recall': round(recall, 4)}
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print('[1] loading (same data and caps as the pilot)')
    df = load()
    X, y = df[FEATS].to_numpy(np.float32), df['y'].to_numpy()
    groups = df.groupby(['y', 'sub']).size()
    print(f'    {len(groups)} capture groups:')
    for (c, s), n in groups.items():
        print(f'      {CLASSES[c]:10s} / {s:28s} {n:>9,}')
    res = {'n_total': int(len(df)), 'n_groups': int(len(groups))}

    print('[2] A: random stratified split')
    tr, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
    tr, _ = train_test_split(tr, test_size=0.15 / 0.85, stratify=y[tr], random_state=SEED)
    res['A_random'], p = fit_eval(X[tr], y[tr], X[te], y[te], 'A random')
    res['A_random']['per_subattack'] = per_group_recall(df, te, p)

    print('[3] B: per-class temporal split')
    tr, _, te = temporal_idx(df)
    res['B_temporal_class'], p = fit_eval(X[tr], y[tr], X[te], y[te], 'B temporal/class')
    res['B_temporal_class']['per_subattack'] = per_group_recall(df, te, p)
    missing = sorted(set(df['sub'].to_numpy()[te]) - set(df['sub'].to_numpy()[tr]))
    res['B_temporal_class']['subattacks_absent_from_train'] = missing
    print(f'    sub-attacks present in test but absent from training: {missing or "none"}')

    print('[4] D: per-sub-attack temporal split')
    tr, _, te = subattack_temporal_idx(df)
    res['D_temporal_subattack'], p = fit_eval(X[tr], y[tr], X[te], y[te], 'D temporal/sub-attack')
    res['D_temporal_subattack']['per_subattack'] = per_group_recall(df, te, p)

    print('\n=== summary (macro-F1 / balanced accuracy) ===')
    for k in ('A_random', 'B_temporal_class', 'D_temporal_subattack'):
        print(f'  {k:22s} macro-F1={res[k]["macro_f1"]:.3f}  bal-acc={res[k]["balanced_accuracy"]:.3f}')
    a, b, d = (res[k]['macro_f1'] for k in ('A_random', 'B_temporal_class', 'D_temporal_subattack'))
    print(f'  pure time effect (A->D):          {d - a:+.3f} macro-F1')
    print(f'  unseen sub-attack effect (D->B):  {b - d:+.3f} macro-F1')

    print('\n=== recall per sub-attack (A random | D temporal/sub-attack) ===')
    for g, v in res['D_temporal_subattack']['per_subattack'].items():
        ra = res['A_random']['per_subattack'].get(g, {}).get('recall', float('nan'))
        print(f'  {g:42s} {ra:.3f} | {v["recall"]:.3f}   (n_test={v["n_test"]:,})')

    json.dump(res, open(OUT / 'subattack_results.json', 'w'), indent=2, default=str)
    print('\n[DONE]', OUT / 'subattack_results.json')


if __name__ == '__main__':
    main()
