# -*- coding: utf-8 -*-
"""
deep_split_noise_study.py
=========================
Deep-learning confirmation of the split-design and label-noise findings obtained with
XGBoost (pilot_temporal_split.py, temporal_split_by_subattack.py, rule_sensitivity.py).

Factorial design, identical data sample for every run (flagged_loader.py cache):
  split     random   : stratified 70/15/15 (the paper's protocol)
            temporal : 70/15/15 by time inside each of the 16 capture groups
  cleaning  raw      : folder labels as distributed
            r1       : attack flows with an endpoint outside the testbed removed (rule R1)
            all      : rules R1 | R2 | R3 removed      (optional, --cleaning raw r1 all)
  model     ResNet1D, GRU, Transformer (default), FT_Transformer (optional, slow)
  seed      17, 42 (default); the data split is fixed (seed 42), only training varies

Models, architectures and the training loop are imported unchanged from
src/stage3_ml_models.py (class-weighted cross-entropy, Adam, AMP, gradient clipping,
ReduceLROnPlateau, early stopping on the validation part of each split). Only the epoch
cap is set by --max-epochs so that all 24+ runs share the same budget.

Each finished run is written to results_2026_03_03/deep_split/<model>_<split>_<cleaning>_s<seed>.json;
rerunning the script skips finished runs, so it can be stopped and resumed at any time.
  python experiments/deep_split_noise_study.py                     # run everything missing
  python experiments/deep_split_noise_study.py --models ResNet1D --seeds 42
  python experiments/deep_split_noise_study.py --summary           # table of finished runs

Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\deep_split_noise_study.py
"""
import argparse, gc, json, logging, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(ROOT / 'src'))
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, FEATS, SEED  # noqa: E402
from temporal_split_by_subattack import subattack_temporal_idx  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = ROOT / 'results_2026_03_03' / 'deep_split'
MODEL_CLASSES = {'ResNet1D': 'ResNet1DModel', 'GRU': 'GRUModel',
                 'Transformer': 'TransformerModel', 'FT_Transformer': 'FTTransformerModel'}


def splits(df, kind):
    """Return train / validation / test row indices for one split design."""
    y = df['y'].to_numpy()
    if kind == 'random':
        rest, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
        tr, va = train_test_split(rest, test_size=0.15 / 0.85, stratify=y[rest], random_state=SEED)
        return tr, va, te
    return subattack_temporal_idx(df)


NEEDED = FEATS + ['y', 'sub', 'ts', 'r1_external', 'r2_service', 'r3_benign_pair']


def prepare(data):
    """Build the feature matrix ONCE; every run then works on row indices only."""
    X = data[FEATS].to_numpy(np.float32)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)   # models scale internally
    meta = data[['y', 'sub', 'ts']].copy()
    meta['sub'] = meta['sub'].astype('category')
    flags = {c: data[c].to_numpy() for c in ('r1_external', 'r2_service', 'r3_benign_pair')}
    return X, meta, flags


def kept_rows(flags, how):
    """Global row positions kept by a cleaning variant."""
    if how == 'raw':
        return np.arange(len(flags['r1_external']))
    bg = flags['r1_external']
    if how == 'all':
        bg = bg | flags['r2_service'] | flags['r3_benign_pair']
    return np.where(~bg)[0]


def metrics(y, p, sub):
    labels = list(range(len(CLASSES)))
    out = {'accuracy': float(accuracy_score(y, p)),
           'balanced_accuracy': float(balanced_accuracy_score(y, p)),
           'macro_f1': float(f1_score(y, p, average='macro', labels=labels, zero_division=0)),
           'per_class_f1': dict(zip(CLASSES, f1_score(y, p, average=None, labels=labels, zero_division=0).round(4).tolist())),
           'per_class_recall': dict(zip(CLASSES, recall_score(y, p, average=None, labels=labels, zero_division=0).round(4).tolist())),
           'per_subattack_recall': {}}
    for c, s in sorted(set(zip(y, sub))):
        m = (y == c) & (sub == s)
        out['per_subattack_recall'][f'{CLASSES[c]} / {s}'] = round(float((p[m] == c).mean()), 4)
    return out


def run_one(model_name, split, cleaning, seed, data, max_epochs):
    import torch
    import stage3_ml_models as S
    S.DL_MODELS[model_name]['epochs'] = max_epochs            # same budget for every run
    np.random.seed(seed); torch.manual_seed(seed)

    X_all, meta_all, flags = data
    rows = kept_rows(flags, cleaning)
    meta = meta_all.iloc[rows].reset_index(drop=True)      # 3 small columns only
    tr, va, te = splits(meta, split)                        # positions within `rows`
    tr, va, te = rows[tr], rows[va], rows[te]               # -> global positions
    y = meta_all['y'].to_numpy()
    sub = meta_all['sub'].astype(str).to_numpy()
    cw = compute_class_weight('balanced', classes=np.arange(len(CLASSES)), y=y[tr]).astype(np.float32)

    model = getattr(S, MODEL_CLASSES[model_name])(random_state=seed)
    t = time.time()
    model.fit(X_all[tr], y[tr], X_all[va], y[va], class_weights=cw)
    fit_s = time.time() - t
    p = model.predict(X_all[te])
    r = metrics(y[te], p, sub[te])
    r.update({'model': model_name, 'split': split, 'cleaning': cleaning, 'seed': seed,
              'max_epochs': max_epochs, 'epochs_run': len((getattr(model, 'history', None) or {}).get('train_loss', [])),
              'fit_seconds': round(fit_s, 1), 'n_train': int(len(tr)), 'n_val': int(len(va)), 'n_test': int(len(te))})
    r['_pred'] = (y[te].astype(np.int8), np.asarray(p).astype(np.int8).ravel(), sub[te])
    del model; gc.collect(); torch.cuda.empty_cache()
    return r


def summary():
    rows = [json.load(open(f)) for f in sorted(OUT.glob('*.json'))]
    if not rows:
        print('no finished runs yet'); return
    d = pd.DataFrame(rows)
    g = d.groupby(['model', 'split', 'cleaning'])
    t = g.agg(runs=('seed', 'count'),
              macro_f1=('macro_f1', 'mean'), macro_f1_sd=('macro_f1', 'std'),
              bal_acc=('balanced_accuracy', 'mean'), bal_acc_sd=('balanced_accuracy', 'std'),
              acc=('accuracy', 'mean')).reset_index()
    pd.set_option('display.width', 160)
    print('\n=== mean over seeds (sd) ===')
    print(t.round(3).to_string(index=False))
    pcf = pd.DataFrame([{**{'model': r['model'], 'split': r['split'], 'cleaning': r['cleaning']},
                         **r['per_class_f1']} for r in rows]).groupby(['model', 'split', 'cleaning']).mean()
    print('\n=== per-class F1 (mean over seeds) ===')
    print(pcf.round(3).to_string())
    t.to_csv(OUT / 'summary.csv', index=False)
    print('\n[saved]', OUT / 'summary.csv')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--models', nargs='+', default=['ResNet1D', 'GRU', 'Transformer'],
                    choices=list(MODEL_CLASSES))
    ap.add_argument('--splits', nargs='+', default=['random', 'temporal'], choices=['random', 'temporal'])
    ap.add_argument('--cleaning', nargs='+', default=['raw', 'r1'], choices=['raw', 'r1', 'all'])
    ap.add_argument('--seeds', nargs='+', type=int, default=[17, 42])
    ap.add_argument('--max-epochs', type=int, default=30)
    ap.add_argument('--summary', action='store_true', help='only print the table of finished runs')
    ap.add_argument('--out', default=None, help='output folder name under results_2026_03_03 (default deep_split)')
    a = ap.parse_args()
    global OUT
    if a.out:
        OUT = OUT.parent / a.out
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return

    logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(message)s', datefmt='%H:%M:%S')
    jobs = [(m, s, c, sd) for m in a.models for s in a.splits for c in a.cleaning for sd in a.seeds]
    todo = [j for j in jobs if not (OUT / f'{j[0]}_{j[1]}_{j[2]}_s{j[3]}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} already finished, {len(todo)} to do '
          f'(max {a.max_epochs} epochs each)')
    if not todo:
        summary(); return
    raw = get_flagged(columns=NEEDED)                        # no IP / port text columns
    data = prepare(raw)
    del raw; gc.collect()
    for i, (m, s, c, sd) in enumerate(todo, 1):
        print(f'\n===== [{i}/{len(todo)}] {m} | split={s} | cleaning={c} | seed={sd} =====', flush=True)
        r = run_one(m, s, c, sd, data, a.max_epochs)
        yt, yp, st = r.pop('_pred')
        np.savez_compressed(OUT / f'{m}_{s}_{c}_s{sd}.npz', y=yt, p=yp, sub=st)
        json.dump(r, open(OUT / f'{m}_{s}_{c}_s{sd}.json', 'w'), indent=2)
        print(f'[result] macro-F1={r["macro_f1"]:.4f}  bal-acc={r["balanced_accuracy"]:.4f}  '
              f'acc={r["accuracy"]:.4f}  epochs={r["epochs_run"]}  time={r["fit_seconds"] / 60:.1f} min', flush=True)
    summary()


if __name__ == '__main__':
    main()
