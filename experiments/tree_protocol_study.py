# -*- coding: utf-8 -*-
"""
tree_protocol_study.py
======================
Two experiments with the tree ensembles on the sample of deep_split_noise_study.py
(all models: balanced sample weights, NaN/inf -> 0):

A. "main"  - the four protocol conditions of the paper (cleaning applied, then split),
             XGBoost (1 run, deterministic), LightGBM and random forest (seeds 42, 17, 7).
B. "decomp"- train-set versus test-set cleaning. The split is made ONCE on the raw rows;
             training and test parts are then filtered independently with the R1 mask:
             train {raw, r1} x test {raw, r1}, seed 42, all three models.
             Separates "a better model" (train cleaning) from "an easier test set"
             (test cleaning).

Every run stores its test predictions, so confidence intervals and paired tests can be
computed afterwards (experiments/bootstrap_ci.py).
Output: results_2026_03_03/tree_protocol/{main,decomp}/<run>.json + <run>.npz
Resumable: finished runs are skipped.
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\tree_protocol_study.py
"""
import gc, json, sys, time
from pathlib import Path

import numpy as np
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import NEEDED, kept_rows, metrics, prepare, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'tree_protocol'
SEEDS = {'XGBoost': [42], 'LightGBM': [42, 17, 7], 'RandomForest': [42, 17, 7]}
DECOMP_SEEDS = {'LightGBM': [42, 17, 7]}      # LightGBM varies strongly with the seed; the others use 42


def model(name, seed):
    m = make(name)
    m.set_params(random_state=seed)
    return m


def save(path, r, y_true, p, sub):
    json.dump(r, open(path.with_suffix('.json'), 'w'), indent=1)
    np.savez_compressed(path.with_suffix('.npz'), y=y_true.astype(np.int8), p=p, sub=sub)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). A random forest of this size takes several GB, '
                         'so run with 1 inside a PowerShell loop: every fit then starts in a fresh process.')
    a = ap.parse_args()
    jobs = []
    for m, seeds in SEEDS.items():
        for sd in seeds:
            for s in ['random', 'temporal']:
                for c in ['raw', 'r1']:
                    jobs.append(('main', m, sd, s, c, c))
    for m in SEEDS:
        for sd in DECOMP_SEEDS.get(m, [42]):
            for s in ['random', 'temporal']:
                for ctr in ['raw', 'r1']:
                    for cte in ['raw', 'r1']:
                        jobs.append(('decomp', m, sd, s, ctr, cte))
    name = lambda j: (f'{j[1]}_{j[3]}_{j[4]}_s{j[2]}' if j[0] == 'main'
                      else f'{j[1]}_{j[3]}_train-{j[4]}_test-{j[5]}' + ('' if j[2] == 42 else f'_s{j[2]}'))
    todo = [j for j in jobs if not (OUT / j[0] / f'{name(j)}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(todo)} to do', flush=True)
    if not todo:
        return
    for d in ('main', 'decomp'):
        (OUT / d).mkdir(parents=True, exist_ok=True)
    raw = get_flagged(columns=NEEDED)
    X, meta, flags = prepare(raw)
    del raw; gc.collect()
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    keep = np.zeros(len(y), bool); keep[kept_rows(flags, 'r1')] = True
    raw_split = {s: splits(meta, s) for s in ['random', 'temporal']}      # for the decomposition

    # one fit per (kind, model, seed, split, train cleaning); a decomposition fit serves both test sets
    fits = {}
    for j in todo:
        fits.setdefault(j[:5], []).append(j)
    done = 0
    for n_fit, (key, js) in enumerate(fits.items(), 1):
        if a.max_fits and n_fit > a.max_fits:
            break
        kind, m, sd, s, ctr = key
        if kind == 'main':
            rows = kept_rows(flags, ctr)
            tr, _, te = splits(meta.iloc[rows].reset_index(drop=True), s)
            tr, tests = rows[tr], {ctr: rows[te]}
        else:
            tr, _, te = raw_split[s]
            tr = tr[keep[tr]] if ctr == 'r1' else tr
            tests = {'raw': te, 'r1': te[keep[te]]}
        clf = model(m, sd)
        t = time.time()
        clf.fit(X[tr], y[tr], sample_weight=compute_sample_weight('balanced', y[tr]))
        fit_s = time.time() - t
        for j in js:
            te = tests[j[5]]
            p = np.asarray(clf.predict(X[te])).astype(np.int8).ravel()
            r = metrics(y[te], p, sub[te])
            r.update({'kind': kind, 'model': m, 'seed': sd, 'split': s, 'train_cleaning': ctr,
                      'test_cleaning': j[5], 'n_train': int(len(tr)), 'n_test': int(len(te)),
                      'fit_seconds': round(fit_s, 1)})
            save(OUT / kind / name(j), r, y[te], p, sub[te])
            done += 1
            print(f'[{done}/{len(todo)}] {kind:6s} {m:12s} s{sd:<3d} {s:8s} train={ctr:3s} test={j[5]:3s} '
                  f'macro-F1={r["macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} '
                  f'({fit_s / 60:.1f} min)', flush=True)
        del clf; gc.collect()
    left = len(todo) - done
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)


if __name__ == '__main__':
    main()
