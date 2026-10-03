# -*- coding: utf-8 -*-
r"""
cleaning_train_only.py
======================
Reviewer request (Table 4): each cleaning variant was scored on its own, differently cleaned
test set, so part of a variant's gain may only reflect an easier test set. Here cleaning is
applied to the TRAINING rows only, and every variant is scored on the SAME test rows.

Design (sample of flagged_loader.py, 3,626,502 flows; XGBoost of extra_baselines.make,
balanced sample weights computed on the kept training rows, NaN/inf -> 0; with
--models RandomForest also the random forest of extra_baselines.make, same rows and weights):
  split     random | temporal, made ONCE on all raw rows (deep_split_noise_study.splits);
            the validation part is not used (no early stopping), as in tree_protocol_study.py
  variant   training rows are dropped when flagged by
              none    nothing
              R1      external endpoint
              R2      service port
              R3      IP pair seen in Benign
              R1+R3   R1 | R3
              All     R1 | R2 | R3
              All*    R1 | R3 | (R2 outside DOS/DDOS): flood traffic may legitimately hit
                      port 53 and similar ports (rule_sensitivity.py "all, floods-R2")
            Benign rows are never flagged, so the Benign training rows are the same in every variant.
  test set  test_R1   test rows not flagged by R1          (common to all variants)
            test_All  test rows not flagged by R1|R2|R3    (common to all variants)
7 variants x 2 splits = 14 fits per model (XGBoost about 30 s each on the GPU, the random forest
a few minutes and several GB, so one fit per process); each fit is scored on both test sets,
giving 28 runs per model. The split, the training rows and the test rows do not depend on the
model, so the XGBoost and random-forest runs of a (split, test set) share the same test rows.

Stored per (variant, split, test set): metrics() of deep_split_noise_study (accuracy, balanced
accuracy, macro-F1, per-class F1 / recall, per-sub-attack recall), attack_macro_f1 (mean F1 of
the seven attack classes, Benign excluded), per-class precision, confusion matrix, class counts
of the training and test rows, n_train, n_train_dropped, n_test, fit_seconds.
Predictions: <run>.npz with y, p (int8), sub and rows (global row positions of the test flows).
The test rows of one (split, test set) are identical and in the same order for all seven
variants, so paired bootstrap comparisons between variants are possible.

Output: results_2026_03_03/q1_revision/cleaning_train_only/
          <model>_<split>_train-<variant>_test-<R1|All>.json + .npz   (<model>: XGBoost, RandomForest)
            (<variant> in the file name: none, R1, R2, R3, R1R3, All, AllStar)
          summary.csv               XGBoost runs only, columns unchanged (read by
                                    the manuscript build, which expects 28 rows)
          summary_RandomForest.csv  the same table for the random forest
          summary_models.csv        all models, with a 'model' column
          (written when all selected runs are finished, or with --summary)
Resumable: a fit is skipped when the JSONs of both its test sets exist; the existing XGBoost
files keep their names and are never rewritten.
Memory: X (81 features, NaN/inf -> 0) ~1.2 GB and the training copy X[tr] ~0.8 GB. The last fit of
a process copies the test rows it still needs and frees X before fitting, so with --max-fits 1 the
random forest fit holds only X[tr] and the two test copies (~0.3 GB) besides its trees.
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  XGBoost (its 28 runs exist from the first release; the call then only rewrites the summary):
  & $py experiments\cleaning_train_only.py 2>&1 | Tee-Object -FilePath cleaning_train_only.log
  Random forest, one fit per process (14 fits of a few minutes each; finished fits are skipped):
  1..14 | ForEach-Object { & $py experiments\cleaning_train_only.py --models RandomForest --max-fits 1 2>&1 | Tee-Object -FilePath cleaning_train_only_rf.log -Append }
  & $py experiments\cleaning_train_only.py --summary 2>&1 | Tee-Object -FilePath cleaning_train_only_summary.log
"""
import argparse, gc, json, os, sys, time
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'cleaning_train_only'
LABELS = list(range(len(CLASSES)))
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']
FLOODS = [CLASSES.index('DOS'), CLASSES.index('DDOS')]
SPLITS = ['random', 'temporal']
MODELS = ['XGBoost', 'RandomForest']          # extra_baselines.make names; XGBoost = the paper's Table 8
# (variant, file-name slug, rule that removes training rows)
VARIANTS = [('none', 'none', 'no cleaning'),
            ('R1', 'R1', 'R1 external endpoint'),
            ('R2', 'R2', 'R2 service port'),
            ('R3', 'R3', 'R3 IP pair seen in Benign'),
            ('R1+R3', 'R1R3', 'R1 | R3'),
            ('All', 'All', 'R1 | R2 | R3'),
            ('All*', 'AllStar', 'R1 | R3 | (R2 outside DOS/DDOS)')]
TESTS = {'R1': 'test rows not flagged by R1', 'All': 'test rows not flagged by R1 | R2 | R3'}


def run_name(model, split, slug, test):
    """<model>_<split>_train-<slug>_test-<test>; the XGBoost names are those of the first release."""
    return f'{model}_{split}_train-{slug}_test-{test}'


def drop_masks(flags, y):
    """Row mask of every variant: True = flagged (removed from training)."""
    r1, r2, r3 = (np.asarray(flags[c], bool) for c in ('r1_external', 'r2_service', 'r3_benign_pair'))
    flood = np.isin(y, FLOODS)
    return {'none': np.zeros(len(y), bool), 'R1': r1, 'R2': r2, 'R3': r3, 'R1+R3': r1 | r3,
            'All': r1 | r2 | r3, 'All*': r1 | r3 | (r2 & ~flood)}


def counts(v):
    return dict(zip(CLASSES, np.bincount(v, minlength=len(CLASSES)).tolist()))


def score(y, p, sub):
    r = metrics(y, p, sub)
    f1 = f1_score(y, p, average=None, labels=LABELS, zero_division=0)
    r['attack_macro_f1'] = float(f1[ATTACKS].mean())
    r['per_class_precision'] = dict(zip(CLASSES, precision_score(
        y, p, average=None, labels=LABELS, zero_division=0).round(4).tolist()))
    r['confusion'] = confusion_matrix(y, p, labels=LABELS).tolist()
    return r


def save(path, r, y_true, p, sub, rows):
    # npz first, JSON last and atomically: the JSON marks a finished run for the resume check,
    # so a process killed while writing never leaves a JSON without its predictions
    np.savez_compressed(path.with_suffix('.npz'), y=y_true.astype(np.int8), p=p,
                        sub=np.asarray(sub, dtype=str), rows=rows.astype(np.int32))   # str: loads without pickle
    tmp = path.with_name(path.name + '.json.tmp')
    with open(tmp, 'w') as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path.with_suffix('.json'))


def summary():
    import pandas as pd
    rows = []
    for m in MODELS:
        for f in sorted(OUT.glob(f'{m}_*_train-*_test-*.json')):
            with open(f) as fh:
                rows.append(json.load(fh))
    if not rows:
        print('no finished runs yet'); return
    order = {v[0]: i for i, v in enumerate(VARIANTS)}
    d = pd.DataFrame([{'model': r.get('model', 'XGBoost'), 'split': r['split'], 'test_set': r['test_set'],
                       'variant': r['train_variant'], 'n_train': r['n_train'], 'n_test': r['n_test'],
                       'macro_f1': r['macro_f1'], 'attack_macro_f1': r['attack_macro_f1'],
                       'balanced_accuracy': r['balanced_accuracy'], 'accuracy': r['accuracy'],
                       **{f'f1_{c}': r['per_class_f1'][c] for c in CLASSES}}
                      for r in rows])
    d['_m'] = d['model'].map(MODELS.index)
    d['_o'] = d['variant'].map(order)
    d = d.sort_values(['_m', 'split', 'test_set', '_o']).drop(columns=['_m', '_o'])
    pd.set_option('display.width', 200)
    for (m, s, t), g in d.groupby(['model', 'split', 'test_set'], sort=False):
        print(f'\n=== {m}  split={s}  test=test_{t}  (n_test={g["n_test"].iloc[0]:,}) ===')
        print(g[['variant', 'n_train', 'macro_f1', 'attack_macro_f1', 'balanced_accuracy', 'accuracy']]
              .round(4).to_string(index=False))
    # summary.csv keeps its original content and columns (XGBoost only): the paper build script
    # keys it by (split, test_set, variant) and expects 28 rows
    for m, g in d.groupby('model', sort=False):
        path = OUT / ('summary.csv' if m == 'XGBoost' else f'summary_{m}.csv')
        g.drop(columns='model').to_csv(path, index=False)
        print('[saved]', path, flush=True)
    d.to_csv(OUT / 'summary_models.csv', index=False)
    print('[saved]', OUT / 'summary_models.csv', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit); with 1 inside a PowerShell loop '
                         'every fit starts in a fresh process')
    ap.add_argument('--models', nargs='+', choices=MODELS, default=['XGBoost'],
                    help='models to fit (default XGBoost); the random forest needs several GB, '
                         'so run it with --max-fits 1 inside a PowerShell loop')
    ap.add_argument('--summary', action='store_true', help='only print / write the table of finished runs')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return

    fits = [(m, s, v) for m in a.models for s in SPLITS for v in VARIANTS]
    todo = [(m, s, v) for m, s, v in fits
            if not all((OUT / f'{run_name(m, s, v[1], t)}.json').exists() for t in TESTS)]
    print(f'[plan] {len(fits)} fits ({", ".join(a.models)}) x {len(TESTS)} test sets, '
          f'{len(fits) - len(todo)} fits finished, {len(todo)} to do', flush=True)
    if not todo:
        summary(); return

    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    # splits() returns index LABELS of the frame it gets (subattack_temporal_idx uses g.index);
    # with a 0..N-1 index these are the global row positions of X, y, sub and the flags
    meta = meta.reset_index(drop=True)
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    drop = drop_masks(flags, y)
    del flags; gc.collect()

    split_cache = {}                      # split -> (training rows, {test set: test rows}), global positions
    n_runs = sum(not (OUT / f'{run_name(m, s, v[1], t)}.json').exists() for m, s, v in todo for t in TESTS)
    n_here = min(len(todo), a.max_fits) if a.max_fits else len(todo)   # fits of this process
    done = 0
    for n_fit, (m, s, (v, slug, rule)) in enumerate(todo, 1):
        if a.max_fits and n_fit > a.max_fits:
            break
        if s not in split_cache:
            tr_all, _, te = splits(meta, s)                    # ONCE on all raw rows
            split_cache[s] = (tr_all, {'R1': te[~drop['R1'][te]], 'All': te[~drop['All'][te]]})
        tr_all, tests = split_cache[s]
        tr = tr_all[~drop[v][tr_all]]
        need = [(tname, te) for tname, te in tests.items()
                if not (OUT / f'{run_name(m, s, slug, tname)}.json').exists()]
        present = np.unique(y[tr])        # XGBoost needs labels 0..K-1: re-encode if a class lost all training rows
        missing = [CLASSES[c] for c in LABELS if c not in present]
        if missing:
            print(f'  [warn] {m} {s} train-{v}: no training rows for {missing}', flush=True)

        Xtr = X[tr]                       # the same rows and order as before; a named copy only
        Xte = None
        if n_fit == n_here:               # last fit of this process: keep only the rows it still needs and
            Xte = {tname: X[te] for tname, te in need}   # free X (~1.2 GB) before the fit (the random
            del X                                        # forest needs several GB)
            gc.collect()
        clf = make(m)                     # model seed = SEED for both models (extra_baselines.make)
        t = time.time()
        clf.fit(Xtr, np.searchsorted(present, y[tr]), sample_weight=compute_sample_weight('balanced', y[tr]))
        fit_s = time.time() - t
        del Xtr; gc.collect()
        for tname, te in need:
            path = OUT / run_name(m, s, slug, tname)
            xt = X[te] if Xte is None else Xte.pop(tname)
            p = present[np.asarray(clf.predict(xt)).astype(int).ravel()].astype(np.int8)
            del xt
            r = score(y[te], p, sub[te])
            r.update({'model': m, 'seed': SEED, 'split': s,
                      'train_variant': v, 'train_rule': rule, 'test_set': tname, 'test_rule': TESTS[tname],
                      'n_train': int(len(tr)), 'n_train_dropped': int(len(tr_all) - len(tr)),
                      'n_test': int(len(te)), 'train_class_counts': counts(y[tr]),
                      'test_class_counts': counts(y[te]), 'missing_train_classes': missing,
                      'fit_seconds': round(fit_s, 1)})
            save(path, r, y[te], p, sub[te], te)
            done += 1
            print(f'[{done}/{n_runs}] {m:12s} {s:8s} train={v:6s} test={tname:3s} n_train={len(tr):>9,} '
                  f'macro-F1={r["macro_f1"]:.4f} attack-F1={r["attack_macro_f1"]:.4f} '
                  f'bal-acc={r["balanced_accuracy"]:.4f} ({fit_s:.0f} s)', flush=True)
        del clf, tr; gc.collect()

    left = n_runs - done
    if left:
        print(f'[left] {left} runs still to do', flush=True)
    else:
        print('[DONE] all runs finished', flush=True)
        summary()


if __name__ == '__main__':
    main()
