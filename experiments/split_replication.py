# -*- coding: utf-8 -*-
"""
split_replication.py
====================
Reviewer request: "every result rests on one partition". The two central comparisons of the
paper (random versus temporal split, raw versus R1-cleaned labels) are repeated over several
partitions, and a class-weight ablation is added. Same sample, features and preprocessing as
deep_split_noise_study.py / tree_protocol_study.py (81 features, NaN/inf -> 0, fixed
hyper-parameters of extra_baselines.make, model seed 42).

Study "splits" (default) - 32 fits
  models     XGBoost, RandomForest (balanced sample weights computed on the training part)
  labels     raw | r1   (kept_rows first, then the partition is drawn on the kept rows)
  random     stratified 70/15/15 with split seeds 42, 1, 2, 3, 4      (seed 42 = paper partition)
  temporal   inside each of the 16 capture groups, flows in time order, train/val/test cut
             0.60/0.20/0.20, 0.70/0.15/0.15 (= paper partition), 0.80/0.10/0.10
  (5 + 3) partitions x 2 label conditions x 2 models = 32 fits
Study "weights" (--study weights) - 6 fits
  XGBoost, raw labels, random (seed 42) and temporal (0.70 cut), sample weights
  none | sqrt (square root of the balanced weights, rescaled to mean 1 like the other two) | balanced
The validation part of every partition is not used (no tuning); it is only held out so that the
train/test sizes follow the paper's 70/15/15 protocol.

Every run stores metrics() of deep_split_noise_study.py plus attack_macro_f1 (macro-F1 over the
7 attack classes, Benign excluded), per-class precision, the confusion matrix, the run description,
the class weights used, n_train/n_val/n_test and fit_seconds. --save-preds also writes the test
predictions (.npz: y, p int8, sub) for bootstrap / paired tests; with --save-preds a run whose
.npz is missing is fitted again (so the flag can be added later).
--summary prints, per model and label condition, the mean and range of macro-F1 over the random
seeds and over the temporal cuts, the range of the split effect (every random seed minus every
temporal cut) and of the cleaning effect (r1 minus raw for the same partition), and the weight table.

Output: results_2026_03_03/q1_revision/split_replication/{splits,weights}/<run>.json [+ <run>.npz]
        results_2026_03_03/q1_revision/split_replication/summary.json, splits_runs.csv, weights_runs.csv
Resumable: finished runs are skipped. A random forest of this size needs several GB of RAM, so it
is run one fit per process (--max-fits 1 inside a PowerShell loop).
Run (PowerShell):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\split_replication.py --models XGBoost
  1..16 | ForEach-Object { & $py experiments\\split_replication.py --models RandomForest --max-fits 1 }
  & $py experiments\\split_replication.py --study weights
  & $py experiments\\split_replication.py --summary
"""
import argparse, gc, json, os, sys, time
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'split_replication'
MODELS = ['XGBoost', 'RandomForest']
CLEANING = ['raw', 'r1']
RANDOM_SEEDS = [42, 1, 2, 3, 4]
CUTS = {'60-20-20': (0.60, 0.80), '70-15-15': (0.70, 0.85), '80-10-10': (0.80, 0.90)}  # end of train, end of val
PARTITIONS = [('random', f's{s}') for s in RANDOM_SEEDS] + [('temporal', c) for c in CUTS]
WEIGHTS = ['none', 'sqrt', 'balanced']
WEIGHT_DEF = {'none': 'unweighted', 'sqrt': 'sqrt(balanced) rescaled to mean 1',
              'balanced': "compute_sample_weight('balanced', y_train) (mean 1)"}
ALL = list(range(len(CLASSES)))
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']


# ---------------------------------------------------------------- partitions (positions within `meta`)
def random_split(meta, seed):
    """Stratified 70/15/15 exactly as splits(meta, 'random'), with a chosen random_state."""
    y = meta['y'].to_numpy()
    rest, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=seed)
    tr, va = train_test_split(rest, test_size=0.15 / 0.85, stratify=y[rest], random_state=seed)
    return tr, va, te


def temporal_split(meta, cut):
    """Time-ordered cut inside every capture group, as subattack_temporal_idx with other fractions."""
    end_tr, end_va = CUTS[cut]
    tr, va, te = [], [], []
    for _, g in meta.groupby(['y', 'sub'], sort=True, observed=True):
        idx = g.sort_values('ts', kind='stable').index.to_numpy()
        a, b = int(end_tr * len(idx)), int(end_va * len(idx))
        tr.append(idx[:a]); va.append(idx[a:b]); te.append(idx[b:])
    return np.concatenate(tr), np.concatenate(va), np.concatenate(te)


def partition(meta, split, rep):
    return random_split(meta, int(rep[1:])) if split == 'random' else temporal_split(meta, rep)


# ---------------------------------------------------------------- runs
def plan(study, models):
    if study == 'splits':
        return [dict(study=study, model=m, cleaning=c, split=s, rep=r, weights='balanced',
                     name=f'{m}_{c}_{s}_{r}')
                for m in models for c in CLEANING for s, r in PARTITIONS]
    return [dict(study=study, model='XGBoost', cleaning='raw', split=s, rep=r, weights=w,
                 name=f'XGBoost_raw_{s}_{r}_w-{w}')
            for s, r in [('random', 's42'), ('temporal', '70-15-15')] for w in WEIGHTS]


def sample_weights(scheme, y):
    if scheme == 'none':
        return None
    w = compute_sample_weight('balanced', y)
    if scheme == 'sqrt':
        w = np.sqrt(w)
        w /= w.mean()                   # balanced and none also have mean weight 1
    return w


def class_weights(w, y):
    if w is None:
        return None
    cls, first = np.unique(y, return_index=True)
    return {CLASSES[k]: round(float(w[i]), 4) for k, i in zip(cls, first)}


def score(y, p, sub):
    r = metrics(y, p, sub)
    r['attack_macro_f1'] = float(f1_score(y, p, average='macro', labels=ATTACKS, zero_division=0))
    r['per_class_precision'] = dict(zip(CLASSES, precision_score(y, p, average=None, labels=ALL,
                                                                 zero_division=0).round(4).tolist()))
    r['confusion'] = confusion_matrix(y, p, labels=ALL).tolist()
    return r


def finished(out, j, save_preds):
    """A run is finished when its JSON exists (and its .npz too when predictions are requested)."""
    return (out / f'{j["name"]}.json').exists() and (not save_preds or (out / f'{j["name"]}.npz').exists())


def write_json(path, r):
    """Write via a temporary file: an interrupted process never leaves a truncated JSON that
    would be skipped as finished and break --summary."""
    tmp = path.with_suffix('.part')
    with open(tmp, 'w') as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path)


def run(a):
    jobs = plan(a.study, a.models)
    out = OUT / a.study
    todo = [j for j in jobs if not finished(out, j, a.save_preds)]
    print(f'[plan] study={a.study}: {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if not todo:
        return
    out.mkdir(parents=True, exist_ok=True)
    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    done = 0
    for j in todo:
        if a.max_fits and done >= a.max_fits:
            break
        rows = kept_rows(flags, j['cleaning'])
        part = meta.iloc[rows].reset_index(drop=True)            # 3 small columns only
        tr, va, te = partition(part, j['split'], j['rep'])
        tr, te, n_val = rows[tr], rows[te], len(va)               # -> global positions
        del part, va, rows
        ytr = y[tr]
        w = sample_weights(j['weights'], ytr)
        clf = make(j['model'])
        clf.set_params(random_state=SEED)
        t = time.time()
        clf.fit(X[tr], ytr, sample_weight=w)
        fit_s = time.time() - t
        p = np.asarray(clf.predict(X[te])).astype(np.int8).ravel()
        r = score(y[te], p, sub[te])
        r.update({'study': j['study'], 'model': j['model'], 'model_seed': SEED, 'cleaning': j['cleaning'],
                  'split': j['split'], 'replicate': j['rep'],
                  'split_seed': int(j['rep'][1:]) if j['split'] == 'random' else None,
                  'cut_train_val_test': None if j['split'] == 'random' else
                  [round(x, 2) for x in (CUTS[j['rep']][0], CUTS[j['rep']][1] - CUTS[j['rep']][0],
                                         1 - CUTS[j['rep']][1])],
                  'weights': j['weights'], 'weights_definition': WEIGHT_DEF[j['weights']],
                  'class_weights': class_weights(w, ytr),
                  'n_train': int(len(tr)), 'n_val': int(n_val), 'n_test': int(len(te)),
                  'fit_seconds': round(fit_s, 1)})
        if a.save_preds:                                          # before the JSON: JSON = run complete
            np.savez_compressed(out / f'{j["name"]}.npz', y=y[te].astype(np.int8), p=p,
                                sub=sub[te].astype(str))          # fixed-width text, loads without pickle
        write_json(out / f'{j["name"]}.json', r)
        done += 1
        print(f'[{done}/{len(todo)}] {j["study"]:7s} {j["model"]:12s} {j["cleaning"]:3s} {j["split"]:8s} '
              f'{j["rep"]:8s} w={j["weights"]:8s} macro-F1={r["macro_f1"]:.4f} attack-F1={r["attack_macro_f1"]:.4f} '
              f'bal-acc={r["balanced_accuracy"]:.4f} ({fit_s / 60:.1f} min)', flush=True)
        del clf, w, p, ytr, tr, te; gc.collect()
    left = len(todo) - done
    print(f'[left] {left} runs still to do' if left else f'[DONE] study={a.study} finished', flush=True)


# ---------------------------------------------------------------- summary
def stats(v):
    v = np.asarray(list(v), float)
    return {'n': int(len(v)), 'mean': float(v.mean()), 'min': float(v.min()), 'max': float(v.max())} if len(v) else None


def fmt(s, sign=False):
    if s is None:
        return f'{"n/a":>26s}'
    f = '+.3f' if sign else '.3f'
    return f'{s["mean"]:{f}} [{s["min"]:{f}}, {s["max"]:{f}}] n={s["n"]:<2d}'


def summary():
    import pandas as pd
    pd.set_option('display.width', 180)
    res = {}
    keys = ('study', 'model', 'cleaning', 'split', 'replicate', 'weights', 'macro_f1', 'attack_macro_f1',
            'balanced_accuracy', 'accuracy', 'n_train', 'n_test', 'fit_seconds')
    for study in ('splits', 'weights'):
        runs = []
        for f in sorted((OUT / study).glob('*.json')):
            with open(f) as fh:
                runs.append(json.load(fh))
        print(f'\n##### study={study}: {len(runs)} finished runs')
        if not runs:
            continue
        d = pd.DataFrame([{k: r[k] for k in keys} for r in runs])
        d.to_csv(OUT / f'{study}_runs.csv', index=False)
        if study == 'weights':
            d['weights'] = pd.Categorical(d['weights'], WEIGHTS, ordered=True)
            t = d.pivot_table(index=['split', 'weights'], observed=True,
                              values=['macro_f1', 'attack_macro_f1', 'balanced_accuracy', 'accuracy'])
            print('\n=== class-weight ablation (XGBoost, raw labels) ===')
            print(t[['macro_f1', 'attack_macro_f1', 'balanced_accuracy', 'accuracy']].round(4).to_string())
            pcf = pd.DataFrame([{'split': r['split'], 'weights': r['weights'], **r['per_class_f1']} for r in runs])
            pcf['weights'] = pd.Categorical(pcf['weights'], WEIGHTS, ordered=True)
            print('\n=== per-class F1 ===')
            print(pcf.set_index(['split', 'weights']).sort_index()[CLASSES].round(3).to_string())
            res['weights'] = t.round(4).reset_index().astype({'weights': str}).to_dict('records')
            continue
        order = [r for _, r in PARTITIONS]
        for metric in ('macro_f1', 'attack_macro_f1'):
            t = d.pivot_table(index=['model', 'cleaning'], columns='replicate', values=metric)
            print(f'\n=== {metric} per partition (random split seeds | temporal cuts) ===')
            print(t[[c for c in order if c in t.columns]].round(3).to_string())
            res[metric] = {}
            print(f'\n=== {metric}: mean [min, max] over partitions ===')
            print(f'  {"model":12s} {"lab":3s}  {"random seeds":>26s}  {"temporal cuts":>26s}  '
                  f'{"split effect (rand - temp)":>28s}')
            for m in MODELS:
                if not (d['model'] == m).any():
                    continue
                val = {}
                for c in CLEANING:
                    g = d[(d['model'] == m) & (d['cleaning'] == c)]
                    val[c] = {s: dict(zip(g.loc[g['split'] == s, 'replicate'], g.loc[g['split'] == s, metric]))
                              for s in ('random', 'temporal')}
                    R, T = val[c]['random'], val[c]['temporal']
                    if not (R or T):
                        continue
                    s = {'random': stats(R.values()), 'temporal': stats(T.values()),
                         'split_effect': stats(r - t for r in R.values() for t in T.values())}
                    res[metric][f'{m}/{c}'] = s
                    print(f'  {m:12s} {c:3s}  {fmt(s["random"])}  {fmt(s["temporal"])}  '
                          f'{fmt(s["split_effect"], True):>28s}')
                for sp in ('random', 'temporal'):
                    common = sorted(set(val['raw'][sp]) & set(val['r1'][sp]))
                    s = stats(val['r1'][sp][k] - val['raw'][sp][k] for k in common)
                    res[metric][f'{m}/cleaning_effect/{sp}'] = s
                    print(f'  {m:12s} cleaning effect (r1 - raw), {sp:8s} partitions: {fmt(s, True)}')
    with open(OUT / 'summary.json', 'w') as f:
        json.dump(res, f, indent=1)
    print('\n[saved]', OUT / 'summary.json')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--study', choices=['splits', 'weights'], default='splits')
    ap.add_argument('--models', nargs='+', choices=MODELS, default=MODELS,
                    help='models of the splits study (the weights study always uses XGBoost)')
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). A random forest of this size takes several GB, '
                         'so run with 1 inside a PowerShell loop: every fit then starts in a fresh process.')
    ap.add_argument('--save-preds', action='store_true', help='also store test predictions (.npz)')
    ap.add_argument('--summary', action='store_true', help='only print the tables of finished runs')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary()
    else:
        run(a)


if __name__ == '__main__':
    main()
