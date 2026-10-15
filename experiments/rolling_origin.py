# -*- coding: utf-8 -*-
r"""
rolling_origin.py
=================
Round-2 review (Reviewer 2, point 2): the chronological split within capture groups keeps the campaign and the
class session on both sides, so a lower score could come from the DIRECTION of time (testing on later traffic),
from testing on a CONTIGUOUS BLOCK of a session at all (block difficulty), or from the random split letting a
model MEMORISE the session (neighbouring flows on both sides). This script separates the three with partitions
of every capture group, all with 70% (or, for the rolling windows, 40%) of the group's flows for training:

  design    training part (fractions of the group's flows in time order)   test part       separates
  random    stratified random 70/15/15 (deep_split_noise_study.splits)       random 15%      memorisation (reference)
  forward   [0, 0.70)                                                       [0.85, 1.00)    = the paper's temporal split
  reverse   [0.30, 1.00)                                                    [0, 0.15)       direction of time
  middle    [0, 0.35) + [0.65, 1.00)                                        [0.425, 0.575)  block without direction
  roll1     [0, 0.40)                                                       [0.55, 0.70)    rolling origin, equal
  roll2     [0.15, 0.55)                                                    [0.70, 0.85)    training size (40%) and
  roll3     [0.30, 0.70)                                                    [0.85, 1.00)    gap (15%) at three origins
Every design leaves a gap of 15% of the group between training and test (7.5% on each side for 'middle'),
like the validation period of the paper's split, which the tree ensembles do not use. Cut positions are
int(fraction x n) of the time-ordered rows of each group (stable sort on the timestamp), so 'forward' is
exactly subattack_temporal_idx (checked when the data are loaded).
  forward vs reverse            direction of time (same sizes and gap, mirrored)
  middle vs random              testing on a contiguous block without a time direction
  forward vs middle             what the direction adds to a block
  roll1-3                       whether the loss depends on the origin (stationarity within the sessions)

Labels: raw and R1 (the R1-flagged attack flows removed before partitioning, as in the main factorial).
Models: XGBoost and the random forest of extra_baselines.make (seed 42), balanced sample weights, NaN/inf -> 0.
7 designs x 2 labels x 2 models = 28 fits; random and forward repeat the published seed-42 runs of
tree_protocol/main (the summary checks that they are reproduced).

Output: results_2026_03_03/q1_revision/rolling_origin/
          <model>_<design>_<labels>.json + .npz (y, p, sub, rows: global row positions, test rows in group time order)
          summary.csv (one line per run), summary_effects.csv (per model and labels: random - design and the
          contrasts above), reproduced.csv
Resumable: a run is skipped when its JSON exists. --max-fits 1 for the random forest (several GB per fit).
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\rolling_origin.py --plan
  & $py experiments\rolling_origin.py --models XGBoost 2>&1 | Tee-Object -FilePath rolling_origin_xgb.log
  1..14 | ForEach-Object { & $py experiments\rolling_origin.py --models RandomForest --max-fits 1 2>&1 | Tee-Object -FilePath rolling_origin_rf.log -Append }
  & $py experiments\rolling_origin.py --summary
"""
import argparse, gc, json, os, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
RES = HERE.parent / 'results_2026_03_03'
OUT = RES / 'q1_revision' / 'rolling_origin'
TP = RES / 'tree_protocol' / 'main'
LABELS = list(range(len(CLASSES)))
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']
MODELS = ['XGBoost', 'RandomForest']
CLEANINGS = ['raw', 'r1']
# design -> (training intervals, test interval) as fractions of each group's time-ordered rows
DESIGNS = {'random': None,
           'forward': ([(0.0, 0.70)], (0.85, 1.0)),
           'reverse': ([(0.30, 1.0)], (0.0, 0.15)),
           'middle': ([(0.0, 0.35), (0.65, 1.0)], (0.425, 0.575)),
           'roll1': ([(0.0, 0.40)], (0.55, 0.70)),
           'roll2': ([(0.15, 0.55)], (0.70, 0.85)),
           'roll3': ([(0.30, 0.70)], (0.85, 1.0))}
CONTRASTS = [('random', 'forward', 'loss of the paper temporal split'),
             ('random', 'reverse', 'loss when testing on the earliest block'),
             ('random', 'middle', 'loss when testing on a middle block'),
             ('reverse', 'forward', 'direction of time (forward vs mirrored)'),
             ('middle', 'forward', 'forward vs middle block'),
             ('roll1', 'roll3', 'rolling origin: earliest vs latest window')]


def partition(meta, design):
    """Training and test row labels of `meta` (index = global row positions) for one design."""
    if DESIGNS[design] is None:
        tr, _, te = splits(meta, 'random')
        return tr, te
    tr_iv, te_iv = DESIGNS[design]
    tr, te = [], []
    for _, g in meta.groupby(['y', 'sub'], sort=True, observed=True):
        idx = g.sort_values('ts', kind='stable').index.to_numpy()
        n = len(idx)
        cut = lambda f: int(f * n)
        for lo, hi in tr_iv:
            tr.append(idx[cut(lo):cut(hi)])
        te.append(idx[cut(te_iv[0]):cut(te_iv[1])])
    return np.concatenate(tr), np.concatenate(te)


def score(y, p, sub):
    r = metrics(y, p, sub)
    f1 = f1_score(y, p, average=None, labels=LABELS, zero_division=0)
    r['attack_macro_f1'] = float(f1[ATTACKS].mean())
    r['per_class_precision'] = dict(zip(CLASSES, precision_score(
        y, p, average=None, labels=LABELS, zero_division=0).round(4).tolist()))
    r['confusion'] = confusion_matrix(y, p, labels=LABELS).tolist()
    return r


def counts(v):
    return dict(zip(CLASSES, np.bincount(v, minlength=len(CLASSES)).tolist()))


def save(path, r, y_te, p, sub_te, rows):
    np.savez_compressed(path.with_suffix('.npz'), y=y_te.astype(np.int8), p=p.astype(np.int8),
                        sub=np.asarray(sub_te, dtype=str), rows=rows.astype(np.int32))
    tmp = path.with_name(path.name + '.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path.with_suffix('.json'))


def summary():
    rows = []
    for f in sorted(OUT.glob('*.json')):
        if f.name.startswith('summary'):
            continue
        with open(f, encoding='utf-8') as fh:
            r = json.load(fh)
        rows.append({k: r[k] for k in ('model', 'design', 'cleaning', 'macro_f1', 'attack_macro_f1',
                                        'balanced_accuracy', 'accuracy', 'n_train', 'n_test')})
    if not rows:
        print('no finished runs yet'); return
    d = pd.DataFrame(rows)
    d['_d'] = d['design'].map(list(DESIGNS).index)
    d = d.sort_values(['model', 'cleaning', '_d']).drop(columns='_d')
    d.to_csv(OUT / 'summary.csv', index=False)
    eff = []
    for (m, c), g in d.groupby(['model', 'cleaning']):
        v = g.set_index('design')
        for a, b, what in CONTRASTS:
            if a in v.index and b in v.index:
                for metric in ('macro_f1', 'attack_macro_f1', 'balanced_accuracy'):
                    eff.append({'model': m, 'cleaning': c, 'contrast': f'{a} - {b}', 'meaning': what, 'metric': metric,
                                'a': v.loc[a, metric], 'b': v.loc[b, metric], 'diff': round(v.loc[a, metric] - v.loc[b, metric], 4)})
    pd.DataFrame(eff).to_csv(OUT / 'summary_effects.csv', index=False)
    rep = []
    for r in rows:
        if r['design'] in ('random', 'forward'):
            split = 'random' if r['design'] == 'random' else 'temporal'
            f = TP / f'{r["model"]}_{split}_{r["cleaning"]}_s{SEED}.json'
            if f.exists():
                with open(f, encoding='utf-8') as fh:
                    o = json.load(fh)
                rep.append({'model': r['model'], 'design': r['design'], 'cleaning': r['cleaning'], 'macro_f1': r['macro_f1'],
                            'published': o.get('macro_f1'), 'reproduced': r['macro_f1'] == o.get('macro_f1')})
    pd.DataFrame(rep).to_csv(OUT / 'reproduced.csv', index=False)
    pd.set_option('display.width', 200)
    print(d.round(4).to_string(index=False))
    if eff:
        e = pd.DataFrame(eff)
        print('\n=== contrasts (macro-F1) ===')
        print(e[e['metric'] == 'macro_f1'].drop(columns='metric').round(4).to_string(index=False))
    if rep:
        rp = pd.DataFrame(rep)
        print(f'\n[reproduced] {int(rp["reproduced"].sum())} of {len(rp)} random/forward runs identical to tree_protocol/main')
    print('[saved]', OUT / 'summary.csv')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--models', nargs='+', choices=MODELS, default=['XGBoost'])
    ap.add_argument('--designs', nargs='+', choices=list(DESIGNS), default=list(DESIGNS))
    ap.add_argument('--max-fits', type=int, default=0)
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--plan', action='store_true')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return
    jobs = [(m, d, c) for m in a.models for c in CLEANINGS for d in a.designs]
    todo = [j for j in jobs if not (OUT / f'{j[0]}_{j[1]}_{j[2]}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if a.plan or not todo:
        if not todo:
            summary()
        return

    X, meta, flags = load_prepared()
    meta = meta.reset_index(drop=True)
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    # 'forward' must be exactly the paper's temporal split (subattack_temporal_idx)
    tr_f, te_f = partition(meta, 'forward')
    tr_p, _, te_p = splits(meta, 'temporal')
    assert np.array_equal(np.sort(tr_f), np.sort(tr_p)) and np.array_equal(te_f, te_p), 'forward != temporal split'
    print('[check] forward partition = splits(temporal) on the raw rows', flush=True)

    n_here = min(len(todo), a.max_fits) if a.max_fits else len(todo)
    for n_fit, (m, d, c) in enumerate(todo, 1):
        if a.max_fits and n_fit > a.max_fits:
            break
        rows = kept_rows(flags, c)
        mk = meta.iloc[rows].copy()
        mk.index = rows                                    # index labels = global row positions
        tr, te = partition(mk, d)
        if d == 'random':                                  # splits('random') returns positions 0..n-1 of the
            tr, te = rows[tr], rows[te]                    # kept rows, as in the main factorial
        present = np.unique(y[tr])
        missing = [CLASSES[k] for k in LABELS if k not in present]
        Xtr = X[tr]
        last = n_fit == n_here
        Xte = X[te] if last else None
        if last:
            del X; gc.collect()
        clf = make(m)
        t0 = time.time()
        clf.fit(Xtr, np.searchsorted(present, y[tr]), sample_weight=compute_sample_weight('balanced', y[tr]))
        fit_s = time.time() - t0
        del Xtr; gc.collect()
        xt = X[te] if Xte is None else Xte
        p = present[np.asarray(clf.predict(xt)).astype(int).ravel()].astype(np.int8)
        del xt, Xte; gc.collect()
        r = score(y[te], p, sub[te])
        r.update({'model': m, 'seed': SEED, 'design': d, 'cleaning': c,
                  'design_definition': 'stratified random 70/15/15 (split seed 42)' if DESIGNS[d] is None else
                  {'train': DESIGNS[d][0], 'test': DESIGNS[d][1], 'unit': 'fractions of the time-ordered rows of '
                   'each capture group (cut at int(fraction x n))'},
                  'n_train': int(len(tr)), 'n_test': int(len(te)), 'train_class_counts': counts(y[tr]),
                  'test_class_counts': counts(y[te]), 'missing_train_classes': missing, 'fit_seconds': round(fit_s, 1),
                  'script': 'experiments/rolling_origin.py', 'created': time.strftime('%Y-%m-%d %H:%M:%S')})
        save(OUT / f'{m}_{d}_{c}', r, y[te], p, sub[te], te)
        print(f'[{n_fit}/{len(todo)}] {m:12s} {d:8s} {c:3s} n_train={len(tr):>9,} n_test={len(te):>8,} '
              f'macro-F1={r["macro_f1"]:.4f} attack-F1={r["attack_macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} '
              f'({fit_s:.0f} s)', flush=True)
        del clf; gc.collect()
        if last:
            break
    left = [j for j in jobs if not (OUT / f'{j[0]}_{j[1]}_{j[2]}.json').exists()]
    if not left:
        print('[DONE] all runs finished', flush=True)
        summary()


if __name__ == '__main__':
    main()
