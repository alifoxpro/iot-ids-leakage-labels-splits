# -*- coding: utf-8 -*-
"""
day_disjoint_split.py
=====================
Reviewer question: the within-session temporal split (70/15/15 by time inside each capture
group) trains and tests on the same capture session. Does it still leak session context
(same hosts, ports and background of that session)? This script moves the train/test cut
to a calendar-day boundary wherever the sample allows it.

Split ("day-disjoint"), built separately for every capture group (class + sub-folder).
Capture days = distinct ts.dt.normalize() values of the group's flows in the sample:
  multi-day group   (flows on 2 or more capture days)
                    training = all flows of the days BEFORE the last capture day
                    test     = all flows of the last capture day
                    (flows without a timestamp cannot be placed on a day and are left out)
  single-day group  the within-session chronological cut of subattack_temporal_idx
                    (training = first 70%, test = last 15%, the middle 15% is unused), i.e.
                    exactly the test rows of the tree_protocol temporal runs
No validation part is used (tree ensembles with fixed hyper-parameters).
Label conditions raw | r1: kept_rows() is applied first; the capture days, the multi-day
decision and the split are then all computed on the kept rows only.
Models: XGBoost and RandomForest (extra_baselines.make, seed 42), balanced sample weights,
81 features with NaN/inf -> 0 (deep_split_noise_study.prepare). 2 models x 2 labels = 4 fits.

A macro-F1 restricted to the classes of the multi-day groups is NOT meaningful (one class can
mix multi-day and single-day groups), so every run JSON reports per_subattack_recall next to
the per_subattack_recall of the matching within-session run
results_2026_03_03/tree_protocol/main/<Model>_temporal_<labels>_s42.json.

Output: results_2026_03_03/q1_revision/day_disjoint/
  <Model>_day_<labels>_s42.json   metrics (metrics()), run description, n_train/n_test,
                                  fit_seconds, per-sub-attack comparison with the
                                  within-session temporal run
  <Model>_day_<labels>_s42.npz    test predictions: y, p (int8), sub (for bootstrap_ci.py)
  days.json                       per label condition and capture group: capture days with
                                  flow counts, multi-day or not, train/test sizes, time gap,
                                  contiguous_cut (multi-day group whose capture runs past
                                  midnight: < 1 h between the last training and the first
                                  test flow, so the cut is day-disjoint but NOT session-disjoint;
                                  read those groups like the within-session split)
Resumable: finished runs are skipped (a run counts as finished once its JSON exists; the JSON
is written last, after the predictions). --summary prints the comparison table of the finished
runs without loading any data.
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\day_disjoint_split.py
  # one fit per process (a random forest of this size takes several GB):
  for ($i = 0; $i -lt 4; $i++) { & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\day_disjoint_split.py --max-fits 1 }
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\day_disjoint_split.py --summary
"""
import argparse, gc, json, os, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402
from temporal_split_by_subattack import subattack_temporal_idx  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'day_disjoint'
REF = ROOT / 'results_2026_03_03' / 'tree_protocol' / 'main'
DAYS = OUT / 'days.json'
MODELS = ['XGBoost', 'RandomForest']        # XGBoost first: the cheap fits finish before the forests
LABELS = ['raw', 'r1']
MULTI_RULE = 'multi-day: train = all days before the last capture day, test = last capture day'
SINGLE_RULE = 'single day: within-session cut of subattack_temporal_idx (first 70% train, last 15% test)'
CONTIGUOUS_H = 1.0     # multi-day group whose last training flow is < 1 h before the first test flow


def run_name(m, c):
    return f'{m}_day_{c}_s{SEED}'


def _ts(x):
    return None if pd.isna(x) else str(x)


def day_disjoint_idx(meta):
    """Train / test positions WITHIN `meta` (RangeIndex 0..n-1) and a description per capture group."""
    n = len(meta)
    tr_w, _, te_w = subattack_temporal_idx(meta)            # within-session cut (single-day groups)
    in_tr = np.zeros(n, bool); in_tr[np.asarray(tr_w, dtype=np.int64)] = True
    in_te = np.zeros(n, bool); in_te[np.asarray(te_w, dtype=np.int64)] = True
    del tr_w, te_w
    ts = meta['ts']
    day = ts.dt.normalize().to_numpy()
    tr, te, info = [], [], {}
    for (c, s), g in meta.groupby(['y', 'sub'], sort=True, observed=True):
        idx = g.index.to_numpy()
        if len(idx) == 0:
            continue
        d = day[idx]
        ok = ~np.isnat(d)
        days, counts = np.unique(d[ok], return_counts=True)
        multi = len(days) >= 2
        if multi:
            g_tr, g_te = idx[ok & (d < days[-1])], idx[ok & (d == days[-1])]
        else:
            g_tr, g_te = idx[in_tr[idx]], idx[in_te[idx]]
        tr.append(g_tr); te.append(g_te)
        t_end, t_start = ts.iloc[g_tr].max(), ts.iloc[g_te].min()
        gap = (None if pd.isna(t_end) or pd.isna(t_start)
               else round((t_start - t_end).total_seconds() / 3600, 2))
        info[f'{CLASSES[c]} / {s}'] = {
            'multi_day': bool(multi),
            # a capture that runs past midnight is cut at the day boundary with (almost) no gap:
            # such a group is day-disjoint but NOT session-disjoint
            'contiguous_cut': bool(multi and gap is not None and gap < CONTIGUOUS_H),
            'rule': MULTI_RULE if multi else SINGLE_RULE,
            'capture_days': {str(pd.Timestamp(k).date()): int(v) for k, v in zip(days, counts)},
            'n_flows': int(len(idx)), 'n_no_timestamp': int((~ok).sum()),
            'n_train': int(len(g_tr)), 'n_test': int(len(g_te)),
            'test_share': round(len(g_te) / len(idx), 4),
            'train_end': _ts(t_end), 'test_start': _ts(t_start), 'gap_hours': gap}
    return np.concatenate(tr), np.concatenate(te), info


def reference(m, c):
    """The matching within-session temporal run of tree_protocol_study.py (None if missing)."""
    f = REF / f'{m}_temporal_{c}_s{SEED}.json'
    return (json.load(open(f)) if f.exists() else None), f


def summary():
    runs = {}
    for f in sorted(OUT.glob(f'*_day_*_s{SEED}.json')):
        r = json.load(open(f))
        runs[(r['model'], r['labels'])] = r
    if not runs:
        print('no finished runs yet'); return
    fmt = lambda v: '  -  ' if v is None else f'{v:.3f}'
    for c in LABELS:
        rs = {m: runs[(m, c)] for m in MODELS if (m, c) in runs}
        if not rs:
            continue
        print(f'\n=== labels={c}: recall per sub-attack, day-disjoint | within-session temporal ===')
        print(f'  {"capture group":38s} {"days":7s} {"n_test":>9s}' + ''.join(f'  {m:>13s}' for m in rs))
        print(f'  {"macro-F1 (all classes)":38s} {"":7s} {"":>9s}' +
              ''.join(f'  {fmt(r["macro_f1"])} | {fmt(r["reference_macro_f1"])}' for r in rs.values()))
        groups = next(iter(rs.values()))['per_subattack_comparison']
        for g, v in groups.items():
            cells = ''
            for r in rs.values():
                x = r['per_subattack_comparison'].get(g, {})
                cells += f'  {fmt(x.get("day_disjoint"))} | {fmt(x.get("within_session_temporal"))}'
            kind = ('multi*' if v.get('contiguous_cut') else 'multi') if v['multi_day'] else 'single'
            print(f'  {g:38s} {kind:7s} {v["n_test"]:>9,}{cells}')
        print('  multi* = the day boundary falls inside a continuous capture (< 1 h between train and test)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). A random forest of this size takes several GB, '
                         'so run with 1 inside a PowerShell loop: every fit then starts in a fresh process.')
    ap.add_argument('--summary', action='store_true', help='only print the comparison table of finished runs')
    a = ap.parse_args()
    if a.summary:
        summary(); return
    jobs = [(m, c) for m in MODELS for c in LABELS]
    todo = [j for j in jobs if not (OUT / f'{run_name(*j)}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if not todo and DAYS.exists():
        summary(); return
    OUT.mkdir(parents=True, exist_ok=True)

    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()

    # split of every label condition (cheap) -> days.json is always complete
    split = {}
    days = {'description': 'Capture days (ts.dt.normalize()) of every capture group in the flagged sample, '
                           'computed on the rows kept by each label condition. ' + MULTI_RULE + '; ' + SINGLE_RULE +
                           '. gap_hours = first test flow - last training flow; contiguous_cut = multi-day group '
                           f'with gap_hours < {CONTIGUOUS_H:g} (the capture runs past midnight, so train and test '
                           'are adjacent in time: day-disjoint but not session-disjoint).',
            'conditions': {}}
    for c in LABELS:
        rows = kept_rows(flags, c)
        tr, te, info = day_disjoint_idx(meta.iloc[rows].reset_index(drop=True))
        tr, te = rows[tr], rows[te]                          # -> global positions
        missing = [CLASSES[k] for k in range(len(CLASSES)) if not (y[tr] == k).any()]
        split[c] = (tr, te, info)
        days['conditions'][c] = {
            'n_kept': int(len(rows)), 'n_train': int(len(tr)), 'n_test': int(len(te)),
            'multi_day_groups': [g for g, v in info.items() if v['multi_day']],
            'single_day_groups': [g for g, v in info.items() if not v['multi_day']],
            'contiguous_cut_groups': [g for g, v in info.items() if v['contiguous_cut']],
            'classes_absent_from_training': missing,
            'groups': info}
        n_multi = len(days['conditions'][c]['multi_day_groups'])
        n_cont = len(days['conditions'][c]['contiguous_cut_groups'])
        print(f'[days] labels={c:3s} {n_multi}/{len(info)} capture groups multi-day '
              f'({n_cont} cut inside a continuous capture)  train={len(tr):,} test={len(te):,}' +
              (f'  WARNING classes absent from training: {missing}' if missing else ''), flush=True)
        del rows
    with open(DAYS, 'w') as fh:
        json.dump(days, fh, indent=1)
    del meta, flags; gc.collect()

    done = 0
    for n_fit, (m, c) in enumerate(todo, 1):
        if a.max_fits and n_fit > a.max_fits:
            break
        tr, te, info = split[c]
        clf = make(m)
        clf.set_params(random_state=SEED)
        t = time.time()
        clf.fit(X[tr], y[tr], sample_weight=compute_sample_weight('balanced', y[tr]))
        fit_s = time.time() - t
        p = np.asarray(clf.predict(X[te])).astype(np.int8).ravel()
        del clf; gc.collect()

        r = metrics(y[te], p, sub[te])
        ref, ref_file = reference(m, c)
        ref_rec = ref['per_subattack_recall'] if ref else {}
        r.update({
            'model': m, 'seed': SEED, 'split': 'day_disjoint', 'labels': c,
            'train_cleaning': c, 'test_cleaning': c,
            'description': f'Capture-day-disjoint split, labels={c}. ' + MULTI_RULE + '; ' + SINGLE_RULE +
                           '. Balanced sample weights, no validation part. Days per group: days.json.',
            'n_train': int(len(tr)), 'n_test': int(len(te)), 'fit_seconds': round(fit_s, 1),
            'multi_day_groups': [g for g, v in info.items() if v['multi_day']],
            'single_day_groups': [g for g, v in info.items() if not v['multi_day']],
            'contiguous_cut_groups': [g for g, v in info.items() if v['contiguous_cut']],
            'note': 'macro-F1 restricted to the classes of the multi-day groups is not reported (not meaningful: '
                    'a class can mix multi-day and single-day groups); compare per_subattack_recall instead.',
            'reference_run': str(ref_file.relative_to(ROOT)).replace('\\', '/') if ref else None,
            'reference_macro_f1': ref['macro_f1'] if ref else None,
            'reference_balanced_accuracy': ref['balanced_accuracy'] if ref else None,
            'reference_per_subattack_recall': ref_rec,
            'per_subattack_comparison': {
                g: {'multi_day': v['multi_day'], 'contiguous_cut': v['contiguous_cut'],
                    'gap_hours': v['gap_hours'], 'n_train': v['n_train'], 'n_test': v['n_test'],
                    'day_disjoint': r['per_subattack_recall'].get(g),
                    'within_session_temporal': ref_rec.get(g)}
                for g, v in info.items()}})
        path = OUT / run_name(m, c)
        # predictions first, JSON last and atomically: the JSON marks the run as finished (resume)
        np.savez_compressed(path.with_suffix('.npz'), y=y[te].astype(np.int8), p=p, sub=sub[te].astype(str))
        tmp = path.with_suffix('.json.tmp')
        with open(tmp, 'w') as fh:
            json.dump(r, fh, indent=1)
        os.replace(tmp, path.with_suffix('.json'))
        done += 1
        ref_txt = f'{ref["macro_f1"]:.4f}' if ref else 'n/a'
        print(f'[{done}/{len(todo)}] {m:12s} labels={c:3s} macro-F1={r["macro_f1"]:.4f} '
              f'bal-acc={r["balanced_accuracy"]:.4f} (within-session temporal macro-F1={ref_txt}) '
              f'train={len(tr):,} test={len(te):,} ({fit_s / 60:.1f} min)', flush=True)
        del p, r; gc.collect()
    left = len(todo) - done
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)
    if not left:
        summary()


if __name__ == '__main__':
    main()
