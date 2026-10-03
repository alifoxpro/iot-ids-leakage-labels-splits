# -*- coding: utf-8 -*-
"""
tree_seeds_summary.py
=====================
Summary of the tree-ensemble seed study (reviewer points expe-08, expe-09, expe-17, disc-11, stat-09).
No model is trained; only stored results are read.

Inputs (results_2026_03_03/)
  tree_protocol/main/<Model>_<split>_<cleaning>_s<seed>.json|.npz   XGBoost s42; LightGBM and random forest
                                  s42, s17, s7 (the paper's runs; npz: y, p of the test rows)
  q1_revision/tree_seeds/runs/*.json                                 tree_seeds_proba.py: refits of the s42
                                  runs (+ s17 / s7 with --with-old-seeds) and the new seeds 123 / 2024, with
                                  per-class average precision, confusion matrix, fit and inference time
  tree_protocol/bootstrap.json                                       (optional) i.i.d. class-stratified
                                  bootstrap 95% CIs of the stored runs (bootstrap_ci.py, B = 2,000)
  q1_revision/analyses/c_block_bootstrap_ci.csv                      (optional) moving-block bootstrap CIs
                                  of the seed-42 runs (revision_analyses.py part c, blocks of 5,000 flows)

Which run gives which value
  hard-label metrics (macro-F1, attack macro-F1, balanced accuracy, accuracy, per-class F1 / precision /
  recall): the tree_protocol/main run for seeds 42, 17, 7 (= the values in the paper), the tree_seeds run
  for seeds 123 and 2024. --prefer-refit uses the tree_seeds refit whenever one exists instead.
  Per-class precision, recall and F1 are recomputed exactly from the confusion matrix (tree_seeds JSON)
  or from the stored predictions (tree_protocol npz).
  average precision (macro-AP, attack macro-AP, per-class AP) and macro ROC AUC: tree_seeds runs only
  (probabilities are stored only there); for seed 42 they come from the refit, whose hard-label metrics
  are compared with the paper's run in the crosscheck table.
  training time: every stored fit (both sources); inference time: tree_seeds runs.

Tables (written to results_2026_03_03/q1_revision/tree_seeds/)
  summary_runs.csv        one row per model x split x cleaning x seed (sources given)
  summary_conditions.csv  per model x condition and metric: n, mean, SD (ddof = 1; empty for n = 1), min,
                          max, seeds; plus the seed-42 bootstrap CIs (i.i.d. and block) of macro-F1 and
                          balanced accuracy when available
  summary_table.csv       the same as text cells "mean ± SD [min, max] (n)" for the paper tables
  summary_per_class.csv   per model x condition x class: F1, precision, recall (and AP) mean / SD / min / max /
                          n over seeds, test support, small-support flag (< 200 test flows), seed-42 i.i.d.
                          bootstrap CI of the class F1 (bootstrap.json)
  summary_effects.csv     per model: cleaning effect (r1 - raw, same seed) per split and split effect
                          (random - temporal, same seed) per cleaning; n, mean, SD, min, max, sign consistency
  summary_model_diffs.csv per condition and metric: A - B for LightGBM-XGBoost, RandomForest-XGBoost,
                          RandomForest-LightGBM over all seed pairs (mean difference, min, max, whether the
                          seed ranges overlap, whether every pair has the same sign)
  summary_rankings.csv    per condition: model order by macro-F1, balanced accuracy, macro-AP, attack
                          macro-F1, and whether the orders agree
  summary_timing.csv      per model (and condition): training seconds (all fits, and separately the paper's
                          tree_protocol/main fits and the tree_seeds fits, which ran in other sessions and
                          partly beside other jobs; fit_slowdown_* = tree_seeds refit / paper fit of the
                          same run), inference seconds for the whole test set and per 1,000 flows, device /
                          n_jobs, the highest CPU load and GPU utilisation seen when a fit process started
                          and, where recorded, the CPU use of other processes during the timed inference and
                          during the fit (competing jobs distort timings); hardware in summary.json
  summary_crosscheck.csv  refit versus stored tree_protocol run: macro-F1 / balanced-accuracy difference,
                          share of identical predictions, identical test rows, within tolerance
  summary.json            all of the above plus hardware, the source description and the bootstrap settings
  With --prefer-refit every output name gets the suffix _refit (summary_runs_refit.csv, ..., summary_refit.json),
  so the default (paper-value) tables are not overwritten.

Bootstrap over all seeds (reviewer points disc-11, expe-08, stat-09; skipped with --no-boot)
  From the stored predictions (npz: y, p) of EVERY run used for the hard-label metrics, per condition.
  All runs of a condition (every model and seed) share the same test rows and are resampled JOINTLY
  (the same drawn rows for all of them), B = 2,000, percentile 95% intervals, two methods:
    iid_class  test rows i.i.d. inside each true class (as bootstrap_ci.py / tree_protocol/bootstrap.json)
    block5000  circular moving blocks of 5,000 time-consecutive test rows inside each capture group
               (as revision_analyses.py part c; shorter blocks in small groups). The time order of the
               random-split test rows is rebuilt from the global row positions stored by
               tree_seeds_proba.py (before such a run exists the block method is skipped there).
  ci_test        interval of the seed mean over test-row resamples, seeds fixed (conditional on the models)
  ci_seeds_test  two-level interval: in every resample the seeds are also drawn with replacement, so seed
                 variation and test-set variation are both included (XGBoost has one deterministic run)
  within_ci      the interval of a difference contains 0 = the difference is not resolved
  summary_boot_runs.csv            per run (every seed): CI of macro-F1, balanced accuracy, attack macro-F1
  summary_boot_cells.csv           per model x condition: seed mean with ci_test and ci_seeds_test
  summary_boot_per_class_runs.csv  per run and class: precision, recall, F1 with CI (Supplement S1),
                                   small_support = fewer than 200 test flows
  summary_boot_per_class_cells.csv per model x condition x class: seed mean of precision, recall, F1 with CI
  summary_boot_model_diffs.csv     A - B of the seed means on the same test rows (paired), both intervals, p
  summary_boot_effects.csv         cleaning / split effect of the seed means (seeds present in both
                                   conditions; independent test sets), both intervals, p
  The main intervals are also merged into summary_table.csv (cell CIs), summary_per_class.csv,
  summary_model_diffs.csv and summary_effects.csv ('within_ci_...' marks unresolved differences) and
  summary_rankings.csv ('order_<metric>_resolved': every adjacent pair of the model order has a block
  two-level interval that excludes 0). Average precision has no bootstrap interval (seed range only).
Works with partial results (n is always reported).

Run (PowerShell, from the project folder; under a minute including the bootstrap):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\tree_seeds_summary.py 2>&1 | Tee-Object -FilePath tree_seeds_summary.log
  & $py experiments\\tree_seeds_summary.py --prefer-refit 2>&1 | Tee-Object -FilePath tree_seeds_summary_refit.log
"""
import argparse, json, os, re, sys, time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import CLASSES  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
ROOT = HERE.parent / 'results_2026_03_03'
TP = ROOT / 'tree_protocol' / 'main'
BOOT = ROOT / 'tree_protocol' / 'bootstrap.json'
BLOCK = ROOT / 'q1_revision' / 'analyses' / 'c_block_bootstrap_ci.csv'
OUT = ROOT / 'q1_revision' / 'tree_seeds'
TS = OUT / 'runs'
PAT = re.compile(r'^(XGBoost|LightGBM|RandomForest)_(random|temporal)_(raw|r1)_s(\d+)$')
MODELS = ['XGBoost', 'LightGBM', 'RandomForest']
CONDS = [('random', 'raw'), ('random', 'r1'), ('temporal', 'raw'), ('temporal', 'r1')]
K = len(CLASSES)
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']
HARD = ['macro_f1', 'attack_macro_f1', 'balanced_accuracy', 'accuracy']
SOFT = ['macro_ap', 'attack_macro_ap', 'macro_roc_auc']
METRICS = HARD + SOFT
TIMES = ['fit_seconds', 'inference_seconds', 'inference_s_per_1000']
SMALL = 200
PAIRS = [('LightGBM', 'XGBoost'), ('RandomForest', 'XGBoost'), ('RandomForest', 'LightGBM')]
BOOT_METRICS = ['macro_f1', 'balanced_accuracy', 'attack_macro_f1']
GMUL = 64                   # capture-group id = class * GMUL + group code (as revision_analyses.py)


# ----------------------------------------------------------------------------- helpers
def rnd(v, k=6):
    return None if v is None or (isinstance(v, float) and not np.isfinite(v)) else round(float(v), k)


def read_json(f):
    with open(f, encoding='utf-8') as fh:
        return json.load(fh)


def prf_arr(cm):
    """Per-class precision, recall, F1 of (..., K, K) count matrices (rows = true); 0 when undefined
    (= sklearn with zero_division=0)."""
    cm = np.asarray(cm, float)
    tp = np.diagonal(cm, axis1=-2, axis2=-1); row = cm.sum(-1); col = cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        rec = np.where(row > 0, tp / row, 0.0)
        prec = np.where(col > 0, tp / col, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    return prec, rec, f1


def prf(cm):
    """Per-class precision, recall, F1 and support of a (K, K) count matrix (rows = true)."""
    prec, rec, f1 = prf_arr(cm)
    return prec, rec, f1, np.asarray(cm).sum(1).astype(int)


def stats(v):
    v = np.asarray([x for x in v if x is not None and np.isfinite(x)], float)
    if not len(v):
        return {'n': 0, 'mean': None, 'sd': None, 'min': None, 'max': None}
    return {'n': int(len(v)), 'mean': float(v.mean()), 'sd': float(v.std(ddof=1)) if len(v) > 1 else None,
            'min': float(v.min()), 'max': float(v.max())}


def cell(s, k=3):
    """'mean ± SD [min, max] (n)'; the SD gets one decimal more (seed SDs can be < 0.0005)."""
    if not s or not s['n']:
        return ''
    sd = f' ± {s["sd"]:.{k + 1}f}' if s['sd'] is not None else ''
    rng = f' [{s["min"]:.{k}f}, {s["max"]:.{k}f}]' if s['n'] > 1 else ''
    return f'{s["mean"]:.{k}f}{sd}{rng} ({s["n"]})'


def _js(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


def records(df):
    return df.astype(object).where(df.notna(), None).to_dict('records')


# ----------------------------------------------------------------------------- loading
def hard_from_cm(cm):
    prec, rec, f1, sup = prf(cm)
    return {'per_class_f1': f1, 'per_class_precision': prec, 'per_class_recall': rec, 'support': sup,
            'attack_macro_f1': float(f1[ATTACKS].mean())}


def load_tree_protocol():
    out = {}
    for f in sorted(TP.glob('*.json')):
        m = PAT.match(f.stem)
        if not m:
            continue
        r = read_json(f)
        key = (m[1], m[2], m[3], int(m[4]))
        npz = f.with_suffix('.npz')
        rec = {'source': 'tree_protocol/main', 'macro_f1': r['macro_f1'], 'balanced_accuracy': r['balanced_accuracy'],
               'accuracy': r['accuracy'], 'fit_seconds': r.get('fit_seconds'), 'n_test': r.get('n_test'),
               'npz': str(npz) if npz.exists() else None}
        if npz.exists():
            with np.load(npz) as d:                  # only y and p: no pickle needed
                y, p = d['y'].astype(np.int64), d['p'].astype(np.int64)
            rec.update(hard_from_cm(np.bincount(y * K + p, minlength=K * K).reshape(K, K)))
        else:                                        # fall back to the rounded JSON values (no precision)
            f1 = np.array([r['per_class_f1'][c] for c in CLASSES], float)
            rec.update({'per_class_f1': f1, 'per_class_precision': None, 'support': None,
                        'per_class_recall': np.array([r['per_class_recall'][c] for c in CLASSES], float),
                        'attack_macro_f1': float(f1[ATTACKS].mean())})
        out[key] = rec
    return out


def load_tree_seeds():
    out = {}
    for f in sorted(TS.glob('*.json')):
        m = PAT.match(f.stem)
        if not m:
            continue
        r = read_json(f)
        key = (m[1], m[2], m[3], int(m[4]))
        inf = r.get('inference') or {}
        hw = r.get('hardware') or {}
        ld = inf.get('load_during_timing') or {}
        rec = {'source': 'q1_revision/tree_seeds', 'role': r.get('role'), 'macro_f1': r['macro_f1'],
               'cpu_load_at_start': hw.get('cpu_load_percent_at_start'),
               'gpu_util_at_start': hw.get('gpu_utilization_percent_at_start'),
               'cpu_other_during_inference': ld.get('cpu_percent_other_processes'),
               'gpu_util_before_inference': ld.get('gpu_utilization_percent_before'),
               'cpu_other_during_fit': (r.get('fit_load') or {}).get('cpu_percent_other_processes'),
               'balanced_accuracy': r['balanced_accuracy'], 'accuracy': r['accuracy'],
               'fit_seconds': r.get('fit_seconds'), 'n_test': r.get('n_test'),
               'macro_ap': r.get('macro_ap'), 'attack_macro_ap': r.get('attack_macro_ap'),
               'macro_roc_auc': r.get('macro_roc_auc'), 'macro_ap_float16': r.get('macro_ap_float16'),
               'per_class_ap': np.array([np.nan if r['per_class_ap'].get(c) is None else r['per_class_ap'][c]
                                         for c in CLASSES], float) if r.get('per_class_ap') else None,
               'inference_seconds': inf.get('seconds'), 'inference_s_per_1000': inf.get('seconds_per_1000_flows'),
               'inference_device': inf.get('device'), 'inference_n_jobs': inf.get('n_jobs'),
               'crosscheck': r.get('crosscheck'), 'hardware': r.get('hardware'),
               'npz': str(f.with_suffix('.npz')) if f.with_suffix('.npz').exists() else None}
        rec.update(hard_from_cm(r['confusion']))
        out[key] = rec
    return out


def load_bootstrap():
    """{(model, split, cleaning, seed): {'macro_f1_ci_iid': [lo, hi], ...}} from both optional sources."""
    ci = {}
    if BOOT.exists():
        for k, v in read_json(BOOT).get('runs', {}).items():
            parts = k.split('|')
            if len(parts) != 4 or not parts[3].isdigit():
                continue
            key = (parts[0], parts[1], parts[2], int(parts[3]))
            ci.setdefault(key, {}).update({'macro_f1_ci_iid': v.get('macro_f1_ci'),
                                           'balanced_accuracy_ci_iid': v.get('bal_acc_ci'),
                                           'per_class_f1_ci_iid': v.get('per_class_f1_ci')})
    if BLOCK.exists():
        b = pd.read_csv(BLOCK)
        b = b[b['variant'] == 'block5000']
        for _, r in b.iterrows():
            key = (r['model'], r['split'], r['cleaning'], int(r['seed']))
            name = {'macro_f1': 'macro_f1_ci_block5000', 'bal_acc': 'balanced_accuracy_ci_block5000'}.get(r['metric'])
            if name:
                ci.setdefault(key, {})[name] = [float(r['ci_lo']), float(r['ci_hi'])]
    return ci


# ----------------------------------------------------------------------------- tables
def build_runs(tp, ts, prefer_refit):
    keys = sorted(set(tp) | set(ts), key=lambda k: (MODELS.index(k[0]), CONDS.index(k[1:3]), k[3]))
    runs = []
    for k in keys:
        hard = ts[k] if (k in ts and (prefer_refit or k not in tp)) else tp[k]
        soft = ts.get(k)
        row = {'model': k[0], 'split': k[1], 'cleaning': k[2], 'seed': k[3], 'hard_source': hard['source'],
               'ap_source': soft['source'] if soft else None, 'n_test': hard['n_test'],
               'hard_npz': hard.get('npz')}
        for mt in HARD:
            row[mt] = hard[mt]
        for mt in SOFT + ['macro_ap_float16']:
            row[mt] = soft.get(mt) if soft else None
        row['fit_seconds'] = hard.get('fit_seconds')
        row['fit_seconds_refit'] = soft.get('fit_seconds') if soft and soft is not hard else None
        for mt in ('inference_seconds', 'inference_s_per_1000', 'inference_device', 'inference_n_jobs',
                   'cpu_load_at_start', 'gpu_util_at_start', 'cpu_other_during_inference',
                   'gpu_util_before_inference', 'cpu_other_during_fit'):
            row[mt] = soft.get(mt) if soft else None
        for i, c in enumerate(CLASSES):
            for part, name in (('per_class_f1', 'f1'), ('per_class_precision', 'precision'),
                               ('per_class_recall', 'recall')):
                row[f'{name}_{c}'] = None if hard.get(part) is None else float(hard[part][i])
            row[f'ap_{c}'] = (None if not soft or soft.get('per_class_ap') is None
                              or not np.isfinite(soft['per_class_ap'][i]) else float(soft['per_class_ap'][i]))
            row[f'support_{c}'] = None if hard.get('support') is None else int(hard['support'][i])
        runs.append(row)
    d = pd.DataFrame(runs)
    text_cols = {'model', 'split', 'cleaning', 'hard_source', 'ap_source', 'inference_device', 'hard_npz'}
    for col in d.columns:                  # None -> NaN, float dtype (groupby means, notna, to_numpy)
        if col not in text_cols:
            d[col] = pd.to_numeric(d[col], errors='coerce')
    return d


def by_cond(d):
    for m in MODELS:
        for s, c in CONDS:
            g = d[(d['model'] == m) & (d['split'] == s) & (d['cleaning'] == c)]
            if len(g):
                yield m, s, c, g


def conditions_table(d, ci):
    rows, text = [], []
    for m, s, c, g in by_cond(d):
        row = {'model': m, 'split': s, 'cleaning': c}
        trow = {'model': m, 'split': s, 'cleaning': c, 'seeds_hard': ' '.join(map(str, g['seed']))}
        for mt in METRICS + ['fit_seconds', 'inference_s_per_1000']:
            vals = g[mt].to_numpy(float) if g[mt].notna().any() else []
            st = stats(vals)
            seeds = g.loc[g[mt].notna(), 'seed'].tolist()
            for f, v in st.items():
                row[f'{mt}_{f}'] = v
            row[f'{mt}_seeds'] = ' '.join(map(str, seeds))
            if mt in METRICS:
                trow[mt] = cell(st)
        b = ci.get((m, s, c, 42), {})
        for name in ('macro_f1_ci_iid', 'macro_f1_ci_block5000', 'balanced_accuracy_ci_iid',
                     'balanced_accuracy_ci_block5000'):
            v = b.get(name)
            row[f'{name}_s42'] = None if v is None else f'[{v[0]:.4f}, {v[1]:.4f}]'
            if name in ('macro_f1_ci_iid', 'macro_f1_ci_block5000', 'balanced_accuracy_ci_block5000'):
                trow[f'{name}_s42'] = row[f'{name}_s42']
        rows.append(row); text.append(trow)
    return pd.DataFrame(rows), pd.DataFrame(text)


def per_class_table(d, ci):
    rows = []
    for m, s, c, g in by_cond(d):
        b = ci.get((m, s, c, 42), {}).get('per_class_f1_ci_iid')
        for i, cls in enumerate(CLASSES):
            sup = g[f'support_{cls}'].dropna()
            n_sup = int(sup.iloc[0]) if len(sup) else None
            row = {'model': m, 'split': s, 'cleaning': c, 'class': cls, 'n_test_flows': n_sup,
                   'small_support': None if n_sup is None else bool(n_sup < SMALL)}
            for name in ('f1', 'precision', 'recall', 'ap'):
                st = stats(g[f'{name}_{cls}'].to_numpy(float) if g[f'{name}_{cls}'].notna().any() else [])
                for f, v in st.items():
                    row[f'{name}_{f}'] = v
            row['f1_ci_iid_s42'] = None if not b else f'[{b[i][0]:.4f}, {b[i][1]:.4f}]'
            rows.append(row)
    return pd.DataFrame(rows)


def effects_table(d):
    rows = []
    for m in MODELS:
        g = d[d['model'] == m]
        if not len(g):
            continue
        v = {(r['split'], r['cleaning'], r['seed']): r for r in g.to_dict('records')}
        seeds = sorted(set(g['seed']))
        comps = [('cleaning (r1 - raw)', sp, (sp, 'r1'), (sp, 'raw')) for sp in ('random', 'temporal')] + \
                [('split (random - temporal)', cl, ('random', cl), ('temporal', cl)) for cl in ('raw', 'r1')]
        for what, within, a, b in comps:
            for mt in METRICS:
                diffs, used = [], []
                for sd in seeds:
                    ra, rb = v.get((*a, sd)), v.get((*b, sd))
                    if ra is None or rb is None or ra.get(mt) is None or rb.get(mt) is None:
                        continue
                    if not (np.isfinite(ra[mt]) and np.isfinite(rb[mt])):
                        continue
                    diffs.append(ra[mt] - rb[mt]); used.append(sd)
                if not diffs:
                    continue
                st = stats(diffs)
                rows.append({'model': m, 'effect': what, 'within': within, 'metric': mt, **st,
                             'sign_consistent': None if len(diffs) < 2 else
                             bool(all(x > 0 for x in diffs) or all(x < 0 for x in diffs)),
                             'per_seed': ' '.join(f's{sd}:{x:+.4f}' for sd, x in zip(used, diffs))})
    return pd.DataFrame(rows)


def model_diffs_table(d):
    rows = []
    for s, c in CONDS:
        g = d[(d['split'] == s) & (d['cleaning'] == c)]
        for A, B in PAIRS:
            for mt in METRICS:
                va = g.loc[(g['model'] == A) & g[mt].notna(), mt].to_numpy(float)
                vb = g.loc[(g['model'] == B) & g[mt].notna(), mt].to_numpy(float)
                if not (len(va) and len(vb)):
                    continue
                diff = np.subtract.outer(va, vb).ravel()
                rows.append({'split': s, 'cleaning': c, 'a': A, 'b': B, 'metric': mt,
                             'n_a': len(va), 'n_b': len(vb), 'mean_a': va.mean(), 'mean_b': vb.mean(),
                             'diff_of_means': va.mean() - vb.mean(), 'pair_min': diff.min(), 'pair_max': diff.max(),
                             'share_pairs_a_better': float((diff > 0).mean()),
                             'seed_ranges_overlap': bool(va.min() <= vb.max() and vb.min() <= va.max()),
                             'sign_consistent': None if len(diff) < 2 else bool((diff > 0).all() or (diff < 0).all())})
    return pd.DataFrame(rows)


def rankings_table(d):
    rows = []
    for s, c in CONDS:
        g = d[(d['split'] == s) & (d['cleaning'] == c)]
        row, orders = {'split': s, 'cleaning': c}, {}
        for mt in ('macro_f1', 'balanced_accuracy', 'macro_ap', 'attack_macro_f1'):
            means = g.groupby('model')[mt].mean().dropna()
            if len(means) < 2:
                continue
            order = means.sort_values(ascending=False)
            orders[mt] = tuple(order.index)
            row[f'order_{mt}'] = ' > '.join(f'{k} ({v:.3f})' for k, v in order.items())
        full = [o for o in orders.values() if len(o) == len(MODELS)]
        row['rankings_agree'] = None if len(full) < 2 else bool(len(set(full)) == 1)
        rows.append(row)
    return pd.DataFrame(rows)


def timing_table(d, tp, ts):
    """Fit times of every stored fit (paper runs of tree_protocol/main and tree_seeds runs, also separately:
    they ran in different sessions, the tree_seeds runs partly beside other jobs), the slowdown of the
    tree_seeds refits against the paper fit of the same run, inference times (tree_seeds runs only) and
    the competing load recorded with them."""
    rows = []
    for m in MODELS:
        g = d[d['model'] == m]
        for scope, sel in [('all conditions', g)] + [(f'{s}/{c}', g[(g['split'] == s) & (g['cleaning'] == c)])
                                                    for s, c in CONDS]:
            inside = (lambda k: k[0] == m) if scope == 'all conditions' else \
                     (lambda k, sc=tuple(scope.split('/')): k[:3] == (m, *sc))
            fit_tp = [r['fit_seconds'] for k, r in tp.items() if inside(k) and r.get('fit_seconds') is not None]
            fit_ts = [r['fit_seconds'] for k, r in ts.items() if inside(k) and r.get('fit_seconds') is not None]
            slow = [ts[k]['fit_seconds'] / tp[k]['fit_seconds'] for k in ts
                    if inside(k) and k in tp and ts[k].get('fit_seconds') and tp[k].get('fit_seconds')]
            fit, f_tp, f_ts = stats(fit_tp + fit_ts), stats(fit_tp), stats(fit_ts)
            inf = stats(sel['inference_seconds'].to_numpy(float) if sel['inference_seconds'].notna().any() else [])
            per = stats(sel['inference_s_per_1000'].to_numpy(float) if sel['inference_s_per_1000'].notna().any() else [])
            dev = sel['inference_device'].dropna()
            nj = sel['inference_n_jobs'].dropna()
            n_test = sel['n_test'].dropna()
            load = {k: (float(sel[k].max()) if sel[k].notna().any() else None)      # competing load (highest)
                    for k in ('cpu_load_at_start', 'gpu_util_at_start', 'cpu_other_during_inference',
                              'gpu_util_before_inference', 'cpu_other_during_fit')}
            rows.append({'model': m, 'scope': scope,
                         **{f'fit_seconds_{k}': v for k, v in fit.items()},
                         **{f'fit_seconds_paper_runs_{k}': v for k, v in f_tp.items()},
                         **{f'fit_seconds_tree_seeds_{k}': v for k, v in f_ts.items()},
                         'fit_slowdown_refit_vs_paper_n': len(slow),
                         'fit_slowdown_refit_vs_paper_median': float(np.median(slow)) if slow else None,
                         'fit_slowdown_refit_vs_paper_max': float(np.max(slow)) if slow else None,
                         **{f'inference_seconds_{k}': v for k, v in inf.items()},
                         **{f'inference_ms_per_1000_flows_{k}': (v if v is None or k == 'n' else 1000 * v)
                            for k, v in per.items()},
                         'n_test_flows': None if not len(n_test) or scope == 'all conditions' else int(n_test.iloc[0]),
                         'inference_device': dev.iloc[0] if len(dev) else None,
                         'n_jobs': nj.iloc[0] if len(nj) else None,
                         'cpu_load_percent_at_start_max': load['cpu_load_at_start'],
                         'gpu_utilization_percent_at_start_max': load['gpu_util_at_start'],
                         'n_inference_with_load_record': int(sel['cpu_other_during_inference'].notna().sum()),
                         'cpu_percent_other_during_inference_max': load['cpu_other_during_inference'],
                         'gpu_utilization_percent_before_inference_max': load['gpu_util_before_inference'],
                         'cpu_percent_other_during_fit_max': load['cpu_other_during_fit']})
    return pd.DataFrame(rows)


def crosscheck_table(ts):
    rows = []
    for k, r in sorted(ts.items(), key=lambda kv: (MODELS.index(kv[0][0]), CONDS.index(kv[0][1:3]), kv[0][3])):
        ck = r.get('crosscheck')
        if not ck:
            continue
        rows.append({'model': k[0], 'split': k[1], 'cleaning': k[2], 'seed': k[3],
                     'reference_macro_f1': ck.get('reference_macro_f1'), 'refit_macro_f1': r['macro_f1'],
                     'macro_f1_diff': ck.get('macro_f1_diff'), 'balanced_accuracy_diff': ck.get('balanced_accuracy_diff'),
                     'same_test_rows': ck.get('same_test_rows'), 'prediction_agreement': ck.get('prediction_agreement'),
                     'n_prediction_differences': ck.get('n_prediction_differences'),
                     'n_differences_at_ties': ck.get('n_differences_at_ties'),
                     'tolerance': ck.get('tolerance'), 'within_tolerance': ck.get('within_tolerance'),
                     'reproduced_up_to_ties': ck.get('reproduced_up_to_ties')})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- bootstrap over all seeds
def load_pred(path):
    """y, p, capture group and (tree_seeds runs only) global row positions of a stored run."""
    with np.load(path, allow_pickle=True) as d:     # own result files: tree_protocol 'sub' is a str object array
        y, p = d['y'].astype(np.int64), d['p'].astype(np.int64)
        sub = np.asarray(d['sub']).astype(str) if 'sub' in d.files else None
        rows = d['rows'].astype(np.int64) if 'rows' in d.files else None
    return y, p, sub, rows


def same_rows(y0, s0, y, s):
    return (len(y) == len(y0) and np.array_equal(y, y0)
            and (s is None or s0 is None or np.array_equal(s, s0)))


def block_len(n, L, min_blocks):
    """Block length of revision_analyses.py part (c): l = min(L, max(1, n // min_blocks))."""
    return 1 if L <= 1 else min(L, max(1, n // max(1, min_blocks)))


def joint_boot(y, gid, P, L, B, rng, min_blocks):
    """(B, R, K, K) bootstrap confusion matrices of the R runs in P (R x n predictions of the SAME test
    rows). The rows are resampled inside every group of gid with the same draws for all runs (paired).
    L = 1: i.i.d. rows (multinomial over the joint prediction patterns of the group, i.e. the joint
    version of bootstrap_ci.py). L > 1: circular moving-block bootstrap on the given row order (time
    order inside each group), blocks as in revision_analyses.py (c): ceil(n / l) blocks of l rows with
    random starts, the last one cut so that exactly n rows are drawn. Every group has one true class."""
    R, n = P.shape
    assert R <= 20, 'joint pattern code needs R <= 20 runs (8 ** 20 < 2 ** 63)'
    out = np.zeros((B, R, K, K))
    lengths = {}
    for g in np.unique(gid):
        idx = np.flatnonzero(gid == g)
        c = int(y[idx[0]])
        assert (y[idx] == c).all(), 'a bootstrap stratum must hold a single true class'
        assert len(idx) < 2 ** 24, "float32 pattern counts need fewer than 2 ** 24 rows per stratum"
        ng = len(idx)
        l = block_len(ng, L, min_blocks)
        lengths[int(g)] = l
        Pg = P[:, idx].astype(np.int64)
        if l == 1:
            code = np.zeros(ng, np.int64)
            for r in range(R):                           # run 0 is the most significant digit
                code = code * K + Pg[r]
            u, loc = np.unique(code, return_inverse=True)
            freq = np.bincount(loc.ravel(), minlength=len(u)) / ng
            M = np.zeros((len(u), R * K), np.float32)    # pattern -> one-hot prediction of every run
            rest = u.copy()
            for r in range(R - 1, -1, -1):
                M[np.arange(len(u)), r * K + rest % K] = 1.0
                rest //= K
            ch = max(1, min(B, 500_000 // len(u)))       # (ch, U) count block of at most ~4 MB
            for b0 in range(0, B, ch):
                cnt = rng.multinomial(ng, freq, size=min(ch, B - b0)).astype(np.float32)
                # float32 sums are exact here: every count is <= ng < 2 ** 24
                out[b0:b0 + len(cnt), :, c, :] += (cnt @ M).reshape(len(cnt), R, K)
                del cnt
        else:
            k = -(-ng // l)
            last = ng - (k - 1) * l
            s = rng.integers(0, ng, size=(B, k))         # the same block starts for every run
            ch = max(1, min(B, 1_000_000 // (k * K)))     # (ch, k, K) int32 gathers of at most ~4 MB
            for r in range(R):
                C = np.zeros((2 * ng + 1, K), np.int32)
                C[np.arange(1, 2 * ng + 1), np.r_[Pg[r], Pg[r]]] = 1
                C = np.cumsum(C, axis=0, dtype=np.int32)  # C[i] = prediction counts in positions [0, i)
                for b0 in range(0, B, ch):
                    sb = s[b0:b0 + ch]
                    cnt = C[sb[:, -1] + last] - C[sb[:, -1]]
                    if k > 1:
                        cnt = cnt + (C[sb[:, :-1] + l] - C[sb[:, :-1]]).sum(1)
                    out[b0:b0 + len(sb), r, c, :] += cnt
                del C
    return out, lengths


def scalar_metrics(cm, present):
    """macro-F1 over the 8 classes (as metrics()), balanced accuracy = mean recall over the classes
    present in the test set (as sklearn), attack macro-F1; plus per-class (precision, recall, F1)."""
    prec, rec, f1 = prf_arr(cm)
    return ({'macro_f1': f1.mean(-1), 'balanced_accuracy': rec[..., present].mean(-1),
             'attack_macro_f1': f1[..., ATTACKS].mean(-1)}, (prec, rec, f1))


def pct(v):
    lo, hi = np.percentile(v, [2.5, 97.5])
    return float(lo), float(hi)


def boot_p(d):
    """Two-sided bootstrap p of a difference: 2 (min(#d <= 0, #d >= 0) + 1) / (B + 1)."""
    return min(1.0, 2 * (min(int((d <= 0).sum()), int((d >= 0).sum())) + 1) / (len(d) + 1))


def fmt_ci(lo, hi, k=4):
    return None if lo is None or hi is None else f'[{lo:.{k}f}, {hi:.{k}f}]'


def bootstrap_all(d, ts, B, L, min_blocks, seed=42):
    """Test-set bootstrap over ALL stored runs (every seed) of each condition, resampled jointly.
    Returns the tables and the replicate arrays."""
    methods = [('iid_class', 1), (f'block{L}', L)]
    rng2 = np.random.default_rng([seed, 999])            # seed resampling (two-level intervals)
    reps, info = {}, {}
    run_rows, pcr_rows = [], []
    for ci_idx, (s, c) in enumerate(CONDS):
        g = d[(d['split'] == s) & (d['cleaning'] == c) & d['hard_npz'].notna()]
        g = g.sort_values(['model', 'seed'], key=lambda col: col.map(MODELS.index) if col.name == 'model' else col)
        runs, P, y0, s0 = [], [], None, None
        for rr in g.to_dict('records'):
            y, p, sub, _ = load_pred(rr['hard_npz'])
            if y0 is None:
                y0, s0 = y, sub
            elif not same_rows(y0, s0, y, sub):
                print(f'[warn] {rr["model"]} s{int(rr["seed"])} {s}/{c}: test rows differ from the other runs '
                      f'- left out of the bootstrap', flush=True)
                continue
            runs.append((rr['model'], int(rr['seed']), rr['hard_source']))
            P.append(p.astype(np.int8))
        if not runs:
            continue
        # time order inside each capture group: ascending global row (the flagged sample is time-sorted
        # within each class; the temporal split keeps that order). Global rows exist in tree_seeds npz.
        rows = None
        for k_, r_ in ts.items():
            if k_[1:3] == (s, c) and r_.get('npz'):
                y2, _, sub2, rows2 = load_pred(r_['npz'])
                if rows2 is not None and same_rows(y0, s0, y2, sub2):
                    rows = rows2
                    break
        names, code = (np.unique(s0, return_inverse=True) if s0 is not None else (None, None))
        gid_grp = None if code is None else y0 * GMUL + code.ravel()
        order_ok = None
        if rows is not None and s == 'temporal' and gid_grp is not None:
            # check of the claim above: stored temporal order = ascending global rows in every group
            order_ok = bool(all(np.all(np.diff(rows[gid_grp == q]) > 0) for q in np.unique(gid_grp)))
            if not order_ok:
                print(f'[warn] {s}/{c}: stored temporal order is not ascending in global rows - '
                      f'the stored order is used for the block bootstrap', flush=True)
        if gid_grp is None:
            perm, how = None, None
        elif rows is not None and order_ok is not False:
            perm, how = np.argsort(rows, kind='stable'), 'time order (global rows of the tree_seeds npz)'
        elif s == 'temporal':
            perm, how = None, 'time order (stored)'
        else:
            perm, how = None, None                         # random order: no block bootstrap
        P = np.stack(P)
        y = y0 if perm is None else y0[perm]
        P = P if perm is None else P[:, perm]
        gid_grp = None if gid_grp is None else (gid_grp if perm is None else gid_grp[perm])
        obs = np.stack([np.bincount(y * K + P[r].astype(np.int64), minlength=K * K).reshape(K, K)
                        for r in range(len(runs))]).astype(float)
        present = obs[0].sum(1) > 0
        point, point_pc = scalar_metrics(obs, present)
        info[(s, c)] = {'n_runs': len(runs), 'n_test': int(len(y)), 'row_order_block': how,
                        'temporal_order_check': order_ok, 'runs': [f'{m} s{sd} ({src})' for m, sd, src in runs]}
        reps[(s, c)] = {'runs': runs, 'point': point, 'point_pc': point_pc, 'support': obs[0].sum(1)}
        for mi, (mname, Lm) in enumerate(methods):
            gid = y if Lm == 1 else gid_grp
            if gid is None or (Lm > 1 and how is None):
                print(f'[warn] {s}/{c}: no time order for the random-split test rows yet (needs a tree_seeds '
                      f'npz of this condition) - {mname} skipped', flush=True)
                continue
            t0 = time.time()
            cm, lengths = joint_boot(y, gid, P, Lm, B, np.random.default_rng([seed, ci_idx, mi]), min_blocks)
            met, pc = scalar_metrics(cm, present)
            del cm
            reps[(s, c)][mname] = {'met': met, 'pc': pc}
            if Lm > 1:
                info[(s, c)][f'{mname}_groups_shortened'] = int(sum(v < Lm for v in lengths.values()))
            for r, (m, sd, src) in enumerate(runs):
                for mt in BOOT_METRICS:
                    lo, hi = pct(met[mt][:, r])
                    run_rows.append({'model': m, 'split': s, 'cleaning': c, 'seed': sd, 'hard_source': src,
                                     'method': mname, 'metric': mt, 'point': point[mt][r], 'ci_lo': lo, 'ci_hi': hi,
                                     'half_width': (hi - lo) / 2})
                for i, cls in enumerate(CLASSES):
                    row = {'model': m, 'split': s, 'cleaning': c, 'seed': sd, 'class': cls, 'method': mname,
                           'n_test_flows': int(obs[0, i].sum()), 'small_support': bool(obs[0, i].sum() < SMALL)}
                    for j, part in enumerate(('precision', 'recall', 'f1')):
                        lo, hi = pct(pc[j][:, r, i])
                        row.update({part: point_pc[j][r, i], f'{part}_ci_lo': lo, f'{part}_ci_hi': hi})
                    pcr_rows.append(row)
            print(f'[boot] {s:8s} {c:3s} {mname:10s} {len(runs)} runs x {len(y):,} test flows, B={B} '
                  f'({time.time() - t0:.1f} s)', flush=True)

    methods_done = [m for m, _ in methods]

    def cell_vals(key, mname, mt, J, sel=None):
        a = reps[key][mname]['met'][mt]
        return a[:, J].mean(1) if sel is None else a[np.arange(len(a))[:, None], np.asarray(J)[sel]].mean(1)

    # per model x condition: CI of the seed mean (test rows resampled; seeds fixed) and two-level CI
    # (seeds resampled with replacement AND test rows resampled)
    cell_rows, pcc_rows, diff_rows, eff_rows = [], [], [], []
    idx = {key: {m: [r for r, (mm, _, _) in enumerate(v['runs']) if mm == m] for m in MODELS}
           for key, v in reps.items()}
    for key, v in reps.items():
        for m in MODELS:
            J = idx[key][m]
            if not J:
                continue
            seeds = [v['runs'][r][1] for r in J]
            for mname in methods_done:
                if mname not in v:
                    continue
                sel = rng2.integers(0, len(J), size=(B, len(J)))
                for mt in BOOT_METRICS:
                    pt = float(v['point'][mt][J].mean())
                    lo, hi = pct(cell_vals(key, mname, mt, J))
                    lo2, hi2 = pct(cell_vals(key, mname, mt, J, sel))
                    cell_rows.append({'model': m, 'split': key[0], 'cleaning': key[1], 'metric': mt,
                                      'method': mname, 'n_seeds': len(J), 'seeds': ' '.join(map(str, seeds)),
                                      'seed_mean': pt,
                                      'seed_sd': float(np.std(v['point'][mt][J], ddof=1)) if len(J) > 1 else None,
                                      'ci_test_lo': lo, 'ci_test_hi': hi, 'ci_seeds_test_lo': lo2,
                                      'ci_seeds_test_hi': hi2})
                pc = v[mname]['pc']
                for i, cls in enumerate(CLASSES):
                    row = {'model': m, 'split': key[0], 'cleaning': key[1], 'class': cls, 'method': mname,
                           'n_seeds': len(J), 'n_test_flows': int(v['support'][i]),
                           'small_support': bool(v['support'][i] < SMALL)}
                    for j, part in enumerate(('precision', 'recall', 'f1')):
                        lo, hi = pct(pc[j][:, J, i].mean(1))
                        row.update({f'{part}_seed_mean': float(v['point_pc'][j][J, i].mean()),
                                    f'{part}_ci_lo': lo, f'{part}_ci_hi': hi})
                    pcc_rows.append(row)
        # model differences on the same test rows (paired resampling), seed means
        for A, Bm in PAIRS:
            JA, JB = idx[key][A], idx[key][Bm]
            if not (JA and JB):
                continue
            for mname in methods_done:
                if mname not in v:
                    continue
                sa = rng2.integers(0, len(JA), size=(B, len(JA)))
                sb = rng2.integers(0, len(JB), size=(B, len(JB)))
                for mt in BOOT_METRICS:
                    pt = float(v['point'][mt][JA].mean() - v['point'][mt][JB].mean())
                    d1 = cell_vals(key, mname, mt, JA) - cell_vals(key, mname, mt, JB)
                    d2 = cell_vals(key, mname, mt, JA, sa) - cell_vals(key, mname, mt, JB, sb)
                    (lo, hi), (lo2, hi2) = pct(d1), pct(d2)
                    diff_rows.append({'split': key[0], 'cleaning': key[1], 'a': A, 'b': Bm, 'metric': mt,
                                      'method': mname, 'n_a': len(JA), 'n_b': len(JB), 'diff_of_seed_means': pt,
                                      'ci_test_lo': lo, 'ci_test_hi': hi, 'p_test': boot_p(d1),
                                      'ci_seeds_test_lo': lo2, 'ci_seeds_test_hi': hi2, 'p_seeds_test': boot_p(d2),
                                      'within_ci_test': bool(lo <= 0 <= hi),
                                      'within_ci_seeds_test': bool(lo2 <= 0 <= hi2)})
    # cleaning and split effects: different test sets -> independent bootstraps; seeds common to both
    comps = [('cleaning (r1 - raw)', sp, (sp, 'r1'), (sp, 'raw')) for sp in ('random', 'temporal')] + \
            [('split (random - temporal)', cl, ('random', cl), ('temporal', cl)) for cl in ('raw', 'r1')]
    for m in MODELS:
        for what, within, ka, kb in comps:
            if ka not in reps or kb not in reps:
                continue
            sda = {reps[ka]['runs'][r][1]: r for r in idx[ka][m]}
            sdb = {reps[kb]['runs'][r][1]: r for r in idx[kb][m]}
            common = sorted(set(sda) & set(sdb))
            if not common:
                continue
            Ja, Jb = [sda[x] for x in common], [sdb[x] for x in common]
            for mname in methods_done:
                if mname not in reps[ka] or mname not in reps[kb]:
                    continue
                sel = rng2.integers(0, len(common), size=(B, len(common)))   # same seeds in both conditions
                for mt in BOOT_METRICS:
                    pt = float(reps[ka]['point'][mt][Ja].mean() - reps[kb]['point'][mt][Jb].mean())
                    d1 = cell_vals(ka, mname, mt, Ja) - cell_vals(kb, mname, mt, Jb)
                    d2 = cell_vals(ka, mname, mt, Ja, sel) - cell_vals(kb, mname, mt, Jb, sel)
                    (lo, hi), (lo2, hi2) = pct(d1), pct(d2)
                    eff_rows.append({'model': m, 'effect': what, 'within': within, 'metric': mt, 'method': mname,
                                     'n_seeds': len(common), 'seeds': ' '.join(map(str, common)), 'diff': pt,
                                     'ci_test_lo': lo, 'ci_test_hi': hi, 'p_test': boot_p(d1),
                                     'ci_seeds_test_lo': lo2, 'ci_seeds_test_hi': hi2, 'p_seeds_test': boot_p(d2),
                                     'within_ci_test': bool(lo <= 0 <= hi),
                                     'within_ci_seeds_test': bool(lo2 <= 0 <= hi2)})
    return {'runs': pd.DataFrame(run_rows), 'cells': pd.DataFrame(cell_rows),
            'per_class_runs': pd.DataFrame(pcr_rows), 'per_class_cells': pd.DataFrame(pcc_rows),
            'diffs': pd.DataFrame(diff_rows), 'effects': pd.DataFrame(eff_rows),
            'info': {f'{k[0]}/{k[1]}': v for k, v in info.items()}, 'methods': methods_done}


def merge_boot(text, pcl, eff, mdiff, rank, bs, main_method):
    """Adds the bootstrap intervals to the paper-facing tables (whole columns, object dtype).
    main_method = the block method (time-dependent test flows), 'iid_class' = bootstrap_ci.py style."""
    cells, pcc, dif, efb = bs['cells'], bs['per_class_cells'], bs['diffs'], bs['effects']

    def lookup(df, keys):
        """{(method, *key values): row} of a bootstrap table."""
        if not len(df):
            return {}
        return {(r['method'], *[r[k] for k in keys]): r for r in df.to_dict('records')}

    def put(t, col, vals):
        t[col] = pd.Series(vals, index=t.index, dtype=object)

    if len(text):
        L = lookup(cells, ('model', 'split', 'cleaning', 'metric'))
        for mt in BOOT_METRICS:
            for mname, tag in ((main_method, 'block'), ('iid_class', 'iid')):
                rs = [L.get((mname, t['model'], t['split'], t['cleaning'], mt)) for t in text.to_dict('records')]
                put(text, f'{mt}_ci95_seeds+test_{tag}',
                    [None if r is None else fmt_ci(r['ci_seeds_test_lo'], r['ci_seeds_test_hi'], 3) for r in rs])
                put(text, f'{mt}_ci95_test_{tag}',
                    [None if r is None else fmt_ci(r['ci_test_lo'], r['ci_test_hi'], 3) for r in rs])
    if len(pcl):
        L = lookup(pcc, ('model', 'split', 'cleaning', 'class'))
        for mname, tag in ((main_method, 'block'), ('iid_class', 'iid')):
            rs = [L.get((mname, t['model'], t['split'], t['cleaning'], t['class'])) for t in pcl.to_dict('records')]
            for part in ('f1', 'precision', 'recall'):
                put(pcl, f'{part}_ci95_test_{tag}',
                    [None if r is None else fmt_ci(r[f'{part}_ci_lo'], r[f'{part}_ci_hi']) for r in rs])
    for df, src, keys in ((mdiff, dif, ('split', 'cleaning', 'a', 'b', 'metric')),
                          (eff, efb, ('model', 'effect', 'within', 'metric'))):
        if not len(df):
            continue
        L = lookup(src, keys)
        recs = df.to_dict('records')
        rb = [L.get((main_method, *[t[k] for k in keys])) for t in recs]
        ri = [L.get(('iid_class', *[t[k] for k in keys])) for t in recs]
        put(df, 'ci95_seeds+test_block', [None if r is None else fmt_ci(r['ci_seeds_test_lo'], r['ci_seeds_test_hi'])
                                          for r in rb])
        put(df, 'p_seeds+test_block', [None if r is None else r['p_seeds_test'] for r in rb])
        put(df, 'within_ci_seeds+test_block', [None if r is None else bool(r['within_ci_seeds_test']) for r in rb])
        put(df, 'ci95_test_iid', [None if r is None else fmt_ci(r['ci_test_lo'], r['ci_test_hi']) for r in ri])
        put(df, 'within_ci_test_iid', [None if r is None else bool(r['within_ci_test']) for r in ri])
    if len(rank) and len(dif):
        L = lookup(dif, ('split', 'cleaning', 'a', 'b', 'metric'))
        for mt in BOOT_METRICS:
            col = f'order_{mt}'
            if col not in rank.columns:
                continue
            vals = []
            for t in rank.to_dict('records'):
                o = t.get(col)
                if not isinstance(o, str):
                    vals.append(None)
                    continue
                order = [x.split(' (')[0] for x in o.split(' > ')]
                res = []
                for a_, b_ in zip(order[:-1], order[1:]):
                    r = (L.get((main_method, t['split'], t['cleaning'], a_, b_, mt))
                         or L.get((main_method, t['split'], t['cleaning'], b_, a_, mt)))
                    res.append(None if r is None else not bool(r['within_ci_seeds_test']))
                vals.append(None if (not res or None in res) else bool(all(res)))
            put(rank, f'{col}_resolved', vals)
    return text, pcl, eff, mdiff, rank


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--prefer-refit', action='store_true',
                    help='take hard-label metrics of seeds 42/17/7 from the tree_seeds refits when they exist '
                         '(default: the stored tree_protocol/main runs, i.e. the values in the paper)')
    ap.add_argument('--B', type=int, default=2000, help='bootstrap resamples (default 2000, as bootstrap_ci.py)')
    ap.add_argument('--block', type=int, default=5000,
                    help='block length in flows of the moving-block bootstrap (default 5000, as the paper)')
    ap.add_argument('--min-blocks', type=int, default=5,
                    help='a capture group gets at least this many blocks (as revision_analyses.py)')
    ap.add_argument('--no-boot', action='store_true', help='skip the bootstrap (tables of point values only)')
    a = ap.parse_args()
    tp, ts = load_tree_protocol(), load_tree_seeds()
    print(f'[load] tree_protocol/main: {len(tp)} runs, q1_revision/tree_seeds: {len(ts)} runs', flush=True)
    if not (tp or ts):
        print('no runs found'); return
    ci = load_bootstrap()
    d = build_runs(tp, ts, a.prefer_refit)
    cond, text = conditions_table(d, ci)
    pcl = per_class_table(d, ci)
    eff = effects_table(d)
    mdiff = model_diffs_table(d)
    rank = rankings_table(d)
    tim = timing_table(d, tp, ts)
    ck = crosscheck_table(ts)
    hw = next((r['hardware'] for r in ts.values() if r.get('hardware')), None)
    if hw:                                     # machine description only; loads / free RAM are per run
        hw = {k: v for k, v in hw.items() if not k.endswith('_at_start')}
    sfx = '_refit' if a.prefer_refit else ''   # --prefer-refit must not overwrite the paper-value tables
    bs = None
    if not a.no_boot:
        bs = bootstrap_all(d, ts, a.B, a.block, a.min_blocks)
        text, pcl, eff, mdiff, rank = merge_boot(text, pcl, eff, mdiff, rank, bs, f'block{a.block}')

    OUT.mkdir(parents=True, exist_ok=True)
    runs_out = d.copy()
    def rel(v):
        try:
            return os.path.relpath(v, ROOT)
        except ValueError:                                  # other drive
            return v
    runs_out['hard_npz'] = [rel(v) if isinstance(v, str) else None for v in runs_out['hard_npz']]
    tables = {'summary_runs': runs_out, 'summary_conditions': cond, 'summary_table': text, 'summary_per_class': pcl,
              'summary_effects': eff, 'summary_model_diffs': mdiff, 'summary_rankings': rank,
              'summary_timing': tim, 'summary_crosscheck': ck}
    if bs is not None:
        tables.update({'summary_boot_runs': bs['runs'], 'summary_boot_cells': bs['cells'],
                       'summary_boot_per_class_runs': bs['per_class_runs'],
                       'summary_boot_per_class_cells': bs['per_class_cells'],
                       'summary_boot_model_diffs': bs['diffs'], 'summary_boot_effects': bs['effects']})
    for name, t in tables.items():
        t.round(6).to_csv(OUT / f'{name}{sfx}.csv', index=False)
    res = {'sources': {'hard_label_metrics': 'tree_seeds refits where available' if a.prefer_refit else
                       'tree_protocol/main for seeds 42/17/7, tree_seeds for 123/2024',
                       'average_precision': 'tree_seeds runs (probabilities)',
                       'bootstrap_ci_iid_stored_runs': str(BOOT.relative_to(ROOT)) if BOOT.exists() else None,
                       'bootstrap_ci_block5000_seed42': str(BLOCK.relative_to(ROOT)) if BLOCK.exists() else None},
           'bootstrap': None if bs is None else {
               'B': a.B, 'block': a.block, 'min_blocks': a.min_blocks, 'seed': 42, 'methods': bs['methods'],
               'iid_class': 'test rows resampled i.i.d. inside each true class (as bootstrap_ci.py)',
               f'block{a.block}': 'circular moving blocks of time-consecutive test rows inside each capture group '
                                  '(as revision_analyses.py part c); block shortened to n // min_blocks in small groups',
               'joint': 'all runs of a condition (every model and seed) see the SAME resampled test rows, so seed '
                        'means and model differences are resampled consistently (paired)',
               'ci_test': 'percentile 95% CI of the seed mean (or difference of seed means) over test-row '
                          'resamples; the seeds are fixed (conditional on the trained models)',
               'ci_seeds_test': 'two-level: in every resample the model seeds are also drawn with replacement '
                                '(n = 1 for XGBoost: equals ci_test); effects use the same drawn seeds in both '
                                'conditions, model differences draw the seeds of each model independently',
               'within_ci': 'the interval contains 0 (difference not resolved)',
               'p': '2 (min(#d <= 0, #d >= 0) + 1) / (B + 1)',
               'time_order': 'inside a capture group the global row order of the flagged sample is the time order; '
                             'the random-split rows are put into that order with the rows stored by '
                             'tree_seeds_proba.py (no block bootstrap for a random-split condition before such a run exists)',
               'conditions': bs['info']},
           'hardware': hw, **{k: records(v) for k, v in tables.items()}}
    tmp = OUT / f'summary{sfx}.json.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(res, fh, indent=1, default=_js)
    os.replace(tmp, OUT / f'summary{sfx}.json')

    pd.set_option('display.width', 250); pd.set_option('display.max_columns', 30)
    pd.set_option('display.max_colwidth', 60)
    print('\n=== mean ± SD [min, max] (n seeds) per model and condition ===')
    print(text.to_string(index=False))
    if len(eff):
        print('\n=== seed-level effects (same model seed), macro-F1 ===')
        print(eff[eff['metric'] == 'macro_f1'][['model', 'effect', 'within', 'n', 'mean', 'sd', 'min', 'max',
                                                'sign_consistent']].round(4).to_string(index=False))
    if len(mdiff):
        print('\n=== model differences over all seed pairs, macro-F1 and balanced accuracy ===')
        cols = ['split', 'cleaning', 'a', 'b', 'metric', 'diff_of_means', 'pair_min', 'pair_max',
                'seed_ranges_overlap', 'sign_consistent']
        cols += [c for c in ('ci95_seeds+test_block', 'within_ci_seeds+test_block') if c in mdiff.columns]
        print(mdiff[mdiff['metric'].isin(['macro_f1', 'balanced_accuracy'])][cols].round(4).to_string(index=False))
    if bs is not None and len(bs['effects']):
        print(f'\n=== effects with 95% CI (block{a.block}, seeds + test rows resampled), macro-F1 ===')
        e = bs['effects']
        print(e[(e['metric'] == 'macro_f1') & (e['method'] == f'block{a.block}')][
            ['model', 'effect', 'within', 'n_seeds', 'diff', 'ci_seeds_test_lo', 'ci_seeds_test_hi',
             'within_ci_seeds_test']].round(4).to_string(index=False))
    if len(rank):
        print('\n=== model order by metric ===')
        print(rank.to_string(index=False))
    if len(tim):
        print('\n=== training and inference time ===')
        print(tim[['model', 'scope', 'fit_seconds_paper_runs_n', 'fit_seconds_paper_runs_mean',
                   'fit_seconds_tree_seeds_n', 'fit_seconds_tree_seeds_mean', 'fit_slowdown_refit_vs_paper_median',
                   'inference_seconds_n', 'inference_seconds_mean', 'inference_ms_per_1000_flows_mean',
                   'inference_device', 'n_jobs', 'cpu_load_percent_at_start_max',
                   'n_inference_with_load_record', 'cpu_percent_other_during_inference_max',
                   'gpu_utilization_percent_before_inference_max']].round(3).to_string(index=False))
        print('  fit_seconds_paper_runs = tree_protocol/main (the paper); the tree_seeds fits ran in other sessions, '
              'partly beside other jobs (slowdown = refit / paper fit of the same run): report the timings with '
              'this caveat, or repeat them on an idle machine.')
        if hw:
            print(f'  hardware: {hw.get("cpu")}, {hw.get("logical_cpus")} logical CPUs, '
                  f'{hw.get("ram_total_gb")} GB RAM, GPU {hw.get("gpu")}')
    if len(ck):
        print('\n=== refit versus stored tree_protocol run ===')
        print(ck.round(6).to_string(index=False))
        bad = ck[(ck['within_tolerance'] == False) & (ck['reproduced_up_to_ties'] != True)]  # noqa: E712
        if len(bad):
            print(f'  [WARN] {len(bad)} refit(s) outside tolerance and not explained by tied probabilities')
    print(f'\n[saved] {OUT / f"summary{sfx}.json"} and {len(tables)} CSV tables', flush=True)


if __name__ == '__main__':
    main()
