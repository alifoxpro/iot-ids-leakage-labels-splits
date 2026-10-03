# -*- coding: utf-8 -*-
r"""
deep_protocol_summary.py
========================
Tables for reviewer points expe-07, expe-08, stat-06, disc-11, disc-14, expe-09 and expe-17: pools the
deep-model runs of the paper (results_2026_03_03/deep_split: early stopping, seeds 17 and 42) with the
runs of deep_protocol_study.py (new seeds, the fixed-epoch protocol, MLP, CNN1D_Hossain) and, for
side-by-side tables, the tree ensembles. Reads result JSON files only: no model is trained and no data
sample is loaded, so it can be run at any time (also while runs are still missing).

Inputs (results_2026_03_03/)
  deep_split/*.json                          protocol 'earlystop' (the paper's runs, seeds 17 and 42)
  q1_revision/deep_protocol/<folder>/*.json  the folder name is the protocol label: 'earlystop' (pooled
                                             with deep_split), 'fixed', 'fixed_lr-val', 'fixed_lr-none', ...
                                             (mlp_tuning* and summary* are not protocol folders)
  q1_revision/deep_protocol/mlp_tuning*/mlp_config.json   MLP tuning trials (own table)
  trees (unless --no-trees): tree_protocol/main/*.json and q1_revision/tree_seeds/runs/*.json (when present),
                             protocol label 'trees' (fixed number of trees, no validation data)
Duplicates: a (protocol, model, split, cleaning, seed) found in two sources (a rerun of a paper run, a
tree refit) is pooled ONCE, from the first source in the order above (deep_split, tree_protocol/main)
unless --prefer-new; both values and their difference are listed in rerun_check.csv. Fields that only a
rerun can have (macro / attack / per-class AP, ROC AUC, inference time and latency) are then taken from
the rerun when the pooled run lacks them (unless --no-fill); runs.csv lists them in 'filled_fields' and
pooled tables count them in 'n_filled'. The metrics computed from hard predictions (F1, recall, BA,
accuracy, precision) always come from the pooled run.

Derived values (flagged in runs.csv)
  attack_macro_f1  stored by the new runs; for older runs the mean of the stored per-class F1 (4 decimals)
                   over the seven attack classes (attack_f1_derived = True)
  per-class precision  stored by the new runs; for deep_split runs P = F1 R / (2R - F1) from the stored
                   F1 and recall (defined for R > 0; as revision_analyses.py part e)
  best_epoch       stored by the new runs; for deep_split runs epochs_run - 10 when training stopped before
                   max_epochs (patience 10), unknown (empty) when it ran all epochs
  stopped_early    stored; for deep_split runs epochs_run < max_epochs (unknown when equal)

Statistics over seeds: n, mean, SD (ddof = 1; empty for n = 1), min, max and a t-interval for the mean
(mean +- t(0.975, n-1) SD / sqrt(n)). The data split is fixed; only the training seed varies. Two
subsets for the deep models: 'all' runs and runs with epochs_run >= --min-epochs (20: the filter of the
earlier manuscript version), so both can be reported (disc-14).

Outputs (q1_revision/deep_protocol/summary/)
  runs.csv              one row per run (pooled or not): metrics, epochs, times, per-class F1 / recall /
                        precision / AP (columns f1_<class>, rec_<class>, prec_<class>, ap_<class>)
  pooled.csv            per protocol x model x split x cleaning x subset x metric: n, seeds (those with a
                        value), mean, sd, min, max, ci95_low, ci95_high, n_filled (metrics: macro_f1,
                        balanced_accuracy, accuracy, attack_macro_f1, macro_ap, attack_macro_ap,
                        macro_roc_auc, epochs_run, best_epoch, fit_seconds, seconds_per_epoch,
                        inference_s_per_1k). AP exists only for runs with stored probabilities, so its n can
                        be smaller than that of macro-F1 (paper models: seeds 7 123 2024 unless the
                        deep_split seeds were rerun).
  pooled_per_class.csv  the same per class for f1, recall, precision, ap (n_derived = derived precisions)
  effects.csv           paired by seed within protocol and model: split effect (random - temporal) per
                        label condition, cleaning effect (r1 - raw) per split: n, seeds, values, mean,
                        sd, min, max, n_positive, n_negative, ci95 (stat-06: 'consistent in sign')
  protocol_diff.csv     <protocol> - earlystop for the same model, condition and seed (expe-07, disc-14); a
                        folder with an epoch-cap suffix (fixed_e50) is compared with earlystop_e50
  rerun_check.csv       duplicates: pooled value, other value, difference
  early_stop.csv        per cell: epochs_run / best_epoch per seed, number stopped early, number with the
                        selected epoch <= 3, number below --min-epochs, epoch of the lowest validation loss
  cost.csv              per family x model x protocol: fit seconds, seconds per epoch, inference seconds
                        per 1,000 flows (median of the repeats of each run), forward-only time, single-flow
                        latency, parameters, devices (expe-17)
  mlp_tuning.csv        the four MLP configurations and the chosen one
  split_check.csv       poolability guard: n_train / n_val / n_test per split x cleaning over all sources;
                        a [WARN] line is printed when runs of one condition come from different splits
  summary.json          all tables above except runs.csv / pooled_per_class.csv, plus inputs and definitions
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\deep_protocol_summary.py 2>&1 | Tee-Object -FilePath deep_protocol_summary.log
  # variant: pool the reruns instead of the deep_split originals (own output folder)
  & $py experiments\deep_protocol_summary.py --prefer-new --out results_2026_03_03\q1_revision\deep_protocol\summary_prefer_new 2>&1 | Tee-Object -FilePath deep_protocol_summary_prefer_new.log
"""
import argparse, json, math, os, re, sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import CLASSES  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
RES = HERE.parent / 'results_2026_03_03'
DEEP_DIR = RES / 'q1_revision' / 'deep_protocol'
OLD_DIR = RES / 'deep_split'
TREE_FOLDERS = ['tree_protocol/main', 'q1_revision/tree_seeds/runs']
ATTACKS = [c for c in CLASSES if c != 'Benign']
DEEP_MODELS = ['ResNet1D', 'GRU', 'Transformer', 'MLP', 'CNN1D_Hossain']
TREE_MODELS = ['XGBoost', 'LightGBM', 'RandomForest']
MODEL_ORDER = DEEP_MODELS + TREE_MODELS
PATIENCE = 10
METRICS = ['macro_f1', 'balanced_accuracy', 'accuracy', 'attack_macro_f1', 'macro_ap', 'attack_macro_ap',
           'macro_roc_auc', 'epochs_run', 'best_epoch', 'fit_seconds', 'seconds_per_epoch', 'inference_s_per_1k']
EFFECT_METRICS = ['macro_f1', 'balanced_accuracy', 'attack_macro_f1', 'macro_ap']
PER_CLASS = {'f1': 'per_class_f1', 'recall': 'per_class_recall', 'precision': 'per_class_precision',
             'ap': 'per_class_ap'}
SHORT = {'f1': 'f1', 'recall': 'rec', 'precision': 'prec', 'ap': 'ap'}
KEY = ['protocol', 'model', 'split', 'cleaning', 'seed']
# probability / timing fields a rerun can add to a pooled run that lacks them (see docstring)
FILL = (['macro_ap', 'attack_macro_ap', 'macro_roc_auc', 'macro_ap_float16', 'inference_s_per_1k',
         'inference_forward_s_per_1k', 'latency_one_flow_ms', 'inference_device']
        + [f'ap_{c}' for c in CLASSES])


# ----------------------------------------------------------------------------- helpers
def num(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None


def stats(values):
    v = np.array([x for x in (num(x) for x in values) if x is not None], float)
    n = len(v)
    if n == 0:
        return {'n': 0, 'mean': None, 'sd': None, 'min': None, 'max': None, 'ci95_low': None, 'ci95_high': None}
    m = float(v.mean())
    sd = float(v.std(ddof=1)) if n > 1 else None
    half = None
    if n > 1:
        from scipy.stats import t
        half = float(t.ppf(0.975, n - 1) * sd / math.sqrt(n))
    return {'n': n, 'mean': m, 'sd': sd, 'min': float(v.min()), 'max': float(v.max()),
            'ci95_low': None if half is None else m - half, 'ci95_high': None if half is None else m + half}


def fmt(s, sign=False, d=3):
    if s is None or not num(s['n']) or num(s['mean']) is None:
        return 'n/a'
    f = f'+.{d}f' if sign else f'.{d}f'
    sd = '' if num(s['sd']) is None else f' +- {num(s["sd"]):.{d}f}'
    return f'{num(s["mean"]):{f}}{sd} [{num(s["min"]):{f}}, {num(s["max"]):{f}}] n={int(num(s["n"]))}'


def clean_records(df):
    return df.astype(object).where(df.notna(), None).to_dict('records')


def write_json(path, obj):
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1, default=lambda o: o.item() if hasattr(o, 'item') else str(o))
    os.replace(tmp, path)


def derived_precision(f1, r):
    f1, r = num(f1), num(r)
    if f1 is None or r is None or r <= 0 or 2 * r - f1 <= 0:
        return None
    return f1 * r / (2 * r - f1)


# ----------------------------------------------------------------------------- reading runs
def row_of(js, protocol, family, source, stem):
    """One flat row per run, or None when the JSON is not a run of the four protocol conditions."""
    if not isinstance(js, dict) or 'macro_f1' not in js or 'model' not in js or 'split' not in js:
        return None
    cleaning = js.get('cleaning')
    if cleaning is None:
        tc, ec = js.get('train_cleaning'), js.get('test_cleaning')
        if tc is None or tc != ec:
            return None
        cleaning = tc
    seed = js.get('seed')
    if seed is None:
        return None
    r = {'protocol': protocol, 'family': family, 'source': source, 'run': stem, 'model': js['model'],
         'split': js['split'], 'cleaning': cleaning, 'seed': int(seed)}
    for k in ('macro_f1', 'balanced_accuracy', 'accuracy', 'macro_ap', 'attack_macro_ap', 'macro_roc_auc',
              'macro_ap_float16', 'n_train', 'n_val', 'n_test', 'n_params', 'fit_seconds', 'val_seconds',
              'max_epochs', 'epochs_run', 'best_epoch', 'val_best_epoch', 'val_macro_f1_selected'):
        r[k] = js.get(k)
    pcf = js.get('per_class_f1') or {}
    if js.get('attack_macro_f1') is not None:
        r['attack_macro_f1'], r['attack_f1_derived'] = js['attack_macro_f1'], False
    else:
        vals = [num(pcf.get(c)) for c in ATTACKS]
        r['attack_macro_f1'] = float(np.mean(vals)) if vals and all(v is not None for v in vals) else None
        r['attack_f1_derived'] = True
    # epochs / early stopping (deep models only)
    r['stopped_early'] = js.get('stopped_early')
    r['best_epoch_derived'] = False
    if family == 'deep' and r['epochs_run'] is not None and 'best_epoch' not in js:
        me = r['max_epochs'] or 30
        if r['epochs_run'] < me:
            r['best_epoch'], r['stopped_early'] = r['epochs_run'] - PATIENCE, True
        else:
            r['best_epoch'], r['stopped_early'] = None, None
        r['best_epoch_derived'] = True
    r['seconds_per_epoch'] = (r['fit_seconds'] / r['epochs_run']
                              if family == 'deep' and r['fit_seconds'] and r['epochs_run'] else None)
    inf = js.get('inference') or {}
    r['inference_s_per_1k'] = inf.get('seconds_per_1000_flows')
    r['inference_forward_s_per_1k'] = inf.get('forward_seconds_per_1000_flows')
    r['latency_one_flow_ms'] = inf.get('latency_one_flow_ms_median')
    r['inference_device'] = inf.get('device')
    hw = js.get('hardware') or {}
    r['gpu'] = hw.get('gpu') if isinstance(hw, dict) else None
    r['cpu'] = hw.get('cpu') if isinstance(hw, dict) else None
    cfg = js.get('mlp_config')
    r['config'] = cfg.get('tag') if isinstance(cfg, dict) else None
    # per class
    pcr = js.get('per_class_recall') or {}
    pcp = js.get('per_class_precision')
    pca = js.get('per_class_ap') or {}
    r['precision_derived'] = pcp is None
    for c in CLASSES:
        r[f'f1_{c}'] = num(pcf.get(c))
        r[f'rec_{c}'] = num(pcr.get(c))
        r[f'prec_{c}'] = num(pcp.get(c)) if pcp is not None else derived_precision(pcf.get(c), pcr.get(c))
        r[f'ap_{c}'] = num(pca.get(c))
    return r


def read_folder(folder, protocol, family, source):
    rows = []
    for f in sorted(folder.glob('*.json')):
        try:
            with open(f, encoding='utf-8') as fh:
                js = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print(f'  [warn] unreadable {f.name}: {e}')
            continue
        r = row_of(js, protocol, family, source, f.stem)
        if r is not None:
            rows.append(r)
    return rows


def fill_from_duplicates(d):
    """Pooled run without probabilities / timing + a rerun of the same key that has them: copy the FILL
    fields that the pooled run lacks from the first such rerun (source order) and record them."""
    fill = [c for c in FILL if c in d.columns]
    dup = d[d.duplicated(KEY, keep=False)]
    for _, g in dup.groupby(KEY, sort=False):     # g is in pooling order: pooled row first
        i = g.index[g['pooled']][0]
        done = []
        for j in g.index[~g['pooled']]:
            for c in fill:
                if c not in done and pd.isna(d.at[i, c]) and not pd.isna(d.at[j, c]):
                    d.at[i, c] = d.at[j, c]
                    done.append(c)
                    d.at[i, 'filled_from'] = d.at[j, 'source']
        if done:
            d.at[i, 'filled_fields'] = ' '.join(done)
    return d


def collect(a):
    sources = []                                   # (priority order) folder, protocol, family, label
    sources.append((Path(a.old_dir), 'earlystop', 'deep', 'deep_split'))
    deep_dir = Path(a.deep_dir)
    if deep_dir.exists():
        for d in sorted(p for p in deep_dir.iterdir() if p.is_dir()):
            if d.name.startswith(('mlp_tuning', 'summary', '_')):
                continue
            sources.append((d, d.name, 'deep', f'deep_protocol/{d.name}'))
    if not a.no_trees:
        for t in a.tree_folders:
            sources.append((RES / t, 'trees', 'tree', t))
    rows, used = [], []
    for folder, protocol, family, label in sources:
        if not folder.exists():
            continue
        rs = read_folder(folder, protocol, family, label)
        used.append({'source': label, 'protocol': protocol, 'family': family, 'runs': len(rs)})
        for i, r in enumerate(rs):
            r['source_rank'] = len(used) - 1
        rows += rs
    if not rows:
        return pd.DataFrame(), used
    d = pd.DataFrame(rows)
    d = d[d['family'].eq('tree') | d['model'].isin(DEEP_MODELS)]
    rank = d['source_rank'] * (-1 if a.prefer_new else 1)
    d = d.assign(_r=rank).sort_values(KEY + ['_r'])
    d['pooled'] = ~d.duplicated(KEY, keep='first')
    d['filled_fields'], d['filled_from'] = None, None
    if not a.no_fill:
        d = fill_from_duplicates(d)
    d['_m'] = d['model'].map({m: i for i, m in enumerate(MODEL_ORDER)}).fillna(99)
    d = d.sort_values(['family', 'protocol', '_m', 'split', 'cleaning', 'seed']).drop(columns=['_r', '_m'])
    return d.reset_index(drop=True), used


# ----------------------------------------------------------------------------- tables
def subsets(g, family, min_epochs):
    yield 'all', g
    if family == 'deep':
        yield f'epochs_run>={min_epochs}', g[g['epochs_run'].fillna(0) >= min_epochs]


CELL = ['family', 'protocol', 'model', 'split', 'cleaning']


def seeds_of(h, col):
    """Seeds of the runs that have a value for `col` (so 'seeds' always matches n)."""
    return ' '.join(str(s) for s in sorted(h.loc[h[col].notna(), 'seed']))


def n_filled(h, col):
    f = h['filled_fields'].dropna()
    return int(sum(col in v.split() for v in f))


def pooled_tables(P, min_epochs):
    out, pc = [], []
    for key, g in P.groupby(CELL, sort=False):
        fam = key[0]
        for sub, h in subsets(g, fam, min_epochs):
            for m in METRICS:
                if m not in h or h[m].isna().all():
                    continue
                out.append({**dict(zip(CELL, key)), 'subset': sub, 'metric': m, 'seeds': seeds_of(h, m),
                            **stats(h[m].tolist()), 'n_filled': n_filled(h, m)})
            for meas, pre in SHORT.items():
                for c in CLASSES:
                    col = f'{pre}_{c}'
                    if col not in h or h[col].isna().all():
                        continue
                    s = stats(h[col].tolist())
                    n_der = int(h.loc[h[col].notna(), 'precision_derived'].sum()) if meas == 'precision' else 0
                    pc.append({**dict(zip(CELL, key)), 'subset': sub, 'measure': meas, 'class': c,
                               'seeds': seeds_of(h, col), **s, 'n_derived': n_der, 'n_filled': n_filled(h, col)})
    return pd.DataFrame(out), pd.DataFrame(pc)


def effects_table(P):
    out = []
    for (fam, prot, model), g in P.groupby(['family', 'protocol', 'model'], sort=False):
        for m in EFFECT_METRICS:
            if m not in g or g[m].isna().all():
                continue
            piv = g.pivot_table(index='seed', columns=['split', 'cleaning'], values=m, aggfunc='first')
            pairs = [('split: random - temporal', f'labels {c}', ('random', c), ('temporal', c)) for c in ('raw', 'r1')]
            pairs += [('cleaning: r1 - raw', f'{s} split', (s, 'r1'), (s, 'raw')) for s in ('random', 'temporal')]
            for eff, within, A, B in pairs:
                if A not in piv.columns or B not in piv.columns:
                    continue
                dd = (piv[A] - piv[B]).dropna()
                if dd.empty:
                    continue
                s = stats(dd.tolist())
                out.append({'family': fam, 'protocol': prot, 'model': model, 'effect': eff, 'within': within,
                            'metric': m, 'seeds': ' '.join(str(x) for x in dd.index),
                            'values': ' '.join(f'{v:+.4f}' for v in dd.values), **s,
                            'n_positive': int((dd > 0).sum()), 'n_negative': int((dd < 0).sum()),
                            'same_sign_all_seeds': bool((dd > 0).all() or (dd < 0).all())})
    return pd.DataFrame(out)


def protocol_diff_table(P):
    out = []
    deep = P[P['family'] == 'deep']
    for prot in sorted(p for p in set(deep['protocol']) if not p.startswith('earlystop')):
        cap = re.search(r'_e\d+$', prot)
        ref = 'earlystop' + (cap.group(0) if cap else '')          # same epoch cap
        base = deep[deep['protocol'] == ref].set_index(['model', 'split', 'cleaning', 'seed'])
        other = deep[deep['protocol'] == prot].set_index(['model', 'split', 'cleaning', 'seed'])
        common = other.index.intersection(base.index)
        if common.empty:
            continue
        for (model, split, cleaning), idx in pd.Series(list(common), index=common).groupby(level=[0, 1, 2]):
            keys = list(idx.index)
            for m in ['macro_f1', 'balanced_accuracy', 'attack_macro_f1', 'macro_ap', 'epochs_run']:
                dd = pd.Series([num(other.at[k, m]) - num(base.at[k, m])
                                if num(other.at[k, m]) is not None and num(base.at[k, m]) is not None else np.nan
                                for k in keys], index=[k[3] for k in keys]).dropna()
                if dd.empty:
                    continue
                out.append({'comparison': f'{prot} - {ref}', 'model': model, 'split': split,
                            'cleaning': cleaning, 'metric': m, 'seeds': ' '.join(str(x) for x in dd.index),
                            'values': ' '.join(f'{v:+.4f}' for v in dd.values), **stats(dd.tolist()),
                            'n_positive': int((dd > 0).sum()), 'n_negative': int((dd < 0).sum())})
    return pd.DataFrame(out)


def rerun_table(d):
    out = []
    dup = d[d.duplicated(KEY, keep=False)]
    for key, g in dup.groupby(KEY, sort=False):
        a = g[g['pooled']].iloc[0]
        for _, b in g[~g['pooled']].iterrows():
            rec = dict(zip(KEY, key))
            rec.update({'pooled_source': a['source'], 'other_source': b['source']})
            for m in ('macro_f1', 'balanced_accuracy', 'accuracy'):
                va, vb = num(a[m]), num(b[m])
                rec[f'{m}_pooled'], rec[f'{m}_other'] = va, vb
                rec[f'{m}_diff_other_minus_pooled'] = None if va is None or vb is None else vb - va
            out.append(rec)
    return pd.DataFrame(out)


def early_stop_table(P, min_epochs):
    out = []
    for key, g in P[P['family'] == 'deep'].groupby(['protocol', 'model', 'split', 'cleaning'], sort=False):
        g = g.sort_values('seed')
        be = g['best_epoch']
        out.append({**dict(zip(['protocol', 'model', 'split', 'cleaning'], key)), 'n': len(g),
                    'per_seed_epochs_run/best_epoch': ' '.join(
                        f's{s}:{int(e) if pd.notna(e) else "?"}/{int(b) if pd.notna(b) else "?"}'
                        for s, e, b in zip(g['seed'], g['epochs_run'], be)),
                    'n_stopped_early': int(g['stopped_early'].eq(True).sum()),
                    'n_stopped_unknown': int(g['stopped_early'].isna().sum()),
                    'n_selected_epoch_le_3': int((be <= 3).sum()),
                    f'n_epochs_run_lt_{min_epochs}': int((g['epochs_run'] < min_epochs).sum()),
                    'val_best_epoch_per_seed': ' '.join(
                        f's{s}:{int(v)}' for s, v in zip(g['seed'], g['val_best_epoch']) if pd.notna(v)) or None,
                    'best_epoch_derived_runs': int(g['best_epoch_derived'].sum())})
    return pd.DataFrame(out)


def cost_table(P):
    out = []
    for (fam, model, prot), g in P.groupby(['family', 'model', 'protocol'], sort=False):
        rec = {'family': fam, 'model': model, 'protocol': prot, 'runs': len(g)}
        for m, lab in (('fit_seconds', 'fit_s'), ('seconds_per_epoch', 'sec_per_epoch'), ('epochs_run', 'epochs'),
                       ('inference_s_per_1k', 'infer_s_per_1k'), ('inference_forward_s_per_1k', 'forward_s_per_1k'),
                       ('latency_one_flow_ms', 'latency_ms')):
            s = stats(g[m].tolist()) if m in g else stats([])
            rec.update({f'{lab}_n': s['n'], f'{lab}_mean': s['mean'], f'{lab}_min': s['min'], f'{lab}_max': s['max']})
        rec['n_params'] = ' '.join(sorted({str(int(v)) for v in g['n_params'].dropna()})) or None
        rec['inference_device'] = '; '.join(sorted({str(v) for v in g['inference_device'].dropna()})) or None
        rec['gpu'] = '; '.join(sorted({str(v) for v in g['gpu'].dropna()})) or None
        rec['cpu'] = '; '.join(sorted({str(v) for v in g['cpu'].dropna()})) or None
        out.append(rec)
    return pd.DataFrame(out)


def split_check_table(d):
    """Poolability guard: every run of one split x cleaning condition (all sources and models) must have been
    evaluated on the same split, i.e. the same n_train and n_test (and n_val for the deep models)."""
    out = []
    for (split, cleaning), g in d.groupby(['split', 'cleaning'], sort=True):
        rec = {'split': split, 'cleaning': cleaning, 'runs': len(g)}
        ok = True
        for c in ('n_train', 'n_val', 'n_test'):
            vals = sorted({int(v) for v in g[c].dropna()}) if c in g else []
            rec[c] = ' '.join(str(v) for v in vals)
            if len(vals) > 1:
                ok = False
                rec[f'{c}_by_source'] = '; '.join(
                    f'{src}: {" ".join(str(int(v)) for v in sorted(set(h[c].dropna())))}'
                    for src, h in g.groupby('source', sort=False))
        rec['consistent'] = ok
        out.append(rec)
    return pd.DataFrame(out)


def mlp_tuning_table(deep_dir):
    out = []
    for f in sorted(Path(deep_dir).glob('mlp_tuning*/mlp_config.json')):
        with open(f, encoding='utf-8') as fh:
            js = json.load(fh)
        for t in js.get('trials', []):
            out.append({'folder': f.parent.name, **{k: v for k, v in t.items() if k != 'hidden'},
                        'hidden': '-'.join(str(h) for h in t.get('hidden', [])),
                        'chosen': t.get('tag') == js['chosen']['tag'], 'criterion': js.get('criterion')})
    return pd.DataFrame(out)


# ----------------------------------------------------------------------------- printing
def print_tables(P, pooled, eff, pdiff, cost):
    pd.set_option('display.width', 220); pd.set_option('display.max_columns', 30)
    for (fam, prot), g in P.groupby(['family', 'protocol'], sort=False):
        print(f'\n=== {fam} | protocol={prot}: mean +- SD [min, max] n over seeds (all runs) ===')
        pl = pooled[(pooled['family'] == fam) & (pooled['protocol'] == prot) & (pooled['subset'] == 'all')]
        for (model, split, cleaning), h in pl.groupby(['model', 'split', 'cleaning'], sort=False):
            s = {m: h[h['metric'] == m].iloc[0].to_dict() if (h['metric'] == m).any() else None
                 for m in ('macro_f1', 'balanced_accuracy', 'attack_macro_f1', 'macro_ap')}
            ap = f'  AP {s["macro_ap"]["mean"]:.3f} (n={s["macro_ap"]["n"]})' if s['macro_ap'] else ''
            att = f'{s["attack_macro_f1"]["mean"]:.3f}' if s['attack_macro_f1'] else 'n/a'
            print(f'  {model:14s} {split:8s} {cleaning:3s}  macro-F1 {fmt(s["macro_f1"])}   '
                  f'BA {fmt(s["balanced_accuracy"])}   attack-F1 {att}{ap}  '
                  f'seeds {s["macro_f1"]["seeds"] if s["macro_f1"] else ""}')
    if not eff.empty:
        print('\n=== paired effects over seeds (macro-F1): mean +- SD [min, max] n, sign ===')
        e = eff[eff['metric'] == 'macro_f1']
        for _, r in e.iterrows():
            print(f'  {r["family"]:4s} {r["protocol"]:12s} {r["model"]:14s} {r["effect"]:26s} {r["within"]:15s} '
                  f'{fmt(r, sign=True)}  (+{r["n_positive"]} / -{r["n_negative"]})')
    if not pdiff.empty:
        print('\n=== protocol difference (same seed), macro-F1 ===')
        for _, r in pdiff[pdiff['metric'] == 'macro_f1'].iterrows():
            print(f'  {r["comparison"]:28s} {r["model"]:14s} {r["split"]:8s} {r["cleaning"]:3s} {r["values"]}')
    if not cost.empty:
        print('\n=== cost: fit seconds, seconds / epoch, inference seconds per 1,000 flows ===')
        for _, r in cost.iterrows():
            inf = '' if r['infer_s_per_1k_n'] == 0 else (f'  infer {1000 * r["infer_s_per_1k_mean"]:.2f} ms/1k '
                                                           f'(n={r["infer_s_per_1k_n"]})')
            spe = '' if r['sec_per_epoch_n'] == 0 else f'  {r["sec_per_epoch_mean"]:.0f} s/epoch'
            print(f'  {r["family"]:4s} {r["model"]:14s} {r["protocol"]:12s} runs={r["runs"]:<3d} fit '
                  f'{r["fit_s_mean"]:.0f} s [{r["fit_s_min"]:.0f}, {r["fit_s_max"]:.0f}]{spe}{inf}')


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--deep-dir', default=str(DEEP_DIR))
    ap.add_argument('--old-dir', default=str(OLD_DIR))
    ap.add_argument('--tree-folders', nargs='+', default=TREE_FOLDERS, help='folders under results_2026_03_03')
    ap.add_argument('--no-trees', action='store_true')
    ap.add_argument('--prefer-new', action='store_true', help='pool the newer run of a duplicate')
    ap.add_argument('--no-fill', action='store_true',
                    help='do not take AP / ROC AUC / inference time of a pooled run from its rerun')
    ap.add_argument('--min-epochs', type=int, default=20)
    ap.add_argument('--out', default=None, help='output folder (default <deep-dir>/summary)')
    a = ap.parse_args()
    out = Path(a.out) if a.out else Path(a.deep_dir) / 'summary'

    d, used = collect(a)
    for u in used:
        print(f'[input] {u["source"]:34s} protocol={u["protocol"]:12s} {u["runs"]:>3d} runs')
    if d.empty:
        print('no runs found'); return
    out.mkdir(parents=True, exist_ok=True)
    P = d[d['pooled']]
    print(f'[runs] {len(d)} read, {len(P)} pooled, {len(d) - len(P)} duplicates (rerun_check.csv)')

    pooled, pcl = pooled_tables(P, a.min_epochs)
    eff = effects_table(P)
    pdiff = protocol_diff_table(P)
    rer = rerun_table(d)
    es = early_stop_table(P, a.min_epochs)
    cost = cost_table(P)
    mt = mlp_tuning_table(a.deep_dir)
    sc = split_check_table(d)
    for _, r in sc[~sc['consistent']].iterrows():
        print(f'[WARN] {r["split"]}/{r["cleaning"]}: runs with different split sizes are pooled '
              f'(n_train {r["n_train"]}; n_test {r["n_test"]}) - see split_check.csv', flush=True)

    d.to_csv(out / 'runs.csv', index=False)
    tables = {'pooled': pooled, 'pooled_per_class': pcl, 'effects': eff, 'protocol_diff': pdiff,
              'rerun_check': rer, 'early_stop': es, 'cost': cost, 'mlp_tuning': mt, 'split_check': sc}
    for name, t in tables.items():
        t.to_csv(out / f'{name}.csv', index=False)
    write_json(out / 'summary.json', {
        'inputs': used, 'n_runs_read': int(len(d)), 'n_runs_pooled': int(len(P)),
        'definitions': {
            'statistics': 'over training seeds (split fixed): mean, SD ddof=1, min, max, t-interval of the mean',
            'subsets': f"'all' and 'epochs_run>={a.min_epochs}' (deep models)",
            'effects': 'paired by seed: random - temporal (per label condition), r1 - raw (per split)',
            'protocol_diff': '<protocol> - earlystop, same model / condition / seed',
            'duplicates': 'pooled once; ' + ('newest source' if a.prefer_new else 'first source (deep_split, '
                                             'tree_protocol/main)') + ' used',
            'derived': 'attack_macro_f1 from rounded per-class F1 when not stored; deep_split precision '
                       'P = F1 R / (2R - F1); deep_split best_epoch = epochs_run - 10 when stopped early',
            'filled': 'none' if a.no_fill else ('AP, ROC AUC and inference fields missing in a pooled run are '
                                                'taken from its rerun (runs.csv filled_fields; n_filled)'),
            'trees': "protocol 'trees': fixed number of trees, no validation data (tree_protocol, tree_seeds)"},
        **{k: clean_records(v) for k, v in tables.items() if k != 'pooled_per_class'}})
    print_tables(P, pooled, eff, pdiff, cost)
    if not mt.empty:
        print('\n=== MLP tuning ===')
        print(mt.drop(columns=['criterion']).to_string(index=False))
    print(f'\n[saved] {out}  (runs.csv, {", ".join(f"{k}.csv" for k in tables)}, summary.json)')


if __name__ == '__main__':
    main()
