# -*- coding: utf-8 -*-
r"""
variant_seeds.py
================
Reviewer points meth-09 and nove-05: Table 4 (rule_sensitivity.py: cleaning of the training AND the
test data, the split re-made on the cleaned flows) rests on ONE random split (seed 42) and ONE
temporal cut (70/15/15). A variant's difference to 'none' therefore mixes the cleaning effect with
split-to-split noise and carries no interval. Here every cell of Table 4 is repeated over the
partitions of split_replication.py.

Design (everything as in rule_sensitivity.py except the partition)
  data        flagged_loader sample (3,626,502 flows), the 81 model features with NaN KEPT. Each fit
              replaces NaN by the median of its own training rows, exactly as
              pilot_temporal_split.fit_eval (which rule_sensitivity.py uses); the other q1_revision
              scripts replace NaN by 0 instead. The medians are computed column by column (same
              numpy routine, identical values) to avoid full-size temporaries.
  variants    rule_sensitivity.variants: none, R1, R2, R3, R1+R3, all, all floods-R2
              (paper labels none, R1, R2, R3, R1+R3, All, All*). The flagged attack flows are
              removed from ALL rows first; the partition is then drawn on the kept rows.
  partitions  random    stratified 70/15/15, split seeds 42, 1, 2, 3, 4 (split_replication.random_split)
              temporal  inside each of the 16 capture groups, time-ordered cut 60/20/20, 70/15/15,
                        80/10/10 (split_replication.temporal_split)
              seed 42 and 70/15/15 are exactly the partitions of rule_sensitivity.py. The
              validation part is never used (no tuning, no early stopping).
  model       XGBoost of extra_baselines.make (the hyper-parameters of fit_eval), balanced sample
              weights computed on the training rows, model seed 42. Optional: --models RandomForest
              (random forest of extra_baselines.make, same imputation; one fit per process).
  7 variants x 8 partitions = 56 XGBoost fits (about 35 s each on the GPU plus a few s imputation).
  The reference partitions (seed 42, 70/15/15) are run first.

Check against Table 4: every XGBoost run on seed 42 / 70-15-15 is compared with
results_2026_03_03/split_pilot/rule_sensitivity.json as soon as it finishes: n_train and n_test
must be equal, and macro-F1, balanced accuracy, accuracy and every per-class F1 must agree within
--tol (default 0.001). The result is stored in the run JSON ('reference_check'), printed, and
collected in reference_check.csv. --check-splits checks the counts (n_train, n_test, class counts,
dropped fraction) of all 14 reference cells WITHOUT training (reads only y, sub, ts and the flags).

Summary (--summary; also written after the last run)
  diff(v, p) = metric(variant v, partition p) - metric(none, same partition p), for every split seed
  and every temporal cut (the partition is drawn on each variant's own kept rows, as in Table 4).
  Per model, variant v != none, split type and metric (macro_f1, balanced_accuracy,
  attack_macro_f1, accuracy): every diff, mean, SD (ddof 1), min, max, number of positive and
  negative diffs, and the t-based 95% CI mean +/- t(0.975, n - 1) SD / sqrt(n) over the five random
  seeds (the same CI is given for the three cuts, n = 3, for completeness). Also mean and SD of the
  metric itself per variant, and the reference check.

Output: results_2026_03_03/q1_revision/variant_seeds/
          <model>_<variant>_<split>_<rep>.json + .npz (y, p int8, sub, rows = global row positions)
            <variant> in file names: none, R1, R2, R3, R1R3, All, AllStar
            <rep>: s42, s1, s2, s3, s4 (random) | 60-20-20, 70-15-15, 80-10-10 (temporal)
          check_splits.json (--check-splits)
          runs.csv, diffs.csv, diff_summary.csv, value_summary.csv, reference_check.csv, summary.json
Resumable: a run whose JSON exists is skipped (the npz is written first, the JSON last, atomically).
Memory: X with NaN ~1.2 GB, a fit adds the imputed training and test copies (~1 GB) and the model's
buffers. The last fit of a process frees X after the imputation, so with --max-fits 1 the fit itself
holds only the two imputed copies (peak ~2.2 GB during the imputation).

Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\variant_seeds.py --check-splits 2>&1 | Tee-Object -FilePath variant_seeds_check.log
  1..56 | ForEach-Object { & $py experiments\variant_seeds.py --max-fits 1 2>&1 | Tee-Object -FilePath variant_seeds.log -Append }
  & $py experiments\variant_seeds.py --summary 2>&1 | Tee-Object -FilePath variant_seeds_summary.log
  (one fit per process; the first 14 processes fit the seed-42 random and the 70/15/15 temporal cells
  and each prints its check against Table 4 - stop the loop if one says NOT REPRODUCED. If a process
  stopped early, run the loop line again: finished runs are skipped, extra repetitions only print the
  summary. With enough free RAM (> ~6 GB) several XGBoost fits per process save the ~30 s loading:
  1..7 | ForEach-Object { & $py experiments\variant_seeds.py --max-fits 8 2>&1 | Tee-Object -FilePath variant_seeds.log -Append })
Optional random forest (56 fits of a few minutes, one per process):
  1..56 | ForEach-Object { & $py experiments\variant_seeds.py --models RandomForest --max-fits 1 2>&1 | Tee-Object -FilePath variant_seeds_rf.log -Append }
  & $py experiments\variant_seeds.py --summary 2>&1 | Tee-Object -FilePath variant_seeds_summary.log
Self-test of the helpers on synthetic data (no data file is read):
  & $py experiments\variant_seeds.py --selftest
"""
import argparse, gc, json, os, sys, time, warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import t as t_dist
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from extra_baselines import make  # noqa: E402
from flagged_loader import CACHE, FLAGS, get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, FEATS, SEED  # noqa: E402
from rule_sensitivity import variants as rule_variants  # noqa: E402
from split_replication import CUTS, RANDOM_SEEDS, partition, score  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
ROOT = HERE.parent
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'variant_seeds'
REF = ROOT / 'results_2026_03_03' / 'split_pilot' / 'rule_sensitivity.json'
MODELS = ['XGBoost', 'RandomForest']
# rule_sensitivity.py key -> (file-name slug, paper label); order = rule_sensitivity.variants
VARIANTS = {'none': ('none', 'none'), 'R1': ('R1', 'R1'), 'R2': ('R2', 'R2'), 'R3': ('R3', 'R3'),
            'R1+R3': ('R1R3', 'R1+R3'), 'all': ('All', 'All'), 'all, floods-R2': ('AllStar', 'All*')}
LABEL_ORDER = [v[1] for v in VARIANTS.values()]
REF_PART = {'random': 's42', 'temporal': '70-15-15'}
REF_KEY = {'random': 'A_random', 'temporal': 'D_temporal_subattack'}
# reference partitions first, so that the check against Table 4 comes early
PARTS = ([('random', 's42'), ('temporal', '70-15-15')]
         + [('random', f's{s}') for s in RANDOM_SEEDS if s != 42]
         + [('temporal', c) for c in CUTS if c != '70-15-15'])
REP_ORDER = [f's{s}' for s in RANDOM_SEEDS] + list(CUTS)
METRICS = ['macro_f1', 'balanced_accuracy', 'attack_macro_f1', 'accuracy']


# ---------------------------------------------------------------- data
def load(with_X=True):
    """X (81 features, NaN kept, float32), meta (y, sub, ts) and the rule flags of the cached
    flagged sample. Like flagged_loader.load_prepared (one parquet column at a time into a
    preallocated matrix), but WITHOUT the NaN -> 0 replacement, so that fit_eval's median
    imputation can be reproduced."""
    import pyarrow.parquet as pq
    if not CACHE.exists():                    # first run anywhere: build the cache (slow)
        get_flagged(columns=['y'])
    pf = pq.ParquetFile(CACHE)
    meta = pf.read(columns=['y', 'sub', 'ts']).to_pandas()
    meta['sub'] = meta['sub'].astype('category')
    flags = {c: pf.read(columns=[c]).column(0).to_numpy() for c in FLAGS}
    if not with_X:
        return None, meta, flags
    print(f'[loader] {CACHE.name}: {pf.metadata.num_rows:,} rows, 81 features column by column (NaN kept)',
          flush=True)
    X = np.empty((pf.metadata.num_rows, len(FEATS)), np.float32)
    for j, c in enumerate(FEATS):             # parquet nulls come back as NaN (as with pd.read_parquet)
        X[:, j] = pf.read(columns=[c], use_threads=False).column(0).to_numpy().astype(np.float32, copy=False)
    return X, meta, flags


def variant_masks(flags, y):
    """Row masks of rule_sensitivity.variants (True = flagged = removed before the split)."""
    df = pd.DataFrame({**{c: np.asarray(flags[c], bool) for c in FLAGS}, 'y': y})
    m = rule_variants(df)
    assert list(m) == list(VARIANTS), f'variant names changed in rule_sensitivity.py: {list(m)}'
    return {k: np.asarray(v, bool) for k, v in m.items()}


def impute_median(X, tr, te):
    """pilot_temporal_split.fit_eval's imputation: NaN -> median of the TRAINING rows per feature,
    applied to the training and the test copy. np.nanmedian(Xtr, axis=0) runs the same 1-D routine
    on every column, so computing it column by column gives identical values without the full-size
    isnan / np.where temporaries. An all-NaN training column stays NaN, as in fit_eval."""
    Xtr, Xte = X[tr], X[te]
    med = np.full(X.shape[1], np.nan, np.float32)
    n_filled = 0
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', RuntimeWarning)          # 'All-NaN slice encountered'
        for j in range(X.shape[1]):
            a, b = Xtr[:, j], Xte[:, j]                          # views into the copies
            med[j] = np.nanmedian(a)
            ma, mb = np.isnan(a), np.isnan(b)
            if ma.any():
                a[ma] = med[j]
            if mb.any():
                b[mb] = med[j]
            n_filled += int(ma.sum() + mb.sum())
    return Xtr, Xte, med, n_filled


def counts(v):
    return dict(zip(CLASSES, np.bincount(v, minlength=len(CLASSES)).tolist()))


# ---------------------------------------------------------------- runs
def plan(models):
    return [dict(model=m, variant=v, slug=VARIANTS[v][0], label=VARIANTS[v][1], split=s, rep=r,
                 name=f'{m}_{VARIANTS[v][0]}_{s}_{r}')
            for m in models for s, r in PARTS for v in VARIANTS]


def write_json(path, obj):
    tmp = path.with_name(path.name + '.tmp')                     # atomic: JSON = run complete
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def ref_check(r, variant, split, ref, tol):
    """Compare a seed-42 / 70-15-15 run with the same cell of rule_sensitivity.json."""
    R = ref[variant][REF_KEY[split]]
    d = {k: abs(r[k] - R[k]) for k in ('macro_f1', 'balanced_accuracy', 'accuracy')}
    d['per_class_f1_max'] = max(abs(r['per_class_f1'][c] - R['per_class_f1'][c]) for c in CLASSES)
    counts_ok = r['n_train'] == R['n_train'] and r['n_test'] == R['n_test']
    out = {'reference': f'rule_sensitivity.json [{variant!r}][{REF_KEY[split]!r}]',
           'n_train': [r['n_train'], R['n_train']], 'n_test': [r['n_test'], R['n_test']],
           'counts_equal': bool(counts_ok),
           'ref_macro_f1': R['macro_f1'], 'ref_balanced_accuracy': R['balanced_accuracy'],
           'abs_diff': {k: round(float(v), 6) for k, v in d.items()},
           'max_abs_diff': round(float(max(d.values())), 6), 'tol': tol}
    out['reproduced'] = bool(counts_ok and out['max_abs_diff'] <= tol)
    return out


def run(a):
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = plan(a.models)
    todo = [j for j in jobs if not (OUT / f'{j["name"]}.json').exists()]
    print(f'[plan] {len(jobs)} runs ({", ".join(a.models)}), {len(jobs) - len(todo)} finished, '
          f'{len(todo)} to do', flush=True)
    if not todo:
        summary(a)
        return
    ref = json.load(open(REF, encoding='utf-8')) if REF.exists() else None
    if ref is None:
        print(f'[warn] {REF} not found: no reference check', flush=True)
    X, meta, flags = load()
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    masks = variant_masks(flags, y)
    del flags; gc.collect()

    n_here = min(len(todo), a.max_fits) if a.max_fits else len(todo)   # fits of this process
    done = 0
    for j in todo:
        if a.max_fits and done >= a.max_fits:
            break
        drop = masks[j['variant']]
        keep = np.where(~drop)[0]
        part = meta.iloc[keep].reset_index(drop=True)                # 3 small columns only
        tr, va, te = partition(part, j['split'], j['rep'])           # positions within `keep`
        tr, te, n_val = keep[tr], keep[te], len(va)                  # -> global positions
        del part, va
        t0 = time.time()
        Xtr, Xte, med, n_filled = impute_median(X, tr, te)           # copies: X itself is unchanged
        imp_s = time.time() - t0
        if done == n_here - 1:        # last fit of this process: X (~1.2 GB) is not needed any more,
            del X                     # so it is freed before the fit (the random forest needs several GB)
            gc.collect()
        ytr = y[tr]
        present = np.unique(ytr)      # labels 0..K-1 for XGBoost if a class lost all training rows
        missing = [CLASSES[c] for c in range(len(CLASSES)) if c not in present]
        if missing:
            print(f'  [warn] {j["name"]}: no training rows for {missing}', flush=True)
        clf = make(j['model'])
        t = time.time()
        clf.fit(Xtr, np.searchsorted(present, ytr), sample_weight=compute_sample_weight('balanced', ytr))
        fit_s = time.time() - t
        del Xtr; gc.collect()
        p = present[np.asarray(clf.predict(Xte)).astype(int).ravel()].astype(np.int8)
        del Xte, clf; gc.collect()

        r = score(y[te], p, sub[te])
        r.update({'model': j['model'], 'model_seed': SEED, 'variant': j['variant'], 'label': j['label'],
                  'cleaning': 'joint (training and test rows), partition drawn on the kept rows',
                  'split': j['split'], 'replicate': j['rep'],
                  'split_seed': int(j['rep'][1:]) if j['split'] == 'random' else None,
                  'cut_train_val_test': None if j['split'] == 'random' else
                  [round(x, 2) for x in (CUTS[j['rep']][0], CUTS[j['rep']][1] - CUTS[j['rep']][0],
                                         1 - CUTS[j['rep']][1])],
                  'imputation': 'NaN -> median of the training rows (pilot_temporal_split.fit_eval)',
                  'n_values_imputed': n_filled, 'n_all_nan_train_features': int(np.isnan(med).sum()),
                  'weights': "compute_sample_weight('balanced', y_train)",
                  'dropped_fraction': round(float(drop.mean()), 4), 'class_counts': counts(y[keep]),
                  'train_class_counts': counts(ytr), 'test_class_counts': counts(y[te]),
                  'missing_train_classes': missing,
                  'n_train': int(len(tr)), 'n_val': int(n_val), 'n_test': int(len(te)),
                  'fit_seconds': round(fit_s, 1), 'impute_seconds': round(imp_s, 1)})
        is_ref = ref is not None and j['model'] == 'XGBoost' and j['rep'] == REF_PART[j['split']]
        if is_ref:
            r['reference_check'] = ref_check(r, j['variant'], j['split'], ref, a.tol)
        np.savez_compressed(OUT / f'{j["name"]}.npz', y=y[te].astype(np.int8), p=p,
                            sub=sub[te].astype(str), rows=te.astype(np.int32))   # str: loads without pickle
        write_json(OUT / f'{j["name"]}.json', r)
        done += 1
        print(f'[{done}/{len(todo)}] {j["model"]:12s} {j["label"]:5s} {j["split"]:8s} {j["rep"]:8s} '
              f'n_train={len(tr):>9,} macro-F1={r["macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} '
              f'attack-F1={r["attack_macro_f1"]:.4f} (fit {fit_s:.0f} s, impute {imp_s:.0f} s)', flush=True)
        if is_ref:
            c = r['reference_check']
            print(f'      check vs Table 4: {"REPRODUCED" if c["reproduced"] else "NOT REPRODUCED"} '
                  f'(counts equal={c["counts_equal"]}, max |diff|={c["max_abs_diff"]:.6f}, '
                  f'Table 4 macro-F1={c["ref_macro_f1"]:.4f})', flush=True)
        del p, ytr, tr, te, keep; gc.collect()

    left = len(todo) - done
    if left:
        print(f'[left] {left} runs still to do', flush=True)
    else:
        print('[DONE] all runs finished', flush=True)
        summary(a)


# ---------------------------------------------------------------- split check (no training)
def check_splits(a):
    """n_train, n_test, class counts and dropped fraction of the 14 reference cells vs Table 4."""
    ref = json.load(open(REF, encoding='utf-8'))
    _, meta, flags = load(with_X=False)
    y = meta['y'].to_numpy()
    masks = variant_masks(flags, y)
    out, ok_all = [], True
    for v, (slug, label) in VARIANTS.items():
        keep = np.where(~masks[v])[0]
        part = meta.iloc[keep].reset_index(drop=True)
        row = {'variant': v, 'label': label,
               'class_counts_equal': counts(y[keep]) == ref[v]['class_counts'],
               'dropped_fraction': [round(float(masks[v].mean()), 4), ref[v]['dropped_fraction']]}
        row['dropped_fraction_equal'] = row['dropped_fraction'][0] == row['dropped_fraction'][1]
        for s in ('random', 'temporal'):
            tr, _, te = partition(part, s, REF_PART[s])
            R = ref[v][REF_KEY[s]]
            row[s] = {'n_train': [int(len(tr)), R['n_train']], 'n_test': [int(len(te)), R['n_test']],
                      'equal': len(tr) == R['n_train'] and len(te) == R['n_test']}
        row['ok'] = bool(row['class_counts_equal'] and row['dropped_fraction_equal']
                         and row['random']['equal'] and row['temporal']['equal'])
        ok_all &= row['ok']
        out.append(row)
        print(f'[check] {label:5s} class counts {"=" if row["class_counts_equal"] else "!="}  '
              f'random n_train/n_test {row["random"]["n_train"][0]:,}/{row["random"]["n_test"][0]:,} '
              f'{"=" if row["random"]["equal"] else "!="}  temporal {row["temporal"]["n_train"][0]:,}/'
              f'{row["temporal"]["n_test"][0]:,} {"=" if row["temporal"]["equal"] else "!="}  -> '
              f'{"OK" if row["ok"] else "MISMATCH"}', flush=True)
        del part, keep
    OUT.mkdir(parents=True, exist_ok=True)
    write_json(OUT / 'check_splits.json', {'all_ok': bool(ok_all), 'reference': str(REF), 'cells': out})
    print(f'[check] {"all 14 reference partitions match Table 4" if ok_all else "MISMATCH - see check_splits.json"}',
          flush=True)


# ---------------------------------------------------------------- summary
def dstats(v, conf=0.95):
    """mean, SD (ddof 1), min, max, t-based CI of the mean, sign counts."""
    v = np.asarray(v, float)
    n = len(v)
    if n == 0:
        return {'n': 0}
    m = float(v.mean())
    sd = float(v.std(ddof=1)) if n > 1 else np.nan
    h = float(t_dist.ppf(0.5 + conf / 2, n - 1) * sd / np.sqrt(n)) if n > 1 else np.nan
    return {'n': n, 'mean': m, 'sd': sd, 'min': float(v.min()), 'max': float(v.max()),
            'ci_lo': m - h, 'ci_hi': m + h, 'n_pos': int((v > 0).sum()), 'n_neg': int((v < 0).sum())}


def summary(a):
    runs = []
    for f in sorted(OUT.glob('*.json')):
        if f.stem.split('_')[0] in MODELS:
            with open(f, encoding='utf-8') as fh:
                runs.append(json.load(fh))
    print(f'\n##### variant_seeds: {len(runs)} finished runs')
    if not runs:
        return
    pd.set_option('display.width', 220)
    d = pd.DataFrame([{'model': r['model'], 'variant': r['variant'], 'label': r['label'], 'split': r['split'],
                       'replicate': r['replicate'], 'n_train': r['n_train'], 'n_test': r['n_test'],
                       'dropped_fraction': r['dropped_fraction'], **{m: r[m] for m in METRICS}} for r in runs])
    d['_v'] = d['label'].map(LABEL_ORDER.index)
    d['_r'] = d['replicate'].map(REP_ORDER.index)
    d = d.sort_values(['model', 'split', '_v', '_r']).drop(columns=['_v', '_r']).reset_index(drop=True)
    d.to_csv(OUT / 'runs.csv', index=False)

    # differences to 'none' on the same partition (seed / cut)
    base = d[d['variant'] == 'none'].set_index(['model', 'split', 'replicate'])
    diffs = []
    for _, r in d[d['variant'] != 'none'].iterrows():
        k = (r['model'], r['split'], r['replicate'])
        if k not in base.index:
            continue
        for m in METRICS:
            diffs.append({'model': r['model'], 'label': r['label'], 'split': r['split'],
                          'replicate': r['replicate'], 'metric': m, 'value': r[m],
                          'none_value': float(base.loc[k, m]), 'diff': r[m] - float(base.loc[k, m])})
    dd = pd.DataFrame(diffs)
    if len(dd):
        dd.to_csv(OUT / 'diffs.csv', index=False)

    rows, vrows = [], []
    for (model, split), g in d.groupby(['model', 'split'], sort=True):
        full = 5 if split == 'random' else 3
        for lab in LABEL_ORDER:
            gv = g[g['label'] == lab]
            if len(gv):
                for m in METRICS:
                    s = dstats(gv[m])
                    vrows.append({'model': model, 'split': split, 'label': lab, 'metric': m,
                                  'n': s['n'], 'mean': s['mean'], 'sd': s['sd'], 'min': s['min'], 'max': s['max'],
                                  'replicates': ' '.join(gv['replicate'])})
            if lab == 'none' or not len(dd):
                continue
            for m in METRICS:
                x = dd[(dd['model'] == model) & (dd['split'] == split) & (dd['label'] == lab) & (dd['metric'] == m)]
                if not len(x):
                    continue
                x = x.assign(_r=x['replicate'].map(REP_ORDER.index)).sort_values('_r')
                s = dstats(x['diff'])
                rows.append({'model': model, 'split': split, 'label': lab, 'metric': m, **s,
                             'complete': s['n'] == full,
                             'ci_method': f't-based 95% CI over the {"split seeds" if split == "random" else "temporal cuts"}'
                                          f' (df = n - 1)',
                             'diffs': {rep: round(float(v), 5) for rep, v in zip(x['replicate'], x['diff'])}})
    ds = pd.DataFrame(rows)
    vs = pd.DataFrame(vrows)
    if len(ds):
        ds.assign(diffs=ds['diffs'].map(lambda z: ' '.join(f'{k}:{v:+.4f}' for k, v in z.items()))) \
          .to_csv(OUT / 'diff_summary.csv', index=False)
    vs.to_csv(OUT / 'value_summary.csv', index=False)

    for model in [m for m in MODELS if (d['model'] == m).any()]:
        for m in ('macro_f1', 'balanced_accuracy'):
            print(f'\n=== {model}: {m}, variant - none on the same partition (joint cleaning, split re-made) ===')
            for split in ('random', 'temporal'):
                reps = [r for r in REP_ORDER if (split == 'random') == r.startswith('s')]
                print(f'  [{split}]  ' + ' '.join(f'{r:>9s}' for r in reps)
                      + f'   {"mean":>7s} {"SD":>6s} {"min":>7s} {"max":>7s}   95% CI (t)      +/-')
                nv = vs[(vs['model'] == model) & (vs['split'] == split) & (vs['metric'] == m) & (vs['label'] == 'none')]
                if len(nv):
                    print(f'  {"none (value)":13s}' + ' ' * (10 * len(reps))
                          + f'   {nv["mean"].iloc[0]:7.4f} {nv["sd"].iloc[0]:6.4f}')
                if not len(ds):
                    continue
                for lab in LABEL_ORDER[1:]:
                    x = ds[(ds['model'] == model) & (ds['split'] == split) & (ds['label'] == lab) & (ds['metric'] == m)]
                    if not len(x):
                        continue
                    x = x.iloc[0]
                    cells = ' '.join(f'{x["diffs"][r]:+9.4f}' if r in x['diffs'] else f'{"-":>9s}' for r in reps)
                    ci = (f'[{x["ci_lo"]:+.4f}, {x["ci_hi"]:+.4f}]' if x['n'] > 1 else f'{"n/a":17s}')
                    print(f'  {lab:13s}{cells}   {x["mean"]:+7.4f} {x["sd"]:6.4f} {x["min"]:+7.4f} {x["max"]:+7.4f}'
                          f'   {ci}  {x["n_pos"]}/{x["n_neg"]}{"" if x["complete"] else "  (incomplete)"}')

    checks = [{'model': r['model'], 'label': r['label'], 'split': r['split'], 'replicate': r['replicate'],
               'macro_f1': r['macro_f1'], 'ref_macro_f1': r['reference_check']['ref_macro_f1'],
               'counts_equal': r['reference_check']['counts_equal'],
               'max_abs_diff': r['reference_check']['max_abs_diff'], 'reproduced': r['reference_check']['reproduced']}
              for r in runs if 'reference_check' in r]
    ck = pd.DataFrame(checks)
    if len(ck):
        ck.to_csv(OUT / 'reference_check.csv', index=False)
        n_ok = int(ck['reproduced'].sum())
        print(f'\n=== reference check (seed 42 / 70-15-15 vs rule_sensitivity.json): {n_ok}/{len(ck)} reproduced, '
              f'max |diff| = {ck["max_abs_diff"].max():.6f} ===')
        bad = ck[~ck['reproduced']]
        if len(bad):
            print(bad.to_string(index=False))
    res = {'settings': {'variants': VARIANTS, 'partitions': [f'{s}/{r}' for s, r in PARTS], 'metrics': METRICS,
                        'diff': 'metric(variant, partition) - metric(none, same partition); the partition is '
                                'drawn on the rows kept by each variant (Table 4 design)',
                        'ci': 'mean +/- t(0.975, n - 1) * SD / sqrt(n) over the split seeds (random) or cuts (temporal)',
                        'imputation': 'NaN -> training median per fit (pilot_temporal_split.fit_eval)'},
           'reference_check': {'n_checked': len(checks), 'n_reproduced': int(sum(c['reproduced'] for c in checks)),
                               'cells': checks},
           'diff_summary': ds.to_dict('records') if len(ds) else [],
           'value_summary': vs.to_dict('records')}
    write_json(OUT / 'summary.json', clean(res))
    print('\n[saved]', OUT / 'summary.json', flush=True)


def clean(o):
    """JSON-safe copy: numpy scalars -> Python, NaN -> None."""
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, (bool, np.bool_)):
        return bool(o)
    if isinstance(o, (int, np.integer)):
        return int(o)
    if isinstance(o, (float, np.floating)):
        return None if not np.isfinite(o) else round(float(o), 6)
    return o


# ---------------------------------------------------------------- self-test (synthetic data only)
def selftest():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(5000, 9)).astype(np.float32)
    X[rng.random(X.shape) < 0.1] = np.nan
    X[:, 3] = np.nan                                            # all-NaN column
    X[rng.random(5000) < 0.3, 5] = -0.0
    tr, te = rng.permutation(5000)[:3500], rng.permutation(5000)[:700]
    a, b, med, n = impute_median(X, tr, te)
    with warnings.catch_warnings():                            # fit_eval, literally
        warnings.simplefilter('ignore', RuntimeWarning)
        Xtr, Xte = X[tr], X[te]
        m0 = np.nanmedian(Xtr, axis=0)
        Xtr = np.where(np.isnan(Xtr), m0, Xtr); Xte = np.where(np.isnan(Xte), m0, Xte)
    assert Xtr.dtype == a.dtype and Xte.dtype == b.dtype
    assert np.array_equal(Xtr, a, equal_nan=True) and np.array_equal(Xte, b, equal_nan=True)
    assert np.array_equal(m0, med, equal_nan=True) and np.isnan(X).any()  # X itself untouched
    y = rng.integers(0, len(CLASSES), 5000)
    fl = {c: rng.random(5000) < 0.2 for c in FLAGS}
    fl = {c: v & (y != CLASSES.index('Benign')) for c, v in fl.items()}
    mk = variant_masks(fl, y)
    flood = np.isin(y, [CLASSES.index('DOS'), CLASSES.index('DDOS')])
    r1, r2, r3 = (fl[c] for c in FLAGS)
    assert np.array_equal(mk['all, floods-R2'], r1 | r3 | (r2 & ~flood))
    assert np.array_equal(mk['all'], r1 | r2 | r3) and not mk['none'].any()
    s = dstats([0.01, 0.02, 0.0, 0.015, 0.005])
    h = 2.7764451 * np.std([0.01, 0.02, 0.0, 0.015, 0.005], ddof=1) / np.sqrt(5)
    assert abs(s['ci_hi'] - s['mean'] - h) < 1e-6 and s['n_pos'] == 4
    assert len(plan(['XGBoost'])) == 56 and plan(['XGBoost'])[0]['rep'] == 's42'
    print('[selftest] OK: imputation identical to fit_eval, variant masks, t-CI, plan (56 XGBoost runs)')


def main():
    ap = argparse.ArgumentParser(description='Table 4 cleaning variants over 5 split seeds and 3 temporal cuts.')
    ap.add_argument('--models', nargs='+', choices=MODELS, default=['XGBoost'])
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N fits (0 = no limit); run inside a PowerShell loop so that every batch '
                         'starts in a fresh process (use 1 for the random forest)')
    ap.add_argument('--tol', type=float, default=1e-3, help='tolerance of the check against rule_sensitivity.json')
    ap.add_argument('--check-splits', action='store_true',
                    help='only compare the reference partitions with Table 4 (counts, no training)')
    ap.add_argument('--summary', action='store_true', help='only print / write the tables of finished runs')
    ap.add_argument('--selftest', action='store_true', help='test the helpers on synthetic data and exit')
    a = ap.parse_args()
    if a.selftest:
        selftest()
    elif a.check_splits:
        check_splits(a)
    elif a.summary:
        OUT.mkdir(parents=True, exist_ok=True)
        summary(a)
    else:
        run(a)


if __name__ == '__main__':
    main()
