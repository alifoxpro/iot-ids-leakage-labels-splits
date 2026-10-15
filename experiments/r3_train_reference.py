# -*- coding: utf-8 -*-
r"""
r3_train_reference.py
=====================
Round-2 review (Reviewer 1, point 1): rule R3 flags an attack flow when its unordered IP pair also occurs
in Benign, and the reference set of Benign pairs was built from ALL Benign flows, including the Benign flows
of the validation and test periods. This script freezes the reference on the Benign TRAINING flows of each
split (R3tr), so that no validation or test flow informs the rule, and repeats the training-only cleaning
design of cleaning_train_only.py with R3tr next to R3.

Design (sample of flagged_loader.load_prepared(), 3,626,502 flows, NaN/inf -> 0; models of
extra_baselines.make, seed 42; balanced sample weights on the kept training rows):
  split      random | temporal, made ONCE on all raw rows (deep_split_noise_study.splits); the validation
             part is not used by the tree ensembles (no early stopping), so its labels and masks play no
             role here (as in cleaning_train_only.py)
  reference  R3   : IP pairs of every Benign flow read from the Benign captures (flagged_loader, as published)
             R3tr : IP pairs of the Benign flows in the TRAINING part of this split only (frozen before
                    validation and testing). Benign flows are never flagged, so the Benign training rows are
                    the same in every variant.
  variant    training rows dropped when flagged by
               none, R1, R3, R1+R3, All (R1|R2|R3), All* (R1|R3|(R2 outside DOS/DDOS))   (as cleaning_train_only)
               R3tr, R1+R3tr, Alltr (R1|R2|R3tr), All*tr (R1|R3tr|(R2 outside DOS/DDOS))
  test set   test_R1    test rows not flagged by R1               (independent of R3)
             test_All   test rows not flagged by R1|R2|R3         (the published test set)
             test_Alltr test rows not flagged by R1|R2|R3tr       (reference frozen on the training Benign flows)
10 variants x 2 splits = 20 fits per model, each scored on the three test sets (60 runs per model). The
variants without R3tr are refits of cleaning_train_only.py (same rows, same model seed): their test_R1 and
test_All results reproduce that script's files, which the summary checks (reproduced = identical macro-F1).

Also written (extent.json / extent_groups.csv): per split, the R3 and R3tr flags of the attack flows in the
training, validation and test parts, per capture group; the agreement of R3 recomputed from the Benign flows
of the sample with the published flag (the published reference also holds Benign flows removed later as exact
duplicates, so it can only be larger).

Output: results_2026_03_03/q1_revision/r3_train_reference/
          <model>_<split>_train-<variant>_test-<R1|All|Alltr>.json + .npz   (npz: y, p, sub, rows)
          extent.json, extent_groups.csv, summary.csv (all runs), summary_effects.csv (R3tr minus R3 variant,
          per model, split and test set), reproduced.csv
Resumable: a fit is skipped when the JSONs of its three test sets exist.
Memory: as cleaning_train_only.py (X ~1.2 GB, X[tr] ~0.8 GB); the IP pairs are kept as int32 codes.
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\r3_train_reference.py --plan
  & $py experiments\r3_train_reference.py --models XGBoost 2>&1 | Tee-Object -FilePath r3_train_reference_xgb.log
  1..20 | ForEach-Object { & $py experiments\r3_train_reference.py --models RandomForest --max-fits 1 2>&1 | Tee-Object -FilePath r3_train_reference_rf.log -Append }
  & $py experiments\r3_train_reference.py --summary
"""
import argparse, gc, json, os, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import CACHE, load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402
from relabel_background import pair_key  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
RES = HERE.parent / 'results_2026_03_03' / 'q1_revision'
OUT = RES / 'r3_train_reference'
CTO = RES / 'cleaning_train_only'                 # published training-only runs (read only)
LABELS = list(range(len(CLASSES)))
BENIGN = CLASSES.index('Benign')
ATTACKS = [i for i in LABELS if i != BENIGN]
FLOODS = [CLASSES.index('DOS'), CLASSES.index('DDOS')]
SPLITS = ['random', 'temporal']
MODELS = ['XGBoost', 'RandomForest']
# (variant, file-name slug, uses R3tr, rule text)
VARIANTS = [('none', 'none', False, 'no cleaning'),
            ('R1', 'R1', False, 'R1 external endpoint'),
            ('R3', 'R3', False, 'R3 IP pair seen in Benign (all Benign flows)'),
            ('R1+R3', 'R1R3', False, 'R1 | R3'),
            ('All', 'All', False, 'R1 | R2 | R3'),
            ('All*', 'AllStar', False, 'R1 | R3 | (R2 outside DOS/DDOS)'),
            ('R3tr', 'R3tr', True, 'R3 with the Benign pairs of the training part only'),
            ('R1+R3tr', 'R1R3tr', True, 'R1 | R3tr'),
            ('Alltr', 'Alltr', True, 'R1 | R2 | R3tr'),
            ('All*tr', 'AllStartr', True, 'R1 | R3tr | (R2 outside DOS/DDOS)')]
PAIRS = {'R3tr': 'R3', 'R1+R3tr': 'R1+R3', 'Alltr': 'All', 'All*tr': 'All*'}   # new variant -> published one
TESTS = {'R1': 'test rows not flagged by R1', 'All': 'test rows not flagged by R1 | R2 | R3',
         'Alltr': 'test rows not flagged by R1 | R2 | R3tr'}


def run_name(model, split, slug, test):
    return f'{model}_{split}_train-{slug}_test-{test}'


def pair_codes():
    """int32 code of the unordered IP pair of every row of the cached sample (row order of load_prepared)."""
    import pyarrow.parquet as pq
    t = pq.read_table(CACHE, columns=['Src IP', 'Dst IP']).to_pandas()
    codes, _ = pd.factorize(pair_key(t['Src IP'], t['Dst IP']))
    del t; gc.collect()
    return codes.astype(np.int32)


def r3_from(codes, y, ref_rows):
    """R3 for the attack rows: IP pair occurs among the Benign rows `ref_rows`; False for Benign."""
    ref = np.zeros(codes.max() + 1, bool)
    ref[codes[ref_rows]] = True
    return ref[codes] & (y != BENIGN)


def drop_masks(r1, r2, r3, r3tr, y):
    flood = np.isin(y, FLOODS)
    return {'none': np.zeros(len(y), bool), 'R1': r1, 'R3': r3, 'R1+R3': r1 | r3, 'All': r1 | r2 | r3,
            'All*': r1 | r3 | (r2 & ~flood), 'R3tr': r3tr, 'R1+R3tr': r1 | r3tr, 'Alltr': r1 | r2 | r3tr,
            'All*tr': r1 | r3tr | (r2 & ~flood)}


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
    np.savez_compressed(path.with_suffix('.npz'), y=y_true.astype(np.int8), p=p,
                        sub=np.asarray(sub, dtype=str), rows=rows.astype(np.int32))
    tmp = path.with_name(path.name + '.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path.with_suffix('.json'))


def extent(meta, y, sub, flags, codes):
    """R3 versus R3tr on the attack rows of the training, validation and test parts of both splits."""
    r3 = np.asarray(flags['r3_benign_pair'], bool)
    r3_sample = r3_from(codes, y, np.flatnonzero(y == BENIGN))
    att = y != BENIGN
    res = {'published_r3_vs_sample_reference': {
        'attack_rows': int(att.sum()), 'published_r3': int(r3[att].sum()), 'sample_reference_r3': int(r3_sample[att].sum()),
        'agree': int((r3[att] == r3_sample[att]).sum()), 'published_only': int((r3 & ~r3_sample)[att].sum()),
        'sample_only': int((~r3 & r3_sample)[att].sum())}, 'splits': {}}
    rows = []
    for s in SPLITS:
        tr, va, te = splits(meta, s)
        r3tr = r3_from(codes, y, tr[y[tr] == BENIGN])
        part = {}
        for pname, idx in (('train', tr), ('validation', va), ('test', te)):
            a = idx[att[idx]]
            part[pname] = {'attack_rows': int(len(a)), 'r3': int(r3[a].sum()), 'r3tr': int(r3tr[a].sum()),
                           'r3_only': int((r3 & ~r3tr)[a].sum()), 'r3tr_only': int((~r3 & r3tr)[a].sum())}
            for (c, g) in sorted(set(zip(y[a], sub[a]))):
                m = a[(y[a] == c) & (sub[a] == g)]
                rows.append({'split': s, 'part': pname, 'class': CLASSES[c], 'capture_group': g, 'flows': int(len(m)),
                             'r3_share': round(float(r3[m].mean()), 4), 'r3tr_share': round(float(r3tr[m].mean()), 4),
                             'r3_only': int((r3 & ~r3tr)[m].sum()), 'r3tr_only': int((~r3 & r3tr)[m].sum())})
        b = tr[y[tr] == BENIGN]
        part['reference'] = {'benign_train_rows': int(len(b)), 'benign_rows_all': int((y == BENIGN).sum()),
                             'pairs_train': int(len(np.unique(codes[b]))),
                             'pairs_all_benign_sample': int(len(np.unique(codes[y == BENIGN])))}
        res['splits'][s] = part
    return res, pd.DataFrame(rows)


def summary():
    rows = []
    for f in sorted(OUT.glob('*_train-*_test-*.json')):
        with open(f, encoding='utf-8') as fh:
            r = json.load(fh)
        rows.append({'model': r['model'], 'split': r['split'], 'test_set': r['test_set'], 'variant': r['train_variant'],
                     'reference': r['r3_reference'], 'n_train': r['n_train'], 'n_test': r['n_test'],
                     'macro_f1': r['macro_f1'], 'attack_macro_f1': r['attack_macro_f1'],
                     'balanced_accuracy': r['balanced_accuracy'], 'accuracy': r['accuracy']})
    if not rows:
        print('no finished runs yet'); return
    d = pd.DataFrame(rows)
    order = {v[0]: i for i, v in enumerate(VARIANTS)}
    d = d.sort_values(['model', 'split', 'test_set', 'variant'], key=lambda c: c.map(order) if c.name == 'variant' else c)
    d.to_csv(OUT / 'summary.csv', index=False)
    eff = []
    for (m, s, t), g in d.groupby(['model', 'split', 'test_set']):
        v = g.set_index('variant')
        for new, old in PAIRS.items():
            if new in v.index and old in v.index:
                eff.append({'model': m, 'split': s, 'test_set': t, 'variant': old, 'variant_tr': new,
                            'macro_f1': v.loc[old, 'macro_f1'], 'macro_f1_tr': v.loc[new, 'macro_f1'],
                            'diff_macro_f1': round(v.loc[new, 'macro_f1'] - v.loc[old, 'macro_f1'], 4),
                            'gain_over_none': None if 'none' not in v.index else round(v.loc[old, 'macro_f1'] - v.loc['none', 'macro_f1'], 4),
                            'gain_over_none_tr': None if 'none' not in v.index else round(v.loc[new, 'macro_f1'] - v.loc['none', 'macro_f1'], 4),
                            'n_train': v.loc[old, 'n_train'], 'n_train_tr': v.loc[new, 'n_train']})
    pd.DataFrame(eff).to_csv(OUT / 'summary_effects.csv', index=False)
    rep = []                                    # refits of cleaning_train_only.py: identical results?
    for r in rows:
        if r['reference'] != 'all' or r['test_set'] == 'Alltr':
            continue
        slug = next(v[1] for v in VARIANTS if v[0] == r['variant'])
        f = CTO / f'{r["model"]}_{r["split"]}_train-{slug}_test-{r["test_set"]}.json'
        if f.exists():
            with open(f, encoding='utf-8') as fh:
                o = json.load(fh)
            rep.append({'model': r['model'], 'split': r['split'], 'test_set': r['test_set'], 'variant': r['variant'],
                        'macro_f1': r['macro_f1'], 'published': o['macro_f1'], 'n_test': r['n_test'],
                        'published_n_test': o['n_test'], 'reproduced': r['macro_f1'] == o['macro_f1'] and r['n_test'] == o['n_test']})
    pd.DataFrame(rep).to_csv(OUT / 'reproduced.csv', index=False)
    pd.set_option('display.width', 220)
    print(d.round(4).to_string(index=False))
    if eff:
        print('\n=== R3tr variant minus R3 variant (macro-F1) ===')
        print(pd.DataFrame(eff).round(4).to_string(index=False))
    if rep:
        rp = pd.DataFrame(rep)
        print(f'\n[reproduced] {int(rp["reproduced"].sum())} of {len(rp)} refits identical to cleaning_train_only.py')
    print('[saved]', OUT / 'summary.csv')


def plan(models):
    fits = [(m, s, v) for m in models for s in SPLITS for v in VARIANTS]
    todo = [(m, s, v) for m, s, v in fits if not all((OUT / f'{run_name(m, s, v[1], t)}.json').exists() for t in TESTS)]
    print(f'[plan] {len(fits)} fits ({", ".join(models)}) x {len(TESTS)} test sets, {len(fits) - len(todo)} finished, '
          f'{len(todo)} to do; extent: {"done" if (OUT / "extent.json").exists() else "to do"}', flush=True)
    return todo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--models', nargs='+', choices=MODELS, default=['XGBoost'])
    ap.add_argument('--max-fits', type=int, default=0, help='stop after N fits (1 inside a PowerShell loop)')
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--plan', action='store_true')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return
    todo = plan(a.models)
    if a.plan or (not todo and (OUT / 'extent.json').exists()):
        if not todo:
            summary()
        return

    X, meta, flags = load_prepared()
    meta = meta.reset_index(drop=True)            # RangeIndex: split positions = global row positions
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    codes = pair_codes()
    assert len(codes) == len(y), (len(codes), len(y))
    if not (OUT / 'extent.json').exists():
        res, groups = extent(meta, y, sub, flags, codes)
        groups.to_csv(OUT / 'extent_groups.csv', index=False)
        with open(OUT / 'extent.json', 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=1)
        print('[extent]', json.dumps(res['published_r3_vs_sample_reference']), flush=True)
        for s, part in res['splits'].items():
            print(f'  {s:8s} ' + '  '.join(f'{p}: R3 {v["r3"]:,} R3tr {v["r3tr"]:,}' for p, v in part.items() if p != 'reference')
                  + f'  reference pairs {part["reference"]["pairs_train"]:,} of {part["reference"]["pairs_all_benign_sample"]:,}', flush=True)
    r1 = np.asarray(flags['r1_external'], bool)
    r2 = np.asarray(flags['r2_service'], bool)
    r3 = np.asarray(flags['r3_benign_pair'], bool)
    del flags; gc.collect()

    cache = {}
    n_here = min(len(todo), a.max_fits) if a.max_fits else len(todo)
    done = 0
    for n_fit, (m, s, (v, slug, uses_tr, rule)) in enumerate(todo, 1):
        if a.max_fits and n_fit > a.max_fits:
            break
        if s not in cache:
            tr_all, _, te = splits(meta, s)                       # ONCE on all raw rows
            r3tr = r3_from(codes, y, tr_all[y[tr_all] == BENIGN])
            drop = drop_masks(r1, r2, r3, r3tr, y)
            cache[s] = (tr_all, drop, {'R1': te[~drop['R1'][te]], 'All': te[~drop['All'][te]],
                                       'Alltr': te[~drop['Alltr'][te]]})
        tr_all, drop, tests = cache[s]
        tr = tr_all[~drop[v][tr_all]]
        need = [(t, te) for t, te in tests.items() if not (OUT / f'{run_name(m, s, slug, t)}.json').exists()]
        present = np.unique(y[tr])
        missing = [CLASSES[c] for c in LABELS if c not in present]
        Xtr = X[tr]
        Xte = None
        if n_fit == n_here:                                   # last fit of this process: free X first
            Xte = {t: X[te] for t, te in need}
            del X; gc.collect()
        clf = make(m)
        t0 = time.time()
        clf.fit(Xtr, np.searchsorted(present, y[tr]), sample_weight=compute_sample_weight('balanced', y[tr]))
        fit_s = time.time() - t0
        del Xtr; gc.collect()
        for tname, te in need:
            xt = X[te] if Xte is None else Xte.pop(tname)
            p = present[np.asarray(clf.predict(xt)).astype(int).ravel()].astype(np.int8)
            del xt
            r = score(y[te], p, sub[te])
            r.update({'model': m, 'seed': SEED, 'split': s, 'train_variant': v, 'train_rule': rule,
                      # reference of the R3 flags of the training rows (none / R1 do not use R3)
                      'r3_reference': 'train' if uses_tr else 'all',
                      'test_set': tname, 'test_rule': TESTS[tname], 'n_train': int(len(tr)),
                      'n_train_dropped': int(len(tr_all) - len(tr)), 'n_test': int(len(te)),
                      'train_class_counts': counts(y[tr]), 'test_class_counts': counts(y[te]),
                      'missing_train_classes': missing, 'fit_seconds': round(fit_s, 1),
                      'validation_part': 'not used (no early stopping); its labels and masks play no role',
                      'script': 'experiments/r3_train_reference.py', 'created': time.strftime('%Y-%m-%d %H:%M:%S')})
            save(OUT / run_name(m, s, slug, tname), r, y[te], p, sub[te], te)
            done += 1
            print(f'[{done}] {m:12s} {s:8s} train={v:8s} test={tname:5s} n_train={len(tr):>9,} n_test={len(te):>8,} '
                  f'macro-F1={r["macro_f1"]:.4f} attack-F1={r["attack_macro_f1"]:.4f} ({fit_s:.0f} s)', flush=True)
        del clf, tr; gc.collect()
    left = plan(a.models)
    if not left:
        print('[DONE] all fits finished', flush=True)
        summary()


if __name__ == '__main__':
    main()
