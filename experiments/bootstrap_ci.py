# -*- coding: utf-8 -*-
"""
bootstrap_ci.py
===============
Uncertainty for the protocol study, from the saved test predictions (*.npz: y, p, sub).

* 95% CI of macro-F1 and balanced accuracy for every run: stratified bootstrap
  (test rows resampled with replacement inside each true class, B = 2000).
  Resampling rows inside class c is the same as drawing the predicted labels of that
  class from a multinomial with the class's confusion-matrix row, which is what is done.
* Paired comparisons between models on the SAME test rows (same split and cleaning):
  the joint (prediction A, prediction B) table of each true class is resampled, giving
  the bootstrap distribution of the macro-F1 difference; two-sided p-value =
  2 * (min(#d <= 0, #d >= 0) + 1) / (B + 1); Holm correction over all comparisons.
* Effect of the split (random vs temporal) and of cleaning: difference of two independent
  bootstraps (different test sets), 95% CI.

Inputs : results_2026_03_03/tree_protocol/main/*.npz  (+ any deep folder given with --deep)
Output : results_2026_03_03/tree_protocol/bootstrap.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\bootstrap_ci.py --deep deep_split_e4
"""
import argparse, itertools, json, re, sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent / 'results_2026_03_03'
K = 8
B = 2000
rng = np.random.default_rng(42)
sys.stdout.reconfigure(encoding='utf-8')


def per_class_f1(cm):
    tp = np.diagonal(cm, axis1=-2, axis2=-1); row = cm.sum(-1); col = cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        rec = np.where(row > 0, tp / row, 0.0); prec = np.where(col > 0, tp / col, 0.0)
        return np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)


def f1_ba(cm):
    """cm: (..., K, K) counts, rows = true. Returns macro-F1 and balanced accuracy."""
    tp = np.diagonal(cm, axis1=-2, axis2=-1)
    row = cm.sum(-1); col = cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        rec = np.where(row > 0, tp / row, 0.0)
        prec = np.where(col > 0, tp / col, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    return f1.mean(-1), rec.mean(-1)


def boot_cm(y, p):
    """B bootstrap confusion matrices (stratified by true class)."""
    out = np.zeros((B, K, K))
    for c in range(K):
        pc = p[y == c]
        if len(pc) == 0:
            continue
        prob = np.bincount(pc, minlength=K) / len(pc)
        out[:, c, :] = rng.multinomial(len(pc), prob, size=B)
    return out


def boot_pair(y, pa, pb):
    """B paired bootstrap confusion matrices for two models on the same rows."""
    ca, cb = np.zeros((B, K, K)), np.zeros((B, K, K))
    for c in range(K):
        m = y == c
        if not m.any():
            continue
        joint = np.bincount(pa[m] * K + pb[m], minlength=K * K)
        draw = rng.multinomial(m.sum(), joint / m.sum(), size=B).reshape(B, K, K)
        ca[:, c, :] = draw.sum(2); cb[:, c, :] = draw.sum(1)
    return ca, cb


def ci(v):
    return [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]


def holm(pvals):
    order = np.argsort(pvals); adj = np.empty(len(pvals)); run = 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (len(pvals) - r) * pvals[i])); adj[i] = run
    return adj


def load(folder, pattern):
    runs = {}
    for f in sorted((ROOT / folder).glob('*.npz')):
        m = re.match(pattern, f.stem)
        if m:
            d = np.load(f)
            runs[m.groups()] = (d['y'].astype(int), d['p'].astype(int))
    return runs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--deep', nargs='*', default=[], help='deep-model result folders with *.npz')
    a = ap.parse_args()
    pat = r'(\w+?)_(random|temporal)_(raw|r1)_s(\d+)$'
    runs = load('tree_protocol/main', pat)
    for d in a.deep:
        runs.update(load(d, pat))
    res = {'runs': {}, 'paired': [], 'effects': []}

    # ---- per run CIs
    boots = {}
    for key, (y, p) in runs.items():
        bcm = boot_cm(y, p)
        bf, bb = f1_ba(bcm)
        pcf = per_class_f1(bcm)
        pf, pb = f1_ba(np.bincount(y * K + p, minlength=K * K).reshape(K, K).astype(float))
        res['runs']['|'.join(key)] = {'macro_f1': round(float(pf), 4), 'macro_f1_ci': ci(bf),
                                      'bal_acc': round(float(pb), 4), 'bal_acc_ci': ci(bb), 'n_test': int(len(y)),
                                      'class_n_test': np.bincount(y, minlength=K).tolist(),
                                      'per_class_f1_ci': [ci(pcf[:, c]) for c in range(K)]}
        boots[key] = bf
    # ---- paired model comparisons (seed 42, same condition)
    models = sorted({k[0] for k in runs})
    comps = []
    for s, c in itertools.product(['random', 'temporal'], ['raw', 'r1']):
        for ma, mb in itertools.combinations(models, 2):
            ka, kb = (ma, s, c, '42'), (mb, s, c, '42')
            if ka in runs and kb in runs and np.array_equal(runs[ka][0], runs[kb][0]):
                ca, cb = boot_pair(runs[ka][0], runs[ka][1], runs[kb][1])
                d = f1_ba(ca)[0] - f1_ba(cb)[0]
                obs = res['runs']['|'.join(ka)]['macro_f1'] - res['runs']['|'.join(kb)]['macro_f1']
                # (k + 1) / (B + 1): never 0; with B = 2000 the smallest two-sided p is about 0.001
                pv = min(1.0, 2 * (min((d <= 0).sum(), (d >= 0).sum()) + 1) / (B + 1))
                comps.append({'split': s, 'cleaning': c, 'a': ma, 'b': mb, 'diff': round(obs, 4),
                              'ci': ci(d), 'p': float(pv)})
    if comps:
        for cmp_, pa in zip(comps, holm(np.array([x['p'] for x in comps]))):
            cmp_['p_holm'] = round(float(pa), 4)
    res['paired'] = comps
    # ---- split and cleaning effects (independent bootstraps)
    for m in models:
        for label, k1, k2 in [('split (raw)', (m, 'random', 'raw', '42'), (m, 'temporal', 'raw', '42')),
                              ('split (r1)', (m, 'random', 'r1', '42'), (m, 'temporal', 'r1', '42')),
                              ('cleaning (random)', (m, 'random', 'r1', '42'), (m, 'random', 'raw', '42')),
                              ('cleaning (temporal)', (m, 'temporal', 'r1', '42'), (m, 'temporal', 'raw', '42'))]:
            if k1 in boots and k2 in boots:
                d = boots[k1] - boots[k2]
                res['effects'].append({'model': m, 'effect': label,
                                       'diff': round(float(np.median(d)), 4), 'ci': ci(d)})

    json.dump(res, open(ROOT / 'tree_protocol' / 'bootstrap.json', 'w'), indent=1)
    print('=== macro-F1 with 95% CI (seed 42) ===')
    for k, v in res['runs'].items():
        if k.endswith('|42'):
            print(f'{k:36s} {v["macro_f1"]:.3f} [{v["macro_f1_ci"][0]:.3f}, {v["macro_f1_ci"][1]:.3f}]  n={v["n_test"]:,}')
    print('\n=== paired model comparisons (macro-F1, Holm-adjusted p) ===')
    for x in comps:
        print(f'{x["split"]:8s} {x["cleaning"]:3s} {x["a"]:12s} - {x["b"]:12s} {x["diff"]:+.3f} '
              f'[{x["ci"][0]:+.3f}, {x["ci"][1]:+.3f}]  p_holm={x["p_holm"]:.4f}')
    print('\n=== effects (macro-F1 difference, 95% CI) ===')
    for x in res['effects']:
        print(f'{x["model"]:12s} {x["effect"]:20s} {x["diff"]:+.3f} [{x["ci"][0]:+.3f}, {x["ci"][1]:+.3f}]')


if __name__ == '__main__':
    main()
