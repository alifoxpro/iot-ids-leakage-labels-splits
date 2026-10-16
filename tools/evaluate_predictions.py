# -*- coding: utf-8 -*-
r"""
tools/evaluate_predictions.py -- recompute the reported metrics of every run from its stored test predictions and check
them against the run's result file.

Every run that stored predictions has <run>.npz (y: true class, p: predicted class, optionally proba: class
probabilities, rows: global row positions of the test flows in the experimental sample, sub: capture group) next to its
result file <run>.json. The .npz files are too large for git; they are in the release assets of the repository
(unzip them into the repository folder, see RELEASE_CHECKLIST.md). For every pair this script recomputes accuracy,
balanced accuracy, macro-F1 (eight classes, in the class order of results_2026_03_03/multiclass/stage1_artifacts) and,
where probabilities were stored, macro-averaged average precision, and compares them with the values in the JSON.

Usage (from the repository folder):
  python tools/evaluate_predictions.py                         # every run under results_2026_03_03
  python tools/evaluate_predictions.py --folders q1_revision/rolling_origin q1_revision/shared_budget
Output: results_2026_03_03/evaluation_check.csv (one line per run: recomputed and stored values, largest difference)
Exit code 1 if any recomputed value differs from the stored one by more than --tol (default 1e-9).
"""
import argparse, json, sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / 'results_2026_03_03'
K = 8
KEYS = ('accuracy', 'balanced_accuracy', 'macro_f1', 'macro_ap')


def metrics(y, p, proba=None):
    cm = np.bincount(y * K + p, minlength=K * K).reshape(K, K).astype(float)
    tp, row, col = np.diag(cm), cm.sum(1), cm.sum(0)
    with np.errstate(divide='ignore', invalid='ignore'):
        rec = np.where(row > 0, tp / row, 0.0)
        prec = np.where(col > 0, tp / col, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    out = {'accuracy': float(tp.sum() / cm.sum()), 'balanced_accuracy': float(rec[row > 0].mean()),
           'macro_f1': float(f1.mean())}
    if proba is not None:
        from sklearn.metrics import average_precision_score
        ap = [average_precision_score(y == k, proba[:, k]) for k in range(K) if (y == k).any() and (y != k).any()]
        out['macro_ap'] = float(np.mean(ap))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--folders', nargs='*', default=None, help='sub-folders of results_2026_03_03 (default: all)')
    ap.add_argument('--tol', type=float, default=1e-9)
    a = ap.parse_args()
    roots = [RES / f for f in a.folders] if a.folders else [RES]
    rows, worst = [], 0.0
    for root in roots:
        for npz in sorted(root.rglob('*.npz')):
            js = npz.with_suffix('.json')
            if not js.exists():
                continue
            with open(js, encoding='utf-8') as f:
                r = json.load(f)
            if not isinstance(r, dict) or 'macro_f1' not in r:
                continue
            with np.load(npz, allow_pickle=False) as d:
                if 'y' not in d.files or 'p' not in d.files:
                    continue
                y, p = d['y'].astype(np.int64), d['p'].astype(np.int64)
                proba = d['proba'].astype(np.float32) if 'proba' in d.files else None
            m = metrics(y, p, proba if r.get('macro_ap') is not None else None)
            ref = {k: r[k] for k in m if r.get(k) is not None}
            if 'macro_ap' in m and r.get('macro_ap_float16') is not None:       # the stored probabilities are float16
                ref['macro_ap'] = r['macro_ap_float16']
            diff = max(abs(m[k] - v) for k, v in ref.items())
            worst = max(worst, diff)
            rows.append({'run': str(npz.relative_to(RES).with_suffix('')).replace('\\', '/'), 'n_test': int(len(y)),
                         **{f'{k}': round(m[k], 6) for k in m}, **{f'stored_{k}': v for k, v in ref.items()},
                         'max_abs_diff': diff})
    import csv
    out = RES / 'evaluation_check.csv'
    if rows:
        with open(out, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r}, key=lambda k: (k != 'run', k)))
            w.writeheader(); w.writerows(rows)
    bad = [r for r in rows if r['max_abs_diff'] > a.tol]
    print(f'[evaluate] {len(rows)} runs with stored predictions; largest difference {worst:.2e}; '
          f'{len(bad)} above the tolerance {a.tol:g}' + (f'; written {out}' if rows else ''))
    for r in bad[:20]:
        print('  ', r['run'], r['max_abs_diff'])
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
