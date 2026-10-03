# -*- coding: utf-8 -*-
"""
extra_baselines.py
==================
Additional tree-based comparisons on exactly the same sample, splits and label conditions as
deep_split_noise_study.py:
  models     XGBoost (re-run to store confusion matrices), LightGBM, Random Forest
  split      random | temporal (70/15/15 inside each capture group)
  cleaning   raw | r1
All models use balanced class weights computed on the training part; features are the 81
model features with NaN/inf replaced by 0 (as for the deep models).
Output: results_2026_03_03/extra_baselines/<model>_<split>_<cleaning>.json
        (metrics, per-class F1/recall, per-sub-attack recall, confusion matrix, fit time)
Resumable: finished runs are skipped.
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\extra_baselines.py
"""
import gc, json, sys, time
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import NEEDED, kept_rows, metrics, prepare, splits  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'extra_baselines'


def make(name):
    if name == 'XGBoost':
        import xgboost as xgb
        return xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1, tree_method='hist',
                                 device='cuda', random_state=SEED, eval_metric='mlogloss')
    if name == 'LightGBM':
        import lightgbm as lgb
        return lgb.LGBMClassifier(n_estimators=300, num_leaves=127, learning_rate=0.1, subsample=0.8,
                                  subsample_freq=1, colsample_bytree=0.8, random_state=SEED, n_jobs=-1,
                                  verbose=-1)
    if name == 'RandomForest':
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(n_estimators=100, max_depth=24, min_samples_leaf=2, max_samples=0.3,
                                      n_jobs=2, random_state=SEED)
    raise ValueError(name)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = [(m, s, c) for m in ['XGBoost', 'LightGBM', 'RandomForest']
            for s in ['random', 'temporal'] for c in ['raw', 'r1']]
    todo = [j for j in jobs if not (OUT / f'{j[0]}_{j[1]}_{j[2]}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if not todo:
        return
    raw = get_flagged(columns=NEEDED)
    X_all, meta_all, flags = prepare(raw)
    del raw; gc.collect()
    y_all = meta_all['y'].to_numpy()
    sub_all = meta_all['sub'].astype(str).to_numpy()
    for i, (m, s, c) in enumerate(todo, 1):
        rows = kept_rows(flags, c)
        meta = meta_all.iloc[rows].reset_index(drop=True)
        tr, _, te = splits(meta, s)
        tr, te = rows[tr], rows[te]
        clf = make(m)
        w = compute_sample_weight('balanced', y_all[tr])
        t = time.time()
        clf.fit(X_all[tr], y_all[tr], sample_weight=w)
        fit_s = time.time() - t
        p = np.asarray(clf.predict(X_all[te])).astype(int).ravel()
        r = metrics(y_all[te], p, sub_all[te])
        r.update({'model': m, 'split': s, 'cleaning': c, 'fit_seconds': round(fit_s, 1),
                  'n_train': int(len(tr)), 'n_test': int(len(te)),
                  'confusion': confusion_matrix(y_all[te], p, labels=list(range(len(CLASSES)))).tolist()})
        json.dump(r, open(OUT / f'{m}_{s}_{c}.json', 'w'), indent=1)
        print(f'[{i}/{len(todo)}] {m:12s} {s:8s} {c:3s}  macro-F1={r["macro_f1"]:.4f}  '
              f'bal-acc={r["balanced_accuracy"]:.4f}  acc={r["accuracy"]:.4f}  ({fit_s / 60:.1f} min)', flush=True)
        del clf; gc.collect()


if __name__ == '__main__':
    main()
