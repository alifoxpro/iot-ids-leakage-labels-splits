# -*- coding: utf-8 -*-
"""
pilot_temporal_split.py
=======================
Pilot for the "split design" question: does a random flow-level split inflate the
scores compared with a per-class temporal split?

Same data, same model (XGBoost, class-weighted: n_estimators=200, max_depth=8,
learning_rate=0.1, balanced sample weights; see fit_eval), two splits:
  A  random stratified 70/15/15 split (the protocol used in the paper)
  B  per-class temporal split: within each class, flows are ordered by Timestamp;
     the first 70% train, next 15% validation, last 15% test
     (classes were captured on different days, so one global cut is impossible)
  C  unseen-attack variant: Web-Based trained on SQLi + XSS only and tested on the
     held-out Uploading Attack (reported as recall of the Web-Based class)

For speed, every flow of the six smaller classes is kept and DOS / DDOS are capped
with a uniform random sample (time order is preserved inside the sample).
Exact duplicates (same 76 raw features, within a class) are removed before splitting,
keeping the earliest flow.
Output: results_2026_03_03/split_pilot/pilot_results.json
"""
import glob, json, sys, time, warnings
from pathlib import Path
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

sys.stdout.reconfigure(encoding='utf-8')
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data' / 'CIC IoT-DIAD 2024'
# Stage-1 feature metadata: only feature_columns (the 81 model features, in order) and
# label_mapping (class order) are used. The stage-1 cache is git-ignored, so a fresh clone
# reads the git-tracked stage1_artifacts copy; both files hold identical values for these two
# fields (checked below whenever both are present).
META_CACHE = ROOT / 'results_2026_03_03' / 'multiclass' / 'stage1_cache' / 'metadata.json'
META_TRACKED = (ROOT / 'results_2026_03_03' / 'multiclass' / 'stage1_artifacts'
                / 'CIC_IoT_DIAD_2024_metadata.json')


def _read_meta():
    def load(path):
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def used(m):                                       # the two fields read below, order included
        return list(m['feature_columns']), list(m['label_mapping'].items())

    if not META_CACHE.exists():
        return load(META_TRACKED), META_TRACKED
    cached = load(META_CACHE)
    if META_TRACKED.exists() and used(load(META_TRACKED)) != used(cached):
        raise RuntimeError(f'{META_CACHE} and {META_TRACKED} differ in feature_columns / label_mapping')
    return cached, META_CACHE


META, META_PATH = _read_meta()
FEATS = META['feature_columns']
STATS = ['feat_mean', 'feat_std', 'feat_min', 'feat_max', 'feat_range']
RAW = [c for c in FEATS if c not in STATS]          # 76 CICFlowMeter columns
CLASSES = list(META['label_mapping'].keys())
OUT = ROOT / 'results_2026_03_03' / 'split_pilot'
CAP = {'DOS': 1_500_000, 'DDOS': 1_000_000}
SAMPLE_FRAC = {'DOS': 0.15, 'DDOS': 0.45}               # thin while reading (memory)
SEED = 42
TS_FMT = '%d/%m/%Y %I:%M:%S %p'


def load():
    frames = []
    for cls in CLASSES:
        files = sorted(glob.glob(str(DATA / cls / '**' / '*.csv'), recursive=True))
        parts, n0 = [], 0
        frac = SAMPLE_FRAC.get(cls, 1.0)
        for f in files:                                   # chunked, float32, sampled early
            if 'Timestamp' not in pd.read_csv(f, nrows=0).columns:
                print(f'  skip headerless file: {Path(f).name}')   # empty DOS TCP FLOOD stubs
                continue
            for ch in pd.read_csv(f, usecols=RAW + ['Timestamp'], chunksize=400_000,
                                  low_memory=False):
                n0 += len(ch)
                if frac < 1.0:
                    ch = ch.sample(frac=frac, random_state=SEED)
                for c in RAW:
                    ch[c] = pd.to_numeric(ch[c], errors='coerce').astype(np.float32)
                ch['sub'] = Path(f).parent.name if Path(f).parent.name != cls else cls
                parts.append(ch)
        df = pd.concat(parts, ignore_index=True); del parts
        df[RAW] = df[RAW].replace([np.inf, -np.inf], np.nan)
        df['ts'] = pd.to_datetime(df['Timestamp'], format=TS_FMT, errors='coerce')
        df = df.drop(columns='Timestamp')
        df = df.sort_values('ts', kind='stable').drop_duplicates(subset=RAW, keep='first')
        if cls in CAP and len(df) > CAP[cls]:
            df = df.sample(CAP[cls], random_state=SEED).sort_values('ts', kind='stable')
        df['y'] = CLASSES.index(cls)
        print(f'  {cls:11s} rows={n0:>10,}  after dedup/cap={len(df):>9,}  '
              f'bad ts={df["ts"].isna().sum()}  {df["ts"].min()} -> {df["ts"].max()}', flush=True)
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    v = df[RAW].to_numpy(np.float32)                    # same row-wise stats as stage 1
    df['feat_mean'] = np.nanmean(v, 1); df['feat_std'] = np.nanstd(v, 1)
    df['feat_min'] = np.nanmin(v, 1); df['feat_max'] = np.nanmax(v, 1)
    df['feat_range'] = df['feat_max'] - df['feat_min']
    return df


def temporal_idx(df):
    tr, va, te = [], [], []
    for c in range(len(CLASSES)):
        idx = df.index[df['y'] == c].to_numpy()          # already time-ordered per class
        a, b = int(0.70 * len(idx)), int(0.85 * len(idx))
        tr += list(idx[:a]); va += list(idx[a:b]); te += list(idx[b:])
    return np.array(tr), np.array(va), np.array(te)


def fit_eval(Xtr, ytr, Xte, yte, label):
    med = np.nanmedian(Xtr, axis=0)                      # impute with train statistics only
    Xtr = np.where(np.isnan(Xtr), med, Xtr); Xte = np.where(np.isnan(Xte), med, Xte)
    clf = xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                            tree_method='hist', device='cuda', random_state=SEED,
                            eval_metric='mlogloss')
    t = time.time()
    clf.fit(Xtr, ytr, sample_weight=compute_sample_weight('balanced', ytr))
    p = clf.predict(Xte)
    r = {'accuracy': accuracy_score(yte, p), 'balanced_accuracy': balanced_accuracy_score(yte, p),
         'macro_f1': f1_score(yte, p, average='macro'),
         'per_class_f1': dict(zip(CLASSES, f1_score(yte, p, average=None, labels=range(8)).round(4).tolist())),
         'per_class_recall': dict(zip(CLASSES, recall_score(yte, p, average=None, labels=range(8)).round(4).tolist())),
         'n_train': int(len(ytr)), 'n_test': int(len(yte)), 'fit_seconds': round(time.time() - t, 1)}
    print(f'[{label}] acc={r["accuracy"]:.4f}  bal-acc={r["balanced_accuracy"]:.4f}  '
          f'macro-F1={r["macro_f1"]:.4f}  (train {len(ytr):,}, test {len(yte):,})', flush=True)
    return r, p


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print('[1] loading')
    df = load()
    X, y = df[FEATS].to_numpy(np.float32), df['y'].to_numpy()
    res = {'n_total': int(len(df)), 'caps': CAP}

    print('[2] A: random stratified split')
    tr, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
    tr, _ = train_test_split(tr, test_size=0.15 / 0.85, stratify=y[tr], random_state=SEED)
    res['A_random'], _ = fit_eval(X[tr], y[tr], X[te], y[te], 'A random')

    print('[3] B: per-class temporal split')
    tr, _, te = temporal_idx(df)
    res['B_temporal'], _ = fit_eval(X[tr], y[tr], X[te], y[te], 'B temporal')

    print('[4] C: unseen Web-Based variant (train SQLi+XSS, test Uploading Attack)')
    web = CLASSES.index('Web-Based')
    held = (df['y'] == web) & (df['sub'] == 'Uploading Attack')
    tr_mask = np.zeros(len(df), bool); tr_mask[tr] = True
    tr_c = np.where(tr_mask & ~held.to_numpy())[0]
    te_c = np.where(held.to_numpy())[0]
    _, p = fit_eval(X[tr_c], y[tr_c], X[te_c], y[te_c], 'C unseen-variant')
    rec = float((p == web).mean())
    res['C_unseen_uploading'] = {'web_based_recall': rec, 'n_test': int(len(te_c)),
                                 'predicted_as': {CLASSES[k]: int((p == k).sum()) for k in np.unique(p)}}
    print(f'[C] Uploading Attack recognised as Web-Based: {rec:.3f}  {res["C_unseen_uploading"]["predicted_as"]}')

    json.dump(res, open(OUT / 'pilot_results.json', 'w'), indent=2, default=str)
    print('[DONE]', OUT / 'pilot_results.json')


if __name__ == '__main__':
    main()
