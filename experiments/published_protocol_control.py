# -*- coding: utf-8 -*-
"""
published_protocol_control.py
=============================
Identifier NECESSITY control in the published setting (reviewer request).

identifier_leakage.py showed that the identifier columns are SUFFICIENT for near-perfect scores
on our de-duplicated sample with the eight folder-level classes. The reviewer asks whether they
are also NECESSARY to reach the published accuracy in the setting of the published studies
(Hossain 2025; Ghosh et al. 2025): their class set, no de-duplication, no resampling, a
stratified random 80/20 split and label-encoded categorical columns. If the 81 flow features
alone already reach the published accuracy there, the identifiers are not needed to explain it;
if only the identifier feature sets reach it, they are.

Data (built directly from the raw CSVs on the first run and cached):
  classes    Benign, BruteForce, DDoS, DoS, Mirai, Spoofing (ARP + DNS), SQL Injection, XSS
             (SQL Injection and XSS are separate classes; Recon and Uploading Attack are excluded)
  sampling   DoS / DDoS thinned while reading (SAMPLE_FRAC 0.15 / 0.45) and capped
             (CAP 1.5M / 1.0M, uniform random, seed 42), as in the split pilot; every flow of the
             other classes is kept. NO de-duplication.
  columns    76 CICFlowMeter features (float32, inf -> NaN) + the five row statistics of
             pilot_temporal_split.load = 81 features, plus Flow ID, Src IP, Src Port, Dst IP,
             Dst Port, Protocol and Timestamp (raw string). The text identifiers are label-encoded
             over the whole table, before the split, in sorted order (pd.factorize(sort=True), which
             is what sklearn's LabelEncoder does); ports and protocol are used as numbers.
Design (3 feature sets x 2 weightings = 6 fits):
  features   F0  81 flow features
             FT  F0 + Timestamp (label-encoded raw 'dd/mm/yyyy hh:mm:ss AM' string, so the codes
                 follow the text order, not the time order)
             FA  F0 + all seven identifiers
  weighting  none      (the published study used no resampling)
             balanced  (compute_sample_weight('balanced', y_train))
  model      XGBoost of extra_baselines.make, on the CPU (device='cpu', n_jobs=4: GPU memory)
  split      stratified random 80/20, seed 42 (the same split for every run); NaN/inf -> 0
             before training, as deep_split_noise_study.prepare does
Reported per run: accuracy, balanced accuracy, macro-F1 (plus weighted F1, macro precision and
recall), per-class F1 / recall, per-capture-group recall, confusion matrix, class counts,
n_train / n_test, fit time, gain importance of the identifier columns, and the share of test flows
whose 76 raw values occur exactly in the training part (with the scores on the test flows with and
without such a duplicate).

Output: results_2026_03_03/q1_revision/published_control/
  data.parquet              the built table (first run only)
  data_summary.json         flows read / kept per class and capture group, duplicate shares,
                            number of distinct values of every identifier
  <set>_<weighting>.json    one per run (F0_none, FT_none, FA_none, F0_balanced, ...)
  <set>_<weighting>.npz     test predictions: y, p (int8), sub, idx (row in data.parquet)
  summary.csv               table of the finished runs (--summary, or after the last run)
Resumable: finished runs are skipped.
Run (PowerShell; the cache is built in its own process, then one fit per process):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\published_protocol_control.py --build-only
  for ($i = 0; $i -lt 6; $i++) { & $py experiments\\published_protocol_control.py --max-fits 1 }
  & $py experiments\\published_protocol_control.py --summary
"""
import argparse, gc, json, sys, time, warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deep_split_noise_study as dsn  # noqa: E402
from extra_baselines import make  # noqa: E402
from pilot_temporal_split import CAP, FEATS, RAW, SAMPLE_FRAC, SEED  # noqa: E402
from relabel_background import capture_groups  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'published_control'
CACHE = OUT / 'data.parquet'

# (published class, dataset folder, capture groups used - None = every group of the folder)
PUB = [('Benign', 'Benign', None), ('BruteForce', 'BruteForce', None), ('DDoS', 'DDOS', None),
       ('DoS', 'DOS', None), ('Mirai', 'Mirai', None), ('Spoofing', 'Spoofing', None),
       ('SQL Injection', 'Web-Based', {'Sqlinjection'}), ('XSS', 'Web-Based', {'XSS'})]
PUB_CLASSES = [c for c, _, _ in PUB]
dsn.CLASSES = PUB_CLASSES              # dsn.metrics() takes the class names from its module-level CLASSES
metrics = dsn.metrics

IDS7 = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
STR_IDS = ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp']            # text -> label-encoded
NUM_IDS = ['Src Port', 'Dst Port', 'Protocol']                    # used as numbers
LE = {c: 'le_' + c.lower().replace(' ', '_') for c in STR_IDS}    # 'Flow ID' -> 'le_flow_id'
ID_COLS = [LE.get(c, c) for c in IDS7]                            # model columns, in CSV order
ID_NAME = dict(zip(ID_COLS, IDS7))
FSETS = {'F0': ([], '81 flow features'),
         'FT': ([LE['Timestamp']], '81 flow features + Timestamp (raw string, label-encoded in sorted order)'),
         'FA': (ID_COLS, '81 flow features + Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp '
                         '(text columns label-encoded in sorted order; ports and protocol numeric)')}
WEIGHTINGS = {'none': 'no class weights (the published study used no resampling)',
              'balanced': "compute_sample_weight('balanced', y_train)"}
JOBS = [(f, w) for w in WEIGHTINGS for f in FSETS]                # published weighting first
name = lambda j: f'{j[0]}_{j[1]}'


# ----------------------------------------------------------------------------- data build
def _read(files, frac):
    """Chunked read of the 76 features + 7 identifiers; thinned per chunk as in flagged_loader._read."""
    parts, n_read = [], 0
    for f in files:
        for ch in pd.read_csv(f, usecols=RAW + IDS7, chunksize=400_000, low_memory=False,
                              dtype={c: 'string[pyarrow]' for c in STR_IDS}):     # compact text columns
            n_read += len(ch)
            if frac < 1.0:
                ch = ch.sample(frac=frac, random_state=SEED)
            for c in RAW + NUM_IDS:
                v = pd.to_numeric(ch[c], errors='coerce').to_numpy(np.float32)
                v[np.isinf(v)] = np.nan
                ch[c] = v
            parts.append(ch)
    return pd.concat(parts, ignore_index=True), n_read


def _row_stats(df):
    """The five row statistics of pilot_temporal_split.load (NaN-aware, float32), 500K rows at a time."""
    pos = [df.columns.get_loc(c) for c in RAW]
    st = np.empty((len(df), 5), np.float32)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', RuntimeWarning)           # all-NaN rows -> NaN, as in the pilot
        for i in range(0, len(df), 500_000):
            v = df.iloc[i:i + 500_000, pos].to_numpy(np.float32)
            j = i + len(v)
            st[i:j, 0] = np.nanmean(v, 1); st[i:j, 1] = np.nanstd(v, 1)
            st[i:j, 2] = np.nanmin(v, 1); st[i:j, 3] = np.nanmax(v, 1)
    st[:, 4] = st[:, 3] - st[:, 2]
    for k, c in enumerate(['feat_mean', 'feat_std', 'feat_min', 'feat_max', 'feat_range']):
        df[c] = st[:, k]


def _raw_hash(df):
    """64-bit key of the 76 raw values of each flow (NaN == NaN, -0 == +0) for exact-duplicate tests."""
    h = np.zeros(len(df), np.uint64)
    for c in RAW:
        v = df[c].to_numpy(np.float32, copy=True)
        v += np.float32(0)                                        # -0.0 -> +0.0
        v[np.isnan(v)] = np.nan                                   # a single NaN bit pattern
        h = (h * np.uint64(1099511628211)) ^ pd.util.hash_array(v)
    return h


def build():
    print('[build] reading the raw CSVs (first run only, slow)', flush=True)
    frames, per_class = [], {}
    for k, (cls, folder, groups) in enumerate(PUB):
        frac, cap = SAMPLE_FRAC.get(folder, 1.0), CAP.get(folder)
        parts, info, n_read = [], {}, 0
        for sub, files in capture_groups(folder):
            if groups is not None and sub not in groups:
                continue
            df, n = _read(files, frac)
            df['sub'] = sub
            info[sub] = {'files': len(files), 'flows_read': int(n), 'after_read_sampling': int(len(df))}
            n_read += n
            parts.append(df)
        if not parts:                                             # folder or group names changed
            raise RuntimeError(f'no CSV files found for class {cls!r} (folder {folder!r}, groups {groups})')
        df = pd.concat(parts, ignore_index=True); del parts
        n_s = len(df)
        if cap and n_s > cap:                                     # uniform sample, file order kept
            df = df.sample(cap, random_state=SEED).sort_index().reset_index(drop=True)
        df['y'] = np.full(len(df), k, np.int8)
        kept = df['sub'].value_counts()
        for s in info:
            info[s]['kept'] = int(kept.get(s, 0))
        per_class[cls] = {'folder': folder, 'sample_frac': frac, 'cap': cap, 'flows_read': int(n_read),
                          'after_read_sampling': int(n_s), 'kept': int(len(df)), 'groups': info}
        print(f'  {cls:13s} read={n_read:>10,}  after read-sampling={n_s:>9,}  kept={len(df):>9,}', flush=True)
        frames.append(df); gc.collect()
    df = pd.concat(frames, ignore_index=True); del frames; gc.collect()
    df['sub'] = df['sub'].astype('category')
    _row_stats(df)
    df['raw_hash'] = _raw_hash(df)
    for c in STR_IDS:                                             # whole table, before the split
        df[LE[c]] = pd.factorize(df[c], sort=True)[0].astype(np.int32)

    h, y = df['raw_hash'].to_numpy(), df['y'].to_numpy()
    hy = pd.DataFrame({'h': h, 'y': y}).drop_duplicates()
    multi = hy.loc[hy['h'].duplicated(keep=False), 'h'].unique()   # raw vectors seen under >1 class
    summ = {'classes': PUB_CLASSES, 'n_flows': int(len(df)), 'deduplicated': False,
            'class_counts': {c: int(n) for c, n in zip(PUB_CLASSES, np.bincount(y, minlength=len(PUB)))},
            'per_class': per_class,
            'exact_duplicate_share': {                            # rows that repeat an earlier row (76 raw values)
                'all_classes': round(1 - len(np.unique(h)) / len(h), 4),
                **{c: round(1 - len(np.unique(h[y == k])) / max(int((y == k).sum()), 1), 4)
                   for k, c in enumerate(PUB_CLASSES)}},
            'rows_whose_raw_vector_occurs_under_another_class': round(float(np.isin(h, multi).mean()), 4),
            'distinct_values': {c: int(df[c].nunique()) for c in IDS7}}
    del hy, multi; gc.collect()
    with open(OUT / 'data_summary.json', 'w') as fh:              # written before the cache appears, so that
        json.dump(summ, fh, indent=1)                             # a finished cache always has its summary
    tmp = CACHE.with_name('data.tmp.parquet')
    df.to_parquet(tmp, index=False)
    tmp.replace(CACHE)                                            # no half-written cache after a crash
    print(f'[build] cached {CACHE.name}: {len(df):,} flows, {df.shape[1]} columns; exact duplicates '
          f'{summ["exact_duplicate_share"]["all_classes"]:.1%}; distinct timestamps '
          f'{summ["distinct_values"]["Timestamp"]:,}', flush=True)
    del df, h, y; gc.collect()


# ----------------------------------------------------------------------------- experiment
def load(cols):
    """Row-aligned arrays from the cache, read one column at a time (no second full copy in RAM)."""
    import pyarrow.parquet as pq
    col = lambda c: pq.read_table(CACHE, columns=[c]).column(0)
    X = np.empty((pq.ParquetFile(CACHE).metadata.num_rows, len(cols)), np.float32)
    for j, c in enumerate(cols):
        X[:, j] = col(c).to_numpy()
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)   # as deep_split_noise_study.prepare
    y = col('y').to_numpy().astype(np.int64)
    h = col('raw_hash').to_numpy()
    sub = col('sub').to_pandas().astype(str).to_numpy()
    return X, y, h, sub


def dup_report(h, y, tr, te):
    """Which test flows have their 76 raw values in the training part (any label / same label)."""
    hy = h ^ ((y.astype(np.uint64) + np.uint64(1)) * np.uint64(0x9E3779B97F4A7C15))
    any_ = np.isin(h[te], h[tr])
    same = np.isin(hy[te], hy[tr])
    yt = y[te]
    per = lambda m: {c: round(float(m[yt == k].mean()), 4) for k, c in enumerate(PUB_CLASSES)}
    return any_, {
        'definition': 'test flow whose 76 raw CICFlowMeter values (NaN == NaN) occur in a training flow '
                      '(64-bit row hash)',
        'share_any': round(float(any_.mean()), 4),
        'share_same_label': round(float(same.mean()), 4),
        'share_other_label_only': round(float((any_ & ~same).mean()), 4),
        'per_class_share_any': per(any_), 'per_class_share_same_label': per(same)}


def subset_scores(y, p, m):
    if not m.any():
        return {'n': 0}
    lab = np.unique(y[m])                                         # macro over the classes present
    return {'n': int(m.sum()), 'accuracy': round(float(accuracy_score(y[m], p[m])), 4),
            'macro_f1': round(float(f1_score(y[m], p[m], labels=lab, average='macro', zero_division=0)), 4),
            'per_class_recall': {PUB_CLASSES[c]: round(float((p[m][y[m] == c] == c).mean()), 4) for c in lab}}


def summary():
    rows = [json.load(open(OUT / f'{name(j)}.json')) for j in JOBS if (OUT / f'{name(j)}.json').exists()]
    if not rows:
        print('no finished runs yet'); return
    t = pd.DataFrame([{'run': r['run'], 'accuracy': r['accuracy'], 'bal_acc': r['balanced_accuracy'],
                       'macro_f1': r['macro_f1'], 'weighted_f1': r['weighted_f1'],
                       'macro_f1_no_dup': r['test_subsets']['without_train_duplicate'].get('macro_f1'),
                       'test_dup_share': r['test_duplicates']['share_any'],
                       'n_train': r['n_train'], 'n_test': r['n_test'], 'fit_min': r['fit_seconds'] / 60}
                      for r in rows])
    pd.set_option('display.width', 180)
    print('\n=== published-setting control (XGBoost, stratified random 80/20) ===')
    print(t.round(4).to_string(index=False))
    print('\n=== per-class F1 ===')
    print(pd.DataFrame([{'run': r['run'], **r['per_class_f1']} for r in rows]).set_index('run').round(3).to_string())
    t.to_csv(OUT / 'summary.csv', index=False)
    print('\n[saved]', OUT / 'summary.csv')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit); run with 1 inside a PowerShell loop so that '
                         'every fit starts in a fresh process')
    ap.add_argument('--build-only', action='store_true', help='only build the data cache, then exit')
    ap.add_argument('--summary', action='store_true', help='only print the table of finished runs')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return
    todo = [j for j in JOBS if not (OUT / f'{name(j)}.json').exists()]
    print(f'[plan] {len(JOBS)} runs, {len(JOBS) - len(todo)} finished, {len(todo)} to do', flush=True)
    if not CACHE.exists():
        build()
    if a.build_only:
        return
    if not todo:
        summary(); return

    batch = todo[:a.max_fits] if a.max_fits else todo
    cols = FEATS + [c for c in ID_COLS if any(c in FSETS[f][0] for f, _ in batch)]   # only what is needed
    X, y, h, sub = load(cols)
    tr, te = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=SEED)
    has_dup, dup = dup_report(h, y, tr, te)
    del h; gc.collect()
    print(f'[data] {len(y):,} flows x {len(cols)} columns; train {len(tr):,}, test {len(te):,}; '
          f'test flows with an exact duplicate in train: {dup["share_any"]:.1%}', flush=True)
    counts = lambda v: {c: int(n) for c, n in zip(PUB_CLASSES, np.bincount(v, minlength=len(PUB)))}
    class_counts = {'all': counts(y), 'train': counts(y[tr]), 'test': counts(y[te])}
    labels = list(range(len(PUB)))
    yt, st = y[te], sub[te]

    for i, (f, w) in enumerate(batch, 1):
        extra = FSETS[f][0]
        cidx = np.array(list(range(len(FEATS))) + [cols.index(c) for c in extra])
        clf = make('XGBoost')
        clf.set_params(device='cpu', n_jobs=4)
        Xtr = X[np.ix_(tr, cidx)]
        Xte = X[np.ix_(te, cidx)]
        if i == len(batch):                   # last fit of this process: free the full matrix (~1 GB) before training
            del X; gc.collect()
        sw = compute_sample_weight('balanced', y[tr]) if w == 'balanced' else None
        t = time.time()
        clf.fit(Xtr, y[tr], sample_weight=sw)
        fit_s = time.time() - t
        del Xtr, sw; gc.collect()
        p = np.asarray(clf.predict(Xte)).astype(np.int8).ravel()
        del Xte

        r = metrics(yt, p, st)
        names = FEATS + [ID_NAME[c] for c in extra]
        imp = np.asarray(clf.feature_importances_, float)
        order = np.argsort(-imp)
        rank = np.empty(len(imp), int); rank[order] = np.arange(1, len(imp) + 1)
        prm = clf.get_params()
        r.update({
            'run': name((f, w)), 'feature_set': f, 'features': FSETS[f][1], 'weighting': w,
            'weighting_desc': WEIGHTINGS[w], 'n_features': int(len(cidx)),
            'description': 'identifier necessity control in the published setting: classes '
                           + ', '.join(PUB_CLASSES) + '; no de-duplication; DoS/DDoS thinned while reading and '
                           'capped; stratified random 80/20 split (seed 42); XGBoost (extra_baselines.make) on '
                           'the CPU; NaN/inf -> 0; text identifiers label-encoded (sorted) over the whole table',
            'model': 'XGBoost',
            'model_params': {k: prm[k] for k in ('n_estimators', 'max_depth', 'learning_rate', 'tree_method',
                                                 'device', 'n_jobs', 'random_state')},
            'split': 'stratified random 80/20, seed 42',
            'n_train': int(len(tr)), 'n_test': int(len(te)), 'fit_seconds': round(fit_s, 1),
            'weighted_f1': float(f1_score(yt, p, labels=labels, average='weighted', zero_division=0)),
            'macro_precision': float(precision_score(yt, p, labels=labels, average='macro', zero_division=0)),
            'macro_recall': float(recall_score(yt, p, labels=labels, average='macro', zero_division=0)),
            'labels': PUB_CLASSES,
            'confusion': confusion_matrix(yt, p, labels=labels).tolist(),
            'class_counts': class_counts,
            'test_duplicates': dup,
            'test_subsets': {'with_train_duplicate': subset_scores(yt, p, has_dup),
                             'without_train_duplicate': subset_scores(yt, p, ~has_dup)},
            'importance_gain_top15': {names[q]: round(float(imp[q]), 4) for q in order[:15]},
            'identifier_importance': {names[q]: {'gain_share': round(float(imp[q]), 4), 'rank': int(rank[q])}
                                      for q in range(len(FEATS), len(names))}})
        np.savez_compressed(OUT / f'{name((f, w))}.npz', y=yt.astype(np.int8), p=p,
                            sub=st.astype(str), idx=te.astype(np.int32))   # 'U' array: loads without pickle
        txt = json.dumps(r, indent=1)                             # serialise first: the JSON marks the run as
        with open(OUT / f'{name((f, w))}.json', 'w') as fh:       # finished, so it must never be half-written
            fh.write(txt)
        print(f'[{len(JOBS) - len(todo) + i}/{len(JOBS)}] {f} {w:8s} acc={r["accuracy"]:.4f}  '
              f'bal-acc={r["balanced_accuracy"]:.4f}  macro-F1={r["macro_f1"]:.4f}  '
              f'(test without train duplicate: macro-F1={r["test_subsets"]["without_train_duplicate"].get("macro_f1", float("nan")):.4f})  '
              f'({fit_s / 60:.1f} min)', flush=True)
        del clf, p; gc.collect()
    left = len(todo) - len(batch)
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)
    if not left:
        summary()


if __name__ == '__main__':
    main()
