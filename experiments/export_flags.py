# -*- coding: utf-8 -*-
"""
export_flags.py
===============
Reviewer request (meth-00): publish the per-flow background flags R1/R2/R3 and the split
membership as a compact file keyed by source CSV and row number, so that the cleaned samples
and the partitions of the paper can be used without re-running the pipeline.

The flagged sample of flagged_loader.py (3,626,502 flows, cached as
results_2026_03_03/split_pilot/flagged_data.parquet) does not record where a flow came from.
This script rebuilds the sample EXACTLY as flagged_loader._build does - same CSV files in the
same order (relabel_background.capture_groups), same chunked read (chunksize 400,000), same
thinning of DOS / DDOS while reading (DataFrame.sample, seed 42; the draw depends only on the
chunk length), same inf -> NaN, same stable time sort and de-duplication on the 76 raw features
inside each class, same caps, same rules R1-R3 - but every flow also carries
  csv   its source file (relative to data/CIC IoT-DIAD 2024/, forward slashes) and
  row   its 0-based record number in that file: row 0 is the first line after the header, in
        the numbering of pandas.read_csv (blank lines, if any, are not counted).
The classes are processed one at a time; only a compact frame of each finished class is kept.

Verification against the cache (when flagged_data.parquet exists): every class is compared
row for row, in the stored order, with its rows in the cache. Column by column, a SHA-1 digest
of the values (NaN made canonical) and, on a digest mismatch, the number of differing rows.
  required   the 76 raw features, y, sub, the number and position of the rows, ts, Src IP,
             Dst IP, Dst Port, Protocol and r1_external / r2_service / r3_benign_pair
  derived    the five row statistics (feat_mean ... feat_range) are computed from the 76 raw
             features per class here and over the whole table in _build; they must be equal or
             differ only by float32 rounding (|difference| <= 1e-5 x the row's largest |feature|)
The cache is read one column and only the row groups holding the class at a time (a few MB).
Mapping check (--spot-check K, default 20): for K rows per CSV file, drawn among the rows of the
sample with a record number < 100,000 (so only the start of the large files is scanned), the raw
CSV record is read again with Python's csv module; its 76 features (inf -> NaN, float32),
timestamp and addresses must equal the rebuilt flow.

Split membership (full run only, all eight classes): deep_split_noise_study.splits(meta, s) for
s = random | temporal, with meta = y, sub (category), ts and index 0..N-1 as in load_prepared /
cleaning_train_only.py,
  on all rows   (raw folder labels; the partition of every raw-label run)           and
  on R1 rows    rows = kept_rows(flags, 'r1'); splits(meta.iloc[rows].reset_index(drop=True), s),
                mapped back with rows[...] (tree_protocol_study.py, deep_split_noise_study.run_one).
Cross-checked, where the files exist, with the stored runs of the experiments:
  tree_protocol/main/XGBoost_<split>_<raw|r1>_s42.npz       y and sub of the test rows, in order
  tree_protocol/main/XGBoost_<split>_<raw|r1>_s42.json      n_train and n_test
  deep_split/ResNet1D_<split>_<raw|r1>_s42.json             n_train, n_val and n_test
  q1_revision/tree_seeds/runs/XGBoost_<split>_<raw|r1>_s42.npz   rows (global positions)
  tree_protocol/decomp/XGBoost_<split>_train-raw_test-r1.npz  y and sub of the R1-kept test rows
  q1_revision/cleaning_train_only/XGBoost_<split>_train-none_test-R1.npz   rows (global positions)
  q1_revision/symmetric_r1/XGBoost_<split>_relabel.npz                     rows (raw partition)
The partitions of the other designs follow from these columns: the train/test-cleaning runs
(tree_protocol 'decomp', cleaning_train_only.py) use split_random / split_temporal and then drop
the flagged rows of the training and/or test part; the Table 4 variants (rule_sensitivity.py,
variant_seeds.py) re-draw the split on each variant's kept rows and are not exported.

Output: results_2026_03_03/q1_revision/export_flags/
  flow_flags.csv.gz, flow_flags.parquet   one line per flow of the sample, sorted by (csv, row):
      csv, row                            key (see above)
      idx                                 row position in flagged_data.parquet = the global row
                                          position used by all experiments (e.g. the 'rows' arrays
                                          of the q1_revision npz files)
      y                                   class index (0 Benign, 1 BruteForce, 2 DDOS, 3 DOS,
                                          4 Mirai, 5 Recon, 6 Spoofing, 7 Web-Based)
      sub                                 capture group (sub-folder, or the class)
      r1_external, r2_service, r3_benign_pair   0/1 (always 0 for Benign)
      split_random, split_temporal        train | val | test on all rows
      split_random_r1, split_temporal_r1  train | val | test on the R1-kept rows, 'excluded' for
                                          the R1-flagged rows
  files.csv            every CSV read: class, capture group, records in the file, records after
                       the DOS/DDOS thinning, flows in the sample
  export_flags.json    definitions, counts per class and split, verification, mapping check,
                       cross-checks, SHA-256 of the two export files, versions, git commit
  parts/<class>.parquet|json, parts/benign_pairs.parquet
                       per-class checkpoints (resume); may be deleted after the export
  flow_flags.csv.gz is the file meant for git (*.parquet is git-ignored); it is written with LF
  line ends, a fixed gzip header time and the stored name flow_flags.csv, so a rebuild gives a
  byte-identical file on any OS (SHA-256 in export_flags.json).
  Reading it back:  pd.read_csv('flow_flags.csv.gz', dtype={'csv': 'category', 'sub': 'category'})
Selftest on a few small classes (e.g. --classes Web-Based, 5.8 MB of CSV, includes the XSS
files) writes to export_flags/selftest/ and exports without split columns (the partitions
need all rows). Without Benign in --classes, the Benign IP pairs for R3 are taken from the
Benign rows of the cache (after de-duplication), so r3 is then only approximately checked.

Resumable: a class whose parts/<class>.json exists is not rebuilt; when export_flags.json
exists the script only reports it (--force rebuilds everything). No model is trained, so there
is no --max-fits; the classes are the resumable units (a crash loses at most one class).
Runtime: the full run reads all CSVs once (about as long as the first flagged_loader run);
peak memory is about that of the largest class (DOS: the thinned DOS CSVs plus the cache columns
of its row groups, one at a time), well below the peak of flagged_loader._build, which holds all
classes at once. If the rebuild does not match the cache, the CSV mapping check fails or a
partition differs from a stored run, nothing is exported and export_flags_FAILED.json lists the
problems (per class: the differing columns; --allow-mismatch exports anyway, with verified=false).
'verified' in export_flags.json is true only when the cache was there and every check passed.
Run (PowerShell, from the project folder):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  # selftest on the Web-Based captures (SQL injection, XSS, uploading; every record re-read from the CSV)
  & $py experiments\\export_flags.py --classes Web-Based --spot-check 100000 2>&1 | Tee-Object -FilePath export_flags_selftest.log
  # full export (all eight classes, split membership, cross-checks)
  & $py experiments\\export_flags.py 2>&1 | Tee-Object -FilePath export_flags.log
"""
import argparse, csv, gc, gzip, hashlib, io, json, subprocess, sys, time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, splits  # noqa: E402
from flagged_loader import CACHE, FLAGS, IDS  # noqa: E402
from pilot_temporal_split import (CAP, CLASSES, DATA, FEATS, META_PATH, RAW, SAMPLE_FRAC,  # noqa: E402
                                  SEED, TS_FMT)
from relabel_background import DNS_ATTACK, SERVICE_PORTS, capture_groups, internal, pair_key  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'export_flags'
RES = ROOT / 'results_2026_03_03'
STATS = [c for c in FEATS if c not in RAW]                      # feat_mean ... feat_range
REQUIRED = RAW + ['y', 'sub', 'ts', 'Src IP', 'Dst IP', 'Dst Port', 'Protocol'] + FLAGS
SPLIT_LABELS = ['train', 'val', 'test', 'excluded']             # codes 0..3
SPLIT_COLS = {('random', 'all'): 'split_random', ('temporal', 'all'): 'split_temporal',
              ('random', 'r1'): 'split_random_r1', ('temporal', 'r1'): 'split_temporal_r1'}
SPOT_MAXROW = 100_000
STAT_RTOL = 1e-5


def rel(path):
    return Path(path).resolve().relative_to(DATA.resolve()).as_posix()


def file_table():
    """Every CSV that flagged_loader._build reads, in reading order."""
    return [{'csv': rel(f), 'class': cls, 'sub': sub}
            for cls in CLASSES for sub, files in capture_groups(cls) for f in files]


def cls_slug(cls):
    return cls.replace(' ', '_').replace('/', '_')


# ------------------------------------------------------------------ rebuild (mirror of flagged_loader)
def read_group(files, frac, file_id, fstats):
    """flagged_loader._read plus csv_id (source file) and row (0-based record number)."""
    parts = []
    for f in files:
        fid = file_id[rel(f)]
        n_rec = n_kept = 0
        for ch in pd.read_csv(f, usecols=RAW + IDS + ['Timestamp'], chunksize=400_000, low_memory=False):
            if len(ch) and ch.index[0] != n_rec:                  # RangeIndex continues over chunks
                raise RuntimeError(f'{rel(f)}: chunk index {ch.index[0]} != records read {n_rec}')
            ch['row'] = ch.index.to_numpy(np.int64)
            n_rec += len(ch)
            if frac < 1.0:
                ch = ch.sample(frac=frac, random_state=SEED)       # draw depends only on len(ch)
            for c in RAW:
                ch[c] = pd.to_numeric(ch[c], errors='coerce').astype(np.float32)
            ch['csv_id'] = np.int16(fid)
            n_kept += len(ch)
            parts.append(ch)
        fstats[fid] = {'records': n_rec, 'after_thinning': n_kept}
    return pd.concat(parts, ignore_index=True)


def build_class(cls, file_id, benign_pairs, fstats):
    """One class of flagged_loader._build, line for line, with csv_id / row carried along."""
    parts = []
    for sub, files in capture_groups(cls):
        df = read_group(files, SAMPLE_FRAC.get(cls, 1.0), file_id, fstats)
        df[RAW] = df[RAW].replace([np.inf, -np.inf], np.nan)
        df['ts'] = pd.to_datetime(df['Timestamp'], format=TS_FMT, errors='coerce')
        df['sub'] = sub
        key = pair_key(df['Src IP'], df['Dst IP'])
        if cls == 'Benign':
            benign_pairs = set(key)                               # as _build: set per Benign group
            for f in FLAGS:
                df[f] = False
        else:
            if benign_pairs is None:
                raise RuntimeError('Benign IP pairs are needed for R3')
            df['r1_external'] = ~(internal(df['Src IP']) & internal(df['Dst IP']))
            svc = df['Src Port'].isin(SERVICE_PORTS) | df['Dst Port'].isin(SERVICE_PORTS)
            if sub == DNS_ATTACK:
                svc = svc & ~((df['Src Port'] == 53) | (df['Dst Port'] == 53))
            df['r2_service'] = svc.to_numpy()
            df['r3_benign_pair'] = pd.Series(key).isin(benign_pairs).to_numpy()
        parts.append(df.drop(columns=['Timestamp', 'Src Port']))
        del df, key
    df = pd.concat(parts, ignore_index=True)
    del parts
    df = df.sort_values('ts', kind='stable').drop_duplicates(subset=RAW, keep='first')
    if cls in CAP and len(df) > CAP[cls]:
        df = df.sample(CAP[cls], random_state=SEED).sort_values('ts', kind='stable')
    df['y'] = CLASSES.index(cls)
    v = df[RAW].to_numpy(np.float32)
    df['feat_mean'] = np.nanmean(v, 1); df['feat_std'] = np.nanstd(v, 1)
    df['feat_min'] = np.nanmin(v, 1); df['feat_max'] = np.nanmax(v, 1)
    df['feat_range'] = df['feat_max'] - df['feat_min']
    del v
    return df.reset_index(drop=True), benign_pairs


# ------------------------------------------------------------------ cache access (lean)
class Cache:
    """flagged_data.parquet, read one column and only the needed row groups at a time."""

    def __init__(self, path):
        import pyarrow.parquet as pq
        self.pf = pq.ParquetFile(path)
        md = self.pf.metadata
        self.n = md.num_rows
        self.starts = np.cumsum([0] + [md.row_group(i).num_rows for i in range(md.num_row_groups)])
        iy = self.pf.schema_arrow.names.index('y')
        self.yrange = []
        for i in range(md.num_row_groups):
            st = md.row_group(i).column(iy).statistics
            self.yrange.append((st.min, st.max) if st is not None and st.has_min_max else None)

    def class_positions(self, c):
        pos = []
        for g, rng in enumerate(self.yrange):
            if rng is not None and not (rng[0] <= c <= rng[1]):
                continue
            y = self.pf.read_row_group(g, columns=['y'], use_threads=False).column(0).to_numpy()
            pos.append(self.starts[g] + np.flatnonzero(y == c))
        return np.concatenate(pos).astype(np.int64) if pos else np.zeros(0, np.int64)

    def values(self, col, pos):
        g0 = int(np.searchsorted(self.starts, pos.min(), 'right') - 1)
        g1 = int(np.searchsorted(self.starts, pos.max(), 'right') - 1)
        t = self.pf.read_row_groups(list(range(g0, g1 + 1)), columns=[col], use_threads=False).column(0)
        return t.to_numpy()[pos - self.starts[g0]]


def canon_bytes(v):
    v = np.asarray(v)
    if v.dtype.kind == 'f':
        v = v.copy(); v[np.isnan(v)] = np.nan
        return v.tobytes()
    if v.dtype.kind == 'M':
        return v.astype('datetime64[ns]').view(np.int64).tobytes()
    if v.dtype.kind in 'OUS':
        return '\x1f'.join(map(str, v)).encode('utf-8')
    return v.astype(np.int64).tobytes()


def equal_mask(a, b):
    a, b = np.asarray(a), np.asarray(b)
    if a.dtype.kind == 'f' or b.dtype.kind == 'f':
        a, b = a.astype(np.float64), b.astype(np.float64)
        return (a == b) | (np.isnan(a) & np.isnan(b))
    if a.dtype.kind == 'M' or b.dtype.kind == 'M':
        return a.astype('datetime64[ns]').view(np.int64) == b.astype('datetime64[ns]').view(np.int64)
    if a.dtype.kind in 'OUS' or b.dtype.kind in 'OUS':
        return a.astype(str) == b.astype(str)
    return a.astype(np.int64) == b.astype(np.int64)


def verify_class(df, cache, c, offset, approx_r3):
    """Row-for-row comparison of one rebuilt class with its rows in the cache."""
    pos = cache.class_positions(c)
    rep = {'n_rebuilt': int(len(df)), 'n_cache': int(len(pos)), 'columns_checked': 0,
           'columns_identical': 0, 'mismatch': {}, 'stats_rounding': {}}
    if offset is not None:                                        # full run: class rows are contiguous
        rep['cache_rows'] = [int(pos[0]) if len(pos) else None, int(pos[-1]) + 1 if len(pos) else None]
        rep['contiguous_at_expected_offset'] = bool(len(pos) and pos[0] == offset
                                                    and np.all(np.diff(pos) == 1))
    if len(pos) != len(df):
        rep['ok'] = False
        rep['error'] = 'different number of rows'
        return rep, pos
    for col in REQUIRED + STATS:
        ours, theirs = df[col].to_numpy(), cache.values(col, pos)
        rep['columns_checked'] += 1
        if hashlib.sha1(canon_bytes(ours)).digest() == hashlib.sha1(canon_bytes(theirs)).digest():
            rep['columns_identical'] += 1
            continue
        n_diff = int((~equal_mask(ours, theirs)).sum())
        if n_diff == 0:                                           # e.g. -0.0 vs 0.0: equal values
            rep['columns_identical'] += 1
            continue
        if col in STATS:
            # float32 summation order may differ between a per-class and a whole-table reduction;
            # the error is bounded relative to the row's largest |feature|, not to the statistic
            # itself (a std or mean near 0 would otherwise give a huge relative difference)
            a, b = ours.astype(np.float64), theirs.astype(np.float64)
            both = ~(np.isnan(a) | np.isnan(b))
            err = np.abs(a[both] - b[both])
            scale = np.maximum(np.abs(df['feat_min'].to_numpy(np.float64)),
                               np.abs(df['feat_max'].to_numpy(np.float64)))[both]
            scale = np.maximum(np.nan_to_num(scale, nan=0.0), np.finfo(np.float32).tiny)
            rdiff = err / np.maximum(np.abs(b[both]), 1e-30)
            sdiff = err / scale
            nan_ok = bool(np.array_equal(np.isnan(a), np.isnan(b)))
            rep['stats_rounding'][col] = {'n_diff': n_diff, 'max_rel_diff': float(rdiff.max(initial=0.0)),
                                          'max_diff_rel_to_row_scale': float(sdiff.max(initial=0.0)),
                                          'nan_pattern_equal': nan_ok}
            if nan_ok and sdiff.max(initial=0.0) <= STAT_RTOL:
                continue
        rep['mismatch'][col] = n_diff
    hard = [k for k in rep['mismatch'] if not (approx_r3 and k == 'r3_benign_pair')]
    rep['ok'] = (not hard) and rep.get('contiguous_at_expected_offset', True)
    if approx_r3:
        rep['note'] = 'r3 approximate: Benign pairs taken from the de-duplicated Benign rows of the cache'
    return rep, pos


# ------------------------------------------------------------------ mapping check against the raw CSV
def _num(x):
    try:
        v = float(x)
    except ValueError:
        return np.nan
    return np.nan if np.isinf(v) else v


def spot_check(df, files, k, rng):
    rep = {'rows_checked': 0, 'files_checked': 0, 'features_exact': 0, 'features_close': 0,
           'ts_equal': 0, 'ips_equal': 0, 'max_rel_diff': 0.0, 'failures': [], 'ok': None}
    if k <= 0:                                                    # check switched off
        return rep
    ids, rows = df['csv_id'].to_numpy(), df['row'].to_numpy()
    for fid in np.unique(ids):
        cand = np.flatnonzero((ids == fid) & (rows < SPOT_MAXROW))
        if not len(cand):
            continue
        if len(cand) > k:
            cand = rng.choice(cand, k, replace=False)
        pick = cand[np.argsort(rows[cand], kind='stable')]
        want = {int(r): i for i, r in enumerate(rows[pick])}
        last, got = max(want), {}
        with open(DATA / files[fid]['csv'], newline='', encoding='utf-8-sig', errors='replace') as fh:
            rd = csv.reader(fh)
            col = {h: i for i, h in enumerate(next(rd))}
            rec_no = -1
            for rec in rd:
                if not rec:                                       # pandas skips blank lines
                    continue
                rec_no += 1
                if rec_no in want:
                    got[rec_no] = rec
                if rec_no >= last:
                    break
        sel = df.iloc[pick]
        ours = sel[RAW].to_numpy(np.float32)
        ts, src, dst = sel['ts'].to_numpy(), sel['Src IP'].astype(str).to_numpy(), sel['Dst IP'].astype(str).to_numpy()
        rep['files_checked'] += 1
        for r, i in want.items():
            rec = got.get(r)
            rep['rows_checked'] += 1
            if rec is None:
                rep['failures'].append({'csv': files[fid]['csv'], 'row': r, 'why': 'record not found'})
                continue
            raw = np.array([_num(rec[col[c]]) for c in RAW], np.float64).astype(np.float32)
            eq = equal_mask(raw, ours[i])
            a, b = raw.astype(np.float64), ours[i].astype(np.float64)
            fin = ~(np.isnan(a) | np.isnan(b))
            rd_ = float((np.abs(a[fin] - b[fin]) / np.maximum(np.abs(b[fin]), 1e-30)).max(initial=0.0))
            close = bool(np.array_equal(np.isnan(a), np.isnan(b)) and rd_ <= 1e-6)
            rep['features_exact'] += int(eq.all()); rep['features_close'] += int(close)
            rep['max_rel_diff'] = max(rep['max_rel_diff'], rd_)
            t = pd.to_datetime(rec[col['Timestamp']], format=TS_FMT, errors='coerce')
            t_ok = bool((pd.isna(t) and pd.isna(ts[i])) or (not pd.isna(t) and t.to_datetime64() == ts[i]))
            ip_ok = rec[col['Src IP']] == src[i] and rec[col['Dst IP']] == dst[i]
            rep['ts_equal'] += int(t_ok); rep['ips_equal'] += int(ip_ok)
            if not (close and t_ok and ip_ok) and len(rep['failures']) < 20:
                rep['failures'].append({'csv': files[fid]['csv'], 'row': r, 'features_close': close,
                                        'ts_equal': bool(t_ok), 'ips_equal': bool(ip_ok)})
    n = rep['rows_checked']
    rep['ok'] = n == rep['features_close'] == rep['ts_equal'] == rep['ips_equal']
    return rep


# ------------------------------------------------------------------ splits and cross-checks
def split_codes(meta, flags):
    """Split membership exactly as in the experiments: codes 0 train, 1 val, 2 test, 3 excluded."""
    n = len(meta)
    keep = np.zeros(n, bool)
    r1rows = kept_rows(flags, 'r1')
    keep[r1rows] = True
    codes, tests = {}, {}
    for (s, cond), name in SPLIT_COLS.items():
        if cond == 'all':
            tr, va, te = splits(meta, s)
        else:
            tr, va, te = splits(meta.iloc[r1rows].reset_index(drop=True), s)
            tr, va, te = r1rows[tr], r1rows[va], r1rows[te]
        code = np.full(n, 3, np.int8)
        for k, part in enumerate((tr, va, te)):
            if (code[part] != 3).any() or len(np.unique(part)) != len(part):
                raise RuntimeError(f'{name}: parts overlap')
            code[part] = k
        covered = code != 3
        if not np.array_equal(covered, np.ones(n, bool) if cond == 'all' else keep):
            raise RuntimeError(f'{name}: parts do not cover the row set')
        codes[name], tests[(s, cond)] = code, te
        print(f'  {name:18s} train={len(tr):>9,} val={len(va):>9,} test={len(te):>9,}', flush=True)
    return codes, tests


def cross_checks(tests, codes, y, sub, r1):
    """Compare the rebuilt partitions with the stored runs of the experiments (files that exist)."""
    out = []

    def add(name, path, fn):
        if not path.exists():
            out.append({'check': name, 'file': path.relative_to(RES).as_posix(), 'ok': None, 'note': 'file missing'})
            return
        try:
            ok, info = fn(path)
        except Exception as e:                                    # a check must never stop the export
            ok, info = False, {'error': repr(e)}
        out.append({'check': name, 'file': path.relative_to(RES).as_posix(), 'ok': bool(ok), **info})

    def seq(te):
        def fn(p):
            d = np.load(p, allow_pickle=True)
            oky = np.array_equal(d['y'].astype(np.int64), y[te].astype(np.int64))
            oks = len(d['sub']) == len(te) and bool(np.all(d['sub'].astype(str) == sub[te]))
            return oky and oks, {'n': int(len(d['y'])), 'y_equal': bool(oky), 'sub_equal': bool(oks)}
        return fn

    def rows_equal(expected):
        def fn(p):
            r = np.load(p, allow_pickle=True)['rows'].astype(np.int64)
            ordered = np.array_equal(r, expected)
            same = ordered or (len(r) == len(expected) and np.array_equal(np.sort(r), np.sort(expected)))
            return same, {'n': int(len(r)), 'same_order': bool(ordered), 'same_rows': bool(same)}
        return fn

    def sizes(**want):
        def fn(p):
            j = json.load(open(p, encoding='utf-8'))
            got = {k: j.get(k) for k in want}
            return got == want, {**got, 'expected': want}
        return fn

    for s in ('random', 'temporal'):
        for cond, cname in (('all', 'raw'), ('r1', 'r1')):
            te = tests[(s, cond)]
            code = codes[SPLIT_COLS[(s, cond)]]
            n = {k: int((code == j).sum()) for j, k in enumerate(('n_train', 'n_val', 'n_test'))}
            base = RES / 'tree_protocol' / 'main' / f'XGBoost_{s}_{cname}_s42'
            add(f'tree_protocol test rows ({s}, {cname})', base.with_suffix('.npz'), seq(te))
            add(f'tree_protocol sizes ({s}, {cname})', base.with_suffix('.json'),
                sizes(n_train=n['n_train'], n_test=n['n_test']))
            add(f'deep_split sizes incl. validation ({s}, {cname})',
                RES / 'deep_split' / f'ResNet1D_{s}_{cname}_s42.json', sizes(**n))
            add(f'tree_seeds test rows ({s}, {cname})',
                RES / 'q1_revision' / 'tree_seeds' / 'runs' / f'XGBoost_{s}_{cname}_s42.npz', rows_equal(te))
        te = tests[(s, 'all')]
        add(f'tree_protocol decomp test-r1 rows ({s})',
            RES / 'tree_protocol' / 'decomp' / f'XGBoost_{s}_train-raw_test-r1.npz', seq(te[~r1[te]]))
        add(f'cleaning_train_only test_R1 rows ({s})',
            RES / 'q1_revision' / 'cleaning_train_only' / f'XGBoost_{s}_train-none_test-R1.npz',
            rows_equal(te[~r1[te]]))
        add(f'symmetric_r1 relabel test rows ({s})',
            RES / 'q1_revision' / 'symmetric_r1' / f'XGBoost_{s}_relabel.npz', rows_equal(te))
    return out


# ------------------------------------------------------------------ export
def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def dump_json(obj, path):
    """Write JSON atomically (a crash never leaves a truncated checkpoint that looks finished)."""
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1, default=str)
    tmp.replace(path)


def write_csv_gz(tab, path):
    """Deterministic gzip on every OS: LF line ends, header time 0, stored name 'flow_flags.csv'
    (pandas would store the name of the temporary file and write CRLF on Windows)."""
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'wb') as raw, \
            gzip.GzipFile(filename=path.name[:-3], mode='wb', fileobj=raw, compresslevel=9, mtime=0) as gz, \
            io.TextIOWrapper(gz, encoding='utf-8', newline='') as txt:
        tab.to_csv(txt, index=False, lineterminator='\n')
    tmp.replace(path)


def write_export(d, codes, files, out):
    paths = [f['csv'] for f in files]
    rank = np.argsort(np.argsort(np.array(paths, dtype=object)))  # file id -> rank of its path
    cats = sorted(paths)
    fr = rank[d['csv_id'].to_numpy()]
    order = np.lexsort((d['row'].to_numpy(), fr))
    tab = pd.DataFrame({'csv': pd.Categorical.from_codes(fr[order], categories=cats),
                        'row': d['row'].to_numpy(np.int64)[order],
                        'idx': d['idx'].to_numpy(np.int64)[order],
                        'y': d['y'].to_numpy(np.int8)[order],
                        'sub': pd.Categorical(d['sub'].astype(str).to_numpy()[order])})
    for f in FLAGS:
        tab[f] = d[f].to_numpy(bool)[order]
    for name, code in codes.items():
        tab[name] = pd.Categorical.from_codes(code[order], categories=SPLIT_LABELS)
    if tab.duplicated(['csv', 'row']).any():
        raise RuntimeError('(csv, row) is not unique')
    res = {}
    pq_path, gz_path = out / 'flow_flags.parquet', out / 'flow_flags.csv.gz'
    tmp = pq_path.with_suffix('.parquet.tmp')
    tab.to_parquet(tmp, index=False)
    tmp.replace(pq_path)
    write_csv_gz(tab.assign(**{f: tab[f].astype(np.int8) for f in FLAGS}), gz_path)
    for p in (gz_path, pq_path):
        res[p.name] = {'bytes': p.stat().st_size, 'sha256': sha256(p)}
        print(f'  [saved] {p}  {p.stat().st_size / 1e6:.1f} MB', flush=True)
    return res, tab


def versions():
    import pyarrow
    v = {'python': sys.version.split()[0], 'numpy': np.__version__, 'pandas': pd.__version__,
         'pyarrow': pyarrow.__version__}
    try:
        v['git_commit'] = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True,
                                         text=True, timeout=20).stdout.strip() or None
        dirty = subprocess.run(['git', 'status', '--porcelain', '--', 'experiments'], cwd=ROOT,
                               capture_output=True, text=True, timeout=20).stdout
        v['git_experiments_uncommitted'] = [ln[3:] for ln in dirty.splitlines() if ln.strip()][:50]
    except Exception:
        v['git_commit'] = None
    # the code that defines the sample, the rules and the splits (the commit may not contain it yet)
    v['sha256_scripts'] = {p: sha256(HERE / p) for p in
                           ('export_flags.py', 'flagged_loader.py', 'pilot_temporal_split.py',
                            'relabel_background.py', 'deep_split_noise_study.py',
                            'temporal_split_by_subattack.py') if (HERE / p).exists()}
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--classes', nargs='+', choices=CLASSES, default=None,
                    help='selftest on these classes only (written to export_flags/selftest/)')
    ap.add_argument('--spot-check', type=int, default=20,
                    help='CSV records re-read per file for the mapping check (0 = off)')
    ap.add_argument('--force', action='store_true', help='rebuild all classes and the export')
    ap.add_argument('--allow-mismatch', action='store_true',
                    help='export even if the rebuild does not match flagged_data.parquet')
    a = ap.parse_args()
    t0 = time.time()
    classes = [c for c in CLASSES if a.classes is None or c in a.classes]
    full = len(classes) == len(CLASSES)
    out = OUT if full else OUT / 'selftest'
    parts = out / 'parts'
    parts.mkdir(parents=True, exist_ok=True)
    summary_path = out / ('export_flags.json' if full else 'selftest.json')
    outputs = [out / 'flow_flags.csv.gz', out / 'flow_flags.parquet']
    if summary_path.exists() and all(p.exists() for p in outputs) and not a.force:
        s = json.load(open(summary_path, encoding='utf-8'))
        if s.get('classes') == classes:                           # a selftest of other classes is redone
            print(f'[done] {summary_path} exists (verified={s.get("verified")}, {s.get("n_flows"):,} flows); '
                  f'--force rebuilds', flush=True)
            return

    files = file_table()
    file_id = {f['csv']: i for i, f in enumerate(files)}
    cache = Cache(CACHE) if CACHE.exists() else None
    print(f'[plan] {"full export" if full else "selftest " + str(classes)}: {len(files)} CSV files, '
          f'cache {"found" if cache else "MISSING (no verification)"}, metadata {META_PATH.name}', flush=True)
    if cache is None and not a.allow_mismatch and full:
        print('  [warn] without the cache the export cannot be verified against the experiments', flush=True)

    benign_pairs, offset = None, 0
    pairs_path = parts / 'benign_pairs.parquet'
    approx_r3 = 'Benign' not in classes

    def part_done(cls):
        return ((parts / f'{cls_slug(cls)}.json').exists() and (parts / f'{cls_slug(cls)}.parquet').exists()
                and (cls != 'Benign' or pairs_path.exists()))

    to_build = [cls for cls in classes if a.force or not part_done(cls)]
    if approx_r3 and to_build:                                    # only when a class is (re)built
        if cache is None:
            raise SystemExit('selftest without Benign needs the cache for the Benign IP pairs')
        pos = cache.class_positions(0)
        benign_pairs = set(pair_key(pd.Series(cache.values('Src IP', pos)), pd.Series(cache.values('Dst IP', pos))))
        print(f'  Benign IP pairs from the cache: {len(benign_pairs):,} (approximate, see docstring)', flush=True)
        del pos
    elif not approx_r3 and 'Benign' not in to_build and any(c != 'Benign' for c in to_build):
        benign_pairs = set(pd.read_parquet(pairs_path)['pair'])  # Benign part finished in an earlier run

    for cls in classes:
        c = CLASSES.index(cls)
        pj, pp = parts / f'{cls_slug(cls)}.json', parts / f'{cls_slug(cls)}.parquet'
        if cls not in to_build:
            rep = json.load(open(pj, encoding='utf-8'))
            print(f'[skip] {cls:11s} part exists ({rep["n_flows"]:,} flows, verified={rep["verified"]})', flush=True)
            offset += rep['n_flows']
            continue
        t = time.time()
        fstats = {}
        df, pairs = build_class(cls, file_id, benign_pairs, fstats)
        if cls == 'Benign':
            benign_pairs = pairs
            pd.DataFrame({'pair': sorted(benign_pairs)}).to_parquet(pairs_path, index=False)
        print(f'  {cls:11s} flows={len(df):>9,}  rebuilt in {time.time() - t:.0f} s', flush=True)
        rep = {'class': cls, 'y': c, 'n_flows': int(len(df)), 'build_seconds': round(time.time() - t, 1)}
        if cache is not None:
            v, pos = verify_class(df, cache, c, offset if full else None, approx_r3 and cls != 'Benign')
            rep['verification'] = v
            rep['verified'] = bool(v['ok'])
            print(f'    cache check: {v["columns_identical"]}/{v["columns_checked"]} columns identical, '
                  f'mismatch={v["mismatch"] or "none"}, rounding-only={list(v["stats_rounding"]) or "none"}, '
                  f'ok={v["ok"]}', flush=True)
            idx = pos if len(pos) == len(df) else np.full(len(df), -1, np.int64)
        else:
            rep['verified'] = None
            idx = np.full(len(df), -1, np.int64)
        sp = spot_check(df, files, a.spot_check, np.random.default_rng(SEED + c))
        rep['spot_check'] = sp
        print(f'    CSV mapping check: {sp["rows_checked"]} records in {sp["files_checked"]} files, '
              f'features exact {sp["features_exact"]}, close {sp["features_close"]}, ts {sp["ts_equal"]}, '
              f'IPs {sp["ips_equal"]}, ok={sp["ok"]}', flush=True)
        in_sample = np.bincount(df['csv_id'].to_numpy(), minlength=len(files))
        rep['files'] = {files[i]['csv']: {**fstats[i], 'in_sample': int(in_sample[i])} for i in sorted(fstats)}
        compact = pd.DataFrame({'csv_id': df['csv_id'].to_numpy(np.int16), 'row': df['row'].to_numpy(np.int64),
                                'idx': idx, 'y': df['y'].to_numpy(np.int8), 'sub': df['sub'].astype(str),
                                'ts': df['ts'].to_numpy()})
        for f in FLAGS:
            compact[f] = df[f].to_numpy(bool)
        del df; gc.collect()
        compact.to_parquet(pp, index=False)
        dump_json(rep, pj)                                        # JSON last = part finished
        offset += rep['n_flows']
        del compact; gc.collect()

    # ---------------------------------------------------------- assemble
    reps = [json.load(open(parts / f'{cls_slug(c)}.json', encoding='utf-8')) for c in classes]
    d = pd.concat([pd.read_parquet(parts / f'{cls_slug(c)}.parquet') for c in classes], ignore_index=True)
    # problems that stop the export (unless --allow-mismatch): the CSV mapping check fails, the
    # rebuild differs from the cache, or a partition differs from a stored run of the experiments
    problems = []
    if any(r['spot_check'].get('ok') is False for r in reps):
        problems.append('CSV mapping check: ' + ', '.join(r['class'] for r in reps if r['spot_check'].get('ok') is False))
    if cache is not None and not all(r['verified'] is True for r in reps):
        problems.append('cache verification: ' + ', '.join(r['class'] for r in reps if r['verified'] is not True))
    summary = {'description': 'Per-flow background flags and split membership of the flagged sample '
                              '(flagged_loader.py), keyed by source CSV and record number',
               'dataset_root': 'data/CIC IoT-DIAD 2024/', 'full_export': full, 'classes': classes,
               'n_flows': int(len(d)), 'verified': None, 'problems': problems,
               'class_counts': {CLASSES[k]: int(n) for k, n in zip(*np.unique(d['y'], return_counts=True))}}
    if full:
        if cache is not None and len(d) != cache.n:
            print(f'[warn] {len(d):,} rebuilt flows but {cache.n:,} rows in the cache', flush=True)
            problems.append(f'{len(d):,} rebuilt flows but {cache.n:,} rows in the cache')
        known = d['idx'].to_numpy() >= 0
        if known.any() and not np.array_equal(d['idx'].to_numpy()[known], np.flatnonzero(known)):
            print('[warn] rebuilt row order differs from the cache order', flush=True)
            problems.append('rebuilt row order differs from the cache order')
        d['idx'] = np.arange(len(d), dtype=np.int64)
        print('[splits] deep_split_noise_study.splits on all rows and on the R1 rows', flush=True)
        meta = pd.DataFrame({'y': d['y'].to_numpy(np.int64), 'sub': d['sub'].astype('category'),
                             'ts': d['ts'].to_numpy()})
        flags = {f: d[f].to_numpy(bool) for f in FLAGS}
        codes, tests = split_codes(meta, flags)
        del meta; gc.collect()
        checks = cross_checks(tests, codes, d['y'].to_numpy(np.int64), d['sub'].astype(str).to_numpy(),
                              flags['r1_external'])
        for ch in checks:
            print(f'  [{ "ok" if ch["ok"] else ("--" if ch["ok"] is None else "FAIL")}] {ch["check"]}', flush=True)
        summary['cross_checks'] = checks
        if any(ch['ok'] is False for ch in checks):
            problems.append('partition differs from stored runs: '
                            + '; '.join(ch['check'] for ch in checks if ch['ok'] is False))
        y = d['y'].to_numpy()
        summary['split_counts'] = {name: {CLASSES[k]: {lab: int(((y == k) & (code == j)).sum())
                                                       for j, lab in enumerate(SPLIT_LABELS) if (code == j).any()}
                                          for k in range(len(CLASSES))}
                                   for name, code in codes.items()}
        del tests
    else:
        codes = {}
        summary['note'] = 'selftest: split columns are omitted (the partitions need all eight classes)'
    summary['flag_counts'] = {CLASSES[k]: {f: int(d.loc[d['y'] == k, f].sum()) for f in FLAGS}
                              for k in np.unique(d['y'])}
    summary['per_class'] = reps
    summary['columns'] = {
        'csv': 'source CSV, relative to data/CIC IoT-DIAD 2024/ (forward slashes)',
        'row': '0-based record number in that CSV (row 0 = first line after the header; pandas.read_csv numbering)',
        'idx': 'row position in results_2026_03_03/split_pilot/flagged_data.parquet = global row position '
               'used by the experiments' + ('' if full else ' (selftest: position in the cache)'),
        'y': 'class index: ' + ', '.join(f'{i} {c}' for i, c in enumerate(CLASSES)),
        'sub': 'capture group (sub-folder, or the class when it has none)',
        'r1_external': 'R1: an endpoint outside 192.168.137.0/24 and 205.174.165.0/24 (attack classes only)',
        'r2_service': 'R2: service port 53, 67, 68, 123, 137, 138, 1900 or 5353 (DNS kept in DNS Spoofing)',
        'r3_benign_pair': 'R3: the unordered IP pair also occurs in the Benign captures',
        'split_random': 'stratified random 70/15/15 (seed 42) on all rows: train | val | test',
        'split_temporal': '70/15/15 by time inside each of the 16 capture groups, on all rows',
        'split_random_r1': 'split_random drawn on the rows not flagged by R1; excluded = R1-flagged',
        'split_temporal_r1': 'split_temporal on the rows not flagged by R1; excluded = R1-flagged'}
    # True = checked against the cache and nothing failed; None = no cache to check against
    summary['verified'] = False if problems else (True if cache is not None else None)
    failed_path = out / 'export_flags_FAILED.json'
    if problems and not a.allow_mismatch:
        dump_json(summary, failed_path)
        raise SystemExit(f'[FAIL] {"; ".join(problems)} - see {failed_path} (--allow-mismatch exports anyway)')
    print('[export]', flush=True)
    d_files = pd.DataFrame(files)
    fs = {}
    for r in reps:
        fs.update(r['files'])
    for k in ('records', 'after_thinning', 'in_sample'):
        d_files[k] = pd.array([fs.get(p, {}).get(k) for p in d_files['csv']], dtype='Int64')
    d_files = d_files[d_files['class'].isin(classes)]
    d_files.to_csv(out / 'files.csv', index=False, lineterminator='\n')
    summary['outputs'], tab = write_export(d, codes, files, out)
    summary['outputs']['files.csv'] = {'bytes': (out / 'files.csv').stat().st_size}
    summary['files'] = d_files.to_dict('records')
    summary['versions'] = versions()
    summary['elapsed_seconds'] = round(time.time() - t0, 1)
    dump_json(summary, summary_path)
    if failed_path.exists() and not problems:
        failed_path.unlink()                                      # stale report of an earlier failed run
    print(f'[DONE] {summary_path}  flows={len(tab):,}  verified={summary["verified"]}  '
          f'({summary["elapsed_seconds"] / 60:.1f} min)', flush=True)


if __name__ == '__main__':
    main()
