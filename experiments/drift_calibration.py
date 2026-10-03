# -*- coding: utf-8 -*-
r"""
drift_calibration.py
====================
Reviewer point stat-08: the drift measures of Section 4.5 / Algorithm 2 / Table 18 have no null
reference. The adversarial-validation AUC of temporal_drift_analysis.py uses shuffled, stratified
3-fold CV on pooled, autocorrelated flows (bursts of near-identical flows fall into both the
training and the validation folds, so the AUC can exceed 0.5 without any real shift), and the
top-20 destination-port Jaccard depends on how many flows a period contains.

For every capture group (same cleaned sample and the same within-group 70/15/15 time cut as
temporal_drift_analysis.py; R1-cleaned data by default, --cleaning all|raw for the other variants)
six two-block comparisons are scored (m = min(n_test, n_train // 2) = n_test under the 70/15 cut;
g = number of validation-period flows between the training and the test period):

  main          training period (first 70%) vs test period (last 15%)          = the paper's measure
  ref_adjacent  NULL REFERENCE: two adjacent, equally sized blocks at the end of the training period,
                each of m flows (= the size of the test period): train[-2m:-m] vs train[-m:]
  -- extras (not asked; skipped with --core-only) ------------------------------------------------
  main_equal    a random, time-ordered subsample of n_test training-period flows vs the test period:
                the paper's comparison with equal block sizes. The adversarial AUC grows with the
                number of training rows, so `main` (0.7 n vs 0.15 n rows) is not size-matched to the
                m-vs-m reference; main_equal is (the AUC analogue of the equal-size Jaccard).
  last_block    the last m training flows vs the test period: contiguous m vs m blocks separated by
                the g validation-period flows
  ref_gap       gap-matched null for last_block: train[-2m-g:-m-g] vs train[-m:], i.e. two contiguous
                m-flow blocks INSIDE the training period separated by the same g flows
  ref_half30    sensitivity reference: the two halves of the last 30% of the training period

For every comparison
  * adversarial-validation AUC with the classifier, features and settings of
    temporal_drift_analysis.drift_auc, unchanged: each block randomly subsampled to at most 50,000
    flows (rng = default_rng(42), first block first), 81 model features with NaN kept, XGBoost
    (100 trees, depth 4, learning rate 0.2, hist, random_state 42, scale_pos_weight = n0 / n1),
    ROC-AUC of StratifiedKFold(3, shuffle=True, random_state=42+k), mean and SD over k = 0..4.
    For `main` this reproduces the drift AUC of the paper (checked against
    split_pilot/temporal_drift_r1.json, or temporal_drift.json for --cleaning all).
  * the same AUC with TIME-BLOCKED folds: the subsampled rows of each block are put in time order
    and cut into --blocks (3) contiguous blocks; fold j holds out block j of both sides and trains on
    the rest (optionally minus --purge x block rows on each side of the held-out block). Mean and SD
    over the folds.
  * top-20 destination-port Jaccard on the full blocks (as in the paper) and on EQUAL-SIZE random
    subsamples: n = size of the smaller block, --jaccard-reps (20) repetitions without replacement,
    mean and SD. The reference blocks already have equal size, so their subsample is the whole block
    (SD 0); main and ref_adjacent use the same n whenever m = n_test.

Per group the summary reports (the requested columns first)
  auc_original, auc_time_blocked, ref_auc, ref_auc_time_blocked,
  excess_auc = auc_original - ref_auc,  excess_auc_time_blocked = auc_time_blocked - ref_auc_time_blocked,
  jaccard_original (full periods), jaccard_equal_size (mean, sd), ref_jaccard (mean, sd),
  jaccard_deficit = ref_jaccard - jaccard_equal_size (> 0: fewer shared top ports than inside training),
  and from the extras: auc_equal_size (+ time-blocked) and excess_auc_equal_size (- ref_auc, size-matched),
  auc_last_block / ref_gap_auc (+ time-blocked) and excess_auc_last_block = auc_last_block - ref_gap_auc
  (size- AND gap-matched), jaccard_last_block / ref_gap_jaccard / jaccard_deficit_last_block, ref30_*,
  block sizes and the time spans (hours) of every block.
AUCs are computed only when both blocks have at least 100 flows (MIN_PERIOD of the original);
Jaccards are always computed.
Reading the time-blocked excess: the two ref_adjacent blocks touch each other, whereas `main` has the
validation period (g flows) between its blocks. Under autocorrelation or smooth drift across that
boundary, the held-out edge of one reference block resembles the training rows of the other block, which
can pull ref_auc_time_blocked down (even below 0.5) and so inflate excess_auc_time_blocked. The size- and
gap-matched excess_auc_last_block_time_blocked has no such asymmetry; report it next to the requested one.
The blocked fold AUCs rest on the number of distinct bursts, not flows, so their SD (3 folds) is wide for
small groups.

Memory: only y, sub, ts, Dst Port and the three rule flags are read for all rows (~90 MB); the
81 features are read for the subsampled rows of ONE capture group at a time (parquet row groups that
contain them, one column at a time; at most ~600k rows x 81 float32 = 200 MB). No full frame is built.

Output: results_2026_03_03/q1_revision/drift_calibration/<tag>/<group>.json  (one per capture group)
        results_2026_03_03/q1_revision/drift_calibration/drift_calibration_<tag>.json|.csv (summary)
        results_2026_03_03/q1_revision/drift_calibration/plan_<tag>.json (expected groups)
<tag> = the cleaning variant (r1 | all | raw), plus a suffix for every non-default setting (e.g.
r1_purge0.02, r1_blocks5), so sensitivity runs never overwrite or get mixed with the main run.
Resumable: a group whose JSON exists with the same settings and all requested comparisons is skipped
(--force recomputes). --max-fits N stops after N capture groups (each group is ~108 small XGBoost fits
on <= 100k rows) so that every group can run in a fresh process. The summary is written automatically
when every group is finished (or with --summary; its `complete` flag checks the plan file).

Run (PowerShell, from the project root):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\drift_calibration.py 2>&1 | Tee-Object -FilePath drift_calibration.log
  # lowest peak memory: one capture group per process (16 groups)
  1..16 | ForEach-Object { & $py experiments\drift_calibration.py --max-fits 1 2>&1 | Tee-Object -FilePath drift_calibration.log -Append }
  # a group that stopped with "[abort]" (XGBoost out of memory) is picked up by any further run:
  & $py experiments\drift_calibration.py 2>&1 | Tee-Object -FilePath drift_calibration.log -Append
  # R1|R2|R3-cleaned sample (the original Table 8 analysis) as a sensitivity run
  & $py experiments\drift_calibration.py --cleaning all 2>&1 | Tee-Object -FilePath drift_calibration_all.log
  # optional: purged time-blocked folds (own tag r1_purge0.02; the main r1 results stay untouched)
  & $py experiments\drift_calibration.py --purge 0.02 2>&1 | Tee-Object -FilePath drift_calibration_purge.log
  # tables only
  & $py experiments\drift_calibration.py --summary 2>&1 | Tee-Object -FilePath drift_calibration_summary.log
  & $py experiments\drift_calibration.py --summary --cleaning all 2>&1 | Tee-Object -FilePath drift_calibration_summary.log -Append
Check the log for `paper check ... MISMATCH` lines before using the numbers: `main` must reproduce the
drift AUC and top-20 Jaccard of split_pilot/temporal_drift_r1.json (temporal_drift.json for --cleaning all).
"""
import argparse, gc, json, os, re, sys, time, traceback, warnings
from pathlib import Path

# Nothing here uses BLAS (XGBoost has its own OpenMP threads, which this does not touch), but numpy's and
# scipy's OpenBLAS each commit ~0.8 GB of per-thread buffers at import on this 24-thread CPU (1.67 GB ->
# 0.12 GB private memory with 1 thread). Must be set before numpy is imported. Results are unchanged.
os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold, cross_val_score

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows  # noqa: E402
from flagged_loader import CACHE, FLAGS, get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, FEATS, SEED  # noqa: E402
from pilot_temporal_split import OUT as PILOT  # noqa: E402
from temporal_drift_analysis import MAX_PER_PERIOD, MIN_PERIOD, REPEATS, top_ports  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'drift_calibration'
PAPER = {'r1': PILOT / 'temporal_drift_r1.json', 'all': PILOT / 'temporal_drift.json'}
TRAIN_END, VAL_END = 0.70, 0.85           # within-group time cut of temporal_drift_analysis.periods
TOP_K = 20
COMPARISONS = ['main', 'ref_adjacent', 'main_equal', 'last_block', 'ref_gap', 'ref_half30']
CORE = ['main', 'ref_adjacent']
XGB_PARAMS = dict(n_estimators=100, max_depth=4, learning_rate=0.2, tree_method='hist',
                  random_state=SEED, eval_metric='logloss')      # = temporal_drift_analysis.drift_auc
# settings that change results: a non-default value goes into the output tag and must match on resume
DEFAULTS = dict(repeats=REPEATS, blocks=3, purge=0.0, jaccard_reps=20, min_period=MIN_PERIOD)


def run_tag(a):
    return '_'.join([a.cleaning] + [f'{k.replace("_", "")}{getattr(a, k):g}' for k, v in DEFAULTS.items()
                                    if getattr(a, k) != v])


# ----------------------------------------------------------------------------- helpers
def rnd(v, k=4):
    return None if v is None or not np.isfinite(v) else round(float(v), k)


def slug(name):
    return re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_')


def write_json(path, obj):
    """Atomic: an interrupted process never leaves a truncated JSON that would count as finished."""
    tmp = path.with_suffix('.part')
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def finished(path, want, cfg):
    """A group is finished when its JSON exists, was computed with the same result-relevant settings
    and holds every requested comparison (a --core-only result is completed by a later full run)."""
    if not path.exists():
        return False
    try:
        with open(path, encoding='utf-8') as fh:
            r = json.load(fh)
        same = all(r['config'].get(k) == cfg[k] for k in list(DEFAULTS) + ['max_per_period', 'train_end',
                                                                          'val_end', 'top_k', 'seed'])
        return same and set(want) <= set(r['comparisons'])
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


# ----------------------------------------------------------------------------- data (lean)
def load_meta(path):
    """y, capture-group code, ts, Dst Port and rule flags of every row, in parquet row order."""
    if path == CACHE and not CACHE.exists():
        get_flagged(columns=['y'])            # first run only: build the cache from the CSVs
    t = pq.read_table(path, columns=['y', 'sub', 'ts', 'Dst Port'] + FLAGS, read_dictionary=['sub'])
    sub = t.column('sub').to_pandas()
    if not isinstance(sub.dtype, pd.CategoricalDtype):
        sub = sub.astype('category')
    meta = {'y': t.column('y').to_numpy().astype(np.int16),
            'code': sub.cat.codes.to_numpy().astype(np.int32),
            'cats': [str(c) for c in sub.cat.categories],
            'ts': t.column('ts').to_numpy(),
            'port': t.column('Dst Port').to_numpy(),        # int64 as in the paper (value_counts ties)
            'flags': {c: t.column(c).to_numpy(zero_copy_only=False) for c in FLAGS}}
    del t, sub
    return meta


def capture_groups(meta, rows):
    """(class, sub, name, global rows in time order) per capture group, in the order of
    temporal_drift_analysis (groupby(['y', 'sub'], sort=True)). Rows keep the parquet order before the
    stable time sort, exactly like g.sort_values('ts', kind='stable') there (NaT last)."""
    key = meta['y'][rows].astype(np.int64) * 4096 + meta['code'][rows]
    out = []
    for k in np.unique(key):
        c, s = int(k // 4096), meta['cats'][int(k % 4096)]
        pos = rows[key == k]
        order = pd.Series(meta['ts'][pos]).sort_values(kind='stable').index.to_numpy()
        out.append((c, s, f'{CLASSES[c]} / {s}' if s != CLASSES[c] else CLASSES[c], pos[order]))
    out.sort(key=lambda g: (g[0], g[1]))
    return out


def read_rows(pf, rows, cols):
    """Float32 values of `cols` for the sorted, unique global `rows`. Only the row groups that contain
    them are read, one column at a time (peak: one column chunk + the result). NaN are kept."""
    sizes = [pf.metadata.row_group(i).num_rows for i in range(pf.metadata.num_row_groups)]
    starts = np.r_[0, np.cumsum(sizes)]
    rg = np.searchsorted(starts, rows, side='right') - 1
    out = np.empty((len(rows), len(cols)), np.float32)
    for g in np.unique(rg):
        sel = np.flatnonzero(rg == g)
        local = rows[sel] - starts[g]
        for j, c in enumerate(cols):
            v = pf.read_row_group(int(g), columns=[c], use_threads=False).column(0).to_numpy()
            out[sel, j] = v[local]
        del v
    return out


# ----------------------------------------------------------------------------- blocks
def make_blocks(pos, which):
    """The two blocks (global rows, time order) of every comparison for one capture group."""
    n = len(pos)
    a, b = int(TRAIN_END * n), int(VAL_END * n)
    tr, te = pos[:a], pos[b:]
    m = min(len(te), a // 2)                   # reference block size: the test-period size if possible
    g = b - a                                  # validation-period flows between training and test period
    h = (a - int(0.70 * a)) // 2               # halves of the last 30% of the training period
    lo = a - 2 * m - g                         # start of the first ref_gap block (never wrap around)
    k_eq = min(len(te), a)                     # main_equal: time-ordered random subsample of the training period
    pick = np.sort(np.random.default_rng(SEED).permutation(a)[:k_eq])
    blk = {'main': (tr, te),
           'ref_adjacent': (tr[a - 2 * m:a - m], tr[a - m:]),
           'main_equal': (tr[pick], te),
           'last_block': (tr[a - m:], te),
           'ref_gap': (tr[lo:lo + m], tr[a - m:]) if lo >= 0 else (tr[:0], tr[:0]),
           'ref_half30': (tr[a - 2 * h:a - h], tr[a - h:])}
    return {k: blk[k] for k in which}, dict(n=n, n_train_period=a, n_val_period=g, n_test_period=len(te),
                                            ref_block_size=m, main_equal_size=k_eq,
                                            ref_gap_block_size=m if lo >= 0 else 0, half30_block_size=h)


def subsample(n0, n1):
    """Row selection of temporal_drift_analysis.drift_auc: a fresh default_rng(SEED), first block first.
    The selected within-block positions are also the time ranks used for the blocked folds."""
    rng = np.random.default_rng(SEED)
    return rng.permutation(n0)[:MAX_PER_PERIOD], rng.permutation(n1)[:MAX_PER_PERIOD]


def blocked_folds(t0, t1, k, purge):
    """Time-blocked folds for X = [block 0 rows; block 1 rows]. t0 / t1: time ranks of the rows of each
    side in X order. Each side is cut into k contiguous time blocks; fold j tests on block j of both sides
    and trains on the other blocks, minus round(purge x side size) rows next to the test block."""
    sides, off = [], 0
    for t in (t0, t1):
        sides.append(np.argsort(t, kind='stable') + off)    # X rows of this side in time order
        off += len(t)
    folds = []
    for j in range(k):
        tr, te = [], []
        for o in sides:
            cut = np.array_split(np.arange(len(o)), k)[j]
            lo, hi, g = int(cut[0]), int(cut[-1]) + 1, int(round(purge * len(o)))
            te.append(o[lo:hi])
            tr.append(np.r_[o[:max(lo - g, 0)], o[min(hi + g, len(o)):]])
        folds.append((np.sort(np.concatenate(tr)), np.sort(np.concatenate(te))))
    return folds


def cv_auc(clf, X, y, cv, tries=4):
    """cross_val_score(roc_auc) that never turns a failed fit into a silent NaN (sklearn's default
    error_score=nan would bias the mean). A transient allocation failure (XGBoost bad_malloc or
    MemoryError when other jobs hold the RAM) is retried after gc and a pause; then it raises, and the
    group is simply recomputed on the next (resumed) run."""
    for i in range(tries):
        try:
            return cross_val_score(clf, X, y, scoring='roc_auc', cv=cv, error_score='raise')
        except (MemoryError, xgb.core.XGBoostError) as e:
            if i == tries - 1:
                raise
            print(f'    [retry {i + 1}] {type(e).__name__}: {str(e)[-80:]}', flush=True)
            gc.collect()
            time.sleep(15 * (i + 1))


def adv_auc(X, n0, n1, t0, t1, a):
    """Shuffled (exact original) and time-blocked adversarial-validation AUC of one comparison."""
    y = np.r_[np.zeros(n0), np.ones(n1)]
    clf = xgb.XGBClassifier(**XGB_PARAMS, scale_pos_weight=n0 / max(n1, 1), n_jobs=a.n_jobs)
    rep = [float(cv_auc(clf, X, y, StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED + k)).mean())
           for k in range(a.repeats)]
    fold = cv_auc(clf, X, y, blocked_folds(t0, t1, a.blocks, a.purge))
    return dict(auc_shuffled=rnd(np.mean(rep)), auc_shuffled_sd=rnd(np.std(rep)),
                auc_shuffled_repeats=[rnd(v) for v in rep],
                auc_blocked=rnd(np.mean(fold)), auc_blocked_sd=rnd(np.std(fold)),
                auc_blocked_folds=[rnd(v) for v in fold])


def jaccard(pa, pb, k=TOP_K):
    A, B = set(top_ports(pd.Series(pa), k).index), set(top_ports(pd.Series(pb), k).index)
    return len(A & B) / len(A | B) if (A | B) else np.nan


def jaccard_equal(pa, pb, reps):
    """Top-k port Jaccard on equal-size random subsamples (n = smaller block, without replacement)."""
    n = min(len(pa), len(pb))
    if n == 0:
        return dict(jaccard_equal=None, jaccard_equal_sd=None, jaccard_n=0, jaccard_reps=0)
    if len(pa) == len(pb):                      # both subsamples are the whole blocks: deterministic
        v = [jaccard(pa, pb)]
    else:
        rng = np.random.default_rng(SEED)
        v = []
        for _ in range(reps):
            sa = pa if len(pa) == n else pa[rng.permutation(len(pa))[:n]]
            sb = pb if len(pb) == n else pb[rng.permutation(len(pb))[:n]]
            v.append(jaccard(sa, sb))
    return dict(jaccard_equal=rnd(np.mean(v)), jaccard_equal_sd=rnd(np.std(v)), jaccard_n=int(n),
                jaccard_reps=len(v))


def span(ts, p):
    s = pd.Series(ts[p]).dropna()
    if not len(s):
        return None, None, None
    return f'{s.iloc[0]:%m-%d %H:%M}', f'{s.iloc[-1]:%m-%d %H:%M}', s


# ----------------------------------------------------------------------------- one capture group
def run_group(c, s, name, pos, meta, pf, a, paper):
    t_start = time.time()
    blocks, sizes = make_blocks(pos, CORE if a.core_only else COMPARISONS)
    print(f'  flows={sizes["n"]:,}  train={sizes["n_train_period"]:,}  test={sizes["n_test_period"]:,}  '
          f'reference block={sizes["ref_block_size"]:,}', flush=True)
    sel = {k: subsample(len(p0), len(p1)) for k, (p0, p1) in blocks.items()
           if min(len(p0), len(p1)) >= a.min_period}
    need = [np.r_[blocks[k][0][s0], blocks[k][1][s1]] for k, (s0, s1) in sel.items()]
    U = np.unique(np.concatenate(need)) if need else np.empty(0, np.int64)
    t = time.time()
    FU = read_rows(pf, U, FEATS) if len(U) else None
    print(f'  features of {len(U):,} rows read ({time.time() - t:.1f} s)', flush=True)

    comp = {}
    for k, (p0, p1) in blocks.items():
        t = time.time()
        f0, l0, s_0 = span(meta['ts'], p0)
        f1, l1, s_1 = span(meta['ts'], p1)
        r = dict(n0=int(len(p0)), n1=int(len(p1)), span0=f'{f0}..{l0}', span1=f'{f1}..{l1}',
                 hours0=rnd((s_0.iloc[-1] - s_0.iloc[0]).total_seconds() / 3600, 2) if s_0 is not None else None,
                 hours1=rnd((s_1.iloc[-1] - s_1.iloc[0]).total_seconds() / 3600, 2) if s_1 is not None else None,
                 gap_hours=rnd((s_1.iloc[0] - s_0.iloc[-1]).total_seconds() / 3600, 2)
                 if s_0 is not None and s_1 is not None else None)
        pa, pb = meta['port'][p0], meta['port'][p1]
        r['jaccard_full'] = rnd(jaccard(pa, pb)) if len(p0) and len(p1) else None
        r.update(jaccard_equal(pa, pb, a.jaccard_reps))
        if k in sel:
            s0, s1 = sel[k]
            X = np.vstack([FU[np.searchsorted(U, p0[s0])], FU[np.searchsorted(U, p1[s1])]])
            r.update(n_sub0=int(len(s0)), n_sub1=int(len(s1)), **adv_auc(X, len(s0), len(s1), s0, s1, a))
            del X
        else:
            r.update(n_sub0=0, n_sub1=0, auc_shuffled=None, auc_shuffled_sd=None, auc_blocked=None,
                     auc_blocked_sd=None, note=f'AUC not computed: a block has < {a.min_period} flows')
        comp[k] = r
        f = lambda v: '   -' if v is None else f'{v:.3f}'
        print(f'  {k:13s} n={r["n0"]:>7,}/{r["n1"]:<7,} AUC shuffled {f(r["auc_shuffled"])}  '
              f'blocked {f(r["auc_blocked"])}  J full {f(r["jaccard_full"])}  '
              f'J equal {f(r["jaccard_equal"])} (n={r["jaccard_n"]:,})  {time.time() - t:.1f} s', flush=True)
    del FU

    g = lambda k, f: comp.get(k, {}).get(f)
    d = lambda x, y: None if x is None or y is None else rnd(x - y)
    sm = dict(
        n_train_period=sizes['n_train_period'], n_test_period=sizes['n_test_period'],
        ref_block_size=sizes['ref_block_size'],
        test_hours=g('main', 'hours1'), ref_block_hours=[g('ref_adjacent', 'hours0'), g('ref_adjacent', 'hours1')],
        auc_original=g('main', 'auc_shuffled'), auc_original_sd=g('main', 'auc_shuffled_sd'),
        auc_time_blocked=g('main', 'auc_blocked'), auc_time_blocked_sd=g('main', 'auc_blocked_sd'),
        ref_auc=g('ref_adjacent', 'auc_shuffled'), ref_auc_sd=g('ref_adjacent', 'auc_shuffled_sd'),
        ref_auc_time_blocked=g('ref_adjacent', 'auc_blocked'),
        ref_auc_time_blocked_sd=g('ref_adjacent', 'auc_blocked_sd'),
        excess_auc=d(g('main', 'auc_shuffled'), g('ref_adjacent', 'auc_shuffled')),
        excess_auc_time_blocked=d(g('main', 'auc_blocked'), g('ref_adjacent', 'auc_blocked')),
        jaccard_original=g('main', 'jaccard_full'),
        jaccard_equal_size=g('main', 'jaccard_equal'), jaccard_equal_size_sd=g('main', 'jaccard_equal_sd'),
        jaccard_n=g('main', 'jaccard_n'),
        ref_jaccard=g('ref_adjacent', 'jaccard_equal'), ref_jaccard_sd=g('ref_adjacent', 'jaccard_equal_sd'),
        ref_jaccard_n=g('ref_adjacent', 'jaccard_n'),
        jaccard_deficit=d(g('ref_adjacent', 'jaccard_equal'), g('main', 'jaccard_equal')))
    if not a.core_only:
        sm.update(
            # size-matched: n_test random training-period flows vs the test period, against the m-vs-m reference
            auc_equal_size=g('main_equal', 'auc_shuffled'), auc_equal_size_time_blocked=g('main_equal', 'auc_blocked'),
            excess_auc_equal_size=d(g('main_equal', 'auc_shuffled'), g('ref_adjacent', 'auc_shuffled')),
            excess_auc_equal_size_time_blocked=d(g('main_equal', 'auc_blocked'), g('ref_adjacent', 'auc_blocked')),
            # size- and gap-matched: last training block vs test period, against two blocks with the same gap
            auc_last_block=g('last_block', 'auc_shuffled'), auc_last_block_time_blocked=g('last_block', 'auc_blocked'),
            ref_gap_auc=g('ref_gap', 'auc_shuffled'), ref_gap_auc_time_blocked=g('ref_gap', 'auc_blocked'),
            excess_auc_last_block=d(g('last_block', 'auc_shuffled'), g('ref_gap', 'auc_shuffled')),
            excess_auc_last_block_time_blocked=d(g('last_block', 'auc_blocked'), g('ref_gap', 'auc_blocked')),
            jaccard_last_block=g('last_block', 'jaccard_equal'), ref_gap_jaccard=g('ref_gap', 'jaccard_equal'),
            jaccard_deficit_last_block=d(g('ref_gap', 'jaccard_equal'), g('last_block', 'jaccard_equal')),
            gap_hours=g('last_block', 'gap_hours'), ref_gap_hours=g('ref_gap', 'gap_hours'),
            ref30_auc=g('ref_half30', 'auc_shuffled'), ref30_auc_time_blocked=g('ref_half30', 'auc_blocked'),
            ref30_jaccard=g('ref_half30', 'jaccard_equal'), ref30_block_size=sizes['half30_block_size'])

    check = None
    if paper is not None and name in paper:
        pv = paper[name]
        ok_auc = (pv.get('drift_auc') is None and sm['auc_original'] is None) or (
            pv.get('drift_auc') is not None and sm['auc_original'] is not None
            and abs(pv['drift_auc'] - sm['auc_original']) <= 0.0015)
        pj = pv.get('top20_port_jaccard')
        ok_j = (pj is None and sm['jaccard_original'] is None) or (
            pj is not None and sm['jaccard_original'] is not None and abs(pj - sm['jaccard_original']) <= 0.0015)
        check = dict(paper_drift_auc=pv.get('drift_auc'), paper_top20_port_jaccard=pv.get('top20_port_jaccard'),
                     auc_reproduced=bool(ok_auc), jaccard_reproduced=bool(ok_j))
        print(f'  paper check: AUC {pv.get("drift_auc")} -> {sm["auc_original"]} '
              f'({"ok" if ok_auc else "MISMATCH"}), Jaccard {pv.get("top20_port_jaccard")} -> '
              f'{sm["jaccard_original"]} ({"ok" if ok_j else "MISMATCH"})', flush=True)
    return dict(group=name, cls=CLASSES[c], sub=s, cleaning=a.cleaning, sizes=sizes, summary=sm,
                comparisons=comp, paper_check=check, config=config(a), seconds=round(time.time() - t_start, 1))


def config(a):
    return dict(tag=run_tag(a), seed=SEED, train_end=TRAIN_END, val_end=VAL_END, max_per_period=MAX_PER_PERIOD,
                min_period=a.min_period, repeats=a.repeats, shuffled_cv='StratifiedKFold(3, shuffle, 42+k)',
                blocks=a.blocks, purge=a.purge, top_k=TOP_K, jaccard_reps=a.jaccard_reps,
                xgb=XGB_PARAMS, scale_pos_weight='n0 / n1', features=len(FEATS),
                comparisons=CORE if a.core_only else COMPARISONS)


# ----------------------------------------------------------------------------- summary
SHOW = [('auc_original', 'AUC'), ('auc_time_blocked', 'AUC blk'), ('ref_auc', 'ref'),
        ('ref_auc_time_blocked', 'ref blk'), ('excess_auc', 'excess'), ('excess_auc_time_blocked', 'exc blk'),
        ('excess_auc_equal_size', 'exc eq'), ('excess_auc_last_block', 'exc lb'),
        ('jaccard_original', 'J orig'), ('jaccard_equal_size', 'J eq'), ('ref_jaccard', 'J ref'),
        ('jaccard_deficit', 'J def')]
EXCESS = ('excess_auc', 'excess_auc_time_blocked', 'excess_auc_equal_size', 'excess_auc_equal_size_time_blocked',
          'excess_auc_last_block', 'excess_auc_last_block_time_blocked', 'jaccard_deficit',
          'jaccard_deficit_last_block')


def summary(out, tag):
    files = sorted((out / tag).glob('*.json'))
    res = [json.load(open(f, encoding='utf-8')) for f in files]
    if not res:
        print('[summary] no finished groups'); return
    res.sort(key=lambda r: (CLASSES.index(r['cls']), r['sub']))
    plan_f = out / f'plan_{tag}.json'
    missing = None                                   # unknown without a plan file
    if plan_f.exists():
        plan = json.load(open(plan_f, encoding='utf-8'))
        have = {r['group'] for r in res if set(plan['comparisons']) <= set(r['comparisons'])}
        missing = [gname for gname in plan['groups'] if gname not in have]
    rows = [dict(group=r['group'], **{k: (json.dumps(v) if isinstance(v, list) else v)
                                      for k, v in r['summary'].items()},
                 auc_reproduced=None if r['paper_check'] is None else r['paper_check']['auc_reproduced'],
                 jaccard_reproduced=None if r['paper_check'] is None else r['paper_check']['jaccard_reproduced'])
            for r in res]
    df = pd.DataFrame(rows)
    df.to_csv(out / f'drift_calibration_{tag}.csv', index=False)
    write_json(out / f'drift_calibration_{tag}.json',
               dict(tag=tag, cleaning=res[0]['cleaning'], n_groups=len(res),
                    complete=None if missing is None else not missing, missing_groups=missing,
                    config=res[0]['config'], groups={r['group']: r for r in res}))
    print(f'\n=== drift calibration, tag={tag} ({len(res)} groups'
          f'{"" if not missing else f"; MISSING {len(missing)}: " + ", ".join(missing)}) ===')
    print(f'{"capture group":34s} {"n test":>7s} ' + ' '.join(f'{h:>7s}' for _, h in SHOW))
    f = lambda v: '      -' if v is None or (isinstance(v, float) and np.isnan(v)) else f'{v:7.3f}'
    for _, r in df.iterrows():
        print(f'{r["group"]:34s} {int(r["n_test_period"]):>7,} '
              + ' '.join(f(r[k]) if k in r else f(None) for k, _ in SHOW))
    for k in EXCESS:
        if k not in df:
            continue
        v = pd.to_numeric(df[k], errors='coerce').dropna()
        if len(v):
            print(f'  {k:36s} median {v.median():+.3f}  range {v.min():+.3f}..{v.max():+.3f}  '
                  f'> 0.05 in {(v > 0.05).sum()}/{len(v)} groups')
    for what in ('auc', 'jaccard'):
        bad = [r['group'] for r in res if r['paper_check'] and not r['paper_check'][f'{what}_reproduced']]
        if bad:
            print(f'  WARNING: paper {what} not reproduced for', ', '.join(bad))
    print('[saved]', out / f'drift_calibration_{tag}.json', '|', out / f'drift_calibration_{tag}.csv')


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description='Null-referenced drift measures per capture group (stat-08).')
    ap.add_argument('--cleaning', choices=['r1', 'all', 'raw'], default='r1',
                    help='r1: main condition of the paper (default); all: R1|R2|R3 removed; raw: no cleaning')
    ap.add_argument('--repeats', type=int, default=REPEATS, help='fold seeds of the shuffled CV (original: 5)')
    ap.add_argument('--blocks', type=int, default=3, help='contiguous time blocks = folds of the blocked CV')
    ap.add_argument('--purge', type=float, default=0.0,
                    help='fraction of each side dropped from training next to the held-out block (0 = none)')
    ap.add_argument('--jaccard-reps', type=int, default=20, help='equal-size subsamples for the Jaccard')
    ap.add_argument('--min-period', type=int, default=MIN_PERIOD, help='minimum block size for an AUC')
    ap.add_argument('--core-only', action='store_true', help='only main and ref_adjacent (skip the extras)')
    ap.add_argument('--groups', nargs='+', default=None, help='only groups whose name contains one of these')
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N capture groups (0 = all); 1 inside a PowerShell loop = one group per process')
    ap.add_argument('--n-jobs', type=int, default=None, help='XGBoost threads (default: all, as the original)')
    ap.add_argument('--force', action='store_true', help='recompute finished groups')
    ap.add_argument('--summary', action='store_true', help='only rebuild the summary of finished groups')
    ap.add_argument('--data', type=Path, default=CACHE, help=argparse.SUPPRESS)      # tests only
    ap.add_argument('--out', type=Path, default=OUT, help=argparse.SUPPRESS)         # tests only
    a = ap.parse_args()
    if a.blocks < 2 or a.repeats < 1 or a.jaccard_reps < 1 or not 0 <= a.purge < 0.5 / a.blocks:
        ap.error('need --blocks >= 2, --repeats >= 1, --jaccard-reps >= 1 and 0 <= --purge < 0.5 / blocks')
    if a.min_period < 2 * a.blocks:                 # every blocked fold needs rows of both sides
        ap.error(f'--min-period must be at least 2 x --blocks = {2 * a.blocks}')
    out, tag = a.out, run_tag(a)
    (out / tag).mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(out, tag); return

    t0 = time.time()
    meta = load_meta(a.data)
    rows = kept_rows(meta['flags'], a.cleaning)
    groups = capture_groups(meta, rows)
    del rows
    want = CORE if a.core_only else COMPARISONS
    cfg = config(a)
    write_json(out / f'plan_{tag}.json', dict(tag=tag, groups=[g[2] for g in groups], comparisons=want))
    sel = [g for g in groups if any(q.lower() in g[2].lower() for q in a.groups)] if a.groups else groups
    todo = [g for g in sel if a.force or not finished(out / tag / f'{slug(g[2])}.json', want, cfg)]
    print(f'[plan] tag={tag}: {len(sel)} capture groups selected, {len(sel) - len(todo)} finished, '
          f'{len(todo)} to do  (metadata {time.time() - t0:.1f} s)', flush=True)
    paper = None
    if a.data == CACHE and a.cleaning in PAPER and PAPER[a.cleaning].exists() \
            and a.repeats == REPEATS and a.min_period == MIN_PERIOD:
        paper = json.load(open(PAPER[a.cleaning], encoding='utf-8'))
    pf = pq.ParquetFile(a.data)
    done = 0
    for i, (c, s, name, pos) in enumerate(todo, 1):
        if a.max_fits and done >= a.max_fits:
            break
        print(f'\n[{i}/{len(todo)}] {name}', flush=True)
        try:
            r = run_group(c, s, name, pos, meta, pf, a, paper)
        except (OSError, MemoryError, xgb.core.XGBoostError):
            # Seen in testing with little free commit memory: XGBoost's native code fails with an access
            # violation (raised by ctypes as OSError) and the process then hangs at exit on its OpenMP
            # threads. Print the error and leave with os._exit so a PowerShell loop never hangs; nothing
            # is saved for this group, so the next run resumes here.
            traceback.print_exc()
            print(f'[abort] {name}: native/memory failure; no result saved. Free RAM and run again '
                  f'(resumes with this group).', flush=True)
            sys.stderr.flush()
            os._exit(3)
        write_json(out / tag / f'{slug(name)}.json', r)
        print(f'  [saved] {tag}/{slug(name)}.json  ({r["seconds"]:.0f} s)', flush=True)
        done += 1
        gc.collect()
    left = [g for g in groups if not finished(out / tag / f'{slug(g[2])}.json', want, cfg)]
    if not left:
        summary(out, tag)
    else:
        print(f'\n[plan] {len(left)} of {len(groups)} capture groups left; run again (resumes)')


if __name__ == '__main__':
    main()
