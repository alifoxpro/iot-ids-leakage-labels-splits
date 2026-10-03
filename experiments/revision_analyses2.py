# -*- coding: utf-8 -*-
r"""
revision_analyses2.py
=====================
Second set of reviewer analyses (points disc-10, disc-11 and stat-09), computed ONLY from stored
results: no model is trained.

Inputs (results_2026_03_03/; every run = <name>.json, plus <name>.npz when predictions were stored)
  tree_protocol/main, tree_protocol/decomp   XGBoost s42, LightGBM and random forest s42/17/7 (npz: y, p, sub)
  q1_revision/tree_seeds/runs                 tree_seeds_proba.py (y, p, proba, rows, sub), when present
  deep_split                                  ResNet1D / GRU / Transformer s17/42: JSON only, no predictions
  q1_revision/deep_protocol/<protocol>        deep_protocol_study.py (y, p, proba, rows, sub), when present;
                                              'earlystop' = the paper's protocol (pooled with deep_split),
                                              any other sub-folder (fixed, fixed_lr-val, ...) is its own
                                              variant; mlp_tuning*, summary and _* folders are skipped
  split_pilot/subattack_results.json          Fig. 4 (pilot XGBoost, raw labels, median imputation)
  split_pilot/temporal_drift.json, temporal_drift_r1.json    Table 13 ('Dst seen', all rules / R1)
  split_pilot/flagged_data.parquet            part (a) only, read column by column with pyarrow: y, sub, ts,
                                              the three rule flags, Protocol, Total Fwd Packet, Total Bwd
                                              packets (the 81-feature matrix is never built; ~0.4 GB peak)
Runs are pooled over seeds per cell = (family tree|deep, model, variant, kind main|decomp, split,
train cleaning, test cleaning). The same seed found twice (e.g. a tree_seeds refit of a tree_protocol run)
is used once: tree_protocol / deep_split come first (the paper's values); the duplicate is listed.
Run subsets of a cell ('runs'): 'all'; 'paper runs' = tree_protocol / deep_split only (the published cell,
before the extra seeds of tree_seeds / deep_protocol); deep cells also 'epochs_run>=20' (--min-epochs: the
runs that trained normally, the filter of Figs. 8-9 and S1) and 'paper runs, epochs_run>=20'. A subset with
the same runs as an earlier one is not repeated (e.g. no 'paper runs' when a cell has no extra seeds).

Parts
 (a) disc-10  unit of evaluation. For every stored prediction (tree ensembles; deep runs with an npz too)
     the test rows are rebuilt exactly as the training script made them (stored 'rows' when present,
     otherwise deep_split_noise_study.splits() / kept_rows() as in revision_analyses.py: clean then split
     for 'main', split the raw rows then filter the test part for 'decomp'; checked row by row against the
     stored y and capture group). Per capture group (and per class):
       flow-level recall (= 'capture detected share': share of the capture's test flows assigned to the
       true class) with a Wilson 95% interval; packet-weighted recall (weight = Total Fwd Packet + Total Bwd
       packets of each test flow, the load_prepared() feature columns, NaN -> 0); recall on the protocol-0
       flows (Protocol column) and on the other flows, flow-level and packet-weighted; the same four
       numbers for 'detected as any attack' (prediction != Benign); protocol-0 share of flows / packets;
       share of the protocol-0 test flows flagged by R1; the per-capture detection indicator
       capture_detected_proto0 = at least --detect (0.5) of the protocol-0 test flows assigned to the true
       class (also packet-weighted), and capture_alarm_proto0 = at least --detect of them predicted as ANY
       attack class; episode view: test flows cut into --window-min (5) minute windows
       (Timestamp), a window counts as detected when its packet-weighted recall >= --detect (all flows,
       and protocol-0 flows only; 'alert' = at least one protocol-0 flow predicted as an attack).
     Run level: flow- and packet-weighted balanced accuracy, attack-flow / attack-packet detection rate.
     Summary over seeds per cell: mean, SD, min, max of every share; indicators as 'runs where true / runs'.
     Focus table: DDoS ICMP Flood, DDoS ICMP Fragmentation, Mirai (GRE) and DDoS ACK Fragmentation.
     deep_split stored no predictions, so its runs enter part (a) only through a deep_protocol_study rerun
     of the same seed (--rerun-existing; identical metrics = its predictions, otherwise a stand-in).
 (b) disc-11 / stat-09  uncertainty of Tables 9-11, Figs. 8-9 and supplementary Table S1.
     Per run: macro-F1, balanced accuracy, accuracy, attack macro-F1 (seven attack classes) and per-class
     precision / recall / F1 with a stratified bootstrap 95% CI (test rows resampled i.i.d. inside each
     true class = multinomial on the rows of the confusion matrix; B = --B, 1000; percentile interval).
     Per cell: n runs, seeds, mean +/- SD (ddof 1), min-max over seeds, and a bootstrap 95% CI of the
     SEED MEAN: all seeds of a cell predict the same test rows, so when every run of the cell has stored
     predictions the rows are resampled jointly for all of them (distinct joint prediction patterns per
     class, multinomial) - the CI reflects the sampling of test flows for the fixed trained models; the SD
     reflects training variability.
     Runs without stored predictions (deep_split) get an APPROXIMATE bootstrap: TP_c = round(recall_c n_c)
     (n_c from the tree run with the same test rows), FP_c from the stored F1 and recall
     (P = F1 R / (2R - F1)), TP*_c ~ Bin(n_c, TP_c/n_c), FP*_c ~ Bin(N - n_c, FP_c/(N - n_c)) independently
     per class. Recall, balanced accuracy and accuracy are exact under the stratified bootstrap (up to the
     4-decimal rounding of the stored recall); per-class F1 is a close marginal approximation; macro-F1
     ignores the cross-class correlation. The approximation is validated on every tree 'main' run (same
     inputs: the rounded JSON values; approximation_check_on_tree_runs), and the error is stored. Seed
     means of cells with approximate runs combine the per-run draws comonotonically (sorted and averaged =
     fully correlated: conservative).
     Every cell is given for its run subsets (see above). A pooled cell 'Deep mean (ResNet1D/GRU/Transformer)'
     pools the runs of the three paper deep models = the deep mean of Figs. 8-9 (SD over runs = model and seed
     variation; per-class F1 with CIs in b_cells_per_class / S1); it is never used in the comparisons.
     Differences, each with the difference of seed means, per-seed paired differences (common seeds),
     a bootstrap 95% CI and two-sided bootstrap p (Holm within view, comparison type and metric; its floor
     is 2/(B+1) times the number of tests, so p_normal = 2(1 - Phi(|diff| / bootstrap SE)) and its Holm
     value are given too), and the
     flags ci_includes_0, seed_ranges_overlap, within_intervals (= either): model pairs within every
     condition (Tables 9-11), split effect, cleaning effect (Tables 9-10), train-cleaning and test-cleaning
     effects (Table 11), and variant / protocol effects (e.g. fixed epochs vs early stopping). Pairs on the
     same test rows with predictions for every run are resampled jointly (paired; same y and capture groups,
     and the same stored rows where an npz has them - a run whose stored rows differ is warned about and
     resampled on its own); all others use independent bootstraps (for pairs on the same rows this
     overstates the variance: conservative).
     Two views (column 'view', Holm within view, comparison type and metric): 'all' (every run of a cell)
     and, when extra seeds exist, 'paper runs' (the published cells; cells without paper runs drop out).
     Table-ready strings: 'mean +/- SD [CI of the seed mean] (n=, min-max)' (Tables 9-11) and, for S1,
     'F1 [CI of the seed mean]' per class with 'n=<test flows>*' when the class has fewer than --min-n
     (200) test flows; one row per model and view ('all', 'paper runs', and for the deep models the
     epochs_run filter; a view whose cells all repeat an earlier view is left out, i.e. the earlier view
     has exactly those runs). Published Tables 9-11: view 'paper runs', or 'all' for a model without a
     'paper runs' row; published S1: the same for the trees, and for the deep models 'paper runs,
     epochs_run>=20', else 'epochs_run>=20', else 'paper runs', else 'all' (first one present).
 (c) stat-09  Wilson 95% intervals.
     Fig. 4: per-sub-attack recall of the pilot XGBoost (random vs per-capture-group temporal split, raw
       labels, median imputation) from split_pilot/subattack_results.json. The pilot stored no predictions,
       so the counts are rebuilt: n_test is stored exactly, k = round(recall n) from the 4-decimal recall;
       k_min / k_max = every count consistent with the rounding, and the 'conservative' interval spans
       Wilson(k_min) to Wilson(k_max) (identical when the count is exact). The closest run with stored
       predictions (tree_protocol XGBoost_*_raw_s42: same model and split, but NaN -> 0 instead of median
       imputation) is reported with exact counts as a second source.
     Table 13: 'Dst seen' (and 'Src seen') shares of temporal_drift.json (all rules) and
       temporal_drift_r1.json (R1): n = n_test_period, k = round(share n) from the 3-decimal share
       (exact for n <= 1000), with the same conservative interval.
     Fig. 9: per-sub-attack recall of every deep run (exact counts from the npz when stored; otherwise n
       from the tree run with the same test rows and k = round(recall n)), and per cell (per model and the
       pooled deep mean of Fig. 9, for every run subset) mean, SD, min-max over runs, ci_mean_lo/hi = mean of
       the per-run Wilson limits (interval of the run mean under fully dependent errors: conservative) and
       the envelope of the per-run intervals; tree runs: exact per-sub-attack Wilson intervals.
     Every row carries small_n = n < --min-n (200).

Output: results_2026_03_03/q1_revision/analyses2/
  a_runs/<run>.json (per-run cache)         a_capture_detection.csv (run x capture group / class)
  a_capture_detection_summary.csv (over seeds)   a_focus.csv   a_run_level.csv   a_capture_detection.json
  b_runs.csv   b_runs_per_class.csv   b_cells.csv   b_cells_per_class.csv (S1)   b_differences.csv
  b_table9_macro_f1.csv   b_table10_bal_acc.csv   b_table11_decomp_macro_f1.csv
  b_table_s1_per_class_f1.csv   b_uncertainty.json
  c_fig4_subattack_wilson.csv   c_table13_seen_wilson.csv   c_fig9_deep_subattack_wilson.csv
  c_fig9_deep_cells.csv   c_tree_subattack_wilson.csv   c_wilson.json
Resumable: a part is skipped when its JSON exists and was made from the same input files (names and
modification times), settings and script VERSION; new runs (e.g. finished tree_seeds / deep_protocol fits)
make it stale, so simply rerun. Part (a) also caches every run (a_runs/, valid while the npz and the settings are
unchanged); only new runs need the parquet columns. --force redoes the selected parts (and the a_runs
caches). Nothing is trained, so there is no --max-fits.
Memory: (a) ~0.4-0.6 GB (parquet columns + one run), (b) ~0.3 GB for ~250 stored runs, (c) small.
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\revision_analyses2.py --dry-run
  & $py experiments\revision_analyses2.py 2>&1 | Tee-Object -FilePath revision_analyses2.log
  & $py experiments\revision_analyses2.py --parts b c 2>&1 | Tee-Object -FilePath revision_analyses2_bc.log
  & $py experiments\revision_analyses2.py --parts a 2>&1 | Tee-Object -FilePath revision_analyses2_a.log
  & $py experiments\revision_analyses2.py --parts b --force 2>&1 | Tee-Object -FilePath revision_analyses2_b.log
"""
import argparse, gc, hashlib, json, math, os, re, sys, time, warnings, zlib
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import flagged_loader  # noqa: E402
from deep_split_noise_study import kept_rows, splits  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
warnings.filterwarnings('ignore', category=FutureWarning)        # pandas groupby(observed=...) notice

RES = HERE.parent / 'results_2026_03_03'
OUT = RES / 'q1_revision' / 'analyses2'
CACHE = flagged_loader.CACHE
K = len(CLASSES)
BENIGN = CLASSES.index('Benign')
ATTACK = [c for c in range(K) if c != BENIGN]
GMUL = 64                                   # group id = class * GMUL + capture-group code
Z = 1.959963984540054                       # 97.5% normal quantile
NAT = np.iinfo(np.int64).min
PKT = ['Total Fwd Packet', 'Total Bwd packets']
METRICS = ['macro_f1', 'bal_acc', 'accuracy', 'attack_macro_f1']
DIFF_METRICS = ['macro_f1', 'bal_acc']
CONDS = [('random', 'raw'), ('random', 'r1'), ('temporal', 'raw'), ('temporal', 'r1')]
DECOMP_CONDS = [('raw', 'raw'), ('raw', 'r1'), ('r1', 'raw'), ('r1', 'r1')]
FOCUS = {'ddos / ddos icmp flood': 'DDoS ICMP Flood', 'ddos / ddos icmp fragmentation': 'DDoS ICMP Fragmentation',
         'mirai / mirai': 'Mirai (GRE)', 'ddos / ddos ack fragmentation': 'DDoS ACK Fragmentation'}
SHORT = {'DDoS ICMP Flood': 'ICMPflood', 'DDoS ICMP Fragmentation': 'ICMPfrag', 'Mirai (GRE)': 'Mirai',
         'DDoS ACK Fragmentation': 'ACKfrag'}
PAPER_DEEP = ('ResNet1D', 'GRU', 'Transformer')             # the deep models of Figs. 8-9
DEEP_MEAN = 'Deep mean (ResNet1D/GRU/Transformer)'          # pooled cell = the deep mean shown in Figs. 8-9
PAPER_SOURCES = ('tree_protocol', 'deep_split')             # folders of the runs behind the published tables
MODEL_ORDER = ['ResNet1D', 'GRU', 'Transformer', 'FT_Transformer', 'MLP', 'CNN1D_Hossain', DEEP_MEAN,
               'XGBoost', 'LightGBM', 'RandomForest']
VERSION = 3                                 # bump when a computation changes: older outputs / caches become stale
# run folders: (family, glob relative to RES); the paper's folders come first (preferred for duplicates)
TREE_DIRS = ['tree_protocol/main', 'tree_protocol/decomp', 'q1_revision/tree_seeds', 'q1_revision/tree_seeds_proba']
DEEP_DIRS = ['deep_split', 'q1_revision/deep_protocol']
KNOWN_ROOTS = {'tree_protocol', 'tree_seeds', 'tree_seeds_proba', 'deep_split', 'deep_protocol'}
GENERIC_SUBDIRS = {'main', 'decomp', 'runs', 'earlystop', 'preds', 'npz', 'predictions'}


def skip_dir(name):
    """Folders that hold no protocol runs (as deep_protocol_summary.collect): MLP tuning trials, summaries."""
    return name.startswith('mlp_tuning') or name == 'summary' or name.startswith('_')


VARIANT_KEYS = ('variant', 'class_weight', 'weighting')
DEFAULT_VALUES = {'', 'balanced', 'default', 'earlystop'}
MAIN_RE = re.compile(r'^(\w+?)_(random|temporal)_(raw|r1|all)_s(\d+)(.*)$')
DECOMP_RE = re.compile(r'^(\w+?)_(random|temporal)_train-(raw|r1|all)_test-(raw|r1|all)(?:_s(\d+))?(.*)$')
STEM = {'a': 'a_capture_detection', 'b': 'b_uncertainty', 'c': 'c_wilson'}
MAX_CELLS = 4_000_000                       # max multinomial cells per draw chunk (memory of the joint bootstrap)


# ----------------------------------------------------------------------------- small helpers
def rnd(v, k=6):
    if v is None or isinstance(v, (str, bool, np.bool_)):
        return bool(v) if isinstance(v, np.bool_) else v
    try:
        f = float(v)
    except (TypeError, ValueError):
        return v
    return round(f, k) if math.isfinite(f) else None


def _js(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return rnd(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, Path):
        return o.as_posix()
    raise TypeError(type(o))


def records(df):
    return df.astype(object).where(df.notna(), None).to_dict('records')


def q(a, b):
    return float(a) / float(b) if b else None


def wilson(k, n, z=Z):
    """Wilson score interval; arrays or scalars; NaN where n = 0."""
    k = np.asarray(k, float); n = np.asarray(n, float)
    with np.errstate(divide='ignore', invalid='ignore'):
        p = k / n
        z2 = z * z
        den = 1 + z2 / n
        c = (p + z2 / (2 * n)) / den
        h = z * np.sqrt(np.maximum(p * (1 - p) / n + z2 / (4 * n * n), 0)) / den
        lo = np.where(n > 0, np.clip(c - h, 0, 1), np.nan)
        hi = np.where(n > 0, np.clip(c + h, 0, 1), np.nan)
    return (float(lo), float(hi)) if lo.ndim == 0 else (lo, hi)


def counts_from_share(share, n, decimals):
    """Counts consistent with a share rounded to `decimals`: (k, k_min, k_max)."""
    half = 0.5 * 10.0 ** (-decimals)
    kmin = max(0, math.ceil((share - half) * n - 1e-9))
    kmax = min(n, math.floor((share + half) * n + 1e-9))
    k = int(round(share * n))
    if kmin > kmax:                            # no integer count reproduces the rounded share: keep round()
        return k, k, k
    return min(max(k, kmin), kmax), kmin, kmax


def boot_p(d):
    """Two-sided bootstrap p of a difference: 2 (min(#d <= 0, #d >= 0) + 1) / (B + 1)."""
    return min(1.0, 2 * (min(int((d <= 0).sum()), int((d >= 0).sum())) + 1) / (len(d) + 1))


def holm(p):
    p = np.asarray(p, float)
    order = np.argsort(p); adj = np.empty(len(p)); run = 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (len(p) - r) * p[i])); adj[i] = run
    return adj


def rng_for(label):
    return np.random.default_rng([SEED, zlib.crc32(label.encode('utf-8'))])


def ci(arr, axis=0):
    lo, hi = np.percentile(arr, [2.5, 97.5], axis=axis)
    return lo, hi


def safe(s):
    return re.sub(r'[^\w.-]+', '__', s)


def is_paper(source):
    """True for a run of the folders behind the published tables (tree_protocol, deep_split)."""
    return str(source).split('/')[0] in PAPER_SOURCES


def subset_masks(paper, epochs, deep, min_epochs):
    """Run subsets of one cell as [(label, bool mask)]: 'all'; 'paper runs' (tree_protocol / deep_split only,
    i.e. the published cell before the extra seeds of tree_seeds / deep_protocol); for deep cells also the runs
    that trained normally (epochs_run >= min_epochs, the filter of Figs. 8-9 and S1), alone and with the paper
    runs. Empty subsets and subsets with the same runs as an earlier one are dropped, so e.g. 'paper runs' only
    appears when the cell has extra runs."""
    paper = np.asarray(list(paper), bool)
    e = pd.to_numeric(pd.Series(list(epochs), dtype=object), errors='coerce').to_numpy(float)
    with np.errstate(invalid='ignore'):
        ok = e >= min_epochs                               # unknown epochs (NaN) -> not in the filtered subset
    cand = [('all', np.ones(len(paper), bool)), ('paper runs', paper)]
    if deep:
        cand += [(f'epochs_run>={min_epochs}', ok), (f'paper runs, epochs_run>={min_epochs}', paper & ok)]
    out = []
    for lab, m in cand:
        if m.any() and not any(np.array_equal(m, s) for _, s in out):
            out.append((lab, m))
    return out


def write(part, obj, tables):
    """CSV tables first, JSON last and atomically: the JSON marks the part as finished (resume)."""
    for name, df in tables.items():
        df.to_csv(OUT / f'{name}.csv', index=False)
    tmp = OUT / f'{STEM[part]}.json.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=1, default=_js)
    os.replace(tmp, OUT / f'{STEM[part]}.json')


def fingerprint(paths):
    return sorted([p.relative_to(RES).as_posix(), int(p.stat().st_mtime)] for p in paths if p is not None and p.exists())


def is_current(part, inputs):
    f = OUT / f'{STEM[part]}.json'
    if not f.exists():
        return False
    try:
        with open(f, encoding='utf-8') as fh:
            return json.load(fh).get('inputs') == inputs
    except (OSError, ValueError):
        return False


# ----------------------------------------------------------------------------- run discovery
def describe(path, js, family, root):
    """Descriptor of one stored run from its file name, JSON fields and folder."""
    stem = path.stem
    d = {'kind': None, 'model': None, 'seed': None, 'split': None, 'train_cleaning': None, 'test_cleaning': None}
    rest = ''
    m = DECOMP_RE.match(stem)
    if m:
        d.update(kind='decomp', model=m[1], split=m[2], train_cleaning=m[3], test_cleaning=m[4],
                 seed=int(m[5]) if m[5] else 42)
        rest = m[6]
    else:
        m = MAIN_RE.match(stem)
        if m:
            d.update(kind='main', model=m[1], split=m[2], train_cleaning=m[3], test_cleaning=m[3], seed=int(m[4]))
            rest = m[5]
    jm = js.get('model')
    if isinstance(jm, str) and jm:
        if d['model'] and d['model'] != jm and d['model'].endswith('_' + jm):
            rest = d['model'][:-len(jm) - 1] + '_' + rest          # prefix in the file name = a variant
        d['model'] = jm
    for k in ('seed', 'split'):
        if js.get(k) is not None:
            d[k] = js[k]
    if js.get('train_cleaning') is not None or js.get('cleaning') is not None:
        d['train_cleaning'] = js.get('train_cleaning', js.get('cleaning'))
        d['test_cleaning'] = js.get('test_cleaning', js.get('cleaning'))
    if js.get('kind') in ('main', 'decomp'):
        d['kind'] = js['kind']
    if d['kind'] is None:
        d['kind'] = 'main' if d['train_cleaning'] == d['test_cleaning'] else 'decomp'
    parts = [] if root.name in KNOWN_ROOTS else [root.name]
    parts += [s for s in path.parent.relative_to(root).parts if s not in GENERIC_SUBDIRS]
    if rest.strip('_'):
        parts.append(rest.strip('_'))
    for k in VARIANT_KEYS:
        v = js.get(k)
        if isinstance(v, (str, int, float, bool)) and str(v).lower() not in DEFAULT_VALUES:
            parts.append(f'{k}={v}')
    try:
        d['seed'] = int(d['seed'])
    except (TypeError, ValueError):
        return None
    if (not d['model'] or d['split'] not in ('random', 'temporal')
            or d['train_cleaning'] not in ('raw', 'r1', 'all') or d['test_cleaning'] not in ('raw', 'r1', 'all')):
        return None
    npz = path.with_suffix('.npz')
    er = js.get('epochs_run')
    return {'id': path.relative_to(RES).with_suffix('').as_posix(), 'family': family,
            'source': path.parent.relative_to(RES).as_posix(), 'json': path,
            'npz': npz if npz.exists() else None, 'has_pred': npz.exists(), **d,
            'variant': '|'.join(parts), 'epochs_run': int(er) if isinstance(er, (int, float)) else None,
            'js': js}


def discover(a, verbose=True):
    runs, bad, dup, seen = [], [], [], {}
    for family, rels in (('tree', a.tree_dirs), ('deep', a.deep_dirs)):
        for rel in rels:
            base = RES / rel
            if not base.is_dir():
                continue
            root = base.parent if base.parent.name in KNOWN_ROOTS else base   # tree_protocol/main -> tree_protocol
            for f in sorted(base.rglob('*.json')):
                if any(skip_dir(s) for s in f.relative_to(base).parts[:-1]) or f.name.endswith('.tmp'):
                    continue
                try:
                    with open(f, encoding='utf-8') as fh:
                        js = json.load(fh)
                except (OSError, ValueError):
                    bad.append(f.relative_to(RES).as_posix()); continue
                if not (isinstance(js, dict) and isinstance(js.get('per_class_f1'), dict)):
                    continue                              # summaries, configs
                r = describe(f, js, family, root)
                if r is None:
                    bad.append(f.relative_to(RES).as_posix()); continue
                key = (r['family'], r['model'], r['variant'], r['kind'], r['split'], r['train_cleaning'],
                       r['test_cleaning'], r['seed'])
                if key in seen:
                    kept = seen[key]
                    d = {'kept': kept['id'], 'skipped': r['id'], 'skipped_has_pred': r['has_pred'],
                         'kept_has_pred': kept['has_pred'], 'macro_f1_kept': rnd(kept['js'].get('macro_f1')),
                         'macro_f1_skipped': rnd(js.get('macro_f1')), 'predictions_used': None}
                    if r['has_pred'] and not kept['has_pred'] and kept.get('alt') is None:
                        # the paper's run stored no predictions (deep_split) but a rerun of the same seed did
                        # (deep_protocol_study --rerun-existing): identical metrics -> its predictions ARE the
                        # paper run's (parts a, b, c exact); otherwise they are used for part (a) only
                        kept['alt'] = r
                        if reproduces(kept['js'], js):
                            kept.update(npz=r['npz'], has_pred=True, pred_from=r['id'])
                            d['predictions_used'] = 'parts a, b, c (rerun reproduces the stored metrics exactly)'
                        else:
                            d['predictions_used'] = 'part a only (rerun metrics differ from the paper run)'
                    dup.append(d)
                    continue
                seen[key] = r
                runs.append(r)
    if verbose:
        n_pred = sum(r['has_pred'] for r in runs)
        n_sub = sum(bool(r.get('pred_from')) for r in runs)
        n_alt = sum(bool(r.get('alt')) and not r.get('pred_from') for r in runs)
        print(f'[runs] {len(runs)} runs ({n_pred} with stored predictions, {n_sub} of them from an identical rerun), '
              f'{len(dup)} duplicate seeds skipped ({n_alt} non-identical reruns used in part a only), '
              f'{len(bad)} unreadable/unparsed JSON', flush=True)
        for b in bad[:10]:
            print(f'  [skip] {b}', flush=True)
    return runs, dup, bad


def reproduces(js_a, js_b):
    """True when two run JSONs carry identical test metrics (same predictions up to a relabelling that
    no metric can see): accuracy, balanced accuracy, macro-F1 (full precision) and every stored per-class
    F1 / recall and per-sub-attack recall (4 decimals)."""
    for k in ('accuracy', 'balanced_accuracy', 'macro_f1'):
        try:
            if abs(float(js_a[k]) - float(js_b[k])) > 1e-12:
                return False
        except (KeyError, TypeError, ValueError):
            return False
    return all(js_a.get(k) == js_b.get(k) for k in ('per_class_f1', 'per_class_recall', 'per_subattack_recall'))


def part_a_runs(runs):
    """Runs with predictions for part (a): every run with an npz, plus, for a paper run without predictions,
    the rerun of the same seed that stored them (deep_protocol_study --rerun-existing; recorded as such)."""
    return [r for r in runs if r['has_pred']] + [r['alt'] for r in runs if not r['has_pred'] and r.get('alt')]


def load_pred(path):
    """y, p, capture group (str) and stored global rows (or None) of an npz; p = argmax(proba) if needed."""
    with np.load(path, allow_pickle=True) as d:          # own result files ('sub' may be an object array)
        y = d['y'].astype(np.int64).ravel()
        if 'p' in d.files:
            p = d['p'].astype(np.int64).ravel()
        else:
            key = next(k for k in ('proba', 'prob', 'probs') if k in d.files)
            p = np.asarray(d[key], np.float32).argmax(1).astype(np.int64)
        sub = np.asarray(d['sub']).astype(str) if 'sub' in d.files else None
        rows = d['rows'].astype(np.int64).ravel() if 'rows' in d.files else None
    return y, p, sub, rows


def signature(y, sub):
    h = hashlib.md5(np.ascontiguousarray(y.astype(np.int8)).tobytes())
    if sub is not None:
        h.update(pd.util.hash_array(np.asarray(sub, dtype=object)).tobytes())
    return f'{len(y)}:{h.hexdigest()[:16]}'


def model_rank(model, family):
    return (0 if family == 'deep' else 1, MODEL_ORDER.index(model) if model in MODEL_ORDER else 99, model)


def model_key(model, family):
    """String sort key (deep models first, then the tree ensembles, paper order) for DataFrames."""
    a, b, c = model_rank(model, family)
    return f'{a}{b:03d}{c}'


def label(cell):
    fam, model, variant = cell[0], cell[1], cell[2]
    s = model + (f' [{variant}]' if variant else '')
    return s + (f' ({cell[7]})' if cell[7] != 'all' else '')


# ----------------------------------------------------------------------------- (a) data of the sample
def ref_key(kind, split, test_cleaning):
    """Key of a test set: the raw test set of 'decomp' IS the raw test set of 'main' (same splits() call)."""
    return ('main' if test_cleaning == 'raw' else kind, split, test_cleaning)


def stored_rows(path):
    """The 'rows' array of an npz (None when the run did not store it); nothing else is read."""
    with np.load(path, allow_pickle=False) as d:
        return d['rows'].astype(np.int64).ravel() if 'rows' in d.files else None


class Sample:
    """y, capture group, time, rule flags, protocol-0 indicator and packets of the cached sample, read
    column by column (no feature matrix). Row order = load_prepared() / get_flagged() order."""

    def __init__(self):
        import pyarrow.parquet as pq
        pf = pq.ParquetFile(CACHE)
        meta = pf.read(columns=['y', 'sub', 'ts']).to_pandas()        # as flagged_loader.load_prepared
        meta['sub'] = meta['sub'].astype('category')
        self.meta = meta
        self.flags = {c: np.asarray(pf.read(columns=[c]).column(0).to_numpy(), bool) for c in flagged_loader.FLAGS}
        self.y = meta['y'].to_numpy().astype(np.int64)
        self.sub = meta['sub'].cat.codes.to_numpy().astype(np.int64)
        self.names = np.array(meta['sub'].cat.categories.astype(str).tolist())
        assert len(self.names) <= GMUL and (self.sub >= 0).all(), 'capture-group codes out of range'
        self.ts = meta['ts'].to_numpy('datetime64[ns]').view(np.int64).copy()
        pk = np.zeros(len(self.y))
        for c in PKT:                                  # the load_prepared() feature columns, NaN/inf -> 0
            v = pf.read(columns=[c], use_threads=False).column(0).to_numpy().astype(np.float32, copy=False)
            pk += np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)
        self.pk = pk
        pr = pf.read(columns=['Protocol']).column(0).to_numpy()
        self.proto0 = np.asarray(pr == 0, bool)
        del pr, v
        self.lut = {n: i for i, n in enumerate(self.names)}
        self._te = {}
        self.refs = {}                                 # ref_key -> (run id, stored global test rows)

    def keep(self, how):
        m = np.zeros(len(self.y), bool)
        m[kept_rows(self.flags, how)] = True
        return m

    def test_rows(self, kind, split, test_cleaning):
        """Global test rows in the stored order: 'main' = cleaning first, then splits() on the kept rows
        (tree_protocol_study main, deep_split_noise_study); 'decomp' = splits() on the raw rows, test part
        filtered (tree_protocol_study decomp)."""
        key = (kind, split, test_cleaning)
        if key not in self._te:
            if kind == 'main' and test_cleaning == 'raw':
                te = splits(self.meta, split)[2]
            elif kind == 'main':
                rows = kept_rows(self.flags, test_cleaning)
                te = rows[splits(self.meta.iloc[rows].reset_index(drop=True), split)[2]]
            else:
                te = self.test_rows('main', split, 'raw')
                if test_cleaning != 'raw':
                    te = te[self.keep(test_cleaning)[te]]
            self._te[key] = np.asarray(te, np.int64)
        return self._te[key]

    def match(self, te, y, sub):
        if (len(te) != len(y) or not len(te) or te.min() < 0 or te.max() >= len(self.y)
                or not np.array_equal(self.y[te], y)):
            return False
        if sub is None:
            return True
        names, inv = np.unique(sub, return_inverse=True)
        if any(n not in self.lut for n in names):
            return False
        return np.array_equal(np.array([self.lut[n] for n in names])[inv.ravel()], self.sub[te])

    def locate(self, r, y, sub, rows):
        """(global test rows, how, rows_check). A rebuilt row set is also compared with the stored 'rows' of
        another run on the same test set (tree_seeds / deep_protocol npz), when one exists: the y / sub check
        alone cannot see a wrong order INSIDE a capture group (temporal split: y and sub are blockwise constant)."""
        if rows is not None:
            if self.match(rows, y, sub):
                return rows, 'rows stored in the npz', 'stored rows'
            return None, 'stored rows do not match', None
        other = 'decomp' if r['kind'] == 'main' else 'main'
        for kind in (r['kind'], other):
            te = self.test_rows(kind, r['split'], r['test_cleaning'])
            if self.match(te, y, sub):
                how = f'rebuilt ({kind}: {"clean then split" if kind == "main" else "split then filter"})'
                ref = self.refs.get(ref_key(kind, r['split'], r['test_cleaning']))
                if ref is None:
                    check = 'no stored rows of the same test set to compare'
                elif np.array_equal(te, ref[1]):
                    check = f'identical to the stored rows of {ref[0]}'
                else:
                    check = f'DIFFERENT from the stored rows of {ref[0]}'
                return te, how, check
        return None, 'test rows could not be rebuilt', None


def windows(ids, n_ids, ts, w, ok, att, mask, w_ns, thr):
    """Per id: number of time windows with flows, windows whose packet-weighted recall >= thr
    (flow share when the window has no packets), windows with at least one flow predicted as an attack."""
    res = {'n': np.zeros(n_ids), 'det': np.zeros(n_ids), 'alert': np.zeros(n_ids)}
    sel = np.flatnonzero(mask & (ts != NAT))
    if not len(sel):
        return res
    win = ts[sel] // w_ns
    key = ids[sel].astype(np.int64) * (1 << 32) + (win - win.min())
    u, inv = np.unique(key, return_inverse=True)
    inv = inv.ravel()
    wt = np.bincount(inv, weights=w[sel]); wc = np.bincount(inv, weights=w[sel] * ok[sel])
    nf = np.bincount(inv).astype(float); cf = np.bincount(inv, weights=ok[sel]); af = np.bincount(inv, weights=att[sel])
    rec = np.where(wt > 0, wc / np.where(wt > 0, wt, 1), cf / nf)
    gi = (u >> 32).astype(np.int64)
    res['n'] = np.bincount(gi, minlength=n_ids).astype(float)
    res['det'] = np.bincount(gi, weights=(rec >= thr).astype(float), minlength=n_ids)
    res['alert'] = np.bincount(gi, weights=(af > 0).astype(float), minlength=n_ids)
    return res


def a_measures(smp, te, y, p, a):
    """Rows (capture group and class level) and run-level numbers of one stored prediction."""
    sc = smp.sub[te]
    w = smp.pk[te]; z = smp.proto0[te].astype(float); ts = smp.ts[te]
    r1 = smp.flags['r1_external'][te].astype(float)
    ok = (p == y).astype(float); att = (p != BENIGN).astype(float)
    w_ns = int(a.window_min * 60 * 1e9)
    rows, run = [], {}
    for level, ids, n_ids in (('capture', y * GMUL + sc, GMUL * K), ('class', y, K)):
        bc = lambda v=None: np.bincount(ids, weights=v, minlength=n_ids)
        S = {'n': bc(), 'n_ok': bc(ok), 'n_att': bc(att), 'pk': bc(w), 'pk_ok': bc(w * ok), 'pk_att': bc(w * att),
             'n0': bc(z), 'n0_ok': bc(z * ok), 'n0_att': bc(z * att), 'pk0': bc(w * z), 'pk0_ok': bc(w * z * ok),
             'pk0_att': bc(w * z * att), 'n0_r1': bc(z * r1)}
        wa = windows(ids, n_ids, ts, w, ok, att, np.ones(len(te), bool), w_ns, a.detect)
        w0 = windows(ids, n_ids, ts, w, ok, att, z > 0, w_ns, a.detect)
        for i in np.flatnonzero(S['n'] > 0):
            c = int(i // GMUL) if level == 'capture' else int(i)
            name = f'{CLASSES[c]} / {smp.names[i % GMUL]}' if level == 'capture' else CLASSES[c]
            s = {k: float(v[i]) for k, v in S.items()}
            n1, pk1 = s['n'] - s['n0'], s['pk'] - s['pk0']
            lo, hi = wilson(s['n_ok'], s['n'])
            lo0, hi0 = wilson(s['n0_ok'], s['n0']) if s['n0'] else (None, None)
            p0, pp0 = q(s['n0_ok'], s['n0']), q(s['pk0_ok'], s['pk0'])
            a0 = q(s['n0_att'], s['n0'])
            rows.append({
                'level': level, 'group': name, 'class': CLASSES[c], 'is_attack': c != BENIGN,
                'focus': FOCUS.get(name.lower()) if level == 'capture' else None,
                'n_test': int(s['n']), 'n_packets': s['pk'], 'proto0_flows': int(s['n0']),
                'proto0_flow_share': q(s['n0'], s['n']), 'proto0_packets': s['pk0'],
                'proto0_packet_share': q(s['pk0'], s['pk']), 'proto0_r1_flagged_share': q(s['n0_r1'], s['n0']),
                'flow_recall': q(s['n_ok'], s['n']), 'flow_recall_lo': lo, 'flow_recall_hi': hi,
                'packet_recall': q(s['pk_ok'], s['pk']),
                'proto0_recall': p0, 'proto0_recall_lo': lo0, 'proto0_recall_hi': hi0, 'proto0_packet_recall': pp0,
                'nonproto0_recall': q(s['n_ok'] - s['n0_ok'], n1), 'nonproto0_packet_recall': q(s['pk_ok'] - s['pk0_ok'], pk1),
                'flow_attack_rate': q(s['n_att'], s['n']), 'packet_attack_rate': q(s['pk_att'], s['pk']),
                'proto0_attack_rate': a0, 'proto0_packet_attack_rate': q(s['pk0_att'], s['pk0']),
                'nonproto0_attack_rate': q(s['n_att'] - s['n0_att'], n1),
                'capture_detected_share': q(s['n_ok'], s['n']),
                'capture_detected_proto0': None if p0 is None else bool(p0 >= a.detect),
                'capture_detected_proto0_packets': None if pp0 is None else bool(pp0 >= a.detect),
                'capture_alarm_proto0': None if a0 is None else bool(a0 >= a.detect),
                'windows_all': int(wa['n'][i]), 'windows_all_detected_share': q(wa['det'][i], wa['n'][i]),
                'windows_proto0': int(w0['n'][i]), 'windows_proto0_detected_share': q(w0['det'][i], w0['n'][i]),
                'windows_proto0_alert_share': q(w0['alert'][i], w0['n'][i])})
        if level == 'class':
            fr = [q(S['n_ok'][c], S['n'][c]) for c in range(K) if S['n'][c] > 0]
            pr = [q(S['pk_ok'][c], S['pk'][c]) for c in range(K) if S['pk'][c] > 0]
            A = {k: float(v[ATTACK].sum()) for k, v in S.items()}
            run = {'flow_bal_acc': float(np.mean(fr)), 'packet_bal_acc': float(np.mean(pr)) if pr else None,
                   'attack_flow_detect': q(A['n_att'], A['n']), 'attack_packet_detect': q(A['pk_att'], A['pk']),
                   'attack_proto0_flow_recall': q(A['n0_ok'], A['n0']),
                   'attack_proto0_packet_recall': q(A['pk0_ok'], A['pk0']),
                   'attack_proto0_flow_detect': q(A['n0_att'], A['n0']),
                   'attack_proto0_packet_detect': q(A['pk0_att'], A['pk0']),
                   'attack_proto0_flow_share': q(A['n0'], A['n']), 'attack_proto0_packet_share': q(A['pk0'], A['pk'])}
    return rows, run


DESC = ['family', 'model', 'variant', 'kind', 'split', 'train_cleaning', 'test_cleaning']
A_MEAS = ['flow_recall', 'packet_recall', 'proto0_recall', 'proto0_packet_recall', 'nonproto0_recall',
          'nonproto0_packet_recall', 'flow_attack_rate', 'packet_attack_rate', 'proto0_attack_rate',
          'proto0_packet_attack_rate', 'windows_all_detected_share', 'windows_proto0_detected_share',
          'windows_proto0_alert_share']
A_CONST = ['n_test', 'proto0_flows', 'proto0_flow_share', 'proto0_packet_share', 'proto0_r1_flagged_share',
           'windows_all', 'windows_proto0']


def part_a(a, runs, inputs):
    if not CACHE.exists():
        print(f'[a] {CACHE} not found - part a skipped (run flagged_loader first)', flush=True)
        return
    cdir = OUT / 'a_runs'
    cdir.mkdir(parents=True, exist_ok=True)
    pr = part_a_runs(runs)
    # the per-run cache depends on the settings AND on the flagged sample it was computed from
    settings = {'detect': a.detect, 'window_min': a.window_min, 'sample': [CACHE.name, int(CACHE.stat().st_mtime)],
                'version': VERSION}

    def cached(r):
        """The per-run cache is valid when it is newer than the npz and was made with the same settings."""
        f = cdir / f'{safe(r["id"])}.json'
        if not f.exists() or f.stat().st_mtime < r['npz'].stat().st_mtime:
            return False
        try:
            with open(f, encoding='utf-8') as fh:
                return json.load(fh).get('settings') == settings
        except (OSError, ValueError):
            return False

    todo = [r for r in pr if a.force or not cached(r)]
    print(f'[a] {len(pr)} runs with predictions, {len(pr) - len(todo)} cached, {len(todo)} to compute', flush=True)
    if todo:
        t = time.time()
        smp = Sample()
        # stored 'rows' of one run per test set (tree_seeds / deep_protocol), to verify the rebuilt row order
        need = {ref_key(r['kind'], r['split'], r['test_cleaning']) for r in todo}
        for r in pr:
            k = ref_key(r['kind'], r['split'], r['test_cleaning'])
            if k in need and k not in smp.refs:
                rw = stored_rows(r['npz'])
                if rw is not None:
                    smp.refs[k] = (r['id'], rw)
        print(f'[a] sample: {len(smp.y):,} flows; y, sub, ts, 3 flags, Protocol, packets ({time.time() - t:.0f} s); '
              f'stored rows for {len(smp.refs)} of {len(need)} test sets', flush=True)
        for i, r in enumerate(todo, 1):
            t = time.time()
            y, p, sub, rows = load_pred(r['npz'])
            te, how, check = smp.locate(r, y, sub, rows)
            if check and check.startswith('DIFFERENT'):
                print(f'  [WARN] {r["id"]}: rebuilt test rows {check}', flush=True)
            out = {'id': r['id'], **{k: r[k] for k in DESC}, 'seed': r['seed'], 'epochs_run': r['epochs_run'],
                   'n_test': int(len(y)), 'row_order': how, 'rows_check': check, 'matched': te is not None,
                   'settings': settings}
            if te is not None:
                out['rows'], out['run_level'] = a_measures(smp, te, y, p, a)
                foc = {x['focus']: x for x in out['rows'] if x.get('focus')}
                msg = '  '.join(f'{SHORT[k]}:'
                                f'{v["flow_recall"]:.2f}/{v["packet_recall"] or 0:.2f}/'
                                f'{(v["proto0_recall"] if v["proto0_recall"] is not None else float("nan")):.2f}'
                                for k, v in foc.items())
                print(f'[a {i}/{len(todo)}] {r["id"]}: flow/packet/proto0 recall {msg} [{how}] '
                      f'({time.time() - t:.1f} s)', flush=True)
            else:
                print(f'[a {i}/{len(todo)}] {r["id"]}: [warn] {how} - skipped', flush=True)
            tmp = cdir / f'{safe(r["id"])}.json.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(out, fh, default=_js)
            os.replace(tmp, cdir / f'{safe(r["id"])}.json')
            del y, p, sub, rows, te; gc.collect()
        del smp; gc.collect()

    ids = {r['id']: r for r in pr}
    det, runl, unmatched = [], [], []
    for f in sorted(cdir.glob('*.json')):
        with open(f, encoding='utf-8') as fh:
            x = json.load(fh)
        if x['id'] not in ids:
            continue
        r = ids[x['id']]
        # a deep_protocol rerun standing in for a deep_split run without predictions: name the paper run
        stand_in = next((q_['id'] for q_ in runs if q_.get('alt') is r and q_.get('pred_from') != r['id']), None)
        base = {'id': x['id'], **{k: x[k] for k in DESC}, 'seed': x['seed'], 'epochs_run': r['epochs_run'],
                'source': r['source'], 'predictions_from': r.get('pred_from'), 'rerun_for': stand_in}
        if not x.get('matched'):
            unmatched.append({'id': x['id'], 'reason': x.get('row_order')}); continue
        det += [{**base, **row} for row in x['rows']]
        runl.append({**base, 'n_test': x['n_test'], 'row_order': x['row_order'], 'rows_check': x.get('rows_check'),
                     **x['run_level']})
    df = pd.DataFrame(det)
    rl = pd.DataFrame(runl)
    if df.empty:
        print('[a] no matched runs', flush=True)
        return
    keys = DESC + ['level', 'group', 'class', 'focus']
    summ = []
    for key, g0 in df.groupby(keys, sort=False, dropna=False):
        # 'all' runs; the paper's runs only (tree_protocol / deep_split) when the cell has extra seeds; deep cells:
        # also the runs that trained normally (epochs_run >= --min-epochs, the filter of Figs. 8-9)
        masks = subset_masks(g0['source'].map(is_paper), g0['epochs_run'], key[0] == 'deep', a.min_epochs)
        for runs_f, msk in masks:
            g = g0[msk]
            row = dict(zip(keys, key))
            row.update({'runs': runs_f, 'n_runs': len(g), 'seeds': ' '.join(map(str, sorted(g['seed']))),
                        'sources': ' '.join(sorted(set(g['source'])))})
            for c in A_CONST:
                row[c] = pd.to_numeric(g[c], errors='coerce').mean()
            for c in A_MEAS:
                v = pd.to_numeric(g[c], errors='coerce')
                row.update({c: v.mean(), f'{c}_sd': v.std(ddof=1) if v.notna().sum() > 1 else None,
                            f'{c}_min': v.min(), f'{c}_max': v.max()})
            for c in ('capture_detected_proto0', 'capture_detected_proto0_packets', 'capture_alarm_proto0'):
                v = g[c].dropna().astype(bool) if c in g else pd.Series(dtype=bool)
                row[f'{c}_runs'] = f'{int(v.sum())}/{len(v)}' if len(v) else None
            summ.append(row)
    sm = pd.DataFrame(summ)
    sm['_r'] = [model_key(m, f) for m, f in zip(sm['model'], sm['family'])]
    sm = sm.sort_values(['level', 'group', 'kind', 'split', 'train_cleaning', 'test_cleaning', '_r', 'variant',
                         'runs']).drop(columns='_r')
    foc_cols = keys[:-2] + ['focus', 'runs', 'n_runs', 'seeds', 'sources', 'n_test', 'proto0_flows', 'proto0_flow_share',
                            'proto0_packet_share', 'proto0_r1_flagged_share', 'flow_recall', 'flow_recall_sd',
                            'packet_recall', 'proto0_recall', 'proto0_recall_min', 'proto0_recall_max',
                            'proto0_packet_recall', 'nonproto0_recall', 'nonproto0_packet_recall',
                            'flow_attack_rate', 'packet_attack_rate', 'proto0_attack_rate',
                            'proto0_packet_attack_rate', 'capture_detected_proto0_runs',
                            'capture_detected_proto0_packets_runs', 'capture_alarm_proto0_runs', 'windows_proto0',
                            'windows_proto0_detected_share', 'windows_proto0_alert_share']
    foc = sm[(sm['level'] == 'capture') & sm['focus'].notna()][foc_cols]
    foc = foc.assign(_f=foc['focus'].map({v: i for i, v in enumerate(FOCUS.values())}),
                     _r=[model_key(m, f) for m, f in zip(foc['model'], foc['family'])]).sort_values(
        ['_f', 'kind', 'split', 'train_cleaning', 'test_cleaning', '_r', 'variant', 'runs']).drop(columns=['_f', '_r'])
    df, sm, foc, rl = df.round(6), sm.round(6), foc.round(6), rl.round(6)
    write('a', {'description': 'disc-10: detection per capture group - flow-level vs packet-weighted recall, '
                               'protocol-0 (flood) flows vs the other flows, capture/episode detection',
                'definitions': {
                    'packet weight': 'Total Fwd Packet + Total Bwd packets of the test flow (load_prepared feature '
                                     'columns, NaN -> 0)',
                    'protocol-0': 'Protocol == 0 in the flagged sample (CICFlowMeter: ICMP, GRE, fragments ...)',
                    'recall': 'share (or packet share) of the flows assigned to the true class',
                    'attack_rate': 'share assigned to any attack class (prediction != Benign); for Benign = false alarms',
                    'capture_detected_share': 'share of the test flows of the capture assigned to the true class '
                                              '(= flow_recall)',
                    'capture_detected_proto0': f'protocol-0 recall >= {a.detect} (None: no protocol-0 test flow); '
                                               '_runs = number of runs of the cell in which this holds / runs',
                    'capture_detected_proto0_packets': f'packet-weighted protocol-0 recall >= {a.detect}',
                    'capture_alarm_proto0': f'share of the protocol-0 test flows predicted as ANY attack class >= '
                                            f'{a.detect} (an alarm, even if the attack class is wrong)',
                    'windows': f'{a.window_min}-minute windows of the flow timestamps; detected = packet-weighted '
                               f'recall >= {a.detect}; alert = >= 1 protocol-0 flow predicted as an attack; flows '
                               'without a timestamp are left out of the window counts',
                    'runs covered': 'every run with stored predictions (tree ensembles; deep runs of '
                                    'deep_protocol_study). deep_split stored no predictions: its seeds are covered '
                                    'only through a deep_protocol_study rerun of the same seed (--rerun-existing); '
                                    'predictions_from = the rerun whose metrics equal the paper run exactly, '
                                    'rerun_for = the paper run a (non-identical) rerun stands in for.',
                    'runs': f"run subset of the cell: 'all'; 'paper runs' = tree_protocol / deep_split only (the "
                            "published cell, shown when the cell also has tree_seeds / deep_protocol runs); deep "
                            f"cells with an early-stopped run also 'epochs_run>={a.min_epochs}' (the filter of Figs. "
                            f"8-9) and 'paper runs, epochs_run>={a.min_epochs}'; sources = folders of the runs",
                    'row_order': 'how the global test rows were obtained (all checked against y and sub)',
                    'rows_check': 'rebuilt rows compared with the stored rows of another run on the same test set '
                                  '(tree_seeds / deep_protocol npz), which also checks the order inside capture '
                                  'groups'},
                'settings': {'detect': a.detect, 'window_min': a.window_min, 'min_epochs': a.min_epochs,
                             'version': VERSION},
                'inputs': inputs,
                'unmatched_runs': unmatched, 'focus': records(foc), 'run_level': records(rl),
                'summary_over_seeds': records(sm)},
          {'a_capture_detection': df, 'a_capture_detection_summary': sm, 'a_focus': foc, 'a_run_level': rl})
    print(f'[a] {len(rl)} runs, {len(sm)} summary rows, {len(unmatched)} unmatched', flush=True)
    for _, x in foc[(foc['kind'] == 'main')].iterrows():
        pr0 = x['proto0_recall']
        print(f'  {x["focus"]:24s} {x["model"]:12s} {x["variant"] or "-":10s} '
              f'{"" if x["runs"] == "all" else x["runs"] + " "}{x["split"]:8s} {x["test_cleaning"]:3s} '
              f'flow={x["flow_recall"]:.3f} packet={x["packet_recall"]:.3f} '
              f'proto0={"  -  " if pd.isna(pr0) else f"{pr0:.3f}"} ({x["proto0_flows"]:.0f} flows) '
              f'detected={x["capture_detected_proto0_runs"]}', flush=True)


# ----------------------------------------------------------------------------- (b) bootstrap machinery
def scores(cm):
    """cm (..., K, K), rows = true. Returns the METRICS dict and per-class P, R, F (0 when undefined)."""
    cm = np.asarray(cm, float)
    tp = np.diagonal(cm, axis1=-2, axis2=-1); row = cm.sum(-1); col = cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        P = np.where(col > 0, tp / np.where(col > 0, col, 1), 0.0)
        R = np.where(row > 0, tp / np.where(row > 0, row, 1), 0.0)
        F = np.where(P + R > 0, 2 * P * R / np.where(P + R > 0, P + R, 1), 0.0)
        acc = tp.sum(-1) / cm.sum((-2, -1))
    return {'macro_f1': F.mean(-1), 'bal_acc': R.mean(-1), 'accuracy': acc, 'attack_macro_f1': F[..., ATTACK].mean(-1)}, P, R, F


def boot_cm(cm, B, rng):
    """(B, K, K) confusion matrices, test rows resampled i.i.d. inside each true class."""
    out = np.zeros((B, K, K))
    for c in range(K):
        n = int(cm[c].sum())
        if n:
            out[:, c, :] = rng.multinomial(n, cm[c] / n, size=B)
    return out


def joint_boot(y, P, B, rng):
    """(B, S, K, K): S prediction vectors on the SAME rows, rows resampled i.i.d. inside each true class,
    the same resample for all S (multinomial over the distinct joint prediction patterns of each class)."""
    S = P.shape[0]
    pw = K ** np.arange(S, dtype=np.int64)
    code = (P.astype(np.int64) * pw[:, None]).sum(0)
    out = np.zeros((B, S, K, K))
    eye = np.eye(K)
    for c in range(K):
        m = y == c
        n = int(m.sum())
        if not n:
            continue
        u, cnt = np.unique(code[m], return_counts=True)
        dec = (u[:, None] // pw[None, :]) % K                 # (U, S) predicted class of each seed
        ch = max(1, min(B, MAX_CELLS // len(u)))
        for b0 in range(0, B, ch):
            b1 = min(B, b0 + ch)
            draw = rng.multinomial(n, cnt / cnt.sum(), size=b1 - b0).astype(float)
            for s in range(S):
                out[b0:b1, s, c, :] = draw @ eye[dec[:, s]]
    return out


def derived_precision(f1, r):
    """P from F1 and recall: F1 = 2PR / (P + R)  =>  P = F1 R / (2R - F1); None when undefined."""
    if f1 is None or r is None or r <= 0 or 2 * r - f1 <= 0:
        return None
    return float(min(1.0, max(0.0, f1 * r / (2 * r - f1))))


def approx_inputs(js, nc):
    """TP and FP counts per class rebuilt from the stored (rounded) per-class recall, F1 / precision."""
    R = np.array([float(js['per_class_recall'][c]) for c in CLASSES])
    F1 = np.array([float(js['per_class_f1'][c]) for c in CLASSES])
    pp = js.get('per_class_precision')
    tp = np.rint(R * nc)
    fp = np.zeros(K)
    for c in range(K):
        P = (float(pp[CLASSES[c]]) if isinstance(pp, dict) and CLASSES[c] in pp else derived_precision(F1[c], R[c]))
        if tp[c] > 0 and P:
            fp[c] = np.rint(tp[c] * (1 - P) / P)
    return tp, fp


def approx_boot(nc, tp, fp, B, rng):
    """Approximate stratified bootstrap from per-class TP / FP counts (classes drawn independently)."""
    N = nc.sum()
    TP = rng.binomial(nc.astype(np.int64), np.clip(tp / np.maximum(nc, 1), 0, 1), size=(B, K)).astype(float)
    FP = rng.binomial((N - nc).astype(np.int64), np.clip(fp / np.maximum(N - nc, 1), 0, 1), size=(B, K)).astype(float)
    with np.errstate(divide='ignore', invalid='ignore'):
        den = 2 * TP + (nc - TP) + FP
        F = np.where(den > 0, 2 * TP / np.where(den > 0, den, 1), 0.0)
        R = np.where(nc > 0, TP / np.maximum(nc, 1), 0.0)
        P = np.where(TP + FP > 0, TP / np.where(TP + FP > 0, TP + FP, 1), 0.0)
    M = {'macro_f1': F.mean(1), 'bal_acc': R.mean(1), 'accuracy': TP.sum(1) / N, 'attack_macro_f1': F[:, ATTACK].mean(1)}
    return M, P, R, F


def comonotonic(arrs, perm):
    """Seed mean of per-run bootstrap draws under full positive dependence (sorted, then averaged). The
    result is put back into a random order (perm, shared by all metrics of a cell) so that differences
    between cells pair the draws at random (independent bootstraps) instead of rank by rank."""
    return np.mean([np.sort(x, axis=0) for x in arrs], axis=0)[perm]


# ----------------------------------------------------------------------------- (b)
def part_b(a, runs, dup, inputs):
    t0 = time.time()
    PRED, Y, ROWS = {}, {}, {}
    for i, r in enumerate(runs, 1):
        r['cm'], r['sig'] = None, None
        r.pop('_rows', None)
        if r['has_pred']:
            y, p, sub, rows = load_pred(r['npz'])
            r['sig'] = signature(y, sub)
            if rows is not None:                      # hash of the stored global rows (checked below)
                r['_rows'] = hashlib.md5(np.ascontiguousarray(rows, np.int64).tobytes()).hexdigest()[:16]
                ROWS.setdefault(r['sig'], []).append(r['_rows'])
            Y.setdefault(r['sig'], y.astype(np.int8))
            PRED[r['id']] = p.astype(np.int8)
            r['cm'] = np.bincount(y * K + p, minlength=K * K).reshape(K, K).astype(float)
            del y, p, sub, rows
        elif isinstance(r['js'].get('confusion'), list) and np.shape(r['js']['confusion']) == (K, K):
            r['cm'] = np.array(r['js']['confusion'], float)
        if i % 25 == 0:
            print(f'[b load {i}/{len(runs)}] ({time.time() - t0:.0f} s)', flush=True)
    # joint (paired) resampling needs the SAME rows in the same order. y / capture group cannot see another order
    # INSIDE a capture group, the stored rows can: a run whose stored rows differ from the most common stored rows
    # of its test set gets its own signature (not resampled jointly with the others). Runs without stored rows
    # (tree_protocol) keep the plain signature; their rebuilt order is checked against stored rows in part (a).
    for r in runs:
        if r.get('_rows') and r['sig'] in ROWS:
            hs = ROWS[r['sig']]
            ref = max(sorted(set(hs)), key=hs.count)
            if r['_rows'] != ref:
                print(f'[b WARN] {r["id"]}: same y / capture groups as other runs but different stored rows - '
                      'not resampled jointly with them', flush=True)
                Y[r['sig'] + '|rows:' + r['_rows']] = Y[r['sig']]
                r['sig'] += '|rows:' + r['_rows']
    gc.collect()
    # class supports of each (kind, split, test cleaning) from runs with a confusion matrix (for approx runs)
    support = {}
    for r in runs:
        if r['cm'] is not None:
            support.setdefault((r['kind'], r['split'], r['test_cleaning']), r['cm'].sum(1))

    # ---- per run
    BOOT, run_rows, pc_rows, val = {}, [], [], []
    for i, r in enumerate(runs, 1):
        rng = rng_for('run|' + r['id'])
        js = r['js']
        if r['cm'] is not None:
            cm = r['cm']; nc = cm.sum(1)
            Mp, Pp, Rp, Fp = scores(cm)
            point = {m: float(Mp[m]) for m in METRICS}
            Mb, Pb, Rb, Fb = scores(boot_cm(cm, a.B, rng))
            if not r['has_pred']:
                method = 'exact (confusion matrix in JSON)'
            elif r.get('pred_from'):
                method = f'exact (predictions of the identical rerun {r["pred_from"]})'
            else:
                method = 'exact'
            if r['family'] == 'tree' and r['kind'] == 'main' and len(val) < 400:   # validate the approximation
                # with the inputs a deep_split run has: rounded recall and F1 only (no stored precision)
                tp, fp = approx_inputs({k: v for k, v in js.items() if k != 'per_class_precision'}, nc)
                Ma, _, _, Fa = approx_boot(nc, tp, fp, a.B, rng_for('val|' + r['id']))
                v = {'id': r['id']}
                for m in ('macro_f1', 'bal_acc'):
                    le, he = ci(Mb[m]); la, ha = ci(Ma[m])
                    v[f'{m}_dlo'] = la - le; v[f'{m}_dhi'] = ha - he
                    v[f'{m}_hw_ratio'] = (ha - la) / (he - le) if he > le else None
                le, he = ci(Fb); la, ha = ci(Fa)
                v['pcf1_max_abs_dbound'] = float(np.max(np.abs(np.r_[la - le, ha - he])))
                val.append(v)
        else:
            support_c = support.get((r['kind'], r['split'], r['test_cleaning']))
            sup = js.get('per_class_test_support')
            nc = (np.array([float(sup[c]) for c in CLASSES]) if isinstance(sup, dict)
                  else (support_c.copy() if support_c is not None else None))
            if nc is None or (js.get('n_test') and int(nc.sum()) != int(js['n_test'])):
                print(f'[b] {r["id"]}: no class support for the approximation - no CI', flush=True)
                nc = None
            point = {'macro_f1': float(js['macro_f1']), 'bal_acc': float(js['balanced_accuracy']),
                     'accuracy': float(js['accuracy']),
                     'attack_macro_f1': float(np.mean([js['per_class_f1'][CLASSES[c]] for c in ATTACK]))}
            Rp = np.array([float(js['per_class_recall'][c]) for c in CLASSES])
            Fp = np.array([float(js['per_class_f1'][c]) for c in CLASSES])
            Pp = np.array([np.nan if (v := derived_precision(Fp[c], Rp[c])) is None else v for c in range(K)])
            if nc is not None:
                tp, fp = approx_inputs(js, nc)
                Mb, Pb, Rb, Fb = approx_boot(nc, tp, fp, a.B, rng)
                method = 'approx (no stored predictions)'
            else:
                Mb = Pb = Rb = Fb = None
                method = 'none'
        r['point'], r['nc'], r['method'] = point, nc, method
        r['pc_point'] = (np.asarray(Pp, float), np.asarray(Rp, float), np.asarray(Fp, float))
        BOOT[r['id']] = None if Mb is None else {'M': Mb, 'P': Pb, 'R': Rb, 'F': Fb}
        base = {'id': r['id'], **{k: r[k] for k in DESC}, 'seed': r['seed'], 'epochs_run': r['epochs_run'],
                'method': method, 'n_test': int(nc.sum()) if nc is not None else r['js'].get('n_test')}
        row = dict(base)
        for m in METRICS:
            lo, hi = ci(Mb[m]) if Mb is not None else (None, None)
            row.update({m: point[m], f'{m}_lo': lo, f'{m}_hi': hi})
        run_rows.append(row)
        for c in range(K):
            x = {**base, 'class': CLASSES[c], 'n_test_class': int(nc[c]) if nc is not None else None,
                 'small_n': bool(nc[c] < a.min_n) if nc is not None else None}
            for nm, pt, bb in (('precision', Pp, Pb), ('recall', Rp, Rb), ('f1', Fp, Fb)):
                lo, hi = ci(bb[:, c]) if bb is not None else (None, None)
                x.update({nm: rnd(pt[c]), f'{nm}_lo': lo, f'{nm}_hi': hi})
            pc_rows.append(x)
        if i % 20 == 0 or i == len(runs):
            print(f'[b run {i}/{len(runs)}] {r["id"]}: macro-F1={point["macro_f1"]:.4f} '
                  f'[{run_rows[-1]["macro_f1_lo"] or float("nan"):.4f}, {run_rows[-1]["macro_f1_hi"] or float("nan"):.4f}] '
                  f'({method})', flush=True)

    # ---- cells
    base_cells = {}
    for r in runs:
        base_cells.setdefault(tuple(r[k] for k in DESC), []).append(r)
    # pooled cell of the three paper deep models (the deep mean of Figs. 8-9); never used in the comparisons
    for bk in [k for k in base_cells if k[0] == 'deep' and k[1] in PAPER_DEEP and k[2] == '']:
        base_cells.setdefault(('deep', DEEP_MEAN) + bk[2:], []).extend(base_cells[bk])
    cells = {}
    for bk, rs in base_cells.items():
        for lab, msk in subset_masks([is_paper(x['source']) for x in rs], [x['epochs_run'] for x in rs],
                                     bk[0] == 'deep', a.min_epochs):
            cells[bk + (lab,)] = [x for x, keep in zip(rs, msk) if keep]
    CB, cell_rows, cpc_rows = {}, [], []
    for j, (key, rs) in enumerate(sorted(cells.items(), key=lambda kv: (kv[0][3], kv[0][4], kv[0][5], kv[0][6],
                                                                          model_rank(kv[0][1], kv[0][0]), kv[0][2], kv[0][7])), 1):
        rs = sorted(rs, key=lambda x: (model_rank(x['model'], x['family']), x['seed']))
        exact = (all(x['has_pred'] for x in rs) and len({x['sig'] for x in rs}) == 1 and K ** len(rs) < 2 ** 62)
        if exact:
            Mj, Pj, Rj, Fj = scores(joint_boot(Y[rs[0]['sig']], np.stack([PRED[x['id']] for x in rs]), a.B,
                                               rng_for('cell|' + '|'.join(map(str, key)))))
            cb = {'M': {m: Mj[m].mean(1) for m in METRICS}, 'P': Pj.mean(1), 'R': Rj.mean(1), 'F': Fj.mean(1)}
            method = 'exact (joint resampling of the shared test rows)' if len(rs) > 1 else 'exact'
        elif all(BOOT[x['id']] is not None for x in rs):
            bs = [BOOT[x['id']] for x in rs]
            perm = rng_for('perm|' + '|'.join(map(str, key))).permutation(a.B)
            cb = {'M': {m: comonotonic([b['M'][m] for b in bs], perm) for m in METRICS},
                  **{k: comonotonic([b[k] for b in bs], perm) for k in 'PRF'}}
            method = ('approx (no stored predictions; seeds combined comonotonically)'
                      if any(x['method'].startswith('approx') for x in rs) else 'per-run exact, seeds combined comonotonically')
        else:
            cb, method = None, 'none'
        CB[key] = cb
        seeds = ' '.join((f'{x["model"]}:' if key[1] == DEEP_MEAN else '') + str(x['seed']) for x in rs)
        er = [x['epochs_run'] for x in rs if x['epochs_run'] is not None]
        nc = next((x['nc'] for x in rs if x['nc'] is not None), None)
        base = dict(zip(DESC + ['runs'], key))
        base.update({'label': label(key), 'n_runs': len(rs), 'seeds': seeds,
                     'sources': ' '.join(sorted({x['source'] for x in rs})), 'method': method,
                     'n_test': int(nc.sum()) if nc is not None else None,
                     'epochs_run': ' '.join(map(str, er)) if er else None})
        for m in METRICS:
            v = np.array([x['point'][m] for x in rs], float)
            lo, hi = ci(cb['M'][m]) if cb is not None else (None, None)
            hw = [(ci(BOOT[x['id']]['M'][m])[1] - ci(BOOT[x['id']]['M'][m])[0]) / 2 for x in rs if BOOT[x['id']] is not None]
            cell_rows.append({**base, 'metric': m, 'mean': v.mean(), 'sd': v.std(ddof=1) if len(v) > 1 else None,
                              'min': v.min(), 'max': v.max(), 'ci_lo': lo, 'ci_hi': hi,
                              'mean_run_ci_half_width': float(np.mean(hw)) if hw else None,
                              'values': ' '.join(f'{x:.4f}' for x in v)})
        for c in range(K):
            f = np.array([x['pc_point'][2][c] for x in rs], float)
            rc = np.array([x['pc_point'][1][c] for x in rs], float)
            pcv = np.array([x['pc_point'][0][c] for x in rs], float)
            lo, hi = ci(cb['F'][:, c]) if cb is not None else (None, None)
            rlo, rhi = ci(cb['R'][:, c]) if cb is not None else (None, None)
            cpc_rows.append({**base, 'class': CLASSES[c], 'n_test_class': int(nc[c]) if nc is not None else None,
                             'small_n': bool(nc[c] < a.min_n) if nc is not None else None,
                             'f1': f.mean(), 'f1_sd': f.std(ddof=1) if len(f) > 1 else None, 'f1_min': f.min(),
                             'f1_max': f.max(), 'f1_ci_lo': lo, 'f1_ci_hi': hi,
                             'recall': rc.mean(), 'recall_ci_lo': rlo, 'recall_ci_hi': rhi,
                             'precision': np.nanmean(pcv) if np.isfinite(pcv).any() else None,
                             'precision_sd': np.nanstd(pcv, ddof=1) if np.isfinite(pcv).sum() > 1 else None})
        if j % 10 == 0 or j == len(cells):
            x = cell_rows[-len(METRICS)]
            print(f'[b cell {j}/{len(cells)}] {x["label"]:28s} {key[3]:6s} {key[4]:8s} {key[5]}/{key[6]} '
                  f'macro-F1 {x["mean"]:.4f} sd={x["sd"] if x["sd"] is not None else float("nan"):.4f} '
                  f'CI=[{x["ci_lo"] if x["ci_lo"] is not None else float("nan"):.4f}, '
                  f'{x["ci_hi"] if x["ci_hi"] is not None else float("nan"):.4f}] n={len(rs)}', flush=True)

    # ---- differences
    diffs = []

    dcache = {}                                           # (A, B) -> bootstrap differences (views share cells)

    def compare(view, ctype, A, Bk):
        ra, rb = cells[A], cells[Bk]
        if CB[A] is None or CB[Bk] is None:
            return
        same = (all(x['has_pred'] for x in ra + rb) and len({x['sig'] for x in ra + rb}) == 1
                and K ** (len(ra) + len(rb)) < 2 ** 62)
        if (A, Bk) in dcache:
            d, how = dcache[(A, Bk)]
        elif same:
            Mj, *_ = scores(joint_boot(Y[ra[0]['sig']], np.stack([PRED[x['id']] for x in ra + rb]), a.B,
                                       rng_for('diff|' + '|'.join(map(str, A + Bk)))))
            d = {m: Mj[m][:, :len(ra)].mean(1) - Mj[m][:, len(ra):].mean(1) for m in DIFF_METRICS}
            how = 'paired (joint resampling of the shared test rows)'
        else:
            d = {m: CB[A]['M'][m] - CB[Bk]['M'][m] for m in DIFF_METRICS}
            approx = any(x['method'].startswith('approx') for x in ra + rb)
            how = 'independent bootstraps' + (' (approx: no stored predictions)' if approx else '')
        dcache[(A, Bk)] = (d, how)
        common = sorted({x['seed'] for x in ra} & {x['seed'] for x in rb})
        for m in DIFF_METRICS:
            va = np.array([x['point'][m] for x in ra]); vb = np.array([x['point'][m] for x in rb])
            obs = va.mean() - vb.mean()
            lo, hi = ci(d[m])
            se = float(np.std(d[m], ddof=1))
            p_norm = math.erfc(abs(obs) / se / math.sqrt(2)) if se > 0 else float(obs == 0)
            ca, cbb = ci(CB[A]['M'][m]), ci(CB[Bk]['M'][m])
            pa = {x['seed']: x['point'][m] for x in ra}; pb = {x['seed']: x['point'][m] for x in rb}
            ps = np.array([pa[s] - pb[s] for s in common])
            overlap = max(va.min(), vb.min()) <= min(va.max(), vb.max())
            inc0 = bool(lo <= 0 <= hi)
            diffs.append({'view': view, 'comparison': ctype, 'metric': m, 'a': label(A), 'b': label(Bk),
                          **{f'a_{k}': v for k, v in zip(DESC + ['runs'], A)},
                          **{f'b_{k}': v for k, v in zip(DESC + ['runs'], Bk) if k in ('model', 'variant', 'kind', 'split',
                                                                                      'train_cleaning', 'test_cleaning', 'runs')},
                          'n_a': len(va), 'n_b': len(vb), 'mean_a': va.mean(), 'mean_b': vb.mean(), 'diff': obs,
                          'ci_lo': lo, 'ci_hi': hi, 'se_boot': se, 'p_boot': boot_p(d[m]), 'p_normal': p_norm,
                          'method': how,
                          'n_common_seeds': len(common),
                          'seed_diff_mean': ps.mean() if len(ps) else None,
                          'seed_diff_sd': ps.std(ddof=1) if len(ps) > 1 else None,
                          'seed_diff_min': ps.min() if len(ps) else None, 'seed_diff_max': ps.max() if len(ps) else None,
                          'seed_diff_same_sign': bool((np.sign(ps) == np.sign(obs)).all()) if len(ps) else None,
                          'sd_a': va.std(ddof=1) if len(va) > 1 else None, 'sd_b': vb.std(ddof=1) if len(vb) > 1 else None,
                          'range_a': f'{va.min():.4f}-{va.max():.4f}', 'range_b': f'{vb.min():.4f}-{vb.max():.4f}',
                          'ci_includes_0': inc0, 'seed_ranges_overlap': bool(overlap),
                          'cell_cis_overlap': bool(max(ca[0], cbb[0]) <= min(ca[1], cbb[1])),
                          'within_intervals': bool(inc0 or overlap)})

    # Two views: 'all' = every run of a cell (the updated tables with the extra seeds of tree_seeds /
    # deep_protocol); 'paper runs' = the published cells (tree_protocol / deep_split runs only; a cell without
    # extra runs is its 'all' cell; cells without any paper run, e.g. MLP or the fixed-epoch variants, drop out).
    # The pooled deep mean is descriptive only (Figs. 8-9) and is never compared.
    base_keys = sorted({k[:7] for k in cells if k[1] != DEEP_MEAN},
                       key=lambda k: (k[3], k[4], k[5], k[6], model_rank(k[1], k[0]), k[2]))

    VIEWS = ['all', 'paper runs', f'epochs_run>={a.min_epochs}', f'paper runs, epochs_run>={a.min_epochs}']
    ids_of = {k: frozenset(x['id'] for x in rs) for k, rs in cells.items()}

    def view_key(bk, view):
        """Cell key holding the runs of base cell bk that a view selects (paper runs and / or epochs_run >=
        --min-epochs): the subset of that label, or the label under which subset_masks kept the same runs
        (e.g. the 'all' cell of a cell without extra runs); None when the view selects no run."""
        rs = cells.get(bk + ('all',))
        if rs is None:
            return None
        paper, ep = view.startswith('paper runs'), 'epochs_run' in view
        want = frozenset(x['id'] for x in rs if (not paper or is_paper(x['source'])) and
                         (not ep or (x['epochs_run'] is not None and x['epochs_run'] >= a.min_epochs)))
        return next((bk + (lab,) for lab in VIEWS if ids_of.get(bk + (lab,)) == want), None) if want else None

    views = ['all'] + (['paper runs'] if any(view_key(bk, 'paper runs') != bk + ('all',) for bk in base_keys) else [])
    for view in views:
        vk = {bk: view_key(bk, view) for bk in base_keys}
        vk = {bk: k for bk, k in vk.items() if k is not None}
        by_cond = {}
        for bk in vk:
            if bk[2] == '':                                   # the paper's setting of every model
                by_cond.setdefault((bk[3], bk[4], bk[5], bk[6]), []).append(bk)
        for cond, ks in by_cond.items():
            ks = sorted(ks, key=lambda k: model_rank(k[1], k[0]))
            for i in range(len(ks)):
                for j in range(i + 1, len(ks)):
                    compare(view, 'model pair (same condition)', vk[ks[i]], vk[ks[j]])
        for bk in vk:
            fam, model, var, kind, split, trc, tec = bk
            if split == 'random' and (o := (fam, model, var, kind, 'temporal', trc, tec)) in vk:
                compare(view, 'split effect (random - temporal)', vk[bk], vk[o])
            if kind == 'main' and trc == tec and trc != 'raw' and (o := (fam, model, var, kind, split, 'raw', 'raw')) in vk:
                compare(view, f'cleaning effect ({trc} - raw)', vk[bk], vk[o])
            if kind == 'decomp' and trc == 'r1' and (o := (fam, model, var, kind, split, 'raw', tec)) in vk:
                compare(view, f'train-cleaning effect (train r1 - train raw, test {tec})', vk[bk], vk[o])
            if kind == 'decomp' and tec == 'r1' and (o := (fam, model, var, kind, split, trc, 'raw')) in vk:
                compare(view, f'test-cleaning effect (test r1 - test raw, train {trc})', vk[bk], vk[o])
        for bk in vk:                                     # variants / protocols against the paper's setting
            if bk[2] != '' and (o := (bk[0], bk[1], '', bk[3], bk[4], bk[5], bk[6])) in vk:
                compare(view, 'variant effect (variant - paper setting)', vk[bk], vk[o])
    dd = pd.DataFrame(diffs)
    if not dd.empty:
        dd['p_holm'] = np.nan
        dd['p_holm_normal'] = np.nan
        for _, g in dd.groupby(['view', 'comparison', 'metric']):
            dd.loc[g.index, 'p_holm'] = holm(g['p_boot'].to_numpy())
            dd.loc[g.index, 'p_holm_normal'] = holm(g['p_normal'].to_numpy())

    # ---- table-ready pivots
    cdf = pd.DataFrame(cell_rows)

    def fmt(x):
        s = f'{x["mean"]:.3f}'
        if x['sd'] is not None and not pd.isna(x['sd']):
            s += f' +/- {x["sd"]:.3f}'
        if x['ci_lo'] is not None and not pd.isna(x['ci_lo']):
            s += f' [{x["ci_lo"]:.3f}, {x["ci_hi"]:.3f}]'
        s += f' (n={x["n_runs"]}' + (f', {x["min"]:.3f}-{x["max"]:.3f}' if x['n_runs'] > 1 else '') + ')'
        return s

    def view_blocks(kind):
        """{(family, model, variant): {view: {(split, train cleaning, test cleaning): cell key}}}, views in VIEWS
        order ('epochs' views for deep models only); a view whose cells are all those of an earlier view of
        the same model is dropped (e.g. 'paper runs' when no extra seeds exist)."""
        blocks = {}
        for bk in sorted({k[:7] for k in cells if k[3] == kind}, key=lambda k: (model_rank(k[1], k[0]), k[2])):
            for view in VIEWS:
                if 'epochs_run' in view and bk[0] != 'deep':
                    continue
                k = view_key(bk, view)
                if k is not None:
                    blocks.setdefault(bk[:3], {}).setdefault(view, {})[bk[4:7]] = k
        out = {}
        for mb, vs in blocks.items():
            kept = {}
            for view in VIEWS:
                if view in vs and vs[view] not in kept.values():
                    kept[view] = vs[view]
            out[mb] = kept
        return out

    cell_by_key = {}
    for x in cell_rows:
        cell_by_key[(tuple(x[c] for c in DESC + ['runs']), x['metric'])] = x

    def pivot(kind, metric):
        """Tables 9-10 (main: columns split/cleaning) and 11 (decomp: rows per split, columns train/test
        cleaning); one row per model and view: 'all' runs, 'paper runs' (the published cell) and, for the
        deep models, the epochs_run filter; 'runs' of a cell = the subset label actually used."""
        out = []
        for (fam, model, var), vs in view_blocks(kind).items():
            for view, cmap in vs.items():
                for split in ((None,) if kind == 'main' else ('random', 'temporal')):
                    row = {'family': fam, 'model': model, 'variant': var, 'view': view}
                    if split:
                        row['split'] = split
                    for (s, trc, tec), k in cmap.items():
                        if split and s != split:
                            continue
                        row[f'{s}/{tec}' if kind == 'main' else f'{trc}/{tec}'] = fmt(cell_by_key[(k, metric)])
                    if len(row) > 4 + bool(split):
                        out.append(row)
        if not out:
            return pd.DataFrame()
        pv = pd.DataFrame(out)
        if kind == 'decomp':
            pv = pv.assign(_s=pv['split'].map({'random': 0, 'temporal': 1})).sort_values('_s', kind='stable').drop(columns='_s')
        order = [f'{a_}/{b_}' for a_, b_ in (CONDS if kind == 'main' else DECOMP_CONDS)]
        idx_cols = ['family', 'model', 'variant', 'view'] + (['split'] if kind == 'decomp' else [])
        return pv[idx_cols + [c for c in order if c in pv.columns]]

    t9 = pivot('main', 'macro_f1')
    t10 = pivot('main', 'bal_acc')
    t11 = pivot('decomp', 'macro_f1')
    vdf = pd.DataFrame(val)
    vsum = {}
    if not vdf.empty:
        for c in [c for c in vdf.columns if c != 'id']:
            v = pd.to_numeric(vdf[c], errors='coerce')
            vsum[c] = {'max_abs': rnd(v.abs().max()), 'median': rnd(v.median())}
    print(f'[b] approximation check on {len(vdf)} tree runs: max |CI bound error| macro-F1 '
          f'{vsum.get("macro_f1_dlo", {}).get("max_abs")}/{vsum.get("macro_f1_dhi", {}).get("max_abs")}, '
          f'balanced accuracy {vsum.get("bal_acc_dlo", {}).get("max_abs")}/{vsum.get("bal_acc_dhi", {}).get("max_abs")}, '
          f'per-class F1 {vsum.get("pcf1_max_abs_dbound", {}).get("max_abs")}', flush=True)
    rdf, pdf, cpdf = pd.DataFrame(run_rows), pd.DataFrame(pc_rows), pd.DataFrame(cpc_rows)

    def s1_pivot():
        """Supplementary Table S1 layout (one row per model, view, split and cleaning): per-class F1 (seed
        mean) [95% bootstrap CI of the seed mean]; 'n=<test flows>*' marks classes with fewer than --min-n
        test flows. The published S1 = view 'paper runs' (trees) / 'paper runs, epochs_run>=...' (deep models;
        a view that repeats an earlier one is not repeated)."""
        pcx = {(tuple(x[c] for c in DESC + ['runs']), x['class']): x for x in cpc_rows}

        def cell(x):
            s = f'{x["f1"]:.3f}'
            if x['f1_ci_lo'] is not None and not pd.isna(x['f1_ci_lo']):
                s += f' [{x["f1_ci_lo"]:.3f}, {x["f1_ci_hi"]:.3f}]'
            if x['small_n'] is not None and bool(x['small_n']):
                s += f' n={int(x["n_test_class"])}*'
            return s
        out = []
        for (fam, model, var), vs in view_blocks('main').items():
            for view, cmap in vs.items():
                for (s, trc, tec), k in sorted(cmap.items(), key=lambda kv: (kv[0][0], kv[0][1] != 'raw', kv[0][1])):
                    c0 = cell_by_key[(k, 'macro_f1')]
                    out.append({'family': fam, 'model': model, 'variant': var, 'view': view, 'runs': k[7],
                                'split': s, 'cleaning': trc, 'n_runs': c0['n_runs'], 'seeds': c0['seeds'],
                                'sources': c0['sources'], 'method': c0['method'],
                                **{c: cell(pcx[(k, c)]) for c in CLASSES}})
        return pd.DataFrame(out)

    ts1 = s1_pivot()
    tables = {'b_runs': rdf.round(6), 'b_runs_per_class': pdf.round(6), 'b_cells': cdf.round(6),
              'b_cells_per_class': cpdf.round(6), 'b_differences': dd.round(6),
              'b_table9_macro_f1': t9, 'b_table10_bal_acc': t10, 'b_table11_decomp_macro_f1': t11,
              'b_table_s1_per_class_f1': ts1}
    n_within = int(dd['within_intervals'].sum()) if not dd.empty else 0
    write('b', {'description': 'disc-11 / stat-09: per-run and per-cell uncertainty; see the module docstring',
                'settings': {'B': a.B, 'min_n': a.min_n, 'min_epochs': a.min_epochs, 'seed': SEED, 'version': VERSION,
                             'runs': "run subset of a cell: 'all'; 'paper runs' (tree_protocol / deep_split only = the "
                                     "published cell; only when the cell has extra runs); deep cells also "
                                     f"'epochs_run>={a.min_epochs}' and 'paper runs, epochs_run>={a.min_epochs}' (the "
                                     'filter of Figs. 8-9 and S1)',
                             'deep_mean': f"'{DEEP_MEAN}' pools the runs of the three paper deep models (the deep "
                                          'mean of Figs. 8-9; SD over runs = model + seed variation; never compared)',
                             'view': "differences between the 'all' cells, and between the published cells ('paper "
                                     "runs' view); Holm within view, comparison type and metric",
                             'ci': 'percentile 2.5 / 97.5 of the stratified (by true class) i.i.d. bootstrap',
                             'cell_ci': 'bootstrap CI of the mean over the seeds of a cell (test-flow sampling only)',
                             'sd': 'standard deviation over seeds (ddof = 1): training variability',
                             'within_intervals': 'ci_includes_0 or seed_ranges_overlap',
                             'p_boot': 'two-sided bootstrap p, floor 2 / (B + 1); p_holm = Holm within view, '
                                       'comparison type and metric (floored at 2 / (B + 1) x number of tests)',
                             'p_normal': '2 (1 - Phi(|diff| / SE)), SE = SD of the bootstrap differences (not '
                                         'floored); p_holm_normal = Holm within view, comparison type and metric'},
                'inputs': inputs, 'duplicates_skipped': dup,
                'approximation_check_on_tree_runs': {'n_runs': len(vdf), 'summary': vsum, 'runs': records(vdf.round(6))},
                'n_differences': len(dd), 'n_differences_within_intervals': n_within,
                'cells': records(cdf.round(6)), 'differences': records(dd.round(6))}, tables)
    print(f'[b] {len(runs)} runs, {len(cells)} cells, {len(dd)} differences ({n_within} within the intervals) '
          f'({time.time() - t0:.0f} s)', flush=True)
    for _, x in cdf[(cdf['metric'] == 'macro_f1') & (cdf['kind'] == 'main')].iterrows():
        print(f'  {x["label"]:30s} {x["split"]:8s} {x["test_cleaning"]:3s} {fmt(x)}', flush=True)
    PRED.clear(); Y.clear(); gc.collect()


# ----------------------------------------------------------------------------- (c)
def group_counts(path):
    """{group name: (class index, n test flows)} of a stored prediction."""
    y, _, sub, _ = load_pred(path)
    df = pd.DataFrame({'y': y, 'sub': sub})
    return {f'{CLASSES[c]} / {s}': (int(c), int(n)) for (c, s), n in df.groupby(['y', 'sub']).size().items()}


def wrow(k, n, share=None, kmin=None, kmax=None):
    lo, hi = wilson(k, n)
    x = {'n': int(n), 'k': int(k), 'share': share if share is not None else q(k, n), 'wilson_lo': lo, 'wilson_hi': hi}
    if kmin is not None:
        x.update({'k_min': int(kmin), 'k_max': int(kmax), 'count_exact': kmin == kmax,
                  'conservative_lo': wilson(kmin, n)[0], 'conservative_hi': wilson(kmax, n)[1]})
    return x


def part_c(a, runs, inputs):
    sp = RES / 'split_pilot'
    # ---- Fig. 4
    f4 = []
    fn = sp / 'subattack_results.json'
    if fn.exists():
        with open(fn, encoding='utf-8') as fh:
            sub = json.load(fh)
        for key, split, in_fig in (('A_random', 'random', True), ('D_temporal_subattack', 'temporal', True),
                                   ('B_temporal_class', 'temporal (per class)', False)):
            for g, v in sub.get(key, {}).get('per_subattack', {}).items():
                n, r = int(v['n_test']), float(v['recall'])
                k, kmin, kmax = counts_from_share(r, n, 4)
                f4.append({'source': 'split_pilot/subattack_results.json', 'run': key, 'split': split, 'in_fig4': in_fig,
                           'imputation': 'median (pilot fit_eval)', 'group': g, **wrow(k, n, r, kmin, kmax),
                           'small_n': n < a.min_n,
                           'count_source': 'k = round(recall n) from the 4-decimal recall; n_test stored exactly'})
    for split in ('random', 'temporal'):
        f = RES / 'tree_protocol' / 'main' / f'XGBoost_{split}_raw_s42.npz'
        if f.exists():
            y, p, s, _ = load_pred(f)
            df = pd.DataFrame({'y': y, 'sub': s, 'ok': p == y})
            for (c, g), x in df.groupby(['y', 'sub']):
                n, k = len(x), int(x['ok'].sum())
                f4.append({'source': f'tree_protocol/main/{f.name}', 'run': f.stem, 'split': split, 'in_fig4': False,
                           'imputation': 'NaN -> 0 (tree_protocol_study)', 'group': f'{CLASSES[c]} / {g}',
                           **wrow(k, n), 'small_n': n < a.min_n, 'count_source': 'exact counts from the stored predictions'})
    f4 = pd.DataFrame(f4)
    print(f'[c] Fig. 4: {int(f4["in_fig4"].sum()) if len(f4) else 0} pilot recalls (+ {len(f4) - int(f4["in_fig4"].sum()) if len(f4) else 0} '
          f'secondary rows)', flush=True)
    for _, x in f4[f4['in_fig4'] & f4['small_n']].iterrows() if len(f4) else []:
        print(f'  {x["split"]:8s} {x["group"]:36s} recall={x["share"]:.3f} n={x["n"]:>4d} '
              f'Wilson [{x["wilson_lo"]:.3f}, {x["wilson_hi"]:.3f}] (small n)', flush=True)
    # ---- Table 13
    t13 = []
    for fname, cleaning in (('temporal_drift.json', 'all rules (R1|R2|R3)'), ('temporal_drift_r1.json', 'R1')):
        f = sp / fname
        if not f.exists():
            continue
        with open(f, encoding='utf-8') as fh:
            dr = json.load(fh)
        for g, v in dr.items():
            n = v.get('n_test_period')
            for var in ('test_dst_ip_seen_in_train', 'test_src_ip_seen_in_train'):
                sh = v.get(var)
                if sh is None or not n:
                    continue
                k, kmin, kmax = counts_from_share(float(sh), int(n), 3)
                t13.append({'source': f'split_pilot/{fname}', 'cleaning': cleaning, 'group': g, 'variable': var,
                            **wrow(k, n, float(sh), kmin, kmax), 'small_n': int(n) < a.min_n,
                            'count_source': 'k = round(share n) from the 3-decimal share (exact for n <= 1000)'})
    t13 = pd.DataFrame(t13)
    for _, x in (t13[(t13['variable'] == 'test_dst_ip_seen_in_train') & t13['small_n']].iterrows() if len(t13) else []):
        print(f'  Table 13 {x["cleaning"]:22s} {x["group"]:34s} dst seen={x["share"]:.3f} n={x["n"]:>4d} '
              f'Wilson [{x["wilson_lo"]:.3f}, {x["wilson_hi"]:.3f}]', flush=True)
    # ---- Fig. 9 (deep) and tree runs: per-sub-attack recall
    supp = {}
    for r in runs:
        if r['family'] == 'tree' and r['has_pred'] and r['kind'] == 'main':
            supp.setdefault((r['split'], r['test_cleaning']), r['npz'])
    supp_counts = {k: group_counts(v) for k, v in supp.items()}
    f9, tr = [], []
    for r in runs:
        base = {'id': r['id'], **{k: r[k] for k in DESC}, 'seed': r['seed'], 'epochs_run': r['epochs_run'],
                'source': r['source'], 'predictions_from': r.get('pred_from')}
        if r['has_pred']:
            y, p, s, _ = load_pred(r['npz'])
            df = pd.DataFrame({'y': y, 'sub': s, 'ok': p == y})
            for (c, g), x in df.groupby(['y', 'sub']):
                n, k = len(x), int(x['ok'].sum())
                (f9 if r['family'] == 'deep' else tr).append(
                    {**base, 'group': f'{CLASSES[c]} / {g}', **wrow(k, n), 'small_n': n < a.min_n,
                     'count_source': 'exact (stored predictions)'})
        elif r['family'] == 'deep':
            cnt = supp_counts.get((r['split'], r['test_cleaning'])) if r['kind'] == 'main' else None
            for g, rv in (r['js'].get('per_subattack_recall') or {}).items():
                if cnt is None or g not in cnt:
                    f9.append({**base, 'group': g, 'n': None, 'k': None, 'share': rv, 'small_n': None,
                               'count_source': 'no support available'})
                    continue
                n = cnt[g][1]
                k, kmin, kmax = counts_from_share(float(rv), n, 4)
                f9.append({**base, 'group': g, **wrow(k, n, float(rv), kmin, kmax), 'small_n': n < a.min_n,
                           'count_source': 'n from the tree run with the same test rows, k = round(recall n)'})
    f9, tr = pd.DataFrame(f9), pd.DataFrame(tr)
    cells9 = []
    if len(f9):
        # per model, plus the pooled deep mean of the three paper models (= the heat map of Fig. 9)
        f9m = f9.assign(run_model=f9['model'])
        pool = f9m[f9m['model'].isin(PAPER_DEEP) & (f9m['variant'] == '')].assign(model=DEEP_MEAN)
        f9p = pd.concat([f9m, pool], ignore_index=True)
        for key, g0 in f9p.groupby(DESC + ['group'], sort=False):
            for filt, msk in subset_masks(g0['source'].map(is_paper), g0['epochs_run'], True, a.min_epochs):
                g = g0[msk]
                v = pd.to_numeric(g['share'], errors='coerce')
                lo_ = pd.to_numeric(g['wilson_lo'], errors='coerce') if 'wilson_lo' in g else pd.Series(dtype=float)
                hi_ = pd.to_numeric(g['wilson_hi'], errors='coerce') if 'wilson_hi' in g else pd.Series(dtype=float)
                full = len(lo_) == len(g) and lo_.notna().all() and hi_.notna().all()
                pooled = key[1] == DEEP_MEAN
                cells9.append({**dict(zip(DESC + ['group'], key)), 'runs': filt, 'n_runs': len(g),
                               'seeds': ' '.join((f'{m}:' if pooled else '') + str(s)
                                                 for m, s in sorted(zip(g['run_model'], g['seed']))),
                               'sources': ' '.join(sorted(set(g['source']))), 'n_test': g['n'].iloc[0],
                               'recall_mean': v.mean(), 'recall_sd': v.std(ddof=1) if v.notna().sum() > 1 else None,
                               'recall_min': v.min(), 'recall_max': v.max(),
                               # CI of the mean over runs if the runs' test-flow errors were fully dependent (the
                               # quantile of a comonotonic mean is the mean of the quantiles): conservative
                               'ci_mean_lo': lo_.mean() if full else None, 'ci_mean_hi': hi_.mean() if full else None,
                               'envelope_lo': lo_.min() if full else None, 'envelope_hi': hi_.max() if full else None,
                               'small_n': g['small_n'].iloc[0]})
    c9 = pd.DataFrame(cells9)
    tables = {'c_fig4_subattack_wilson': f4.round(6), 'c_table13_seen_wilson': t13.round(6),
              'c_fig9_deep_subattack_wilson': f9.round(6), 'c_fig9_deep_cells': c9.round(6),
              'c_tree_subattack_wilson': tr.round(6)}
    write('c', {'description': 'stat-09: Wilson 95% score intervals (z = 1.96) for per-sub-attack recalls '
                               '(Fig. 4, Fig. 9, tree runs) and the Dst/Src seen shares of Table 13',
                'fig4_note': 'The pilot (split_pilot/subattack_results.json, median imputation) stored n_test and '
                             'a 4-decimal recall but no predictions: k = round(recall n); k_min/k_max bound the '
                             'rounding and conservative_lo/hi span their Wilson limits. The tree_protocol XGBoost '
                             'raw s42 runs (NaN -> 0 imputation, a different pipeline) are added with exact counts '
                             '(in_fig4 = false).',
                'table13_note': 'n = n_test_period of the drift JSON (the share is taken over test-period FLOWS, '
                                'temporal_drift_analysis.py), share rounded to 3 decimals: count exact for n <= 1000. '
                                'Flows to the same destination are not independent, so the Wilson interval (i.i.d. '
                                'flows) is a lower bound on the uncertainty, most of all when few distinct '
                                'destinations carry the test period.',
                'iid_note': 'All Wilson intervals treat the test flows of a group as independent Bernoulli trials '
                            '(conditional on the fitted model); flows of one session or episode are correlated, so '
                            'the intervals are optimistic for large, bursty captures (see revision_analyses.py part '
                            'c for a block bootstrap).',
                'fig9_note': 'deep_split stored no predictions: n per sub-attack from the tree run with the same '
                             'test rows (same splits() call), k = round(recall n). Cells (per model, and '
                             f"'{DEEP_MEAN}' = the pooled mean shown in Fig. 9): mean, SD, min-max over runs; "
                             'ci_mean_lo/hi = mean of the per-run Wilson limits (the interval of the run mean when '
                             'the runs err on the same flows: conservative); envelope = widest per-run limits. '
                             "runs: 'all', 'paper runs' (deep_split only), 'epochs_run>=...' (the filter of Fig. 9) "
                             "and 'paper runs, epochs_run>=...' (= Fig. 9 as published); a subset with the same runs "
                             'as an earlier one is not repeated.',
                'min_n': a.min_n, 'version': VERSION, 'inputs': inputs, 'fig4': records(f4.round(6)),
                'table13': records(t13.round(6)),
                'fig9_cells': records(c9.round(6))}, tables)
    print(f'[c] {len(f4)} Fig. 4 rows, {len(t13)} Table 13 rows, {len(f9)} deep sub-attack rows, '
          f'{len(tr)} tree sub-attack rows', flush=True)


# ----------------------------------------------------------------------------- main
def main():
    global RES, OUT, CACHE
    ap = argparse.ArgumentParser(description='Reviewer analyses disc-10, disc-11, stat-09 from stored results.')
    ap.add_argument('--parts', nargs='+', default=list('abc'), choices=list('abc'))
    ap.add_argument('--force', action='store_true', help='recompute the selected parts (and the a_runs caches)')
    ap.add_argument('--dry-run', action='store_true', help='list the discovered runs and the plan; read JSON only')
    ap.add_argument('--B', type=int, default=1000, help='bootstrap resamples (b)')
    ap.add_argument('--detect', type=float, default=0.5, help='detection threshold (a)')
    ap.add_argument('--window-min', type=float, default=5.0, help='episode window in minutes (a)')
    ap.add_argument('--min-n', type=int, default=200, help='flag classes / sub-attacks with fewer test flows')
    ap.add_argument('--min-epochs', type=int, default=20, help='deep runs that trained normally (Figs. 8-9 filter)')
    ap.add_argument('--tree-dirs', nargs='+', default=TREE_DIRS, help='tree run folders relative to the results root')
    ap.add_argument('--deep-dirs', nargs='+', default=DEEP_DIRS, help='deep run folders relative to the results root')
    ap.add_argument('--res', default=None, help='results root (default results_2026_03_03; for tests)')
    ap.add_argument('--cache', default=None, help='flagged sample parquet (default flagged_loader.CACHE; for tests)')
    ap.add_argument('--out', default=None, help='output folder (default <res>/q1_revision/analyses2)')
    a = ap.parse_args()
    if a.res:
        RES = Path(a.res).resolve()
    OUT = Path(a.out).resolve() if a.out else RES / 'q1_revision' / 'analyses2'
    if a.cache:
        CACHE = Path(a.cache).resolve()
    runs, dup, bad = discover(a)
    # a part is up to date when its JSON was made from the same input files (name, mtime) and settings
    fa = sorted([r['id'], int(r['npz'].stat().st_mtime)] for r in part_a_runs(runs))
    fa += [[CACHE.name, int(CACHE.stat().st_mtime)]] if CACHE.exists() else []
    run_files = [r['json'] for r in runs] + [r['npz'] for r in runs if r['npz'] is not None]
    ins = {'a': {'files': fa, 'settings': {'detect': a.detect, 'window_min': a.window_min, 'min_epochs': a.min_epochs,
                                           'version': VERSION}},
           'b': {'files': fingerprint(run_files),
                 'settings': {'B': a.B, 'min_n': a.min_n, 'min_epochs': a.min_epochs, 'version': VERSION}},
           'c': {'files': fingerprint([RES / 'split_pilot' / f for f in ('subattack_results.json', 'temporal_drift.json',
                                                                          'temporal_drift_r1.json')] + run_files),
                 'settings': {'min_n': a.min_n, 'min_epochs': a.min_epochs, 'version': VERSION}}}
    if a.dry_run:
        df = pd.DataFrame([{**{k: r[k] for k in DESC}, 'seed': r['seed'], 'pred': r['has_pred']} for r in runs])
        if len(df):
            g = (df.groupby(DESC, dropna=False).agg(n=('seed', 'size'), seeds=('seed', lambda s: ' '.join(map(str, sorted(s)))),
                                                    with_pred=('pred', 'sum')).reset_index())
            pd.set_option('display.width', 200); pd.set_option('display.max_rows', 500)
            print(g.to_string(index=False))
        for d in dup:
            print(f'[dup] {d["skipped"]} (kept {d["kept"]})'
                  + (f'; its predictions are used for {d["predictions_used"]}' if d['predictions_used'] else ''))
        for p in a.parts:
            print(f'[plan] part {p}: {"up to date" if is_current(p, ins[p]) and not a.force else "to do"}')
        print(f'[plan] flagged sample for part a: {CACHE} ({"found" if CACHE.exists() else "MISSING"})')
        return
    OUT.mkdir(parents=True, exist_ok=True)
    todo = [p for p in a.parts if a.force or not is_current(p, ins[p])]
    print(f'[plan] parts {"".join(a.parts)}: {len(todo)} to do ({"".join(todo) or "-"}); output {OUT}', flush=True)
    fn = {'a': part_a, 'b': part_b, 'c': part_c}
    for p in todo:
        t = time.time()
        if p == 'b':
            fn[p](a, runs, dup, ins[p])
        else:
            fn[p](a, runs, ins[p])
        print(f'[part {p}] done in {time.time() - t:.0f} s -> {OUT / STEM[p]}.json', flush=True)
        gc.collect()
    left = [p for p in a.parts if not is_current(p, ins[p])]
    print(f'[left] parts {"".join(left)} not finished' if left else '[DONE] all selected parts finished', flush=True)


if __name__ == '__main__':
    main()
