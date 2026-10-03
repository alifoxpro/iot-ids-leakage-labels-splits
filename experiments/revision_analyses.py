# -*- coding: utf-8 -*-
"""
revision_analyses.py
====================
Reviewer-requested analyses, computed ONLY from stored results - no model is trained.

Inputs (results_2026_03_03/)
  tree_protocol/main/*.npz|json   XGBoost s42, LightGBM and random forest s42/17/7, four protocol
                                  conditions (npz: y, p, sub of the test rows; for the temporal split
                                  the rows of each capture group are stored in time order)
  tree_protocol/decomp/*.npz      train cleaning x test cleaning; the same fitted model predicted the
                                  raw and the R1 test set, and the R1 test set is a subset of the raw one
  deep_split/*.json               ResNet1D / GRU / Transformer (per_class_f1, per_class_recall, ...)
  split_pilot/temporal_drift_r1.json, split_pilot/subattack_results.json
  flagged sample (flagged_loader.get_flagged, six small columns: y, sub, ts, R1/R2/R3 flags) for (g)
  and to restore the time order of the random-split test rows in (c) and (d)

Parts
 (a) attack-class macro-F1 = mean F1 over the seven attack classes, next to the Benign F1 and the
     8-class macro-F1, for every tree run (from npz) and every deep run (from per_class_f1)
 (b) predictions on the R1-flagged test flows: confusion(test raw) - confusion(test R1) of the same
     decomp model (XGBoost, random forest, each LightGBM seed; both splits; both train cleanings).
     Per true class: share predicted as own class, as Benign, as another attack class (and the same
     shares on the retained flows for comparison)
 (c) circular moving-block bootstrap inside capture groups (test rows in time order; blocks of 1,000
     and 5,000 flows; B = 1,000) for the seed-42 tree runs: 95% CI half-width of macro-F1 (and of
     balanced accuracy), compared with the i.i.d. bootstrap stratified by class (as bootstrap_ci.py)
     and stratified by capture group; CIs of the split effect (random - temporal, independent
     bootstraps) and of the train-cleaning effect of Table 7 (train R1 / test R1 minus
     train raw / test R1, paired: the same resampled flows for both models)
 (d) paired bootstrap of balanced accuracy between the three tree ensembles (seed 42, same
     condition): i.i.d. stratified by class (B = 2,000) and block bootstrap (B = 1,000);
     p = 2 (min(#d <= 0, #d >= 0) + 1) / (B + 1), Holm over the 12 comparisons (per method)
 (e) per-class precision and recall of every tree run (from npz); for the deep runs precision is
     derived from the stored F1 and recall, P = F1 R / (2R - F1) (defined for R > 0). The error of the
     derivation (inputs rounded to 4 decimals) is measured on the tree runs, where P is known exactly
 (f) drift-loss association: for the capture groups with a drift AUC in temporal_drift_r1.json,
     Spearman rho (p, permutation p, n) between drift AUC, top-20 port Jaccard, share of test
     destination IPs seen in training and the random -> temporal recall loss per sub-attack of the R1
     runs (XGBoost s42 and the random-forest seed mean; supplementary: the raw-data XGBoost pilot of
     subattack_results.json, A_random - D_temporal_subattack); Holm over the three variables
 (g) per capture group, the share of flows flagged by R1, R2, R3 and any rule in the training versus
     the test period of the within-group 70/15/15 time split (raw sample): two-proportion z-test per
     group, Wilcoxon signed-rank test of (test - train) over the attack groups

Block bootstrap: inside every capture group the test rows (time order) are treated as a circle and
covered by ceil(n / l) blocks of l consecutive rows with random starts, the last block cut so that
exactly n rows are drawn. A group smaller than the block would be one fixed block (no variance at
all), so l = min(L, max(1, n // min_blocks)) with --min-blocks 5 by default (1 gives the textbook
l = min(L, n)); the block length used for every group is stored in the JSON.
The random-split npz files hold the test rows in random order; their time order is rebuilt from the
flagged sample (same splits() call as tree_protocol_study.py, checked row by row against y and sub).
With --no-flagged the stored order is kept (the block bootstrap then equals an i.i.d. one there).

Output: results_2026_03_03/q1_revision/analyses/
          a_attack_macro_f1.json|.csv|_summary.csv      e_precision_recall.json|.csv|_summary.csv
          b_flagged_predictions.json|.csv|_summary.csv  f_drift_loss.json, f_drift_loss_groups.csv,
          c_block_bootstrap.json, c_block_bootstrap_ci.csv, f_drift_loss_spearman.csv
            c_block_bootstrap_effects.csv               g_flag_share_by_period.json|.csv
          d_paired_balanced_accuracy.json|.csv
Resumable: a part whose JSON exists is skipped (--force recomputes the selected parts).
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\revision_analyses.py
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\revision_analyses.py --parts c d --force
"""
import argparse, gc, itertools, json, os, re, sys, time, warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm, rankdata, spearmanr, wilcoxon

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bootstrap_ci import f1_ba, holm  # noqa: E402
from deep_split_noise_study import kept_rows, splits  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
warnings.filterwarnings('ignore', category=FutureWarning)        # pandas groupby(observed=...) notice
RES = HERE.parent / 'results_2026_03_03'
TREE = RES / 'tree_protocol'
OUT = RES / 'q1_revision' / 'analyses'
K = len(CLASSES)
BENIGN = CLASSES.index('Benign')
ATTACK = [c for c in range(K) if c != BENIGN]
MAIN_PAT = r'^(\w+?)_(random|temporal)_(raw|r1)_s(\d+)$'
DECOMP_PAT = r'^(\w+?)_(random|temporal)_train-(raw|r1)_test-(raw|r1)(?:_s(\d+))?$'
DESC = ('kind', 'model', 'seed', 'split', 'train_cleaning', 'test_cleaning')
FLAG_COLS = ['r1_external', 'r2_service', 'r3_benign_pair']
DRIFT_VARS = ['drift_auc', 'top20_port_jaccard', 'test_dst_ip_seen_in_train']
STEM = {'a': 'a_attack_macro_f1', 'b': 'b_flagged_predictions', 'c': 'c_block_bootstrap',
        'd': 'd_paired_balanced_accuracy', 'e': 'e_precision_recall', 'f': 'f_drift_loss',
        'g': 'g_flag_share_by_period'}
CHUNK = 250                 # bootstrap resamples per gather batch in the block bootstrap (memory)
MAX_GATHER = 4_000_000      # max int32 cells of one gather temporary (~16 MB); shrinks the batch for short blocks
GMUL = 64                   # group id = class * GMUL + capture-group code


# ----------------------------------------------------------------------------- small helpers
def rnd(v, k=4):
    return None if v is None or not np.isfinite(v) else round(float(v), k)


def _js(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return rnd(o, 6)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(type(o))


def records(df):
    return df.astype(object).where(df.notna(), None).to_dict('records')


def write(part, obj, tables):
    """CSV tables first, JSON last: the JSON marks the part as finished (resume)."""
    for name, df in tables.items():
        df.to_csv(OUT / f'{name}.csv', index=False)
    tmp = OUT / f'{STEM[part]}.json.tmp'                 # atomic: a crash never leaves a half JSON
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=1, default=_js)
    os.replace(tmp, OUT / f'{STEM[part]}.json')


def confusion(y, p):
    return np.bincount(y * K + p, minlength=K * K).reshape(K, K)


def prf(cm):
    """Per-class precision, recall, F1 of a (K, K) count matrix (rows = true); 0 when undefined."""
    tp = np.diagonal(cm).astype(float); row = cm.sum(1); col = cm.sum(0)
    with np.errstate(divide='ignore', invalid='ignore'):
        P = np.where(col > 0, tp / col, 0.0)
        R = np.where(row > 0, tp / row, 0.0)
        F = np.where(P + R > 0, 2 * P * R / (P + R), 0.0)
    return P, R, F


def boot_p(d):
    """Two-sided bootstrap p of a difference: 2 (min(#d <= 0, #d >= 0) + 1) / (B + 1)."""
    return min(1.0, 2 * (min(int((d <= 0).sum()), int((d >= 0).sum())) + 1) / (len(d) + 1))


def gname(g, names):
    return f'{CLASSES[g // GMUL]} / {names[g % GMUL]}'


# ----------------------------------------------------------------------------- stored runs
def tree_runs():
    """Every tree run with stored predictions: 'main' (cleaning, then split) and 'decomp'."""
    runs = []
    for f in sorted((TREE / 'main').glob('*.npz')):
        m = re.match(MAIN_PAT, f.stem)
        if m:
            runs.append({'kind': 'main', 'model': m[1], 'seed': int(m[4]), 'split': m[2],
                         'train_cleaning': m[3], 'test_cleaning': m[3], 'path': f})
    for f in sorted((TREE / 'decomp').glob('*.npz')):
        m = re.match(DECOMP_PAT, f.stem)
        if m:
            runs.append({'kind': 'decomp', 'model': m[1], 'seed': int(m[5] or 42), 'split': m[2],
                         'train_cleaning': m[3], 'test_cleaning': m[4], 'path': f})
    return runs


def deep_runs(folders):
    out = []
    for fo in folders:
        for f in sorted((RES / fo).glob('*.json')):
            js = json.load(open(f))
            if isinstance(js, dict) and 'per_class_f1' in js and 'per_class_recall' in js:
                out.append((fo, js))
    return out


_CM = {}


def run_cm(r):
    """Confusion matrix of a stored run (only y and p are read, nothing pickled)."""
    if r['path'] not in _CM:
        with np.load(r['path']) as d:
            _CM[r['path']] = confusion(d['y'].astype(np.int64), d['p'].astype(np.int64))
    return _CM[r['path']]


class Flagged:
    """y, capture group, time and rule flags of the cached sample (six small columns only)."""

    def __init__(self):
        df = get_flagged(columns=['y', 'sub', 'ts'] + FLAG_COLS)
        self.flags = {c: df[c].to_numpy(bool) for c in FLAG_COLS}
        self.meta = df[['y', 'sub', 'ts']].copy()
        del df; gc.collect()
        self.meta['sub'] = self.meta['sub'].astype('category')      # as deep_split_noise_study.prepare
        self.y = self.meta['y'].to_numpy().astype(np.int64)
        self.sub = self.meta['sub'].cat.codes.to_numpy().astype(np.int64)
        self.names = np.array(self.meta['sub'].cat.categories.astype(str).tolist())
        assert len(self.names) <= GMUL and (self.sub >= 0).all(), 'capture-group codes out of range'
        ts = self.meta['ts'].to_numpy('datetime64[ns]').view(np.int64).copy()
        ts[ts == np.iinfo(np.int64).min] = np.iinfo(np.int64).max    # NaT last, as sort_values does
        self.ts = ts
        self._te = {}

    def random_test(self, kind, cleaning):
        """Global rows of the random-split test set, in the order stored by tree_protocol_study.py."""
        key = 'raw' if cleaning == 'raw' else (kind, cleaning)
        if key not in self._te:
            if cleaning == 'raw':
                te = splits(self.meta, 'random')[2]
            elif kind == 'main':                         # cleaning first, then the split
                rows = kept_rows(self.flags, cleaning)
                te = rows[splits(self.meta.iloc[rows].reset_index(drop=True), 'random')[2]]
            else:                                        # split on raw rows, test part filtered
                te = self.random_test('decomp', 'raw')
                te = te[~self.flags['r1_external'][te]]
            self._te[key] = te
        return self._te[key]


def time_perm(fl, r, y, names, sc):
    """Permutation putting the stored test rows into time order (None = keep the stored order)."""
    if r['split'] == 'temporal':
        return None, 'time order (stored)'
    if fl is None:
        return None, 'random order (flagged sample not loaded)'
    te = fl.random_test(r['kind'], r['test_cleaning'])
    if (len(te) != len(y) or not np.array_equal(fl.y[te], y)
            or not np.array_equal(fl.names[fl.sub[te]], names[sc])):
        print(f'[warn] {r["path"].name}: test rows could not be matched; stored random order kept', flush=True)
        return None, 'random order (reconstruction did not match)'
    # time, ties (1-s timestamps) broken by global row = capture order, as the temporal split does
    return np.lexsort((te, fl.ts[te])), 'time order (reconstructed)'


def load_ordered(r, fl):
    """y, p, capture-group names and codes of a stored run, rows in time order where possible."""
    with np.load(r['path'], allow_pickle=True) as d:     # own result files; 'sub' is a str object array
        y, p = d['y'].astype(np.int64), d['p'].astype(np.int64)
        names, sc = np.unique(d['sub'].astype(str), return_inverse=True)
    sc = sc.ravel().astype(np.int64)
    assert len(names) <= GMUL, f'{len(names)} capture groups > GMUL={GMUL}'
    perm, how = time_perm(fl, r, y, names, sc)
    if perm is not None:
        y, p, sc = y[perm], p[perm], sc[perm]
    return y, p, names, sc, how


# ----------------------------------------------------------------------------- bootstrap core
def boot_counts(codes, gid, n_codes, L, B, rng, min_blocks=5, lengths=None):
    """B bootstrap count vectors (B, n_codes) of the per-row codes, rows resampled inside each group.
    L = 1 : i.i.d. (multinomial on the group's code frequencies).
    L > 1 : circular moving-block bootstrap on the stored row order of each group: ceil(n / l)
            blocks of l = min(L, max(1, n // min_blocks)) consecutive rows (wrapping around), random
            starts, last block cut so that exactly n rows are drawn. Counts come from cumulative sums
            over the doubled sequence, so no resampled index arrays are built."""
    out = np.zeros((B, n_codes))
    for g in np.unique(gid):
        u, loc = np.unique(codes[gid == g], return_inverse=True)
        loc = loc.ravel()
        n = len(loc)
        l = 1 if L <= 1 else min(L, max(1, n // max(1, min_blocks)))
        if lengths is not None:
            lengths[int(g)] = int(l)
        if l == 1:
            out[:, u] += rng.multinomial(n, np.bincount(loc, minlength=len(u)) / n, size=B)
            continue
        k = -(-n // l)
        r = n - (k - 1) * l
        C = np.zeros((2 * n + 1, len(u)), np.int32)
        C[np.arange(1, 2 * n + 1), np.r_[loc, loc]] = 1
        C = np.cumsum(C, axis=0, dtype=np.int32)          # C[i] = code counts in positions [0, i)
        ch = max(1, min(CHUNK, int(MAX_GATHER // (k * len(u)))))   # bounds the (ch, k, u) temporaries
        for b0 in range(0, B, ch):
            s = rng.integers(0, n, size=(min(ch, B - b0), k))
            cnt = C[s[:, -1] + r] - C[s[:, -1]]
            if k > 1:
                cnt = cnt + (C[s[:, :-1] + l] - C[s[:, :-1]]).sum(1)
            out[b0:b0 + len(s), u] += cnt
        del C
    return out


def variants(a):
    return ([('iid_class', 1, 'class'), ('iid_group', 1, 'group')]
            + [(f'block{L}', L, 'group') for L in a.blocks])


def gids(y, sc):
    return {'class': y, 'group': y * GMUL + sc}


def paired_cms(ya, pa, pb, gid, L, B, rng, min_blocks):
    """Paired resampling: both models see the same drawn rows. Returns (B,K,K) matrices of a and b."""
    cnt = boot_counts(ya * K * K + pa * K + pb, gid, K ** 3, L, B, rng, min_blocks).reshape(-1, K, K, K)
    return cnt.sum(3), cnt.sum(2)


# ----------------------------------------------------------------------------- (a)
def part_a(a, fl):
    runs, deep = tree_runs(), deep_runs(a.deep)
    n, rows, dev = len(runs) + len(deep), [], []
    for i, r in enumerate(runs, 1):
        cm = run_cm(r)
        _, _, F = prf(cm)
        dev.append(abs(F.mean() - json.load(open(r['path'].with_suffix('.json')))['macro_f1']))
        rows.append({'source': 'tree_' + r['kind'], **{k: r[k] for k in DESC}, 'n_test': int(cm.sum()),
                     'macro_f1': F.mean(), 'attack_macro_f1': F[ATTACK].mean(), 'benign_f1': F[BENIGN]})
    for folder, js in deep:
        f1 = np.array([js['per_class_f1'][c] for c in CLASSES], float)
        rows.append({'source': folder, 'kind': 'deep', 'model': js['model'], 'seed': js['seed'],
                     'split': js['split'], 'train_cleaning': js['cleaning'], 'test_cleaning': js['cleaning'],
                     'n_test': js.get('n_test'), 'macro_f1': js['macro_f1'],
                     'attack_macro_f1': f1[ATTACK].mean(), 'benign_f1': f1[BENIGN]})
    for i, x in enumerate(rows, 1):
        print(f'[a {i}/{n}] {x["source"]:12s} {x["model"]:12s} s{x["seed"]:<3d} {x["split"]:8s} '
              f'train={x["train_cleaning"]:3s} test={x["test_cleaning"]:3s} macro-F1={x["macro_f1"]:.4f} '
              f'attack-macro-F1={x["attack_macro_f1"]:.4f} Benign-F1={x["benign_f1"]:.4f}', flush=True)
    df = pd.DataFrame(rows)
    sm = (df.groupby(['source', 'model', 'split', 'train_cleaning', 'test_cleaning'], sort=True)
            .agg(n_runs=('seed', 'count'),
                 attack_macro_f1=('attack_macro_f1', 'mean'), attack_macro_f1_sd=('attack_macro_f1', 'std'),
                 benign_f1=('benign_f1', 'mean'), benign_f1_sd=('benign_f1', 'std'),
                 macro_f1=('macro_f1', 'mean'), macro_f1_sd=('macro_f1', 'std')).reset_index())
    df, sm = df.round(4), sm.round(4)
    write('a', {'description': 'attack_macro_f1 = mean per-class F1 over the seven attack classes '
                               '(Benign excluded); tree runs from the stored predictions, deep runs from '
                               'per_class_f1 (4 decimals)',
                'check_max_abs_diff_macro_f1_npz_vs_json': rnd(max(dev) if dev else np.nan, 8),
                'runs': records(df), 'summary_mean_over_seeds': records(sm)},
          {STEM['a']: df, STEM['a'] + '_summary': sm})


# ----------------------------------------------------------------------------- (b)
def part_b(a, fl):
    dec = {(r['model'], r['seed'], r['split'], r['train_cleaning'], r['test_cleaning']): r
           for r in tree_runs() if r['kind'] == 'decomp'}
    keys = sorted({k[:4] for k in dec if (*k[:4], 'raw') in dec and (*k[:4], 'r1') in dec})
    out, rows = [], []
    frac = lambda x, n: x / n if n else np.nan
    for i, (m, sd, s, ctr) in enumerate(keys, 1):
        c_raw, c_r1 = run_cm(dec[(m, sd, s, ctr, 'raw')]), run_cm(dec[(m, sd, s, ctr, 'r1')])
        d = c_raw - c_r1                                    # predictions on the flagged flows
        ok = bool((d >= 0).all() and d[BENIGN].sum() == 0)
        base = {'model': m, 'seed': sd, 'split': s, 'train_cleaning': ctr}

        def row(label, cls, n_raw):
            nf = d[cls].sum(); own = sum(d[c, c] for c in cls); ben = d[cls, BENIGN].sum()
            nk = c_r1[cls].sum(); own_k = sum(c_r1[c, c] for c in cls); ben_k = c_r1[cls, BENIGN].sum()
            top = None
            if len(cls) == 1:
                oth = [j for j in ATTACK if j != cls[0]]
                j = oth[int(np.argmax(d[cls[0], oth]))]
                top = CLASSES[j] if d[cls[0], j] > 0 else None
            return {**base, 'class': label, 'n_test_raw': int(n_raw), 'n_flagged': int(nf),
                    'flagged_share_of_test': frac(nf, n_raw),
                    'flagged_pred_own': frac(own, nf), 'flagged_pred_benign': frac(ben, nf),
                    'flagged_pred_other_attack': frac(nf - own - ben, nf), 'flagged_top_other_attack': top,
                    'n_retained': int(nk), 'retained_pred_own': frac(own_k, nk),
                    'retained_pred_benign': frac(ben_k, nk), 'retained_pred_other_attack': frac(nk - own_k - ben_k, nk)}

        by = [row(CLASSES[c], [c], c_raw[c].sum()) for c in ATTACK]
        by.append(row('all attack classes', ATTACK, c_raw[ATTACK].sum()))
        rows += by
        out.append({**base, 'consistent': ok, 'n_test_raw': int(c_raw.sum()), 'n_test_r1': int(c_r1.sum()),
                    'n_flagged': int(d.sum()), 'confusion_flagged': d.tolist(),
                    'by_class': [{k: (rnd(v) if isinstance(v, float) else v) for k, v in x.items()} for x in by]})
        t = by[-1]
        print(f'[b {i}/{len(keys)}] {m:12s} s{sd:<3d} {s:8s} train={ctr:3s} flagged={int(d.sum()):>7,}  '
              f'pred own={t["flagged_pred_own"]:.3f} Benign={t["flagged_pred_benign"]:.3f} '
              f'other={t["flagged_pred_other_attack"]:.3f}  (retained: own={t["retained_pred_own"]:.3f} '
              f'Benign={t["retained_pred_benign"]:.3f}){"" if ok else "  [INCONSISTENT: negative counts]"}',
              flush=True)
    df = pd.DataFrame(rows)
    num = ['n_flagged', 'flagged_share_of_test', 'flagged_pred_own', 'flagged_pred_benign',
           'flagged_pred_other_attack', 'retained_pred_own', 'retained_pred_benign', 'retained_pred_other_attack']
    sm = df.groupby(['model', 'split', 'train_cleaning', 'class'], sort=False)
    sm = sm[num].mean().join(sm['seed'].nunique().rename('n_seeds')).reset_index()
    write('b', {'description': 'confusion(test raw) - confusion(test R1) of the same decomp model = its '
                               'predictions on the R1-flagged test flows (rows = true class). "other" = '
                               'another attack class. consistent = no negative cell and no Benign row.',
                'classes': CLASSES, 'runs': out},
          {STEM['b']: df.round(4), STEM['b'] + '_summary': sm.round(4)})


# ----------------------------------------------------------------------------- (c)
def part_c(a, fl):
    rng = np.random.default_rng(SEED)
    V = variants(a)
    main = {(r['model'], r['split'], r['train_cleaning']): r for r in tree_runs()
            if r['kind'] == 'main' and r['seed'] == 42}
    runs_out, ci_rows, eff, boots, point = [], [], [], {}, {}
    for i, (key, r) in enumerate(sorted(main.items()), 1):
        t = time.time()
        y, p, names, sc, how = load_ordered(r, fl)
        G = gids(y, sc)
        point[key] = tuple(float(v) for v in f1_ba(confusion(y, p).astype(float)))
        entry = {'model': key[0], 'seed': 42, 'split': key[1], 'cleaning': key[2], 'n_test': int(len(y)),
                 'row_order': how, 'macro_f1': rnd(point[key][0]), 'bal_acc': rnd(point[key][1]),
                 'variants': {}, 'block_lengths': {}}
        hw0, msg = {}, []
        for name, L, strat in V:
            lengths = {}
            cnt = boot_counts(y * K + p, G[strat], K * K, L, a.B, rng, a.min_blocks, lengths)
            bf, bb = f1_ba(cnt.reshape(-1, K, K))
            boots[(key, name)] = (bf, bb)
            v = {}
            for j, (met, arr) in enumerate((('macro_f1', bf), ('bal_acc', bb))):
                lo, hi = np.percentile(arr, [2.5, 97.5])
                hw = (hi - lo) / 2
                if name == 'iid_class':
                    hw0[met] = hw
                ratio = hw / hw0[met] if hw0.get(met) else np.nan
                v[met] = {'ci': [rnd(lo, 5), rnd(hi, 5)], 'half_width': rnd(hw, 5),
                          'sd': rnd(arr.std(ddof=1), 5), 'ratio_to_iid_class': rnd(ratio, 3)}
                ci_rows.append({'model': key[0], 'seed': 42, 'split': key[1], 'cleaning': key[2],
                                'n_test': len(y), 'row_order': how, 'variant': name, 'block': L,
                                'metric': met, 'point': point[key][j], 'ci_lo': lo, 'ci_hi': hi,
                                'half_width': hw, 'sd': arr.std(ddof=1), 'ratio_to_iid_class': ratio,
                                'n_groups_block_shortened': sum(l < L for l in lengths.values()) if L > 1 else None})
            entry['variants'][name] = v
            if L > 1:
                entry['block_lengths'][name] = {gname(g, names): l for g, l in lengths.items()}
            msg.append(f'{name}={v["macro_f1"]["half_width"]:.4f}')
        runs_out.append(entry)
        print(f'[c {i}/{len(main)}] {key[0]:12s} {key[1]:8s} {key[2]:3s} macro-F1={point[key][0]:.4f}  '
              f'CI half-width {" ".join(msg)}  [{how}] ({time.time() - t:.0f} s)', flush=True)
        del y, p, sc, G; gc.collect()

    def effect(label, m, sd, cond, name, j, obs, d):
        lo, hi = np.percentile(d, [2.5, 97.5])
        eff.append({'effect': label, 'model': m, 'seed': sd, 'condition': cond, 'variant': name,
                    'metric': ('macro_f1', 'bal_acc')[j], 'diff': obs, 'ci_lo': lo, 'ci_hi': hi,
                    'half_width': (hi - lo) / 2, 'p': boot_p(d)})

    # split effect: random - temporal, independent bootstraps (different test sets)
    for (m, s, c) in sorted(main):
        if s == 'random' and (m, 'temporal', c) in main:
            kr, kt = (m, 'random', c), (m, 'temporal', c)
            for name, _, _ in V:
                for j in (0, 1):
                    effect('split (random - temporal)', m, 42, f'cleaning={c}', name, j,
                           point[kr][j] - point[kt][j], boots[(kr, name)][j] - boots[(kt, name)][j])
    del boots; gc.collect()
    # train-cleaning effect of Table 7: train R1 / test R1 minus train raw / test R1, paired
    dec = {(r['model'], r['seed'], r['split'], r['train_cleaning'], r['test_cleaning']): r
           for r in tree_runs() if r['kind'] == 'decomp'}
    pairs = sorted({k[:3] for k in dec if (*k[:3], 'r1', 'r1') in dec and (*k[:3], 'raw', 'r1') in dec})
    for i, (m, sd, s) in enumerate(pairs, 1):
        t = time.time()
        ya, pa, na, sca, how = load_ordered(dec[(m, sd, s, 'r1', 'r1')], fl)
        yb, pb, nb, scb, _ = load_ordered(dec[(m, sd, s, 'raw', 'r1')], fl)
        if not (np.array_equal(ya, yb) and np.array_equal(na[sca], nb[scb])):
            print(f'[warn] {m} s{sd} {s}: the two R1 test sets differ - skipped', flush=True)
            continue
        G = gids(ya, sca)
        oa, ob = f1_ba(confusion(ya, pa).astype(float)), f1_ba(confusion(yb, pb).astype(float))
        msg = []
        for name, L, strat in V:
            ca, cb = paired_cms(ya, pa, pb, G[strat], L, a.B, rng, a.min_blocks)
            ra, rb = f1_ba(ca), f1_ba(cb)
            for j in (0, 1):
                effect('train cleaning (train R1 - train raw, test R1)', m, sd, f'split={s}', name, j,
                       float(oa[j] - ob[j]), ra[j] - rb[j])
            msg.append(f'{name}=[{eff[-2]["ci_lo"]:+.4f}, {eff[-2]["ci_hi"]:+.4f}]')
        print(f'[c paired {i}/{len(pairs)}] {m:12s} s{sd:<3d} {s:8s} train-cleaning effect on macro-F1 '
              f'{float(oa[0] - ob[0]):+.4f}  95% CI {" ".join(msg)}  [{how}] ({time.time() - t:.0f} s)', flush=True)
        del ya, pa, yb, pb, sca, scb, G; gc.collect()

    ci_df, eff_df = pd.DataFrame(ci_rows).round(5), pd.DataFrame(eff).round(5)
    write('c', {'settings': {'B': a.B, 'blocks': a.blocks, 'min_blocks': a.min_blocks, 'seed': SEED,
                             'variants': {'iid_class': 'i.i.d. rows, stratified by true class (bootstrap_ci.py)',
                                          'iid_group': 'i.i.d. rows, stratified by capture group',
                                          'blockL': 'circular moving blocks of L time-consecutive test rows '
                                                    'inside each capture group; L shortened to n // min_blocks '
                                                    'for small groups (block_lengths)'},
                             'ci': 'percentile 2.5 / 97.5; half_width = (hi - lo) / 2',
                             'split_effect': 'independent bootstraps of the random and the temporal test set',
                             'train_cleaning_effect': 'paired: the same resampled R1 test rows for both models'},
                'runs': runs_out, 'effects': records(eff_df)},
          {'c_block_bootstrap_ci': ci_df, 'c_block_bootstrap_effects': eff_df})


# ----------------------------------------------------------------------------- (d)
def part_d(a, fl):
    rng = np.random.default_rng(SEED + 1)
    methods = [('iid_class', 1, 'class', a.B_paired)] + [(f'block{L}', L, 'group', a.B) for L in a.blocks]
    main = {(r['model'], r['split'], r['train_cleaning']): r for r in tree_runs()
            if r['kind'] == 'main' and r['seed'] == 42}
    models = sorted({k[0] for k in main})
    conds = sorted({k[1:] for k in main})
    n_cmp = sum(len(list(itertools.combinations([m for m in models if (m, *c) in main], 2))) for c in conds)
    rows = []
    for s, c in conds:
        runs = {m: load_ordered(main[(m, s, c)], fl) for m in models if (m, s, c) in main}
        for ma, mb in itertools.combinations(sorted(runs), 2):
            t = time.time()
            ya, pa, na, sca, how = runs[ma]
            yb, pb, nb, scb, _ = runs[mb]
            if not (np.array_equal(ya, yb) and np.array_equal(na[sca], nb[scb])):
                print(f'[warn] {s} {c}: {ma} and {mb} have different test rows - skipped', flush=True)
                continue
            G = gids(ya, sca)
            ba_a, ba_b = f1_ba(confusion(ya, pa).astype(float))[1], f1_ba(confusion(yb, pb).astype(float))[1]
            row = {'split': s, 'cleaning': c, 'a': ma, 'b': mb, 'n_test': len(ya), 'row_order': how,
                   'bal_acc_a': float(ba_a), 'bal_acc_b': float(ba_b), 'diff': float(ba_a - ba_b)}
            for name, L, strat, B in methods:
                ca, cb = paired_cms(ya, pa, pb, G[strat], L, B, rng, a.min_blocks)
                d = f1_ba(ca)[1] - f1_ba(cb)[1]
                lo, hi = np.percentile(d, [2.5, 97.5])
                row.update({f'{name}_B': B, f'{name}_ci_lo': lo, f'{name}_ci_hi': hi, f'{name}_p': boot_p(d)})
            rows.append(row)
            print(f'[d {len(rows)}/{n_cmp}] {s:8s} {c:3s} {ma:12s} - {mb:12s} bal-acc diff={row["diff"]:+.4f}  '
                  + '  '.join(f'{nm}: [{row[f"{nm}_ci_lo"]:+.4f}, {row[f"{nm}_ci_hi"]:+.4f}] p={row[f"{nm}_p"]:.4f}'
                              for nm, *_ in methods) + f'  ({time.time() - t:.0f} s)', flush=True)
        del runs; gc.collect()
    for name, *_ in methods:
        adj = holm(np.array([x[f'{name}_p'] for x in rows], float))
        for x, v in zip(rows, adj):
            x[f'{name}_p_holm'] = float(v)
    df = pd.DataFrame(rows).round(5)
    write('d', {'description': 'paired bootstrap of the balanced-accuracy difference a - b on identical '
                               'test rows (seed 42); p = 2 (min(#d <= 0, #d >= 0) + 1) / (B + 1); Holm over '
                               'all comparisons, separately for each resampling method',
                'methods': {nm: {'block': L, 'strata': st, 'B': B} for nm, L, st, B in methods},
                'min_blocks': a.min_blocks, 'comparisons': records(df)},
          {STEM['d']: df})


# ----------------------------------------------------------------------------- (e)
def derived_precision(f1, r):
    """P from F1 and recall: F1 = 2PR / (P + R)  =>  P = F1 R / (2R - F1); undefined for R = 0."""
    if f1 is None or r is None or r <= 0 or 2 * r - f1 <= 0:
        return None
    return float(min(1.0, max(0.0, f1 * r / (2 * r - f1))))


def part_e(a, fl):
    runs, deep = tree_runs(), deep_runs(a.deep)
    n, rows, err = len(runs) + len(deep), [], []
    for i, r in enumerate(runs, 1):
        cm = run_cm(r)
        P, R, F = prf(cm)
        js = json.load(open(r['path'].with_suffix('.json')))
        for c, name in enumerate(CLASSES):
            rows.append({'source': 'tree_' + r['kind'], **{k: r[k] for k in DESC}, 'class': name,
                         'support': int(cm[c].sum()), 'n_predicted': int(cm[:, c].sum()),
                         'precision': P[c], 'recall': R[c], 'f1': F[c], 'precision_from': 'confusion matrix'})
            pdv = derived_precision(js['per_class_f1'][name], js['per_class_recall'][name])
            if pdv is not None and cm[:, c].sum() > 0:
                err.append((R[c], abs(pdv - P[c])))
        print(f'[e {i}/{n}] tree_{r["kind"]:6s} {r["model"]:12s} s{r["seed"]:<3d} {r["split"]:8s} '
              f'train={r["train_cleaning"]:3s} test={r["test_cleaning"]:3s} precision '
              + ' '.join(f'{CLASSES[c][:6]}={P[c]:.3f}' for c in range(K)), flush=True)
    for j, (folder, js) in enumerate(deep, len(runs) + 1):
        ps = []
        for name in CLASSES:
            f1, rc = js['per_class_f1'][name], js['per_class_recall'][name]
            pdv = derived_precision(f1, rc)
            ps.append(pdv)
            rows.append({'source': folder, 'kind': 'deep', 'model': js['model'], 'seed': js['seed'],
                         'split': js['split'], 'train_cleaning': js['cleaning'], 'test_cleaning': js['cleaning'],
                         'class': name, 'support': None, 'n_predicted': None, 'precision': pdv,
                         'recall': rc, 'f1': f1, 'precision_from': 'F1*R/(2R-F1)'})
        print(f'[e {j}/{n}] {folder:11s} {js["model"]:12s} s{js["seed"]:<3d} {js["split"]:8s} '
              f'cleaning={js["cleaning"]:3s} precision (derived) '
              + ' '.join(f'{c[:6]}=' + ('  -  ' if v is None else f'{v:.3f}') for c, v in zip(CLASSES, ps)),
              flush=True)
    e = np.array(err) if err else np.zeros((0, 2))
    big = e[e[:, 0] >= 0.05, 1] if len(e) else e
    check = {'n_class_runs': int(len(e)),
             'max_abs_error': rnd(e[:, 1].max() if len(e) else np.nan, 6),
             'median_abs_error': rnd(np.median(e[:, 1]) if len(e) else np.nan, 6),
             'max_abs_error_recall_ge_0.05': rnd(big.max() if len(big) else np.nan, 6)}
    print(f'[e check] derived vs exact precision on the tree runs: max |error| = {check["max_abs_error"]}, '
          f'median = {check["median_abs_error"]}, max for recall >= 0.05 = {check["max_abs_error_recall_ge_0.05"]}',
          flush=True)
    df = pd.DataFrame(rows)
    for c in ('support', 'n_predicted'):
        df[c] = df[c].astype('Int64')
    sm = (df.groupby(['source', 'model', 'split', 'train_cleaning', 'test_cleaning', 'class'], sort=False)
            .agg(n_runs=('seed', 'count'), precision=('precision', 'mean'), precision_sd=('precision', 'std'),
                 recall=('recall', 'mean'), recall_sd=('recall', 'std'), f1=('f1', 'mean'), f1_sd=('f1', 'std'))
            .reset_index())
    df, sm = df.round(4), sm.round(4)
    write('e', {'description': 'per-class precision / recall / F1; tree runs from the stored predictions, '
                               'deep runs: recall and F1 as stored, precision = F1 R / (2R - F1) '
                               '(None when R = 0, clipped to [0, 1])',
                'derivation_check_on_tree_runs': check, 'rows': records(df),
                'summary_mean_over_seeds': records(sm)},
          {STEM['e']: df, STEM['e'] + '_summary': sm})


# ----------------------------------------------------------------------------- (f)
def spearman(x, y, n_perm, rng):
    """Spearman rho, its scipy p-value and a two-sided permutation p-value."""
    if len(x) < 4 or np.ptp(x) == 0 or np.ptp(y) == 0:
        return None, None, None
    rho, p = spearmanr(x, y)
    rx = rankdata(x); rx = (rx - rx.mean()) / rx.std()
    perm = rankdata(y)[np.argsort(rng.random((n_perm, len(y))), axis=1)]
    perm = (perm - perm.mean(1, keepdims=True)) / perm.std(1, keepdims=True)
    r = (perm * rx).mean(1)                              # Pearson of ranks = Spearman
    p_perm = (int((np.abs(r) >= abs(rho) - 1e-12).sum()) + 1) / (n_perm + 1)
    return float(rho), float(p), float(p_perm)


def part_f(a, fl):
    rng = np.random.default_rng(SEED)
    drift = json.load(open(RES / 'split_pilot' / 'temporal_drift_r1.json'))
    pilot = json.load(open(RES / 'split_pilot' / 'subattack_results.json'))
    rec = {}
    for f in sorted((TREE / 'main').glob('*.json')):
        m = re.match(MAIN_PAT, f.stem)
        if m and m[3] == 'r1':
            rec[(m[1], int(m[4]), m[2])] = json.load(open(f))['per_subattack_recall']

    def loss(model, only=None):
        """Mean over seeds of recall(random, R1) - recall(temporal, R1) per sub-attack."""
        seeds = sorted(sd for (mm, sd, s) in rec if mm == model and s == 'random'
                       and (model, sd, 'temporal') in rec and (only is None or sd in only))
        per = {}
        for sd in seeds:
            ra, te = rec[(model, sd, 'random')], rec[(model, sd, 'temporal')]
            for g in ra.keys() & te.keys():
                per.setdefault(g, []).append(ra[g] - te[g])
        return {g: float(np.mean(v)) for g, v in per.items()}, seeds

    series, info = {}, {}
    series['XGBoost_s42'], sd_x = loss('XGBoost', [42])
    series['RandomForest_seed_mean'], sd_r = loss('RandomForest')
    pa, pdd = pilot['A_random']['per_subattack'], pilot['D_temporal_subattack']['per_subattack']
    series['pilot_raw_XGBoost'] = {g: pa[g]['recall'] - pdd[g]['recall'] for g in pa.keys() & pdd.keys()}
    info = {'XGBoost_s42': {'source': 'tree_protocol/main, R1 runs', 'seeds': sd_x},
            'RandomForest_seed_mean': {'source': 'tree_protocol/main, R1 runs', 'seeds': sd_r},
            'pilot_raw_XGBoost': {'source': 'split_pilot/subattack_results.json (raw labels, pilot data): '
                                            'A_random - D_temporal_subattack; supplementary'}}
    groups = []
    for name, v in drift.items():
        if not isinstance(v, dict) or v.get('drift_auc') is None:
            continue
        g = name if ' / ' in name else f'{name} / {name}'          # per_subattack_recall key format
        row = {'group': g, 'is_attack': g.split(' / ')[0] != CLASSES[BENIGN],
               'n_test_period': v.get('n_test_period'), 'drift_auc_sd': v.get('drift_auc_sd')}
        row.update({k: v.get(k) for k in DRIFT_VARS})
        row.update({f'loss_{s}': series[s].get(g) for s in series})
        groups.append(row)
    gdf = pd.DataFrame(groups, columns=['group', 'is_attack', 'n_test_period', 'drift_auc_sd', *DRIFT_VARS,
                                        *[f'loss_{s}' for s in series]])
    gdf['is_attack'] = gdf['is_attack'].astype(bool)
    corr, n_all, i = [], len(series) * 2 * len(DRIFT_VARS), 0
    for sname in series:
        for gset in ('all groups with a drift AUC', 'attack groups only'):
            sub = gdf if gset.startswith('all') else gdf[gdf['is_attack']]
            blk = []
            for var in DRIFT_VARS:
                i += 1
                x = pd.to_numeric(sub[var], errors='coerce').to_numpy(float)
                yv = pd.to_numeric(sub[f'loss_{sname}'], errors='coerce').to_numpy(float)
                ok = np.isfinite(x) & np.isfinite(yv)
                rho, p, pp = spearman(x[ok], yv[ok], a.perm, rng)
                blk.append({'loss_series': sname, 'groups': gset, 'variable': var, 'n': int(ok.sum()),
                            'rho': rho, 'p': p, 'p_perm': pp, 'p_holm': None})
                f = lambda v, s: '  -   ' if v is None else format(v, s)
                print(f'[f {i}/{n_all}] {sname:24s} {gset:28s} {var:26s} n={int(ok.sum()):2d} '
                      f'rho={f(rho, "+.3f")} p={f(p, ".4f")} p_perm={f(pp, ".4f")}', flush=True)
            idx = [k for k, b in enumerate(blk) if b['p'] is not None]
            if idx:
                for k, v in zip(idx, holm(np.array([blk[k]['p'] for k in idx]))):
                    blk[k]['p_holm'] = float(v)
            corr += blk
    cdf = pd.DataFrame(corr).round(4)
    write('f', {'description': 'loss = recall(random split) - recall(temporal split) per sub-attack, R1 '
                               'condition; drift variables from temporal_drift_r1.json; expected signs: '
                               'drift_auc +, top20_port_jaccard -, test_dst_ip_seen_in_train -. '
                               'p_holm: Holm over the three variables of one series and group set.',
                'loss_series': info, 'permutations': a.perm, 'groups': records(gdf.round(4)),
                'spearman': records(cdf)},
          {'f_drift_loss_groups': gdf.round(4), 'f_drift_loss_spearman': cdf})


# ----------------------------------------------------------------------------- (g)
def two_prop_p(x1, n1, x2, n2):
    if n1 == 0 or n2 == 0:
        return np.nan
    pp = (x1 + x2) / (n1 + n2)
    se = np.sqrt(pp * (1 - pp) * (1 / n1 + 1 / n2))
    return np.nan if se == 0 else float(2 * norm.sf(abs(x2 / n2 - x1 / n1) / se))


def part_g(a, fl):
    tr, va, te = splits(fl.meta, 'temporal')             # raw rows, 70/15/15 by time in each group
    period = np.full(len(fl.y), -1, np.int8)
    for k, idx in enumerate((tr, va, te)):
        period[np.asarray(idx, dtype=np.int64)] = k
    del tr, va, te; gc.collect()
    n_unassigned = int((period < 0).sum())
    gid = fl.y * GMUL + fl.sub
    rules = {'R1': fl.flags['r1_external'], 'R2': fl.flags['r2_service'], 'R3': fl.flags['r3_benign_pair']}
    rules['any'] = rules['R1'] | rules['R2'] | rules['R3']
    ok = period >= 0                                     # rows outside every period are left out
    cell = (gid * 3 + period)[ok]
    n_cells = GMUL * K * 3
    tot = np.bincount(cell, minlength=n_cells).reshape(-1, 3)
    hit = {k: np.bincount(cell, weights=v[ok].astype(float), minlength=n_cells).reshape(-1, 3)
           for k, v in rules.items()}
    del cell, period, ok; gc.collect()

    def row(name, cls, t, h):
        x = {'group': name, 'class': cls, 'is_attack': cls != CLASSES[BENIGN], 'n_all': int(t.sum()),
             'n_train': int(t[0]), 'n_val': int(t[1]), 'n_test': int(t[2])}
        for k in rules:
            s_tr = h[k][0] / t[0] if t[0] else np.nan
            s_te = h[k][2] / t[2] if t[2] else np.nan
            x.update({f'{k}_all': h[k].sum() / t.sum(), f'{k}_train': s_tr,
                      f'{k}_val': h[k][1] / t[1] if t[1] else np.nan, f'{k}_test': s_te,
                      f'{k}_diff_pp': 100 * (s_te - s_tr), f'{k}_p': two_prop_p(h[k][0], t[0], h[k][2], t[2])})
        return x

    gs = [g for g in range(GMUL * K) if tot[g].sum() > 0]
    rows = []
    for i, g in enumerate(gs, 1):
        rows.append(row(gname(g, fl.names), CLASSES[g // GMUL], tot[g], {k: hit[k][g] for k in rules}))
        x = rows[-1]
        print(f'[g {i}/{len(gs)}] {x["group"]:40s} train={x["n_train"]:>8,} test={x["n_test"]:>7,}  '
              f'any: {x["any_train"]:.3f} -> {x["any_test"]:.3f}  R1: {x["R1_train"]:.3f} -> {x["R1_test"]:.3f}  '
              f'R2: {x["R2_train"]:.3f} -> {x["R2_test"]:.3f}  R3: {x["R3_train"]:.3f} -> {x["R3_test"]:.3f}',
              flush=True)
    att = [g for g in gs if g // GMUL != BENIGN]
    pooled = row('all attack groups (pooled)', 'attack', tot[att].sum(0), {k: hit[k][att].sum(0) for k in rules})
    across = {}
    for k in rules:
        d = np.array([x[f'{k}_diff_pp'] for x in rows if x['is_attack'] and np.isfinite(x[f'{k}_diff_pp'])])
        try:
            w = wilcoxon(d) if len(d) >= 5 and np.any(d != 0) else None
        except ValueError:
            w = None
        across[k] = {'n_groups': int(len(d)), 'n_test_higher': int((d > 0).sum()), 'n_test_lower': int((d < 0).sum()),
                     'median_diff_pp': rnd(np.median(d) if len(d) else np.nan),
                     'wilcoxon_p': rnd(w.pvalue, 6) if w is not None else None}
        print(f'[g across] {k:3s}: test share higher in {across[k]["n_test_higher"]}/{len(d)} attack groups, '
              f'median diff {across[k]["median_diff_pp"]} pp, Wilcoxon p = {across[k]["wilcoxon_p"]}', flush=True)
    df = pd.DataFrame(rows + [pooled]).round(5)
    write('g', {'description': 'share of flows flagged by each rule in the training (first 70%) and test '
                               '(last 15%) period of the within-capture-group time split, raw sample; '
                               'diff_pp = 100 (test - train); p = two-proportion z-test; Benign is never flagged',
                'n_rows_without_period': n_unassigned, 'groups': records(df), 'across_attack_groups': across},
          {STEM['g']: df})


# ----------------------------------------------------------------------------- main
PART_FN = {'a': part_a, 'b': part_b, 'c': part_c, 'd': part_d, 'e': part_e, 'f': part_f, 'g': part_g}


def main():
    ap = argparse.ArgumentParser(description='Reviewer analyses from stored results (no training).')
    ap.add_argument('--parts', nargs='+', default=list('abcdefg'), choices=list('abcdefg'))
    ap.add_argument('--force', action='store_true', help='recompute selected parts even if their JSON exists')
    ap.add_argument('--B', type=int, default=1000, help='resamples of the block bootstrap (c, d) and of c')
    ap.add_argument('--B-paired', type=int, default=2000, help='resamples of the i.i.d. paired test in d')
    ap.add_argument('--blocks', nargs='+', type=int, default=[1000, 5000], help='block lengths (flows)')
    ap.add_argument('--min-blocks', type=int, default=5,
                    help='a capture group gets at least this many blocks (block shortened); 1 = textbook')
    ap.add_argument('--perm', type=int, default=20000, help='permutations for the Spearman p-value (f)')
    ap.add_argument('--deep', nargs='+', default=['deep_split'], help='deep-model result folders (a, e)')
    ap.add_argument('--no-flagged', action='store_true',
                    help='do not load the flagged sample: random-split rows keep their stored order, g skipped')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    todo = [p for p in a.parts if a.force or not (OUT / f'{STEM[p]}.json').exists()]
    print(f'[plan] parts {"".join(a.parts)}: {len(todo)} to do ({"".join(todo) or "-"}), '
          f'{len(a.parts) - len(todo)} finished', flush=True)
    if not todo:
        return
    fl = None
    if any(p in 'cdg' for p in todo):
        if a.no_flagged:
            print('[note] --no-flagged: random-split test rows keep their stored (random) order; part g skipped',
                  flush=True)
        else:
            t = time.time()
            fl = Flagged()
            print(f'[load] flagged sample: {len(fl.y):,} flows, 6 columns ({time.time() - t:.0f} s)', flush=True)
    for p in todo:
        if p == 'g' and fl is None:
            print('[skip] part g needs the flagged sample', flush=True)
            continue
        t = time.time()
        PART_FN[p](a, fl)
        print(f'[part {p}] done in {time.time() - t:.0f} s -> {OUT / STEM[p]}.json', flush=True)
        gc.collect()
    left = [p for p in a.parts if not (OUT / f'{STEM[p]}.json').exists()]
    print(f'[left] parts {"".join(left)} still to do' if left else '[DONE] all selected parts finished', flush=True)


if __name__ == '__main__':
    main()
