# -*- coding: utf-8 -*-
r"""
bootstrap_family.py
===================
Round-2 review (Reviewer 1, point 3), computed ONLY from stored predictions (no model is trained):
  (1) the comparison family behind "39 of these 40 comparisons" (Section 5.4): which comparisons, metric,
      condition, statistic (difference of seed means) and resampling, with Holm-adjusted p over the 40;
  (2) PAIRED BLOCK-BOOTSTRAP intervals for the principal differences, for several block lengths and an
      automatically selected one, with the block length used in every capture group (small attack groups);
  (3) a SESSION-LEVEL check: leave-one-capture-group-out (jackknife) values of every principal difference,
      because flow-level intervals alone do not support inference across capture sessions.

Principal differences (macro-F1 unless stated; 'seed mean' = mean over the runs whose predictions are stored)
  leader      the leading model of each condition minus the runner-up (macro-F1: random forest; balanced
              accuracy: XGBoost), seed means and seed 42, paired (same test rows, resampled jointly)
  tree-net    random forest minus the best of the five networks (seed mean over the training seeds that both
              stored: 7, 123, 2024 for the three main networks, all five for MLP and 1-D CNN), paired
  split       random minus temporal split, per model and label condition (different test sets: independent)
  clean       R1 minus raw labels, cleaning before the split (main factorial; different test sets: independent)
  clean-train training rows cleaned with R1 minus none, the same test rows (cleaning_train_only.py: XGBoost and
              the random forest, test sets R1 and All), paired
Resampling (B = --B, default 1000; rows resampled inside each capture group):
  L1          i.i.d. inside each capture group (stratified by group)
  L100 ... L20000  circular moving-block bootstrap of blocks of L time-consecutive test flows inside each group
              (as revision_analyses.py), the block shortened to n // --min-blocks for small groups
  auto        block length of each group chosen from its data: Politis & White (2004), corrected by Patton,
              Politis & White (2009), for the circular block bootstrap, applied to the per-flow error series
              (paired: the difference of the seed-averaged error indicators of the two sides), in time order;
              capped at n // --min-blocks
  The time order of the random-split test rows is rebuilt from the stored global rows (or, for files without
  them, from the same splits() call as the training script, checked row by row against y and capture group).
Leave one group out: the statistic recomputed 16+ times, each time without the test flows of one capture group
  (both sides); min, max, number of sign changes and the jackknife standard error.

Output: results_2026_03_03/q1_revision/bootstrap_family/
          family_40.csv            the 40 comparisons of Section 5.4 (from analyses2/b_differences.csv) with
                                   Holm-adjusted p over exactly these 40
          principal.csv            one row per difference x resampling: estimate, 95% CI, half-width, B
          block_lengths.csv        per difference, side and capture group: n, automatic and effective lengths
          leave_one_group_out.csv  per difference and dropped group: value
          settings.json
Run (PowerShell, from the project folder; about 30-60 min, ~2 GB RAM):
  & $py experiments\bootstrap_family.py 2>&1 | Tee-Object -FilePath bootstrap_family.log
"""
import argparse, gc, json, math, os, re, sys, time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bootstrap_ci import holm  # noqa: E402
from deep_split_noise_study import kept_rows, splits  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
RES = HERE.parent / 'results_2026_03_03'
OUT = RES / 'q1_revision' / 'bootstrap_family'
K = len(CLASSES)
TREES = ['XGBoost', 'LightGBM', 'RandomForest']
NETS = ['ResNet1D', 'GRU', 'Transformer', 'MLP', 'CNN1D_Hossain']
CONDS = [(s, c) for s in ('random', 'temporal') for c in ('raw', 'r1')]
SEEDS_TP = {'XGBoost': [42], 'LightGBM': [42, 17, 7], 'RandomForest': [42, 17, 7]}


# ============================================================================ data
class Sample:
    """y, capture group, time and rule flags of the cached sample (small columns only)."""

    def __init__(self):
        df = get_flagged(columns=['y', 'sub', 'ts', 'r1_external', 'r2_service', 'r3_benign_pair'])
        self.flags = {c: df[c].to_numpy(bool) for c in ('r1_external', 'r2_service', 'r3_benign_pair')}
        self.meta = df[['y', 'sub', 'ts']].copy()
        del df; gc.collect()
        self.meta['sub'] = self.meta['sub'].astype('category')
        self.y = self.meta['y'].to_numpy().astype(np.int64)
        self.names = np.array(self.meta['sub'].cat.categories.astype(str).tolist())
        self.sub = self.meta['sub'].cat.codes.to_numpy().astype(np.int64)
        ts = self.meta['ts'].to_numpy('datetime64[ns]').view(np.int64).copy()
        ts[ts == np.iinfo(np.int64).min] = np.iinfo(np.int64).max
        self.ts = ts
        self.gid = self.y * 64 + self.sub
        self._te = {}

    def test_rows(self, split, cleaning):
        """Global test rows of the main factorial (cleaning, then split), as the training scripts made them."""
        if (split, cleaning) not in self._te:
            rows = kept_rows(self.flags, cleaning)
            self._te[(split, cleaning)] = rows[splits(self.meta.iloc[rows].reset_index(drop=True), split)[2]]
        return self._te[(split, cleaning)]


class Run:
    """Predictions of one stored run, in canonical order (capture group, time, global row)."""

    def __init__(self, path, S, expect_rows=None):
        with np.load(path, allow_pickle=True) as d:            # own result files
            y, p = d['y'].astype(np.int64), d['p'].astype(np.int64)
            rows = d['rows'].astype(np.int64) if 'rows' in d.files else None
            sub = d['sub'].astype(str)
        if rows is None:
            rows = expect_rows
        if rows is None or len(rows) != len(y) or not np.array_equal(S.y[rows], y) \
                or not np.array_equal(S.names[S.sub[rows]], sub):
            raise ValueError(f'{path.name}: test rows could not be matched')
        o = np.lexsort((rows, S.ts[rows], S.gid[rows]))
        self.name, self.rows, self.y, self.p = path.stem, rows[o], y[o], p[o]
        self.gid = S.gid[self.rows]


def tree_main_runs(S, model, split, cleaning, seeds=None):
    out = []
    for sd in (seeds or SEEDS_TP[model] + ([123, 2024] if model != 'XGBoost' else [])):
        f = RES / 'tree_protocol' / 'main' / f'{model}_{split}_{cleaning}_s{sd}.npz'
        if not f.exists():
            f = RES / 'q1_revision' / 'tree_seeds' / 'runs' / f'{model}_{split}_{cleaning}_s{sd}.npz'
        if f.exists():
            out.append(Run(f, S, S.test_rows(split, cleaning)))
    return out


def deep_main_runs(S, model, split, cleaning, seeds=None):
    out = []
    for f in sorted((RES / 'q1_revision' / 'deep_protocol' / 'earlystop').glob(f'{model}_{split}_{cleaning}_s*.npz')):
        sd = int(re.search(r'_s(\d+)$', f.stem)[1])
        if seeds is None or sd in seeds:
            out.append(Run(f, S, S.test_rows(split, cleaning)))
    return out


def seed_of(run):
    return int(re.search(r'_s(\d+)$', run.name)[1]) if re.search(r'_s(\d+)$', run.name) else 42


# ============================================================================ statistics
def cms(runs, idx):
    """Confusion matrices (len(runs), K, K) of the runs on the resampled positions idx."""
    out = np.empty((len(runs), K, K))
    for i, r in enumerate(runs):
        out[i] = np.bincount(r.y[idx] * K + r.p[idx], minlength=K * K).reshape(K, K)
    return out


def metric(cm, which):
    tp = np.diagonal(cm, axis1=-2, axis2=-1)
    row, col = cm.sum(-1), cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        rec = np.where(row > 0, tp / row, 0.0)
        if which == 'balanced_accuracy':
            return rec.mean(-1)
        prec = np.where(col > 0, tp / col, 0.0)
        return np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0).mean(-1)


def stat(runs, idx, which):
    return float(metric(cms(runs, idx), which).mean())       # seed mean


def groups(gid):
    """(start, length, group id) of the contiguous groups of a canonical gid array."""
    cut = np.flatnonzero(np.r_[True, gid[1:] != gid[:-1], True])
    return [(int(a), int(b - a), int(gid[a])) for a, b in zip(cut[:-1], cut[1:])]


def draw(bounds, lens, rng):
    out = []
    for (s0, n, _), l in zip(bounds, lens):
        if l <= 1:
            out.append(s0 + rng.integers(0, n, n))
            continue
        k = -(-n // l)
        st = rng.integers(0, n, k)
        out.append(s0 + ((st[:, None] + np.arange(l)[None, :]).ravel()[:n] % n))
    return np.concatenate(out)


def pw_block(x):
    """Politis & White (2004) / Patton et al. (2009) optimal block length of the circular block bootstrap."""
    n = len(x)
    if n < 20 or np.var(x) == 0:
        return 1.0
    x = x - x.mean()
    kn = max(5, int(math.ceil(math.sqrt(math.log10(n)))))
    mmax = int(math.ceil(math.sqrt(n))) + kn
    mmax = min(mmax, n - 1)
    f = np.fft.rfft(x, 2 * n)                                # autocovariances by FFT
    acv = np.fft.irfft(f * np.conj(f))[:mmax + 1] / n
    rho = np.abs(acv[1:] / acv[0])
    thr = 2.0 * math.sqrt(math.log10(n) / n)
    mhat, cnt = None, 0
    for i, v in enumerate(rho):
        cnt = cnt + 1 if v < thr else 0
        if cnt == kn:
            mhat = i + 1 - kn
            break
    if mhat is None:
        mhat = mmax
    M = min(2 * max(mhat, 1), mmax)
    k = np.arange(-M, M + 1)
    t = np.abs(k) / M
    lam = np.where(t <= 0.5, 1.0, np.where(t <= 1.0, 2 * (1 - t), 0.0))
    g = acv[np.abs(k)]
    G = float(np.sum(lam * np.abs(k) * g))
    g0 = float(np.sum(lam * g))
    D = 4.0 / 3.0 * g0 ** 2
    if D <= 0:
        return 1.0
    b = (2 * G ** 2 / D) ** (1 / 3) * n ** (1 / 3)
    return float(min(max(b, 1.0), math.ceil(min(3 * math.sqrt(n), n / 3))))


def lengths(bounds, L, min_blocks, series=None):
    """Block length per group: fixed L or 'auto' (Politis-White on `series`), capped at n // min_blocks."""
    out = []
    for s0, n, _ in bounds:
        cap = max(1, n // max(1, min_blocks))
        if L == 'auto':
            out.append(int(min(cap, max(1, round(pw_block(series[s0:s0 + n]))))))
        else:
            out.append(1 if L <= 1 else int(min(L, cap)))
    return out


# ============================================================================ effects
def effect(eid, kind, desc, A, B, which, S, a, rng, rows_bl, rows_lo):
    """A, B: lists of runs. kind 'paired' (same test rows) or 'independent'. Returns result rows."""
    t0 = time.time()
    if kind == 'paired':
        ref = A[0].rows
        for r in A + B:
            assert np.array_equal(r.rows, ref), f'{eid}: runs on different test rows'
        sides = [('both', A[0].gid)]
    else:
        for side in (A, B):
            for r in side:
                assert np.array_equal(r.rows, side[0].rows), f'{eid}: runs of one side on different rows'
        sides = [('a', A[0].gid), ('b', B[0].gid)]
    full = {nm: np.arange(len(g)) for nm, g in sides}
    est = (stat(A, full[sides[0][0]], which) - stat(B, full[sides[-1][0]], which))
    bounds = {nm: groups(g) for nm, g in sides}
    # per-flow error series for the automatic block length (seed-averaged error indicators)
    err = lambda runs: np.mean([(r.p != r.y).astype(float) for r in runs], axis=0)
    series = {'both': err(A) - err(B)} if kind == 'paired' else {'a': err(A), 'b': err(B)}
    res = []
    for L in a.blocks + ['auto']:
        lens = {nm: lengths(bounds[nm], L, a.min_blocks, series[nm]) for nm, _ in sides}
        for nm, _ in sides:
            for (s0, n, g), l in zip(bounds[nm], lens[nm]):
                if L == 'auto' or L == max(a.blocks):
                    rows_bl.append({'effect': eid, 'side': nm, 'L': L, 'group': S.names[g % 64], 'class': CLASSES[g // 64],
                                    'n': n, 'block_used': l, 'blocks': -(-n // l)})
        vals = np.empty(a.B)
        for b in range(a.B):
            if kind == 'paired':
                idx = draw(bounds['both'], lens['both'], rng)
                cmA, cmB = cms(A, idx), cms(B, idx)
            else:
                cmA, cmB = cms(A, draw(bounds['a'], lens['a'], rng)), cms(B, draw(bounds['b'], lens['b'], rng))
            vals[b] = metric(cmA, which).mean() - metric(cmB, which).mean()
        lo, hi = np.percentile(vals, [2.5, 97.5])
        res.append({'effect': eid, 'description': desc, 'metric': which, 'pairing': kind,
                    'runs_a': ';'.join(r.name for r in A), 'runs_b': ';'.join(r.name for r in B),
                    'n_runs_a': len(A), 'n_runs_b': len(B), 'n_test_a': len(A[0].rows), 'n_test_b': len(B[0].rows),
                    'estimate': round(est, 5), 'resampling': 'iid within group' if L == 1 else ('auto' if L == 'auto' else f'block {L}'),
                    'B': a.B, 'ci_lo': round(float(lo), 5), 'ci_hi': round(float(hi), 5),
                    'half_width': round(float(hi - lo) / 2, 5), 'ci_excludes_0': bool(lo > 0 or hi < 0)})
    # leave one capture group out (both sides drop the same group)
    gall = sorted(set(np.unique(A[0].gid)) | set(np.unique(B[0].gid)))
    vals = []
    for g in gall:
        ia = np.flatnonzero(A[0].gid != g)
        ib = ia if kind == 'paired' else np.flatnonzero(B[0].gid != g)
        v = stat(A, ia, which) - stat(B, ib, which)
        vals.append(v)
        rows_lo.append({'effect': eid, 'dropped_group': S.names[g % 64], 'dropped_class': CLASSES[g // 64],
                        'value': round(v, 5), 'estimate': round(est, 5)})
    vals = np.array(vals)
    G = len(vals)
    jse = math.sqrt((G - 1) / G * float(np.sum((vals - vals.mean()) ** 2)))
    for r in res:
        r.update({'logo_min': round(float(vals.min()), 5), 'logo_max': round(float(vals.max()), 5),
                  'logo_sign_changes': int(np.sum(np.sign(vals) != np.sign(est))), 'logo_groups': G,
                  'logo_jackknife_se': round(jse, 5)})
    print(f'[{eid}] {desc}: {est:+.4f}  ' + '  '.join(f'{r["resampling"]}: [{r["ci_lo"]:+.4f}, {r["ci_hi"]:+.4f}]' for r in res)
          + f'  LOGO {vals.min():+.4f}..{vals.max():+.4f}  ({time.time() - t0:.0f} s)', flush=True)
    return res


def family_40():
    d = pd.read_csv(RES / 'q1_revision' / 'analyses2' / 'b_differences.csv')
    six = set(TREES) | {'ResNet1D', 'GRU', 'Transformer'}
    q = d[(d['view'] == 'all') & (d['comparison'] == 'model pair (same condition)') & (d['a_kind'] == 'main')
          & d['a_model'].isin(six) & d['b_model'].isin(six)]
    rows = []
    for (m, s, c), h in q.groupby(['metric', 'a_split', 'a_train_cleaning']):
        means = {}
        for _, r in h.iterrows():
            means[r['a_model']] = r['mean_a']; means[r['b_model']] = r['mean_b']
        lead = max(means, key=means.get)
        for _, r in h[(h['a_model'] == lead) | (h['b_model'] == lead)].iterrows():
            other = r['b_model'] if r['a_model'] == lead else r['a_model']
            sign = 1 if r['a_model'] == lead else -1
            rows.append({'metric': m, 'split': s, 'labels': c, 'leader': lead, 'other': other,
                         'statistic': 'difference of seed means (leader - other)',
                         'runs_leader': int(r['n_a'] if sign == 1 else r['n_b']), 'runs_other': int(r['n_b'] if sign == 1 else r['n_a']),
                         'diff': round(sign * r['diff'], 5), 'ci_lo': round(sign * (r['ci_lo'] if sign == 1 else r['ci_hi']), 5),
                         'ci_hi': round(sign * (r['ci_hi'] if sign == 1 else r['ci_lo']), 5),
                         'ci_includes_0': bool(r['ci_includes_0']), 'resampling': r['method'],
                         'p_boot': r['p_boot'], 'p_normal': r['p_normal']})
    f = pd.DataFrame(rows)
    f['p_holm_40'] = holm(f['p_normal'].to_numpy(float)).round(6)
    f['p_holm_40_boot'] = holm(f['p_boot'].to_numpy(float)).round(6)
    f.to_csv(OUT / 'family_40.csv', index=False)
    print(f'[family] {len(f)} comparisons, {int((~f["ci_includes_0"]).sum())} intervals exclude 0', flush=True)
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--B', type=int, default=1000)
    ap.add_argument('--blocks', nargs='+', type=int, default=[1, 100, 1000, 5000, 20000])
    ap.add_argument('--min-blocks', type=int, default=5)
    ap.add_argument('--seed', type=int, default=2026)
    ap.add_argument('--only', nargs='*', default=None, help='effect ids (prefix match) to compute')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    fam = family_40()
    S = Sample()
    rng = np.random.default_rng(a.seed)
    res, bl, lo = [], [], []
    want = lambda eid: a.only is None or any(eid.startswith(x) for x in a.only)

    for s, c in CONDS:
        tr = {m: tree_main_runs(S, m, s, c) for m in TREES}
        for which, lead in (('macro_f1', 'RandomForest'), ('balanced_accuracy', 'XGBoost')):
            mean = {m: stat(r, np.arange(len(r[0].rows)), which) for m, r in tr.items() if r}
            runner = max((m for m in mean if m != lead), key=mean.get)
            eid = f'leader_{which}_{s}_{c}'
            if want(eid):
                res += effect(eid, 'paired', f'{lead} - {runner} ({which}, {s}, {c}; seed means)', tr[lead], tr[runner],
                              which, S, a, rng, bl, lo)
            eid = f'leader42_{which}_{s}_{c}'
            if want(eid):
                pick = lambda runs: [r for r in runs if seed_of(r) == 42]
                res += effect(eid, 'paired', f'{lead} - {runner} ({which}, {s}, {c}; seed 42)', pick(tr[lead]), pick(tr[runner]),
                              which, S, a, rng, bl, lo)
        # best tree (random forest) vs best network, common seeds
        nets = {m: deep_main_runs(S, m, s, c) for m in NETS}
        nets = {m: r for m, r in nets.items() if r}
        if nets:
            best = max(nets, key=lambda m: stat(nets[m], np.arange(len(nets[m][0].rows)), 'macro_f1'))
            seeds = sorted({seed_of(r) for r in nets[best]} & {seed_of(r) for r in tr['RandomForest']})
            eid = f'treenet_{s}_{c}'
            if want(eid) and seeds:
                res += effect(eid, 'paired', f'RandomForest - {best} (macro_f1, {s}, {c}; seeds {seeds})',
                              [r for r in tr['RandomForest'] if seed_of(r) in seeds],
                              [r for r in nets[best] if seed_of(r) in seeds], 'macro_f1', S, a, rng, bl, lo)
        del tr, nets; gc.collect()

    for m in TREES + NETS:
        get = (lambda s, c: tree_main_runs(S, m, s, c)) if m in TREES else (lambda s, c: deep_main_runs(S, m, s, c))
        for c in ('raw', 'r1'):
            eid = f'split_{m}_{c}'
            if want(eid):
                A, B = get('random', c), get('temporal', c)
                if A and B:
                    res += effect(eid, 'independent', f'random - temporal ({m}, {c})', A, B, 'macro_f1', S, a, rng, bl, lo)
        for s in ('random', 'temporal'):
            eid = f'clean_{m}_{s}'
            if want(eid):
                A, B = get(s, 'r1'), get(s, 'raw')
                if A and B:
                    res += effect(eid, 'independent', f'R1 - raw, cleaned before the split ({m}, {s})', A, B, 'macro_f1',
                                  S, a, rng, bl, lo)
        gc.collect()

    cto = RES / 'q1_revision' / 'cleaning_train_only'
    for m in ('XGBoost', 'RandomForest'):
        for s in ('random', 'temporal'):
            for t in ('R1', 'All'):
                eid = f'cleantrain_{m}_{s}_test{t}'
                fa, fb = cto / f'{m}_{s}_train-R1_test-{t}.npz', cto / f'{m}_{s}_train-none_test-{t}.npz'
                if want(eid) and fa.exists() and fb.exists():
                    res += effect(eid, 'paired', f'train R1 - train none, test {t} ({m}, {s})', [Run(fa, S)], [Run(fb, S)],
                                  'macro_f1', S, a, rng, bl, lo)

    pd.DataFrame(res).to_csv(OUT / 'principal.csv', index=False)
    pd.DataFrame(bl).to_csv(OUT / 'block_lengths.csv', index=False)
    pd.DataFrame(lo).to_csv(OUT / 'leave_one_group_out.csv', index=False)
    with open(OUT / 'settings.json', 'w', encoding='utf-8') as f:
        json.dump({'B': a.B, 'blocks': a.blocks, 'min_blocks': a.min_blocks, 'seed': a.seed,
                   'auto': 'Politis & White (2004), Patton et al. (2009) circular block bootstrap, per capture group, '
                           'on the per-flow error series (paired: difference of the seed-averaged error indicators)',
                   'family_40': 'analyses2/b_differences.csv, view all, model pairs within condition, leader vs the other '
                                'five of ResNet1D, GRU, Transformer, XGBoost, LightGBM, random forest; Holm over the 40',
                   'created': time.strftime('%Y-%m-%d %H:%M:%S')}, f, indent=1)
    print(f'[DONE] {len(res)} rows -> {OUT / "principal.csv"}', flush=True)


if __name__ == '__main__':
    main()
