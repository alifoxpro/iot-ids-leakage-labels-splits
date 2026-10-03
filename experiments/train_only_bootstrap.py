# -*- coding: utf-8 -*-
r"""
train_only_bootstrap.py
=======================
Reviewer points meth-09 and nove-05 (also disc-11): intervals for the training-only cleaning table
(cleaning_train_only.py, Table 8 of the revision). No model is trained; only the stored test
predictions are resampled.

Inputs: results_2026_03_03/q1_revision/cleaning_train_only/<model>_<split>_train-<variant>_test-<R1|All>.npz
        (y, p, sub, rows = global row positions) and the matching JSON. A unit is one
        (model, split, test set): its seven variants were scored on the SAME test rows (checked here),
        so every variant can be compared with 'none' on identical flows. XGBoost is always used; the
        random forest (cleaning_train_only.py --models RandomForest) is included when its 7 runs exist.
        The flagged sample (flagged_loader, three small columns y, sub, ts) restores the time order.

Row order: inside every capture group the test rows are put in time order (timestamp, ties broken by
the global row = capture order), as revision_analyses.py does. For the temporal split this is the
stored order already (checked: stored_order_is_time_order); for the random split it rebuilds the
time order from 'rows'. With --no-flagged the stored order is kept (random order for the random
split, where the block bootstrap then behaves like an i.i.d. one).

Resampling (revision_analyses.boot_counts / paired_cms, unchanged):
  iid_class   i.i.d. rows stratified by true class (reference, as bootstrap_ci.py)
  block1000   circular moving-block bootstrap inside each capture group: blocks of 1,000
  block5000   time-consecutive test flows, random starts, the last block cut to the group size;
              a group smaller than 5 blocks gets l = n // 5 (--min-blocks 5, as revision_analyses);
              the block length used for every group is stored
  B = 1,000 resamples (--B), numpy Generator seeded with (42, crc32(unit name)): reproducible and
  independent of which units were computed before.
Per unit and method:
  cells  each of the 7 variants: point value and 95% percentile interval (2.5 / 97.5) of macro-F1,
         attack macro-F1 (7 attack classes, Benign excluded) and balanced accuracy; SD and half-width
  diffs  each variant minus 'none', PAIRED (the same resampled test flows for both predictions):
         observed difference, 95% interval, SD, two-sided bootstrap p = 2 (min(#d <= 0, #d >= 0) + 1)
         / (B + 1), Holm-adjusted over the 6 variants of the unit (per method and metric), and
         whether the interval excludes 0. The bootstrap p cannot go below 2 / (B + 1) (Holm floor
         6 x 2 / 1001 = 0.012 at B = 1,000), so a normal-approximation p is added as well:
         z = observed difference / bootstrap SD, p_normal = 2 (1 - Phi(|z|)), also Holm-adjusted.
  The point values are recomputed from the predictions and checked against the run JSONs.

Output: results_2026_03_03/q1_revision/train_only_bootstrap/
          <model>_<split>_test-<R1|All>.json   one per unit (cells, diffs, block lengths, checks)
          cells.csv, diffs.csv                 all finished units (rewritten at the end of every call)
Resumable: a unit whose JSON exists is skipped (--force recomputes); an incomplete unit (fewer than
7 finished runs) is skipped with a note and done on a later call.

Run (PowerShell, from the project folder; after cleaning_train_only.py):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\train_only_bootstrap.py 2>&1 | Tee-Object -FilePath train_only_bootstrap.log
After the random-forest runs of cleaning_train_only.py have finished (adds the 4 RF units):
  & $py experiments\train_only_bootstrap.py 2>&1 | Tee-Object -FilePath train_only_bootstrap.log -Append
Only the tables of finished units:  & $py experiments\train_only_bootstrap.py --summary
Self-test on synthetic data:        & $py experiments\train_only_bootstrap.py --selftest
"""
import argparse, gc, json, os, sys, time, zlib
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bootstrap_ci import holm  # noqa: E402
from cleaning_train_only import MODELS, OUT as CTO, SPLITS, TESTS, VARIANTS, run_name  # noqa: E402
from flagged_loader import get_flagged  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402
from revision_analyses import GMUL, boot_counts, boot_p, confusion, paired_cms  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'train_only_bootstrap'
K = len(CLASSES)
ATTACK = [c for c in range(K) if CLASSES[c] != 'Benign']
METRICS = ['macro_f1', 'attack_macro_f1', 'balanced_accuracy']
VNAMES = [v[0] for v in VARIANTS]                 # none, R1, R2, R3, R1+R3, All, All*


# ---------------------------------------------------------------- helpers
def scores(cm):
    """macro-F1, attack macro-F1 and balanced accuracy of (..., K, K) count matrices (rows = true);
    0 where undefined, as bootstrap_ci.f1_ba and sklearn's zero_division=0."""
    tp = np.diagonal(cm, axis1=-2, axis2=-1)
    row, col = cm.sum(-1), cm.sum(-2)
    with np.errstate(divide='ignore', invalid='ignore'):
        R = np.where(row > 0, tp / row, 0.0)
        P = np.where(col > 0, tp / col, 0.0)
        F = np.where(P + R > 0, 2 * P * R / (P + R), 0.0)
    return {'macro_f1': F.mean(-1), 'attack_macro_f1': F[..., ATTACK].mean(-1), 'balanced_accuracy': R.mean(-1)}


def methods(a):
    return [('iid_class', 1, 'class')] + [(f'block{L}', L, 'group') for L in a.blocks]


def unit_name(model, split, test):
    return f'{model}_{split}_test-{test}'


def units():
    """(model, split, test) -> {variant: npz path} for units with all 7 finished runs; notes for others."""
    full, notes = {}, []
    for m in MODELS:
        for s in SPLITS:
            for t in TESTS:
                paths = {v: CTO / f'{run_name(m, s, slug, t)}.npz' for v, slug, _ in VARIANTS}
                ok = [v for v, p in paths.items() if p.exists() and p.with_suffix('.json').exists()]
                if len(ok) == len(VARIANTS):
                    full[(m, s, t)] = paths
                elif ok:
                    notes.append(f'{unit_name(m, s, t)}: {len(ok)}/{len(VARIANTS)} runs finished')
    return full, notes


class TimeIndex:
    """Time, class and capture group of every flow of the flagged sample (3 small columns)."""

    def __init__(self):
        df = get_flagged(columns=['y', 'sub', 'ts'])
        self.y = df['y'].to_numpy().astype(np.int64)
        sub = df['sub'].astype('category')
        self.code = sub.cat.codes.to_numpy().astype(np.int64)
        self.names = np.array(sub.cat.categories.astype(str).tolist())
        ts = df['ts'].to_numpy('datetime64[ns]').view(np.int64).copy()
        ts[ts == np.iinfo(np.int64).min] = np.iinfo(np.int64).max       # NaT last, as sort_values does
        self.ts = ts
        del df, sub; gc.collect()

    def order(self, rows, y, sub):
        """Permutation of the stored test rows into time order (ts, then global row); None if the
        rows do not match the sample."""
        if (rows.max() >= len(self.y) or not np.array_equal(self.y[rows], y)
                or not np.array_equal(self.names[self.code[rows]], sub)):
            return None
        return np.lexsort((rows, self.ts[rows]))


def rnd(v, k=6):
    return None if v is None or not np.isfinite(v) else round(float(v), k)


P_KEYS = ('p', 'p_holm', 'p_normal', 'p_normal_holm')     # kept unrounded in the JSON (tiny p stay > 0)


def jsonable(row):
    """Floats rounded to 6 decimals (p-values kept exact); inf / NaN -> None."""
    return {k: ((float(v) if np.isfinite(v) else None) if k in P_KEYS else rnd(v)) if isinstance(v, float) else v
            for k, v in row.items()}


def normal_p(obs, d):
    """z = observed difference / bootstrap SD and its two-sided normal p (no 2 / (B + 1) floor)."""
    sd = float(d.std(ddof=1))
    if sd > 0:
        z = obs / sd
    else:                                                    # no variation at all in the resamples
        z = 0.0 if obs == 0 else float(np.copysign(np.inf, obs))
    return z, float(2 * norm.sf(abs(z)))


def write_json(path, obj):
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


# ---------------------------------------------------------------- one unit
def run_unit(key, paths, a, tix):
    model, split, test = key
    name = unit_name(*key)
    t0 = time.time()
    with np.load(paths['none']) as d:                      # plain arrays, no pickle
        y, rows, subs = d['y'].astype(np.int64), d['rows'].astype(np.int64), d['sub'].astype(str)
    P, js = {}, {}
    for v in VNAMES:
        with np.load(paths[v]) as d:
            if not (np.array_equal(d['rows'], rows) and np.array_equal(d['y'], y)):
                print(f'[warn] {name}: variant {v} has different test rows - unit skipped', flush=True)
                return None
            P[v] = d['p'].astype(np.int64)
        with open(paths[v].with_suffix('.json'), encoding='utf-8') as f:
            js[v] = json.load(f)
    names, sc = np.unique(subs, return_inverse=True)
    sc = sc.ravel().astype(np.int64)
    assert len(names) <= GMUL, f'{len(names)} capture groups > GMUL={GMUL}'
    del subs

    gid0 = y * GMUL + sc
    perm = tix.order(rows, y, names[sc]) if tix is not None else None
    if perm is None:
        how = 'stored order' + (' (--no-flagged)' if tix is None else ' (rows not matched to the flagged sample)')
        stored_is_time = None
        if tix is not None:
            print(f'[warn] {name}: test rows not matched to the flagged sample; stored order kept', flush=True)
    else:
        how = 'time order within capture groups (timestamp, then global row)'
        # is the stored order already the time order inside every group?  (expected: temporal yes)
        stored_is_time = bool(np.array_equal(np.argsort(gid0, kind='stable'),
                                             np.lexsort((rows, tix.ts[rows], gid0))))
        y, sc, rows = y[perm], sc[perm], rows[perm]
        P = {v: p[perm] for v, p in P.items()}
    G = {'class': y, 'group': y * GMUL + sc}

    point = {v: {m: float(x) for m, x in scores(confusion(y, P[v]).astype(float)).items()} for v in VNAMES}
    dev = max(abs(point[v][m] - js[v][m]) for v in VNAMES for m in METRICS)
    if dev > 1e-9:
        print(f'[warn] {name}: recomputed metrics differ from the JSONs by up to {dev:.2e}', flush=True)

    rng = np.random.default_rng([SEED, zlib.crc32(name.encode())])
    cells, diffs, block_len = [], [], {}
    for meth, L, strat in methods(a):
        tm = time.time()
        for v in VNAMES:
            lengths = {}
            cnt = boot_counts(y * K + P[v], G[strat], K * K, L, a.B, rng, a.min_blocks, lengths)
            bs = scores(cnt.reshape(-1, K, K))
            if L > 1 and v == 'none':                      # depends only on n and L: same for all variants
                block_len[meth] = {f'{CLASSES[g // GMUL]} / {names[g % GMUL]}': int(l) for g, l in lengths.items()}
            for m in METRICS:
                lo, hi = np.percentile(bs[m], [2.5, 97.5])
                cells.append({'model': model, 'split': split, 'test_set': test, 'method': meth, 'block': L,
                              'variant': v, 'metric': m, 'point': point[v][m], 'ci_lo': float(lo), 'ci_hi': float(hi),
                              'half_width': float(hi - lo) / 2, 'sd': float(bs[m].std(ddof=1))})
            del cnt, bs
        fam = {m: [] for m in METRICS}
        for v in VNAMES[1:]:
            ca, cb = paired_cms(y, P[v], P['none'], G[strat], L, a.B, rng, a.min_blocks)
            sa, sb = scores(ca), scores(cb)
            for m in METRICS:
                d = sa[m] - sb[m]
                lo, hi = np.percentile(d, [2.5, 97.5])
                obs = point[v][m] - point['none'][m]
                z, pz = normal_p(obs, d)
                row = {'model': model, 'split': split, 'test_set': test, 'method': meth, 'block': L,
                       'variant': v, 'metric': m, 'value': point[v][m], 'none_value': point['none'][m],
                       'diff': obs, 'ci_lo': float(lo), 'ci_hi': float(hi),
                       'sd': float(d.std(ddof=1)), 'p': boot_p(d), 'z': z, 'p_normal': pz,
                       'ci_excludes_0': bool(lo > 0 or hi < 0)}
                diffs.append(row)
                fam[m].append(row)
            del ca, cb, sa, sb
        for m, rs in fam.items():                           # Holm over the 6 variants of this unit
            for r, ph, pn in zip(rs, holm(np.array([r['p'] for r in rs])),
                                 holm(np.array([r['p_normal'] for r in rs]))):
                r['p_holm'], r['p_normal_holm'] = float(ph), float(pn)
        print(f'  [{name}] {meth:9s} done ({time.time() - tm:.0f} s)', flush=True)

    res = {'model': model, 'split': split, 'test_set': test, 'test_rule': TESTS[test], 'n_test': int(len(y)),
           'n_capture_groups': int(len(np.unique(G['group']))), 'row_order': how,
           'stored_order_is_time_order': stored_is_time,
           'check_max_abs_diff_vs_json': rnd(dev, 12),
           'settings': {'B': a.B, 'blocks': a.blocks, 'min_blocks': a.min_blocks,
                        'rng': f'numpy default_rng([{SEED}, crc32("{name}")])',
                        'ci': 'percentile 2.5 / 97.5', 'diff': 'variant - none, paired resampling',
                        'p': '2 (min(#d <= 0, #d >= 0) + 1) / (B + 1); p_holm over the 6 variants per method and metric',
                        'p_normal': 'z = diff / bootstrap SD, p = 2 (1 - Phi(|z|)) (no 2 / (B + 1) floor); '
                                    'p_normal_holm over the 6 variants per method and metric'},
           'point': point,
           'block_lengths': block_len,
           'n_groups_block_shortened': {meth: int(sum(l < int(meth[5:]) for l in bl.values()))
                                        for meth, bl in block_len.items()},
           'cells': [jsonable(c) for c in cells],
           'diffs': [jsonable(c) for c in diffs]}
    write_json(OUT / f'{name}.json', res)
    print(f'[unit] {name}: n_test={len(y):,}, {how}, done in {time.time() - t0:.0f} s', flush=True)
    return res


# ---------------------------------------------------------------- tables
def tables(a):
    res = []
    for m in MODELS:
        for s in SPLITS:
            for t in TESTS:
                f = OUT / f'{unit_name(m, s, t)}.json'
                if f.exists():
                    with open(f, encoding='utf-8') as fh:
                        res.append(json.load(fh))
    if not res:
        print('no finished units yet')
        return
    cells = pd.DataFrame([c for r in res for c in r['cells']])
    diffs = pd.DataFrame([c for r in res for c in r['diffs']])
    cells.to_csv(OUT / 'cells.csv', index=False)
    diffs.to_csv(OUT / 'diffs.csv', index=False)
    show = f'block{max(a.blocks)}' if a.blocks else 'iid_class'
    for r in res:
        print(f'\n=== {r["model"]} {r["split"]} test_{r["test_set"]} (n_test={r["n_test"]:,}; {r["row_order"]}) '
              f'- 95% intervals, {show} ===')
        for m in ('macro_f1', 'balanced_accuracy'):
            print(f'  {m}: {"variant":7s} {"value":>7s} {"95% CI":>17s}   {"- none":>7s} {"95% CI":>17s} '
                  f'{"p_holm":>7s} {"p_norm_holm":>11s}')
            for v in VNAMES:
                c = [x for x in r['cells'] if x['method'] == show and x['variant'] == v and x['metric'] == m][0]
                line = f'  {" " * len(m)}  {v:7s} {c["point"]:7.4f} [{c["ci_lo"]:.4f}, {c["ci_hi"]:.4f}]'
                if v != 'none':
                    d = [x for x in r['diffs'] if x['method'] == show and x['variant'] == v and x['metric'] == m][0]
                    pn = d.get('p_normal_holm')
                    line += (f'   {d["diff"]:+7.4f} [{d["ci_lo"]:+.4f}, {d["ci_hi"]:+.4f}] {d["p_holm"]:7.3f} '
                             f'{"n/a" if pn is None else format(pn, ".1e"):>11s}'
                             f'{"  *" if d["ci_excludes_0"] else ""}')
                print(line)
    print(f'\n[saved] {OUT / "cells.csv"} ({len(cells)} rows), {OUT / "diffs.csv"} ({len(diffs)} rows)', flush=True)
    print('  * = the 95% interval of the difference excludes 0', flush=True)


# ---------------------------------------------------------------- self-test (synthetic data only)
def selftest():
    rng = np.random.default_rng(0)
    y = rng.integers(0, K, 3000)
    p = np.where(rng.random(3000) < .7, y, rng.integers(0, K, 3000))
    from sklearn.metrics import balanced_accuracy_score, f1_score
    s = scores(confusion(y, p).astype(float))
    assert abs(s['macro_f1'] - f1_score(y, p, average='macro', labels=list(range(K)), zero_division=0)) < 1e-12
    assert abs(s['balanced_accuracy'] - balanced_accuracy_score(y, p)) < 1e-12
    af = f1_score(y, p, average=None, labels=list(range(K)), zero_division=0)[ATTACK].mean()
    assert abs(s['attack_macro_f1'] - af) < 1e-12
    q = np.where(rng.random(3000) < .1, rng.integers(0, K, 3000), p)
    gid = y * GMUL + rng.integers(0, 3, 3000)
    ca, cb = paired_cms(y, q, p, gid, 100, 50, rng, 5)
    assert ca.shape == (50, K, K) and np.array_equal(ca.sum((1, 2)), cb.sum((1, 2)))
    assert np.array_equal(ca.sum(2), cb.sum(2))                      # same resampled rows: same class counts
    assert (ca.sum((1, 2)) == 3000).all()
    z, pz = normal_p(0.02, rng.normal(0.02, 0.01, 1000))
    assert 1.8 < z < 2.2 and 0.02 < pz < 0.07 and normal_p(0.0, np.zeros(10)) == (0.0, 1.0)
    assert normal_p(0.1, np.full(10, 0.1))[1] == 0.0
    js = jsonable({'p': 1e-30, 'p_normal_holm': 1e-40, 'point': 0.1234567891, 'z': float('inf'), 'n': 3})
    assert js == {'p': 1e-30, 'p_normal_holm': 1e-40, 'point': 0.123457, 'z': None, 'n': 3}
    # time order: global rows sorted by (timestamp, row); NaT last
    tix = TimeIndex.__new__(TimeIndex)
    n = 50
    tix.y = rng.integers(0, 2, n).astype(np.int64)
    tix.code = rng.integers(0, 3, n).astype(np.int64)
    tix.names = np.array(['g0', 'g1', 'g2'])
    tix.ts = rng.integers(0, 5, n).astype(np.int64)
    tix.ts[3] = np.iinfo(np.int64).max
    rows = rng.permutation(n)[:30]
    perm = tix.order(rows, tix.y[rows], tix.names[tix.code[rows]])
    assert [tuple(x) for x in zip(tix.ts[rows[perm]], rows[perm])] == sorted(zip(tix.ts[rows], rows))
    assert tix.order(rows, 1 - tix.y[rows], tix.names[tix.code[rows]]) is None     # mismatch -> None
    print('[selftest] OK: scores match sklearn; paired block resampling keeps class and group sizes; '
          'normal p; time order')


def main():
    ap = argparse.ArgumentParser(description='Block-bootstrap intervals for the training-only cleaning runs.')
    ap.add_argument('--B', type=int, default=1000, help='bootstrap resamples')
    ap.add_argument('--blocks', nargs='+', type=int, default=[1000, 5000], help='block lengths (flows)')
    ap.add_argument('--min-blocks', type=int, default=5,
                    help='a capture group gets at least this many blocks (block shortened); 1 = textbook')
    ap.add_argument('--force', action='store_true', help='recompute units whose JSON exists')
    ap.add_argument('--no-flagged', action='store_true',
                    help='do not load the flagged sample; the stored row order is kept')
    ap.add_argument('--summary', action='store_true', help='only print / write the tables of finished units')
    ap.add_argument('--selftest', action='store_true', help='test the helpers on synthetic data and exit')
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        tables(a); return
    full, notes = units()
    for n in notes:
        print(f'[skip] incomplete unit {n}', flush=True)
    todo = [k for k in full if a.force or not (OUT / f'{unit_name(*k)}.json').exists()]
    print(f'[plan] {len(full)} complete units, {len(full) - len(todo)} finished, {len(todo)} to do '
          f'(B={a.B}, blocks={a.blocks}, min_blocks={a.min_blocks})', flush=True)
    if todo:
        tix = None
        if not a.no_flagged:
            t = time.time()
            tix = TimeIndex()
            print(f'[load] flagged sample: {len(tix.y):,} flows, 3 columns ({time.time() - t:.0f} s)', flush=True)
        for i, k in enumerate(todo, 1):
            print(f'[{i}/{len(todo)}] {unit_name(*k)}', flush=True)
            run_unit(k, full[k], a, tix)
            gc.collect()
    tables(a)
    left = [unit_name(*k) for k in full if not (OUT / f'{unit_name(*k)}.json').exists()]
    print(f'[left] {len(left)} units still to do' if left else '[DONE] all complete units finished', flush=True)


if __name__ == '__main__':
    main()
