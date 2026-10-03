# -*- coding: utf-8 -*-
"""
symmetric_r1.py
===============
Symmetric R1 control (reviewer request). Rule R1 (relabel_background.py) removes attack-capture
flows that have an endpoint outside the testbed, but it is applied to the attack classes only:
Benign captures keep their external-endpoint flows. After the paper's R1 cleaning EVERY flow with
an external endpoint is therefore Benign, and a model could profit from that asymmetry instead of
from attack behaviour. This script measures how large the asymmetry is and removes it in two ways.

Data: the cached sample of flagged_loader.py (3,626,502 flows), 81 features, NaN/inf -> 0.
  benign_external = Benign flow with Src IP or Dst IP outside the testbed (relabel_background.internal)
  (the loader's r1_external flag is always False for Benign; for attack rows the same IP test is
   recomputed here and must agree with the flag - the check is stored in external_share.json)

Conditions (compared with the existing raw / r1 runs of tree_protocol_study.py, seed 42):
  sym      R1 applied to ALL classes: every flow with an external endpoint is removed, Benign
           included; the split (random | temporal) is made on the kept rows. No class contains an
           external-endpoint flow any more, so the asymmetry cannot be learned.
  relabel  all rows kept; R1-flagged attack flows are relabelled Benign (y := Benign) in training
           AND test. The split is the raw partition (made on all rows with the folder labels, i.e.
           row-for-row the partition of the raw condition), so relabel differs from raw only in the
           labels. Extra output: false-alarm rate on the relabelled background flows of the test
           part (share predicted as any attack class), overall, per folder class and per capture
           group, next to the false-alarm rate on genuine Benign-capture flows.
Models XGBoost and RandomForest (extra_baselines.make, seed 42, balanced sample weights on the
training labels of the condition) x split random | temporal x condition sym | relabel = 8 fits.

Every run stores metrics (accuracy, balanced accuracy, macro-F1, attack macro-F1 = macro-F1 over
the 7 attack classes, per-class F1 / precision / recall, per-sub-attack recall, Benign false-alarm
rate, confusion matrix), the run description, n_train / n_test and the fit time, plus the test
predictions (for bootstrap CIs / paired tests).
Output: results_2026_03_03/q1_revision/symmetric_r1/
          external_share.json          share of Benign flows with an external endpoint, overall and
                                       in the training / test parts of both splits for the row sets
                                       raw (= relabel), r1 (paper, asymmetric) and sym
          <model>_<split>_<condition>.json / .npz   (npz: y = evaluation label, p, sub, rows =
                                       global test positions, y_folder = original folder label)
          summary.csv                  raw / r1 (tree_protocol, s42) / sym / relabel side by side
Resumable: finished runs are skipped. '--max-fits N' stops after N model fits, so the random
forests can run one fit per process (a fresh process frees all memory).
Run (PowerShell):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\symmetric_r1.py --models XGBoost 2>&1 | Tee-Object -FilePath symmetric_r1_xgb.log
  1..4 | ForEach-Object { & $py experiments\\symmetric_r1.py --models RandomForest --max-fits 1 2>&1 | Tee-Object -FilePath symmetric_r1_rf.log -Append }
  & $py experiments\\symmetric_r1.py --summary
"""
import argparse, gc, json, os, sys, time, warnings
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import get_flagged, load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402
from relabel_background import internal  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
# pandas 2.x warns on every groupby over the categorical 'sub' column (temporal split); in
# PowerShell 2>&1 each warning line shows up as a red NativeCommandError, so silence just that one
warnings.filterwarnings('ignore', message='.*observed=False.*', category=FutureWarning)
ROOT = HERE.parent
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'symmetric_r1'
BASE = ROOT / 'results_2026_03_03' / 'tree_protocol' / 'main'     # raw / r1 runs, same models and seed
STATS = OUT / 'external_share.json'
IPS = ['Src IP', 'Dst IP']
MODELS = ['XGBoost', 'RandomForest']
SPLITS = ['random', 'temporal']
CONDITIONS = ['sym', 'relabel']
BENIGN = CLASSES.index('Benign')
LABELS = list(range(len(CLASSES)))
ATTACKS = [c for c in LABELS if c != BENIGN]
DESCR = {'sym': 'R1 applied to all classes: flows with an external endpoint removed from every class '
                '(Benign included); split made on the kept rows',
         'relabel': 'all rows kept; R1-flagged attack flows relabelled Benign in training and test; '
                    'split = raw partition (all rows, folder labels)'}


def name(m, s, c):
    return f'{m}_{s}_{c}'


def save_json(path, obj):
    """Write via a temporary file: an interrupted write never leaves a JSON that marks a run as done."""
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w') as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def split_rows(meta, rows, s):
    """Train / test GLOBAL positions of split design s made on the row subset `rows`."""
    tr, _, te = splits(meta.iloc[rows].reset_index(drop=True), s)
    return rows[tr], rows[te]


def extra(y, p):
    """Metrics not in deep_split_noise_study.metrics: attack-only macro-F1, precision, false alarms."""
    y, p = np.asarray(y), np.asarray(p)
    b, a = y == BENIGN, y != BENIGN
    return {'attack_macro_f1': float(f1_score(y, p, labels=ATTACKS, average='macro', zero_division=0)),
            'per_class_precision': dict(zip(CLASSES, precision_score(y, p, labels=LABELS, average=None,
                                                                     zero_division=0).round(4).tolist())),
            'benign_false_alarm_rate': round(float((p[b] != BENIGN).mean()), 6) if b.any() else None,
            'attack_missed_as_benign_rate': round(float((p[a] == BENIGN).mean()), 6) if a.any() else None,
            'confusion': confusion_matrix(y, p, labels=LABELS).tolist()}


def fa_block(p, y_folder, m):
    """False-alarm statistics of the flows selected by mask m (all have evaluation label Benign)."""
    if not m.any():
        return {'n_test': 0}
    pm, fm = p[m], y_folder[m]
    return {'n_test': int(m.sum()),
            'false_alarm_rate': round(float((pm != BENIGN).mean()), 6),
            'predicted_as_folder_class': round(float((pm == fm).mean()), 6),
            'predicted_class_share': {CLASSES[k]: round(float((pm == k).mean()), 6) for k in LABELS}}


def part_stats(rows, y, ext, relab):
    """Benign / external-endpoint composition of one set of rows."""
    yb, e = y[rows] == BENIGN, ext[rows]
    nb, nbe, ne, nr = int(yb.sum()), int((yb & e).sum()), int(e.sum()), int(relab[rows].sum())
    return {'n': int(len(rows)), 'n_benign': nb, 'n_benign_external': nbe,
            'benign_external_share': round(nbe / nb, 6) if nb else None,
            'n_external_any_class': ne,
            'external_flows_that_are_benign': round(nbe / ne, 6) if ne else None,
            'n_attack_r1_flows': nr,                                  # = flows relabelled in 'relabel'
            'benign_external_share_after_relabel': round((nbe + nr) / (nb + nr), 6) if nb + nr else None,
            'relabelled_share_of_benign_after_relabel': round(nr / (nb + nr), 6) if nb + nr else None}


def external_share(meta, y, ext, relab, rowsets):
    res = {'n_flows': int(len(y)), 'overall': {}, 'per_class_external_share': {}, 'rowsets': {}}
    b = y == BENIGN
    res['overall'] = {'n_benign': int(b.sum()), 'n_benign_external': int((b & ext).sum()),
                      'benign_external_share': round(float(ext[b].mean()), 6),
                      'n_attack': int((~b).sum()), 'n_attack_r1': int(relab.sum()),
                      'attack_r1_share': round(float(relab[~b].mean()), 6)}
    for k in LABELS:
        m = y == k
        res['per_class_external_share'][CLASSES[k]] = {'n': int(m.sum()), 'n_external': int((m & ext).sum()),
                                                       'share': round(float(ext[m].mean()), 6)}
    for key, rows in rowsets.items():
        res['rowsets'][key] = {'all_rows': part_stats(rows, y, ext, relab)}
        for s in SPLITS:
            tr, te = split_rows(meta, rows, s)
            res['rowsets'][key][s] = {'train': part_stats(tr, y, ext, relab), 'test': part_stats(te, y, ext, relab)}
            del tr, te; gc.collect()
    return res


def print_share(res):
    o = res['overall']
    f = lambda v: 'n/a' if v is None else f'{v:.2%}'  # noqa: E731
    print(f'[share] Benign flows with an external endpoint: {o["n_benign_external"]:,} / {o["n_benign"]:,} '
          f'= {o["benign_external_share"]:.2%}; attack flows flagged by R1: {o["n_attack_r1"]:,} '
          f'= {o["attack_r1_share"]:.2%}', flush=True)
    for key, d in res['rowsets'].items():
        for s in SPLITS:
            tr, te = d[s]['train'], d[s]['test']
            print(f'[share] {key:15s} {s:8s} Benign-external train={f(tr["benign_external_share"]):>7s} '
                  f'test={f(te["benign_external_share"]):>7s} | external flows that are Benign '
                  f'train={f(tr["external_flows_that_are_benign"]):>7s} test={f(te["external_flows_that_are_benign"]):>7s}',
                  flush=True)


def summary():
    import pandas as pd
    rows = []
    for m in MODELS:
        for s in SPLITS:
            for c in ['raw', 'r1'] + CONDITIONS:
                f = (BASE / f'{m}_{s}_{c}_s{SEED}') if c in ('raw', 'r1') else (OUT / name(m, s, c))
                if not f.with_suffix('.json').exists():
                    continue
                with open(f.with_suffix('.json')) as fh:
                    r = json.load(fh)
                if 'attack_macro_f1' not in r:                        # tree_protocol baseline
                    if not f.with_suffix('.npz').exists():
                        continue
                    d = np.load(f.with_suffix('.npz'))
                    r.update(extra(d['y'], d['p']))
                rows.append({'model': m, 'split': s, 'condition': c, 'n_test': r['n_test'],
                             'macro_f1': r['macro_f1'], 'attack_macro_f1': r['attack_macro_f1'],
                             'bal_acc': r['balanced_accuracy'], 'benign_recall': r['per_class_recall']['Benign'],
                             'benign_false_alarm': r['benign_false_alarm_rate'],
                             'background_false_alarm': r.get('relabelled_background', {}).get('false_alarm_rate')})
    if not rows:
        print('no finished runs yet'); return
    t = pd.DataFrame(rows)
    pd.set_option('display.width', 180)
    print('\n=== raw / r1 (tree_protocol, seed 42) versus symmetric R1 controls ===')
    print(t.round(4).to_string(index=False))
    OUT.mkdir(parents=True, exist_ok=True)
    t.to_csv(OUT / 'summary.csv', index=False)
    print('[saved]', OUT / 'summary.csv', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--models', nargs='+', default=MODELS, choices=MODELS)
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). A random forest of this size takes several GB, '
                         'so run it with 1 inside a PowerShell loop: every fit then starts in a fresh process.')
    ap.add_argument('--summary', action='store_true', help='only print the table of finished runs')
    a = ap.parse_args()
    if a.summary:
        summary(); return
    jobs = [(m, s, c) for m in a.models for s in SPLITS for c in CONDITIONS]
    todo = [j for j in jobs if not (OUT / f'{name(*j)}.json').exists()]
    need_stats = not STATS.exists()
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do'
          f'{" + external-endpoint shares" if need_stats else ""}', flush=True)
    if not todo and not need_stats:
        summary(); return
    OUT.mkdir(parents=True, exist_ok=True)

    ips = get_flagged(columns=IPS)          # the two address columns only
    # cast BEFORE combining: on an object array '~True' is the integer -2, which bool() turns into True
    ext = ~(np.asarray(internal(ips['Src IP']), dtype=bool) & np.asarray(internal(ips['Dst IP']), dtype=bool))
    del ips; gc.collect()
    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    r1 = np.asarray(flags['r1_external'], dtype=bool)
    relab = r1 & (y != BENIGN)                             # attack flows flagged by R1
    benign_ext = ext & (y == BENIGN)
    mismatch = int((ext[y != BENIGN] != r1[y != BENIGN]).sum())
    print(f'[data] {len(y):,} flows; Benign with external endpoint {int(benign_ext.sum()):,}; '
          f'attack R1 flows {int(relab.sum()):,}; IP rule vs r1 flag mismatches on attack rows: {mismatch}', flush=True)
    if mismatch:
        print(f'[warn] {mismatch:,} attack flows where the IP rule and the cached r1 flag disagree; '
              f'sym removes both (flag OR IP rule), so no external-endpoint flow is kept', flush=True)
    keep_r1 = np.zeros(len(y), bool); keep_r1[kept_rows(flags, 'r1')] = True
    in_sym = keep_r1 & ~ext                                # paper R1 + IP rule on every class (Benign included)
    rows_sym = np.where(in_sym)[0]
    del keep_r1
    y_rel = y.copy(); y_rel[relab] = BENIGN

    if need_stats:
        res = external_share(meta, y, ext, relab, {'raw_and_relabel': np.arange(len(y)),
                                                   'r1_asymmetric': kept_rows(flags, 'r1'), 'sym': rows_sym})
        res['check_ip_rule_vs_r1_flag_attack_mismatches'] = mismatch
        res['note'] = ('raw_and_relabel = all rows (the relabel condition uses this partition); r1_asymmetric = '
                       'paper cleaning (R1 on attack classes only); sym = R1 on all classes. '
                       '*_after_relabel fields describe the relabel condition on the same rows.')
        save_json(STATS, res)
        print_share(res)
        print('[saved]', STATS, flush=True)

    all_rows = np.arange(len(y))
    n_fit = 0
    for i, (m, s, c) in enumerate(todo, 1):
        if a.max_fits and n_fit >= a.max_fits:
            break
        n_fit += 1
        if c == 'sym':
            tr, te = split_rows(meta, rows_sym, s)
            yv = y
        else:
            tr, te = split_rows(meta, all_rows, s)
            yv = y_rel
        clf = make(m)
        clf.set_params(random_state=SEED)
        w = compute_sample_weight('balanced', yv[tr])
        t = time.time()
        clf.fit(X[tr], yv[tr], sample_weight=w)
        fit_s = time.time() - t
        p = np.asarray(clf.predict(X[te])).astype(np.int8).ravel()
        del clf, w; gc.collect()

        yt, yf, st = yv[te], y[te], sub[te]
        r = metrics(yt, p, st)
        r.update(extra(yt, p))
        r.update({'model': m, 'seed': SEED, 'split': s, 'condition': c, 'description': DESCR[c],
                  'n_train': int(len(tr)), 'n_test': int(len(te)),
                  'n_train_per_class': {CLASSES[k]: int((yv[tr] == k).sum()) for k in LABELS},
                  'fit_seconds': round(fit_s, 1)})
        if c == 'sym':
            r['n_removed_per_class'] = {CLASSES[k]: int(((y == k) & ~in_sym).sum()) for k in LABELS}
        else:
            rt = relab[te]
            r['n_relabelled_train'] = int(relab[tr].sum())
            r['relabelled_background'] = fa_block(p, yf, rt)
            r['relabelled_background']['per_folder_class'] = {
                CLASSES[k]: fa_block(p, yf, rt & (yf == k)) for k in ATTACKS if (rt & (yf == k)).any()}
            r['relabelled_background']['per_capture_group'] = {
                f'{CLASSES[k]} / {g}': fa_block(p, yf, rt & (yf == k) & (st == g))
                for k, g in sorted(set(zip(yf[rt].tolist(), st[rt].tolist())))}
            r['genuine_benign'] = fa_block(p, yf, yf == BENIGN)
        # predictions first, JSON last: the JSON marks the run as finished (resume check)
        np.savez_compressed(OUT / f'{name(m, s, c)}.npz', y=yt.astype(np.int8), p=p, sub=st.astype(str),
                            rows=te.astype(np.int32), y_folder=yf.astype(np.int8))
        save_json(OUT / f'{name(m, s, c)}.json', r)
        fmt = lambda v: 'n/a' if v is None else f'{v:.4f}'  # noqa: E731
        bg = f' bg-FA={fmt(r["relabelled_background"].get("false_alarm_rate"))}' if c == 'relabel' else ''
        print(f'[{i}/{len(todo)}] {m:12s} {s:8s} {c:7s} macro-F1={r["macro_f1"]:.4f} '
              f'attack-F1={r["attack_macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} '
              f'benign-FA={fmt(r["benign_false_alarm_rate"])}{bg} ({fit_s / 60:.1f} min)', flush=True)
        del tr, te, p, yt, yf, st, r; gc.collect()
    left = sum(not (OUT / f'{name(*j)}.json').exists() for j in jobs)
    if left:
        print(f'[left] {left} runs still to do', flush=True)
    else:
        print('[DONE] all runs finished', flush=True)
        summary()


if __name__ == '__main__':
    main()
