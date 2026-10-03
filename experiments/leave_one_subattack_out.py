# -*- coding: utf-8 -*-
"""
leave_one_subattack_out.py
==========================
Leave-one-sub-attack-out test (reviewer request: the drop under the temporal split has not
been attributed to "time" rather than to "unseen attack variants").

Base split : temporal 70/15/15 inside each of the 16 capture groups (splits(meta, 'temporal')
             on the kept rows of the label condition). Every sub-attack therefore has
             training flows, and the test part is the latest 15 % of each capture.
Labels     : raw (folder labels) | r1 (attack flows with an endpoint outside the testbed dropped)
Held out   : the 12 sub-attacks of the four classes with 2+ capture groups
             DDOS (4), DOS (3), Spoofing (2), Web-Based (3)
Per label condition:
  seen   - ONE XGBoost fit on the full base training rows                       (2 fits in total)
  unseen - per held-out sub-attack, XGBoost trained on the base training rows MINUS every
           flow of that sub-attack; its sibling sub-attacks keep the class alive (24 fits)
Both models are scored on the SAME flows: the base test rows of the held-out sub-attack.
Reported: recall of those flows as their own class (seen vs unseen), the share predicted as
each class (where do unseen variants go?), and the share still flagged as an attack (not
Benign). Because the test flows and the time gap are identical, seen -> unseen isolates the
unseen-variant effect from the time effect.
Model: make('XGBoost') from extra_baselines.py; balanced sample weights recomputed on each
training set; 81 features with NaN/inf -> 0. 26 XGBoost fits.

Output: results_2026_03_03/q1_revision/leave_one_subattack_out/
  base_temporal_<labels>.json / .npz  seen model: metrics on the whole base test set, predictions
                                      (y, p, sub), cross-check against tree_protocol/main
  unseen_<labels>_<sub-attack>.json   held-out run: recall seen/unseen, class shares, attack
                                      detection, discordant counts, sibling sub-attack recall,
                                      unseen model's metrics on the whole base test set
  unseen_<labels>_<sub-attack>.npz    held-out test flows only: y, p (unseen), p_seen, sub
  summary.csv                         one row per (sub-attack, labels)
Resumable: finished runs are skipped; --summary only rebuilds summary.csv.
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\leave_one_subattack_out.py
  one fit per process (optional):
  for ($i = 0; $i -lt 26; $i++) { & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\leave_one_subattack_out.py --max-fits 1 }
"""
import argparse, gc, json, os, re, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
ROOT = HERE.parent
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'leave_one_subattack_out'
REF = ROOT / 'results_2026_03_03' / 'tree_protocol' / 'main'     # same seen fit, run earlier
LABELS = ['raw', 'r1']
BENIGN = CLASSES.index('Benign')
HELD_OUT = [('DDOS', 'DDOS ACK Fragmentation'), ('DDOS', 'DDOS HTTP FLOOD'),
            ('DDOS', 'DDOS ICMP FLOOD'), ('DDOS', 'DDOS ICMP Fragmentation'),
            ('DOS', 'DOS HTTP FLOOD'), ('DOS', 'DOS SYN FLOOD'), ('DOS', 'DOS UDP FLOOD'),
            ('Spoofing', 'ARP Spoofing'), ('Spoofing', 'DNS Spoofing'),
            ('Web-Based', 'Sqlinjection'), ('Web-Based', 'Uploading Attack'), ('Web-Based', 'XSS')]


def slug(s):
    return re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_')


def base_name(lab):
    return f'base_temporal_{lab}'


def run_name(lab, sub):
    return f'unseen_{lab}_{slug(sub)}'


def dump_json(path, r):
    """Write the JSON that marks a run as finished atomically (the .npz is written before it)."""
    tmp = path.with_suffix('.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path)


def read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def share(mask):
    return float(mask.mean()) if len(mask) else None


def rnd(v):
    return None if v is None else round(v, 4)


def shares(p):
    n = np.bincount(p.astype(np.int64), minlength=len(CLASSES))
    return {c: round(float(n[k]) / max(len(p), 1), 4) for k, c in enumerate(CLASSES)}


def top_class(sh):
    """Most frequent predicted class; None when there were no test flows (all shares 0)."""
    return max(sh, key=sh.get) if any(sh.values()) else None


def check_groups(meta):
    """HELD_OUT must be exactly the capture groups of the classes that have two or more."""
    pairs = {(CLASSES[int(c)], str(s)) for c, s in meta[['y', 'sub']].drop_duplicates().itertuples(index=False)}
    per_class = pd.Series([c for c, _ in pairs]).value_counts()
    multi = {(c, s) for c, s in pairs if per_class[c] >= 2}
    if multi != set(HELD_OUT):
        raise SystemExit(f'[error] capture groups differ from HELD_OUT: missing {sorted(set(HELD_OUT) - multi)}, '
                         f'extra {sorted(multi - set(HELD_OUT))}')


def base_split(lab, meta, flags):
    """Global train / test positions of the temporal-within-sub-attack split on the kept rows."""
    rows = kept_rows(flags, lab)
    tr, _, te = splits(meta.iloc[rows].reset_index(drop=True), 'temporal')
    return rows[tr], rows[te]


def fit_predict(X, y, tr, te):
    clf = make('XGBoost')
    t = time.time()
    clf.fit(X[tr], y[tr], sample_weight=compute_sample_weight('balanced', y[tr]))
    fit_s = time.time() - t
    p = np.asarray(clf.predict(X[te])).astype(np.int8).ravel()
    del clf; gc.collect()
    return p, fit_s


def run_seen(lab, X, y, sub, tr, te):
    p, fit_s = fit_predict(X, y, tr, te)
    r = metrics(y[te], p, sub[te])
    r.update({'role': 'seen: full base training rows', 'model': 'XGBoost', 'split': 'temporal', 'labels': lab,
              'n_train': int(len(tr)), 'n_test': int(len(te)), 'fit_seconds': round(fit_s, 1)})
    ref = REF / f'XGBoost_temporal_{lab}_s42.json'
    if ref.exists():                      # identical configuration -> should agree up to GPU noise
        old = read_json(ref)['per_subattack_recall']
        d = [abs(r['per_subattack_recall'][k] - v) for k, v in old.items() if k in r['per_subattack_recall']]
        r['crosscheck_tree_protocol_max_abs_diff'] = round(max(d), 4) if d else None
    # predictions first: the JSON marks the run as finished and the unseen runs need the .npz
    np.savez_compressed(OUT / f'{base_name(lab)}.npz', y=y[te].astype(np.int8), p=p, sub=sub[te].astype(str))
    dump_json(OUT / f'{base_name(lab)}.json', r)
    return r, fit_s


def load_seen(lab, y, sub, te):
    f = OUT / f'{base_name(lab)}.npz'
    if not f.exists():
        raise SystemExit(f'[error] {f.name} missing - delete {base_name(lab)}.json and rerun')
    with np.load(f) as d:                 # closes the file handle (Windows)
        ok = (np.array_equal(d['y'], y[te].astype(np.int8))
              and np.array_equal(d['sub'], sub[te].astype(str)))
        p = d['p']
    if not ok:
        raise SystemExit(f'[error] {f.name} does not match the current split - delete {base_name(lab)}.* and rerun')
    return p, read_json(OUT / f'{base_name(lab)}.json')


def run_unseen(lab, cls, s, X, y, sub, tr, te, p_seen_all, seen_json):
    c = CLASSES.index(cls)
    held_tr = (y[tr] == c) & (sub[tr] == s)
    tr_u = tr[~held_tr]                                   # base training rows minus the sub-attack
    m = (y[te] == c) & (sub[te] == s)                     # its base test rows (same as for 'seen')
    p_all, fit_s = fit_predict(X, y, tr_u, te)
    p_u, p_s = p_all[m], p_seen_all[m]
    full = metrics(y[te], p_all, sub[te])
    ok_s, ok_u = p_s == c, p_u == c
    rec_s, rec_u = share(ok_s), share(ok_u)
    key = f'{cls} / {s}'
    siblings = {k: {'seen': seen_json['per_subattack_recall'].get(k), 'unseen': v}
                for k, v in full['per_subattack_recall'].items() if k.startswith(f'{cls} / ') and k != key}
    r = {'held_out_class': cls, 'held_out_subattack': s, 'labels': lab, 'model': 'XGBoost', 'split': 'temporal',
         'n_train': int(len(tr_u)), 'n_train_base': int(len(tr)), 'n_train_removed': int(held_tr.sum()),
         'n_train_class_left': int((y[tr_u] == c).sum()), 'n_test': int(m.sum()),
         'recall_seen': rnd(rec_s), 'recall_unseen': rnd(rec_u),
         'delta': None if rec_s is None else round(rec_u - rec_s, 4),        # from unrounded recalls
         'attack_detection_seen': rnd(share(p_s != BENIGN)), 'attack_detection_unseen': rnd(share(p_u != BENIGN)),
         'seen_predicted_as': shares(p_s), 'unseen_predicted_as': shares(p_u),
         'discordant': {'seen_only_correct': int((ok_s & ~ok_u).sum()),
                        'unseen_only_correct': int((~ok_s & ok_u).sum())},
         'sibling_recall': siblings,
         'full_test_unseen_model': full,
         'full_test_seen_model': {k: seen_json[k] for k in ('accuracy', 'balanced_accuracy', 'macro_f1')},
         'fit_seconds': round(fit_s, 1)}
    name = run_name(lab, s)
    np.savez_compressed(OUT / f'{name}.npz', y=y[te][m].astype(np.int8), p=p_u, p_seen=p_s,
                        sub=sub[te][m].astype(str))
    dump_json(OUT / f'{name}.json', r)                    # last: marks the run as finished
    return r, fit_s


def summary():
    rows = []
    for lab in LABELS:
        for cls, s in HELD_OUT:
            f = OUT / f'{run_name(lab, s)}.json'
            if not f.exists():
                continue
            r = read_json(f)
            un = r['unseen_predicted_as']
            row = {'sub_attack': s, 'class': cls, 'labels': lab, 'n_test': r['n_test'],
                   'n_train_removed': r['n_train_removed'], 'recall_seen': r['recall_seen'],
                   'recall_unseen': r['recall_unseen'], 'delta': r['delta'],
                   'attack_detection_seen': r['attack_detection_seen'],
                   'attack_detection_unseen': r['attack_detection_unseen'],
                   'unseen_top_class': top_class(un)}
            row.update({f'unseen_as_{c}': v for c, v in un.items()})
            row.update({f'seen_as_{c}': v for c, v in r['seen_predicted_as'].items()})
            rows.append(row)
    if not rows:
        print('no finished held-out runs yet'); return
    d = pd.DataFrame(rows)
    d.to_csv(OUT / 'summary.csv', index=False)
    pd.set_option('display.width', 200)
    cols = ['labels', 'class', 'sub_attack', 'n_test', 'recall_seen', 'recall_unseen', 'delta',
            'attack_detection_unseen', 'unseen_top_class']
    print('\n=== held-out sub-attack: recall as its own class (seen -> unseen), same test flows ===')
    print(d[cols].to_string(index=False))
    g = d.groupby('labels')[['recall_seen', 'recall_unseen', 'delta']].mean().round(4)
    print('\n=== unweighted mean over sub-attacks ===')
    print(g.to_string())
    print('\n[saved]', OUT / 'summary.csv', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). With 1 inside a PowerShell loop every '
                         'fit starts in a fresh process.')
    ap.add_argument('--summary', action='store_true', help='only rebuild summary.csv from finished runs')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return
    jobs = []
    for lab in LABELS:                                   # the seen model first: its predictions are reused
        jobs.append((lab, None, None))
        jobs += [(lab, cls, s) for cls, s in HELD_OUT]
    name = lambda j: base_name(j[0]) if j[1] is None else run_name(j[0], j[2])
    todo = [j for j in jobs if not (OUT / f'{name(j)}.json').exists()]
    print(f'[plan] {len(jobs)} runs (one XGBoost fit each), {len(jobs) - len(todo)} finished, '
          f'{len(todo)} to do', flush=True)
    if not todo:
        summary(); return
    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    check_groups(meta)
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    split, seen = {}, {}
    done = 0
    for j in todo:
        if a.max_fits and done >= a.max_fits:
            break
        lab, cls, s = j
        if lab not in split:
            split[lab] = base_split(lab, meta, flags)
        tr, te = split[lab]
        if cls is None:
            r, fit_s = run_seen(lab, X, y, sub, tr, te)
            done += 1
            print(f'[{done}/{len(todo)}] {lab:3s} seen model (full base training, n_train={r["n_train"]:,})  '
                  f'macro-F1={r["macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f}  '
                  f'check vs tree_protocol: {r.get("crosscheck_tree_protocol_max_abs_diff")}  '
                  f'({fit_s / 60:.1f} min)', flush=True)
        else:
            if lab not in seen:
                seen[lab] = load_seen(lab, y, sub, te)
            r, fit_s = run_unseen(lab, cls, s, X, y, sub, tr, te, *seen[lab])
            done += 1
            un = r['unseen_predicted_as']
            fmt = lambda v: 'n/a' if v is None else f'{v:.3f}'
            print(f'[{done}/{len(todo)}] {lab:3s} {cls:9s} / {s:24s} n_test={r["n_test"]:>7,}  '
                  f'recall seen={fmt(r["recall_seen"])} unseen={fmt(r["recall_unseen"])}  '
                  f'unseen top={top_class(un)}  ({fit_s / 60:.1f} min)', flush=True)
        gc.collect()
    left = len(todo) - done
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)
    if not left:
        summary()


if __name__ == '__main__':
    main()
