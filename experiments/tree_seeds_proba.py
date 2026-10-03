# -*- coding: utf-8 -*-
"""
tree_seeds_proba.py
===================
Reviewer points expe-08 / disc-11 (seed variability of the tree ensembles), expe-09 (per-class
precision and a threshold-free metric), expe-17 (training AND inference time) and stat-09.

Same sample, features, preprocessing, splits and hyper-parameters as tree_protocol_study.py "main"
(load_prepared(): 81 features, NaN/inf -> 0; extra_baselines.make(); balanced sample weights
computed on the training part; cleaning first (kept_rows), then splits() on the kept rows;
the validation part is not used). Four conditions: random | temporal x raw | r1.

Runs (one fit each)
  refit   XGBoost s42, LightGBM s42, RandomForest s42 (12 fits): the seed-42 runs of
          tree_protocol/main fitted again, this time storing probabilities and inference time.
          XGBoost stays a single run (deterministic GPU 'hist'); it is only refitted with seed 42.
  new     LightGBM and RandomForest, model seeds 123 and 2024 (16 fits). Together with seeds 42, 17
          and 7 of tree_protocol/main both models then have five seeds (42, 17, 7, 123, 2024).
  old     (only with --with-old-seeds) LightGBM and RandomForest seeds 17 and 7 refitted (16 fits),
          so that probabilities / average precision exist for all five seeds.
The data split is fixed (split seed 42 / the paper's 70/15/15 time cut); only the model seed varies.

Stored per run
  JSON  metrics() of deep_split_noise_study (accuracy, balanced accuracy, macro-F1, per-class F1 and
        recall, per-sub-attack recall), attack_macro_f1 (7 attack classes, Benign excluded),
        per_class_precision, per_class_recall, confusion matrix (rows = true), per-class test support
        and prevalence (= the AP of a random ranking),
        per_class_ap (one-vs-rest average precision, sklearn average_precision_score, computed from the
        probabilities in the model's own precision: float32 XGBoost, float64 LightGBM / random forest),
        macro_ap (mean over the 8 classes), attack_macro_ap (7 attack classes),
        macro_ap_float16 (the same from the stored float16 probabilities, to show the rounding effect),
        per_class_roc_auc and macro_roc_auc (one-vs-rest, as deep_protocol_study.py for the deep models),
        fit_seconds (training time; XGBoost on the GPU, the others on the CPU with n_jobs of make()),
        inference: predict_proba on the whole test matrix (already in memory), after an untimed
        warm-up call on 1,000 rows, repeated --timing-repeats times; seconds (median and all
        repeats), seconds per 1,000 flows, flows per second, device and n_jobs. XGBoost predicts on the
        GPU (booster on cuda, test matrix passed from host memory: XGBoost builds a DMatrix and copies it
        to the GPU, which is included in the time; its one-time warning about mismatched devices is
        expected), LightGBM (n_jobs=-1) and the random forest (n_jobs=2) on the CPU, as tree_protocol did.
        hardware (CPU, cores, RAM, GPU, library versions; CPU load, GPU utilisation and GPU memory in use
        when the process started: other jobs on the machine distort the timings, so run these fits while
        the machine is otherwise idle), train/test class counts,
        fit_load / inference.load_during_timing (runs of the revised script; older JSONs lack them): CPU use of
        OTHER processes during the fit and during the timed predict_proba calls (system-wide busy share minus
        this process's own CPU time, psutil) and GPU utilisation / memory in use just before - a direct
        record of how much competing work the timings contain,
        crosscheck (refits only): macro-F1 / balanced accuracy of the stored tree_protocol/main run,
        difference, share of identical predictions, whether the test rows are identical (y and sub,
        same order), tolerance 1e-4 for XGBoost and the random forest (LightGBM is multi-threaded and
        may differ slightly: the difference is only reported); number of differing predictions and how
        many of them are rows where the refit's two largest probabilities tie (n_tied_top2, TIE_EPS).
        Random forest: the fit is deterministic, but sklearn's predict_proba with n_jobs=2 adds the trees'
        probabilities in thread-completion order. Sums of fractional leaf probabilities (balanced sample
        weights) then differ in the last bit between calls, so the argmax of rows whose two largest
        probabilities are equal in exact arithmetic can flip from call to call - also in the stored
        tree_protocol run. The stored random-forest probabilities here are therefore summed in tree
        order (n_jobs=1: reproducible, untimed), and a refit counts as reproduced when it is within
        tolerance OR every differing prediction is such a tie (reproduced_up_to_ties). Inference is still
        timed with n_jobs=2 as in make().
  NPZ   y (int8), p (int8, argmax of the probabilities = predict()), proba (float16, n_test x 8, columns
        in CLASSES order), classes (str, = CLASSES), rows (int32 global row positions of the
        load_prepared() / flagged sample), sub (capture group, str). The test rows are in the order of
        tree_protocol/main. Inside a capture group the global row order is the time order (the flagged
        sample is time-sorted within each class), so tree_seeds_summary.py uses 'rows' to put the
        random-split test rows into time order for the block bootstrap.
  Same fields and names as deep_protocol_study.py, so tree and deep runs can be compared directly.

Output: results_2026_03_03/q1_revision/tree_seeds/runs/<Model>_<split>_<cleaning>_s<seed>.json + .npz
        (summary tables: experiments/tree_seeds_summary.py)
Resumable: a run is finished when its JSON exists (the npz is written first, the JSON last, both
atomically). --redo-incomplete also redoes finished runs whose JSON was written by the first version of
this script (no ROC AUC, no load record: the four XGBoost refits and LightGBM random/raw s42 of
2026-09-29 11:19-11:24); their predictions are deterministic and identical, only the JSON gains the
missing fields and new timings.
Memory: the feature matrix is read column by column (~1.2 GB); the training and test rows
are copied out and the full matrix is released before the last fit of a process, so with --max-fits 1
the peak is the training copy (~0.8 GB) plus the model (a random forest of this size takes several GB).
Run one fit per process (--max-fits 1 inside a PowerShell loop). --plan lists the runs and their status
without loading data.

Run (PowerShell, from the project folder). Fit times of tree_protocol:
XGBoost ~30 s, LightGBM 90-130 s, random forest 70-140 s; plus ~1 min loading and 1-2 min prediction and
timing, so about 2-5 min per loop iteration (28 iterations: ~1.5-2 h).
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\tree_seeds_proba.py --plan
  # 12 refits (seed 42) + 16 new fits (seeds 123, 2024), one fit per process
  1..28 | ForEach-Object { & $py experiments\\tree_seeds_proba.py --max-fits 1 2>&1 | Tee-Object -FilePath tree_seeds_proba.log -Append }
  # optional: probabilities for seeds 17 and 7 as well (16 more fits; average precision then has 5 seeds)
  1..16 | ForEach-Object { & $py experiments\\tree_seeds_proba.py --with-old-seeds --max-fits 1 2>&1 | Tee-Object -FilePath tree_seeds_proba.log -Append }
  # optional, best on an otherwise idle machine: redo the 5 runs of the first script version (ROC AUC, load record)
  & $py experiments\\tree_seeds_proba.py --plan --redo-incomplete
  1..5 | ForEach-Object { & $py experiments\\tree_seeds_proba.py --redo-incomplete --max-fits 1 2>&1 | Tee-Object -FilePath tree_seeds_proba.log -Append }
  & $py experiments\\tree_seeds_summary.py 2>&1 | Tee-Object -FilePath tree_seeds_summary.log
A loop iteration after all runs are finished only prints the plan and exits (no data is loaded).
"""
import argparse, gc, json, os, platform, subprocess, sys, time
from pathlib import Path

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             roc_auc_score)
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from deep_split_noise_study import kept_rows, metrics, splits  # noqa: E402
from extra_baselines import make  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
ROOT = HERE.parent / 'results_2026_03_03'
OUT = ROOT / 'q1_revision' / 'tree_seeds' / 'runs'
REF = ROOT / 'tree_protocol' / 'main'          # existing runs: XGBoost s42, LightGBM / RF s42, s17, s7
MODELS = ['XGBoost', 'LightGBM', 'RandomForest']
CONDITIONS = [('random', 'raw'), ('random', 'r1'), ('temporal', 'raw'), ('temporal', 'r1')]
REFIT_SEEDS = {'XGBoost': [42], 'LightGBM': [42], 'RandomForest': [42]}
NEW_SEEDS = {'LightGBM': [123, 2024], 'RandomForest': [123, 2024]}
OLD_SEEDS = {'LightGBM': [17, 7], 'RandomForest': [17, 7]}   # in tree_protocol/main, without probabilities
TOL = {'XGBoost': 1e-4, 'RandomForest': 1e-4, 'LightGBM': None}
K = len(CLASSES)
LABELS = list(range(K))
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']
WARMUP_ROWS = 1000
CHECK_ROWS = 20_000                             # predict() on these rows must equal argmax(predict_proba)
TIE_EPS = 1e-9                                  # top-2 probabilities closer than this count as a tie


def run_name(m, s, c, sd):
    return f'{m}_{s}_{c}_s{sd}'                 # same name as in tree_protocol/main


def plan(models, with_old):
    jobs = []
    for role, table in (('refit', REFIT_SEEDS), ('new', NEW_SEEDS)) + ((('old', OLD_SEEDS),) if with_old else ()):
        for m in models:
            for sd in table.get(m, []):
                for s, c in CONDITIONS:
                    jobs.append(dict(role=role, model=m, seed=sd, split=s, cleaning=c, name=run_name(m, s, c, sd)))
    return jobs


# ----------------------------------------------------------------------------- environment
def hardware():
    info = {'cpu': platform.processor(), 'logical_cpus': os.cpu_count(), 'platform': platform.platform()}
    try:                                        # readable CPU name on Windows (read-only registry query)
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as k:
            info['cpu'] = winreg.QueryValueEx(k, 'ProcessorNameString')[0].strip()
    except Exception:
        pass
    try:
        import psutil
        vm = psutil.virtual_memory()
        info.update(physical_cpus=psutil.cpu_count(logical=False), ram_total_gb=round(vm.total / 2**30, 1),
                    ram_available_gb_at_start=round(vm.available / 2**30, 1),
                    cpu_load_percent_at_start=psutil.cpu_percent(interval=0.5))   # other jobs distort timings
    except Exception:
        pass
    try:
        q = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader'],
                           capture_output=True, text=True, timeout=15)
        info['gpu'] = q.stdout.strip().splitlines()[0] if q.returncode == 0 and q.stdout.strip() else None
        q = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,memory.used', '--format=csv,noheader,nounits'],
                           capture_output=True, text=True, timeout=15)
        if q.returncode == 0 and q.stdout.strip():
            u, mem = [v.strip() for v in q.stdout.strip().splitlines()[0].split(',')[:2]]
            info.update(gpu_utilization_percent_at_start=float(u), gpu_memory_used_mib_at_start=float(mem))
    except Exception:
        info.setdefault('gpu', None)
    vers = {}
    for mod in ('numpy', 'sklearn', 'xgboost', 'lightgbm'):
        try:
            vers[mod] = __import__(mod).__version__
        except Exception:
            vers[mod] = None
    vers['python'] = platform.python_version()
    info['versions'] = vers
    return info


class LoadMeter:
    """Competing load during a timed interval (never raises; empty fields when unavailable).
    cpu_percent_other_processes = system-wide busy share (psutil.cpu_percent over the interval) minus this
    process's own CPU time / (wall time x logical CPUs); GPU utilisation and memory in use are read with
    nvidia-smi just BEFORE the interval (a subprocess inside the interval would itself be timed)."""

    def __init__(self):
        self.info, self.me = {}, None
        try:
            q = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,memory.used',
                                '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=15)
            if q.returncode == 0 and q.stdout.strip():
                u, mem = [v.strip() for v in q.stdout.strip().splitlines()[0].split(',')[:2]]
                self.info.update(gpu_utilization_percent_before=float(u), gpu_memory_used_mib_before=float(mem))
        except Exception:
            pass
        try:
            import psutil
            self.ps, self.me = psutil, psutil.Process()
            self.c0 = self.me.cpu_times()
            psutil.cpu_percent(None)                     # starts the system-wide measurement interval
            self.t0 = time.perf_counter()
        except Exception:
            self.me = None

    def stop(self):
        if self.me is not None:
            try:
                sys_pct = float(self.ps.cpu_percent(None))
                wall = time.perf_counter() - self.t0
                c1 = self.me.cpu_times()
                own = ((c1.user - self.c0.user) + (c1.system - self.c0.system)) / (wall * self.ps.cpu_count()) * 100
                self.info.update(seconds=round(wall, 2), cpu_percent_system=round(sys_pct, 1),
                                 cpu_percent_this_process=round(own, 1),
                                 cpu_percent_other_processes=round(max(0.0, sys_pct - own), 1))
            except Exception:
                pass
            self.me = None
        return self.info


def device_info(m, clf):
    if m == 'XGBoost':
        dev = str(clf.get_params().get('device') or 'cpu')
        return {'device': f'{dev} (GPU)' if dev.startswith('cuda') else dev, 'n_jobs': clf.get_params().get('n_jobs'),
                'note': 'booster on the GPU; the test matrix is passed from host memory, the copy is timed'
                        if dev.startswith('cuda') else 'booster on the CPU'}
    n_jobs = clf.get_params().get('n_jobs')
    return {'device': 'cpu', 'n_jobs': n_jobs,
            'threads_used': os.cpu_count() if n_jobs in (-1, None) else n_jobs}


# ----------------------------------------------------------------------------- scoring
def counts(v):
    return dict(zip(CLASSES, np.bincount(v, minlength=K).tolist()))


def per_class_ranking(y, proba):
    """One-vs-rest average precision and ROC AUC per class (None when the class, or every other class,
    is absent from the test set), as deep_protocol_study.py."""
    ap, auc = {}, {}
    for k in LABELS:
        pos = y == k
        ok = bool(pos.any() and (~pos).any())
        ap[CLASSES[k]] = float(average_precision_score(pos, proba[:, k])) if ok else None
        auc[CLASSES[k]] = float(roc_auc_score(pos, proba[:, k])) if ok else None
    return ap, auc


def _mean(vals):
    vals = [v for v in vals if v is not None]
    return float(np.mean(vals)) if vals else None


def score(y, p, sub, proba):
    r = metrics(y, p, sub)
    f1 = f1_score(y, p, average=None, labels=LABELS, zero_division=0)
    r['attack_macro_f1'] = float(f1[ATTACKS].mean())
    r['per_class_precision'] = dict(zip(CLASSES, precision_score(
        y, p, average=None, labels=LABELS, zero_division=0).round(4).tolist()))
    r['confusion'] = confusion_matrix(y, p, labels=LABELS).tolist()
    n = np.bincount(y, minlength=K)
    r['per_class_test_support'] = dict(zip(CLASSES, n.tolist()))
    r['per_class_prevalence'] = dict(zip(CLASSES, (n / n.sum()).round(6).tolist()))   # AP of a random ranking
    ap, auc = per_class_ranking(y, proba)
    r['per_class_ap'] = {c: None if v is None else round(v, 6) for c, v in ap.items()}
    r['macro_ap'] = _mean(ap.values())
    r['attack_macro_ap'] = _mean(ap[CLASSES[k]] for k in ATTACKS)
    ap16, _ = per_class_ranking(y, proba.astype(np.float16).astype(np.float32))
    r['macro_ap_float16'] = _mean(ap16.values())
    r['per_class_roc_auc'] = {c: None if v is None else round(v, 6) for c, v in auc.items()}
    r['macro_roc_auc'] = _mean(auc.values())
    return r


def crosscheck(m, name, r, y_te, sub_te, p, tie):
    """Compare a refit with the stored run of tree_protocol_study.py (same configuration).
    tie: rows whose two largest refit probabilities tie; tree_protocol_study.py predicted the random
    forest with n_jobs=2, whose summation order decides such ties, so differences there are expected."""
    fj, fn = REF / f'{name}.json', REF / f'{name}.npz'
    if not fj.exists():
        return None
    with open(fj) as fh:
        old = json.load(fh)
    out = {'reference_run': f'tree_protocol/main/{name}', 'reference_macro_f1': old['macro_f1'],
           'macro_f1_diff': r['macro_f1'] - old['macro_f1'],
           'reference_balanced_accuracy': old['balanced_accuracy'],
           'balanced_accuracy_diff': r['balanced_accuracy'] - old['balanced_accuracy'],
           'tolerance': TOL[m], 'same_test_rows': None, 'prediction_agreement': None}
    if fn.exists():
        # allow_pickle: the stored 'sub' of tree_protocol_study.py is an object array (own result file)
        with np.load(fn, allow_pickle=True) as d:
            same = len(d['y']) == len(y_te) and np.array_equal(d['y'], y_te.astype(np.int8))
            if same and 'sub' in d.files:
                same = np.array_equal(np.asarray(d['sub'], dtype=str), np.asarray(sub_te, dtype=str))
            out['same_test_rows'] = bool(same)
            if same:
                diff = d['p'].astype(np.int64) != p.astype(np.int64)
                out['prediction_agreement'] = float(1.0 - diff.mean())
                out['n_prediction_differences'] = int(diff.sum())
                out['n_differences_at_ties'] = int((diff & tie).sum())
                out['differences_only_at_ties'] = bool(diff.sum() == (diff & tie).sum())
    within = None if TOL[m] is None else bool(abs(out['macro_f1_diff']) <= TOL[m])
    only_ties = out.get('differences_only_at_ties')
    out['within_tolerance'] = within
    # reproduced = within the macro-F1 tolerance, or every differing prediction is a tie of the refit
    out['reproduced_up_to_ties'] = None if (within is None and only_ties is None) else bool(within or only_ties)
    return out


# ----------------------------------------------------------------------------- output
def _js(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


def save(path, r, y_te, p, proba, rows, sub_te):
    # npz first, JSON last, both atomically (tmp file + os.replace): the JSON marks the run as finished
    # (resume check), and a crash while a finished run is redone never leaves a truncated npz behind it
    tmp = path.with_name(path.name + '.npz.tmp')
    with open(tmp, 'wb') as fh:
        np.savez_compressed(fh, y=y_te.astype(np.int8), p=p.astype(np.int8),
                            proba=proba.astype(np.float16), rows=rows.astype(np.int32),
                            sub=np.asarray(sub_te, dtype=str),          # str: loads without pickle
                            classes=np.asarray(CLASSES, dtype=str))     # column order of proba
    os.replace(tmp, path.with_suffix('.npz'))
    tmp = path.with_name(path.name + '.json.tmp')
    with open(tmp, 'w') as f:
        json.dump(r, f, indent=1, default=_js)
    os.replace(tmp, path.with_suffix('.json'))


# ----------------------------------------------------------------------------- one run
def run_one(j, box, meta, flags, y, sub, repeats, hw, last_fit):
    """box = [X]: the full feature matrix in a list, so that it can be released before the last fit."""
    m, sd, s, c = j['model'], j['seed'], j['split'], j['cleaning']
    rows = kept_rows(flags, c)
    tr, _, te = splits(meta.iloc[rows].reset_index(drop=True), s)   # positions within `rows`
    tr, te = rows[tr], rows[te]                                      # -> global positions
    del rows
    ytr = y[tr]
    present = np.unique(ytr)                  # XGBoost needs labels 0..K'-1 (identity when all 8 are present)
    missing = [CLASSES[k] for k in LABELS if k not in present]
    if missing:
        print(f'  [warn] {j["name"]}: no training rows for {missing}', flush=True)
    Xtr, Xte = box[0][tr], box[0][te]         # contiguous copies (fancy indexing), made before any timer
    if last_fit:
        box[0] = None                         # the full matrix is not needed any more (~1.2 GB less at the peak)
        gc.collect()
    clf = make(m)
    clf.set_params(random_state=sd)
    w = compute_sample_weight('balanced', ytr)
    meter = LoadMeter()                       # competing load during the fit (measured outside the timer)
    t = time.time()
    clf.fit(Xtr, np.searchsorted(present, ytr), sample_weight=w)
    fit_s = time.time() - t
    fit_load = meter.stop()
    del Xtr, w; gc.collect()

    clf.predict_proba(Xte[:WARMUP_ROWS])      # untimed warm-up (GPU context, thread pools)
    times, P = [], None
    meter = LoadMeter()                       # competing load during the timed calls below
    for i in range(max(1, repeats)):
        t = time.perf_counter()
        Q = clf.predict_proba(Xte)
        times.append(time.perf_counter() - t)
        if P is None:
            P = np.asarray(Q)
        del Q
    inf_load = meter.stop()
    stored_how = 'first timed predict_proba call'
    if m == 'RandomForest' and clf.get_params().get('n_jobs') not in (None, 1):
        # sklearn adds the trees' probabilities in thread-completion order when n_jobs > 1: the sums differ
        # in the last bit between calls, and rows whose top-2 probabilities are equal in exact arithmetic
        # can flip. The stored probabilities are summed in tree order (n_jobs=1), which is reproducible;
        # the timing above keeps n_jobs of make().
        nj = clf.get_params()['n_jobs']
        P = None; gc.collect()
        clf.set_params(n_jobs=1)
        P = np.asarray(clf.predict_proba(Xte))
        chk = present[np.asarray(clf.predict(Xte[:CHECK_ROWS])).astype(int).ravel()]
        clf.set_params(n_jobs=nj)
        stored_how = 'predict_proba with n_jobs=1 (trees summed in order: reproducible), untimed'
    else:
        chk = present[np.asarray(clf.predict(Xte[:CHECK_ROWS])).astype(int).ravel()]
    del Xte; gc.collect()
    if P.shape[1] > 1:
        top2 = np.partition(P, P.shape[1] - 2, axis=1)[:, -2:]      # [second largest, largest]
        tie = np.abs(top2[:, 1] - top2[:, 0]) <= TIE_EPS               # predicted class is arbitrary here
        del top2
    else:
        tie = np.zeros(len(P), bool)
    p = present[P.argmax(1)].astype(np.int8)                         # = predict()
    predict_matches = bool(np.array_equal(chk, p[:CHECK_ROWS]))
    # native precision (float32 XGBoost, float64 LightGBM / random forest) for the average precision;
    # the npz stores float16. Classes without training rows keep probability 0.
    proba = np.zeros((len(te), K), P.dtype)
    proba[:, present] = P
    del P; gc.collect()

    y_te, sub_te = y[te], sub[te]
    r = score(y_te, p, sub_te, proba)
    sec = float(np.median(times))
    r.update({'role': j['role'], 'model': m, 'seed': sd, 'split': s, 'cleaning': c,
              'train_cleaning': c, 'test_cleaning': c, 'split_seed': 42 if s == 'random' else None,
              'n_train': int(len(tr)), 'n_test': int(len(te)),
              'train_class_counts': counts(ytr), 'test_class_counts': counts(y_te),
              'missing_train_classes': missing,
              'fit_seconds': round(fit_s, 2),
              'fit_load': fit_load,
              'inference': {'seconds': round(sec, 4), 'seconds_repeats': [round(v, 4) for v in times],
                            'seconds_per_1000_flows': round(1000 * sec / max(1, len(te)), 6),
                            'flows_per_second': round(len(te) / sec, 1) if sec > 0 else None,
                            'n_flows': int(len(te)), 'warmup_rows': WARMUP_ROWS, 'repeats': len(times),
                            'what': 'predict_proba on the whole test matrix (already in memory)',
                            'load_during_timing': inf_load,
                            **device_info(m, clf)},
              'predict_equals_argmax_proba_first_rows': predict_matches,
              'stored_predictions': stored_how,
              'n_tied_top2': int(tie.sum()),               # rows whose two largest probabilities tie (<= TIE_EPS)
              'tie_eps': TIE_EPS,
              'model_params': {k: (v if not isinstance(v, float) or np.isfinite(v) else str(v))   # NaN -> 'nan'
                               for k, v in clf.get_params().items()
                               if isinstance(v, (int, float, str, bool)) or v is None},
              'hardware': hw})
    r['crosscheck'] = crosscheck(m, j['name'], r, y_te, sub_te, p, tie) if j['role'] in ('refit', 'old') else None
    save(OUT / j['name'], r, y_te, p, proba, te, sub_te)
    del clf, proba; gc.collect()
    return r


def finished(name, redo_incomplete=False):
    """A run is finished when its JSON exists; with redo_incomplete, a JSON of the first script version
    (without the ROC AUC fields) counts as unfinished, so that run is fitted again."""
    f = OUT / f'{name}.json'
    if not f.exists():
        return False
    if not redo_incomplete:
        return True
    try:
        with open(f) as fh:
            return 'macro_roc_auc' in json.load(fh)
    except Exception:                         # unreadable JSON: redo
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--models', nargs='+', choices=MODELS, default=MODELS)
    ap.add_argument('--with-old-seeds', action='store_true',
                    help='also refit LightGBM / RandomForest seeds 17 and 7 (probabilities for all five seeds)')
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit). A random forest of this size takes several GB, '
                         'so run with 1 inside a PowerShell loop: every fit then starts in a fresh process.')
    ap.add_argument('--timing-repeats', type=int, default=3,
                    help='timed predict_proba calls on the whole test set (the median is reported)')
    ap.add_argument('--plan', action='store_true', help='only list the runs and their status')
    ap.add_argument('--redo-incomplete', action='store_true',
                    help='also redo finished runs written by the first script version (no ROC AUC / load record)')
    a = ap.parse_args()

    jobs = plan(a.models, a.with_old_seeds)
    todo = [j for j in jobs if not finished(j['name'], a.redo_incomplete)]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if a.plan:
        for j in jobs:
            st = 'done' if j not in todo else ('redo' if (OUT / f'{j["name"]}.json').exists() else 'todo')
            print(f'  {st:4s}  {j["role"]:5s}  {j["name"]}')
        return
    if not todo:
        print('[DONE] all runs finished', flush=True)
        return
    OUT.mkdir(parents=True, exist_ok=True)
    hw = hardware()
    X, meta, flags = load_prepared()          # column by column: peak ~1.6 GB instead of ~3.5 GB
    box = [X]                                 # released before the last fit of this process
    del X
    meta = meta.reset_index(drop=True)        # RangeIndex: split positions = global row positions
    y = meta['y'].to_numpy()
    sub = meta['sub'].astype(str).to_numpy()
    n_run = len(todo) if not a.max_fits else min(a.max_fits, len(todo))
    done = 0
    for j in todo[:n_run]:
        t0 = time.time()
        r = run_one(j, box, meta, flags, y, sub, a.timing_repeats, hw, last_fit=(done + 1 == n_run))
        done += 1
        inf = r['inference']
        print(f'[{done}/{len(todo)}] {j["role"]:5s} {j["model"]:12s} s{j["seed"]:<4d} {j["split"]:8s} {j["cleaning"]:3s} '
              f'macro-F1={r["macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} macro-AP={r["macro_ap"]:.4f} '
              f'fit={r["fit_seconds"]:.0f}s infer={inf["seconds"]:.2f}s ({inf["seconds_per_1000_flows"] * 1000:.3f} ms/1k flows) '
              f'[{(time.time() - t0) / 60:.1f} min]', flush=True)
        ld = inf.get('load_during_timing') or {}
        if ld:
            print(f'  [load] other processes during the timed inference: CPU {ld.get("cpu_percent_other_processes")}%, '
                  f'GPU before {ld.get("gpu_utilization_percent_before")}%; during the fit: CPU '
                  f'{(r.get("fit_load") or {}).get("cpu_percent_other_processes")}%', flush=True)
        ck = r.get('crosscheck')
        if ck:
            if ck.get('n_prediction_differences') == 0:
                flag = ' OK (identical predictions)'
            elif ck['within_tolerance']:
                flag = ' OK'
            elif ck.get('differences_only_at_ties'):
                flag = ' OK (all differing predictions are ties of the refit)'
            elif ck['within_tolerance'] is None:
                flag = ' (reported only)'
            else:
                flag = ' [WARN] outside tolerance'
            agr = ck['prediction_agreement']
            ties = ('' if ck.get('n_prediction_differences') is None else
                    f' differing={ck["n_prediction_differences"]} (at ties {ck["n_differences_at_ties"]})')
            print(f'  [check] vs {ck["reference_run"]}: macro-F1 diff={ck["macro_f1_diff"]:+.6f} '
                  f'same test rows={ck["same_test_rows"]} identical predictions='
                  f'{"n/a" if agr is None else f"{agr:.6f}"}{ties}{flag}', flush=True)
        if not r['predict_equals_argmax_proba_first_rows']:
            print('  [WARN] predict() differs from argmax(predict_proba) on the first rows', flush=True)
    left = len(todo) - done
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)


if __name__ == '__main__':
    main()
