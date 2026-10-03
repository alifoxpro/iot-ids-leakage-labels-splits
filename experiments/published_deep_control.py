# -*- coding: utf-8 -*-
r"""
published_deep_control.py
=========================
Identifier NECESSITY control in the published setting, repeated with the published model family
(reviewer points narr-00: "repeat with one deep model", and expe-07: "no reimplementation of the
published 1-D CNN").

published_protocol_control.py answered the necessity question with XGBoost. This script trains a
Hossain-style 1-D CNN on exactly the same table, split and feature sets, so that the F0 -> FT jump
(identifier-free vs. + label-encoded timestamp) can be compared across model families.

Data, split and features (all taken from published_protocol_control.py; nothing is rebuilt):
  table      results_2026_03_03/q1_revision/published_control/data.parquet (3,243,755 flows, built by
             published_protocol_control.py --build-only): classes Benign, BruteForce, DDoS, DoS, Mirai,
             Spoofing, SQL Injection, XSS; no de-duplication; DoS / DDoS thinned and capped.
             Read one column at a time into float32 with published_protocol_control.load (NaN/inf -> 0);
             only the columns of the runs of the current process are read.
  split      stratified random 80/20, seed 42 -- the same call as published_protocol_control.main, so the
             test rows are those of the XGBoost runs (checked against their .npz: idx and y).
             A stratified 10% of the training part (seed 42) is held out for early stopping (Keras'
             validation_split=0.1, but stratified); the CNN is fitted on the other 90%.
  features   F0  81 flow features
             FT  F0 + Timestamp (raw string label-encoded in sorted order: column le_timestamp)
             FA  F0 + all seven identifiers (optional: --sets F0 FT FA)
             For the CNN the ORDER matters. --order ids-last (default): the 81 flow features in the column
             order of the XGBoost control (FEATS), then the identifier columns in CSV order (Flow ID, Src IP,
             Src Port, Dst IP, Dst Port, Protocol, Timestamp) -- the XGBoost control's matrix. Every flow
             feature keeps its position in F0, FT and FA, so with --pad full (below) F0 is exactly FT with
             the timestamp input held at its training mean (0), and the same seed gives both the same
             initial weights and batch order: a paired ablation of the timestamp column.
             --order ids-first (sensitivity, run-name suffix _idsfirst): identifiers first, where a published
             pipeline that label-encodes the categorical CSV columns in place would leave them; the flow
             features then shift by 1 (FT) or 7 (FA) positions relative to F0.
  scaling    per-column mean / population SD of the whole training part (80%; SD 0 -> 1), i.e. sklearn's
             StandardScaler fitted on X_train before the validation split, applied in place to all rows.
Model (Hossain 2025 style; the layer stack of deep_protocol_study.CNN1DHossainNet, same module names):
  input (n_features, 1) -> Conv1d(1, 64, 3) + ReLU + MaxPool1d(2) -> Conv1d(64, 128, 3) + ReLU + MaxPool1d(2)
  -> Flatten -> Dense 128 + ReLU -> Dropout 0.5 -> Dense 8 (softmax inside the loss / at prediction).
  'valid' convolutions and floor max-pooling (Keras defaults). Blind spot of that stack: with 81 inputs
  the last three positions never reach the dense layer (81 -> 79 -> 39 -> 37 -> 18 drops inputs 78-80,
  i.e. feat_min, feat_max, feat_range), with 82 inputs every position does, with 88 the last two do not
  (checked with input gradients). Unpadded, FT - F0 would therefore mix the timestamp effect with three
  flow features that become visible. --pad full (default) appends zeros (= the training mean after
  standardisation) inside the network up to the shortest length at which every real input reaches the
  dense layer: F0 81 -> 82, FT 82 -> 82, FA 88 -> 90, so F0 and FT have the same network (flatten 128 x 19)
  and (with --order ids-last) differ only in the timestamp column. --pad none keeps the strict unpadded
  stack (run-name suffix _nopad; the layer stack of deep_protocol_study.CNN1DHossainNet for 81 inputs, and
  with --init torch also its initialisation): F0 then
  loses feat_min, feat_max and feat_range, FT sees all 82 inputs, and FA (88) loses its last two inputs
  (Protocol and Timestamp with ids-last, feat_max and feat_range with ids-first). The JSON lists the inputs
  that do not reach the dense layer (none with --pad full).
  --init keras (default): Glorot-uniform weights, zero biases (Keras defaults, the likely framework of the
  published model); --init torch: PyTorch default initialisation (as deep_protocol_study.py).
Training (the published setting, NOT the benchmark's deep-model protocol):
  Adam (lr 1e-3, eps 1e-7 as in Keras), batch 1024, a fresh random permutation every epoch, at most 20
  epochs, early stopping on the validation loss with patience 3 (min_delta 0), the weights of the best
  epoch restored. Unweighted cross-entropy (the published setting used no class weights or resampling);
  --weightings balanced adds runs with compute_class_weight('balanced') on the fitted part (training and
  validation loss both weighted, as src/stage3_ml_models). Float32 on the GPU: no AMP, no gradient
  clipping, no LR schedule. Batches come from a DataLoader over index tensors: the standardised matrix is
  held in RAM once and each batch gathers its rows (no per-run copy of the training matrix).
  Non-default --order / --pad / --init / --epochs / --patience / --batch / --lr add a suffix to the run
  name (e.g. _idsfirst, _nopad, _torchinit, _e30), so sensitivity runs never overwrite or shadow the main
  runs.
Reported per run (JSON): accuracy, balanced accuracy, macro-F1, weighted F1, macro precision / recall,
per-class F1 / recall / precision, per-class average precision and ROC AUC (one-vs-rest, from the
softmax outputs), per-capture-group recall, confusion matrix (rows = true), class counts, the share of
test flows whose 76 raw values occur in the training part and the scores on the test flows with /
without such a duplicate (published_protocol_control.dup_report / subset_scores; training part = the
full 80%), training history (loss, accuracy, validation loss / accuracy / macro-F1, seconds per epoch),
epochs run, best epoch, whether early stopping fired, fit time, data-preparation time, inference time
(median of --timing-repeats passes over the whole test set after an untimed warm-up chunk; single-flow
latency), peak GPU memory, parameter count, hardware, whether the test rows equal those of the XGBoost
control, and the XGBoost result of the same feature set and weighting for reference.
Test predictions (.npz): y (int8), p (int8, argmax), proba (float16, n_test x 8, columns in class
order), sub (capture group, str), idx (int32 row in data.parquet) -- the keys of the XGBoost control
plus proba (named as in deep_protocol_study.py).

Output: results_2026_03_03/q1_revision/published_deep/
  CNN1D_<set>_<weighting>_s<seed>[<variant>].json / .npz     one per run
  summary.csv      every finished run in the folder, with the XGBoost reference (--summary; also after
                   the last run of a process). --summary also prints mean / SD / min / max over model
                   seeds where a cell has several, and the identifier effect (set minus F0) for the CNN
                   and for XGBoost.
Resumable: a run is finished when its JSON exists (npz first, JSON last and atomically); finished runs
are skipped. --plan lists the runs and their status without loading data.
Memory: ~1.1 GB for the float32 matrix (3.24M x 81-82) + ~0.2 GB for labels, hashes and indices, plus
the CUDA context (~1-2 GB commit charge); GPU < 1 GB. The whole table is never loaded at once.
Time (RTX 5070 laptop GPU): data preparation ~1-2 min, then roughly 10-25 s per epoch, so about
3-10 min per fit (at most 20 epochs); see the epoch lines of the log.

Run (PowerShell, from the project folder; data.parquet must exist -- it does once
published_protocol_control.py has run; otherwise run that script with --build-only first):
  Set-Location "<project folder>"
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\published_deep_control.py --plan
  # main runs: F0 and FT, published weighting (none), seed 42 -- one fit per process
  1..2 | ForEach-Object { & $py experiments\published_deep_control.py --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append }
  & $py experiments\published_deep_control.py --summary 2>&1 | Tee-Object -FilePath published_deep_summary.log
Optional extensions (each resumable the same way; --summary always lists every finished run):
  # all seven identifiers
  & $py experiments\published_deep_control.py --sets FA --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append
  # two more model seeds for F0 and FT (4 fits)
  1..4 | ForEach-Object { & $py experiments\published_deep_control.py --seeds 17 7 --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append }
  # class-weighted loss, as the balanced XGBoost control (2 fits)
  1..2 | ForEach-Object { & $py experiments\published_deep_control.py --weightings balanced --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append }
  # strict unpadded stack (F0 then sees 78 of its 81 features; 2 fits)
  1..2 | ForEach-Object { & $py experiments\published_deep_control.py --pad none --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append }
  # identifiers placed first, as an in-place label-encoding pipeline would leave them (1 fit: F0 has no
  # identifier, so the order does not change it and its main run CNN1D_F0_none_s42 is reused as the baseline)
  & $py experiments\published_deep_control.py --order ids-first --max-fits 1 2>&1 | Tee-Object -FilePath published_deep.log -Append
  & $py experiments\published_deep_control.py --summary 2>&1 | Tee-Object -FilePath published_deep_summary.log
If a process dies (CUDA error, out of memory), run the same loop again: finished runs are skipped.
"""
import argparse, gc, json, os, platform, subprocess, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, Dataset, Sampler

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import published_protocol_control as ppc  # noqa: E402  (importing it also sets the class names of metrics())
from pilot_temporal_split import FEATS, SEED  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'published_deep'
XGB_DIR = ppc.OUT                                          # published_protocol_control results (read only)
CLASSES = ppc.PUB_CLASSES
K = len(CLASSES)
LABELS = list(range(K))
FSETS = ppc.FSETS                                          # F0 / FT / FA: (extra columns, description)
WEIGHTINGS = {'none': 'no class weights (the published setting used no resampling)',
              'balanced': "compute_class_weight('balanced') on the fitted part, in the training and "
                          "validation loss"}
INITS = {'keras': 'Glorot-uniform weights, zero biases (Keras defaults)',
         'torch': 'PyTorch default initialisation (as deep_protocol_study.CNN1DHossainNet)'}
PADS = {'full': 'zeros appended inside the network up to the shortest length at which every input reaches the '
                'dense layer',
        'none': "no padding: the strict 'valid' stack (some trailing inputs may not reach the dense layer)"}
ORDERS = {'ids-last': '81 flow features (FEATS order, as the XGBoost control matrix), then the identifier columns in '
                      'CSV order; every flow feature keeps its input position across F0 / FT / FA',
          'ids-first': 'identifier columns first, in CSV order (where in-place label encoding of the CSV leaves '
                       'them), then the 81 flow features'}
DEFAULTS = {'order': 'ids-last', 'pad': 'full', 'init': 'keras', 'epochs': 20, 'patience': 3, 'batch': 1024,
            'lr': 1e-3}
ADAM_EPS = 1e-7                                            # Keras default
TEST_FRAC, VAL_FRAC = 0.2, 0.1
PREDICT_CHUNK = 8192                                       # as src/stage3_ml_models.PREDICT_CHUNK
SCALE_CHUNK = 100_000                                      # ~0.2 GB of float64 temporaries per chunk (88 columns)
LAT_WARMUP, LAT_CALLS = 10, 200
PUBLISHED_ACCURACY = 0.9912        # Hossain (2025), 1-D CNN, multi-class accuracy on CIC IoT-DIAD 2024


def feature_order(s, order):
    """Model columns of feature set s, in input order."""
    ids = [c for c in ppc.ID_COLS if c in FSETS[s][0]]      # CSV order
    return ids + FEATS if order == 'ids-first' else FEATS + ids


def variant_tag(a, s=None):
    """Run-name suffix for non-default training settings ('' for the main runs). The order suffix is added only
    for feature sets with identifier columns (s=None: always): F0 is the same network in either order."""
    parts = []
    if a.order != DEFAULTS['order'] and (s is None or FSETS[s][0]):
        parts.append(a.order.replace('-', ''))              # 'idsfirst'
    if a.pad != DEFAULTS['pad']:
        parts.append(f'{a.pad}pad' if a.pad != 'none' else 'nopad')
    if a.init != DEFAULTS['init']:
        parts.append(f'{a.init}init')
    if a.epochs != DEFAULTS['epochs']:
        parts.append(f'e{a.epochs}')
    if a.patience != DEFAULTS['patience']:
        parts.append(f'p{a.patience}')
    if a.batch != DEFAULTS['batch']:
        parts.append(f'b{a.batch}')
    if a.lr != DEFAULTS['lr']:
        parts.append(f'lr{a.lr:g}')
    return ''.join('_' + p for p in parts)


def run_name(s, w, seed, tag=''):
    return f'CNN1D_{s}_{w}_s{seed}{tag}'


def _js(o):
    """JSON fallback for numpy scalars / arrays (a finished fit must never fail at the last step)."""
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(type(o))


def write_json(path, r):
    """Via a temporary file: an interrupted process never leaves a truncated JSON (= finished run)."""
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(json.dumps(r, indent=1, default=_js))
    os.replace(tmp, path)


# ----------------------------------------------------------------------------- data
def split_rows(y):
    """Test part exactly as published_protocol_control.main; validation part from the training part."""
    tr, te = train_test_split(np.arange(len(y)), test_size=TEST_FRAC, stratify=y, random_state=SEED)
    fit, va = train_test_split(tr, test_size=VAL_FRAC, stratify=y[tr], random_state=SEED)
    return tr, fit, va, te


def standardise(X, rows, chunk=SCALE_CHUNK):
    """In place: X = (X - mean) / sd with the per-column mean and population SD of X[rows] (StandardScaler).
    Two passes with float64 accumulators (no cancellation); only one chunk is copied at a time."""
    r = np.sort(rows)                                       # memory order: faster gathers
    k, n = X.shape[1], len(r)
    s = np.zeros(k)
    for i in range(0, n, chunk):
        s += X[r[i:i + chunk]].sum(0, dtype=np.float64)
    mu = s / n
    ss = np.zeros(k)
    for i in range(0, n, chunk):
        d = X[r[i:i + chunk]].astype(np.float64) - mu
        ss += np.einsum('ij,ij->j', d, d)
        del d
    sd = np.sqrt(ss / n)
    sd[~(sd > 0)] = 1.0                                     # constant column -> scale 1 (as sklearn)
    mu32, sd32 = mu.astype(np.float32), sd.astype(np.float32)
    for i in range(0, len(X), chunk):
        X[i:i + chunk] -= mu32
        X[i:i + chunk] /= sd32
    return mu, sd


def gather(X_t, r, cols):
    """Rows r (LongTensor) of the shared CPU matrix, optionally only the feature columns `cols`."""
    xb = X_t.index_select(0, r)
    return xb if cols is None else xb.index_select(1, cols)


class PermutationBatches(Sampler):
    """Keras-style shuffling: a fresh permutation of the fitted positions every epoch, cut into batches.
    Yields LongTensors (no Python list of millions of ints per epoch)."""

    def __init__(self, n, batch, generator):
        self.n, self.batch, self.g = n, batch, generator

    def __len__(self):
        return (self.n + self.batch - 1) // self.batch

    def __iter__(self):
        perm = torch.randperm(self.n, generator=self.g)
        for i in range(0, self.n, self.batch):
            yield perm[i:i + self.batch]


class RowBatches(Dataset):
    """Map-style dataset whose items are whole batches: a LongTensor of positions in `idx` -> (X rows, y)."""

    def __init__(self, X_t, y_t, idx_t, cols=None):
        self.X, self.y, self.idx, self.cols = X_t, y_t, idx_t, cols

    def __len__(self):
        return len(self.idx)

    def __getitem__(self, pos):
        r = self.idx[pos]
        return gather(self.X, r, self.cols), self.y.index_select(0, r)


# ----------------------------------------------------------------------------- model
def reaching_inputs(n):
    """Input positions (of a length-n sequence) that reach the dense layer: two 'valid' k=3 convolutions, each
    followed by floor max-pooling of 2. Matches the input-gradient test (81 -> inputs 78-80 are lost)."""
    p2 = ((n - 2) // 2 - 2) // 2                            # length after the second pooling
    pool1 = {j + d for j in range(2 * p2) for d in range(3)}
    conv1 = {2 * q + e for q in pool1 for e in range(2)}
    return {j + d for j in conv1 for d in range(3)}


def padded_length(n):
    """Shortest length >= n at which every one of the n real inputs reaches the dense layer (81 -> 82, 88 -> 90)."""
    m = n
    while not set(range(n)) <= reaching_inputs(m):
        m += 1
    return m


class HossainCNN1D(nn.Module):
    """Conv1d(1,64,3)+ReLU+MaxPool(2) -> Conv1d(64,128,3)+ReLU+MaxPool(2) -> Dense 128 + ReLU -> Dropout 0.5
    -> Dense n_classes. Same modules and names as deep_protocol_study.CNN1DHossainNet; with pad='full' the input
    is right-padded with zeros (inside forward) so that every input reaches the dense layer."""

    def __init__(self, n_features, n_classes, init='keras', pad='full'):
        super().__init__()
        self.n_pad = padded_length(n_features) - n_features if pad == 'full' else 0
        n = n_features + self.n_pad
        length = ((n - 2) // 2 - 2) // 2                    # 81 -> 18, 82 -> 19, 88 -> 20, 90 -> 21
        self.features = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3), nn.ReLU(), nn.MaxPool1d(2),
            nn.Conv1d(64, 128, kernel_size=3), nn.ReLU(), nn.MaxPool1d(2))
        self.classifier = nn.Sequential(
            nn.Flatten(), nn.Linear(128 * length, 128), nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(128, n_classes))
        if init == 'keras':
            for m in self.modules():
                if isinstance(m, (nn.Conv1d, nn.Linear)):
                    nn.init.xavier_uniform_(m.weight)       # Keras glorot_uniform (same fans for Conv1D)
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        x = x.unsqueeze(1)
        if self.n_pad:
            x = F.pad(x, (0, self.n_pad))                   # zeros on the right (= training mean)
        return self.classifier(self.features(x))


def macro_f1_from_pred(y, p):
    cm = np.bincount(y * K + p, minlength=K * K).reshape(K, K).astype(float)
    tp, row, col = np.diagonal(cm), cm.sum(1), cm.sum(0)
    with np.errstate(divide='ignore', invalid='ignore'):
        prec = np.where(col > 0, tp / col, 0.0)
        rec = np.where(row > 0, tp / row, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    return float(f1.mean())


def evaluate(net, X_t, y_t, idx_t, cols, w, device):
    """(weighted mean) cross-entropy, accuracy and macro-F1 on the rows idx_t, fp32, chunks of PREDICT_CHUNK."""
    net.eval()
    tot, den = 0.0, 0.0
    pred = np.empty(len(idx_t), np.int64)
    with torch.no_grad():
        for i in range(0, len(idx_t), PREDICT_CHUNK):
            r = idx_t[i:i + PREDICT_CHUNK]
            xb = gather(X_t, r, cols).to(device, non_blocking=True)
            yb = y_t.index_select(0, r).to(device, non_blocking=True)
            out = net(xb)
            tot += float(F.cross_entropy(out, yb, weight=w, reduction='sum'))
            den += float(w[yb].sum()) if w is not None else len(yb)
            pred[i:i + len(r)] = out.argmax(1).cpu().numpy()
    yv = y_t.index_select(0, idx_t).numpy()
    return tot / den, float((pred == yv).mean()), macro_f1_from_pred(yv, pred)


def train(net, X_t, y_t, fit_t, va_t, cols, w, device, a, seed):
    """Keras-style fit: shuffled mini-batches, early stopping on the validation loss, best weights restored."""
    g = torch.Generator().manual_seed(seed)
    dl = DataLoader(RowBatches(X_t, y_t, fit_t, cols), sampler=PermutationBatches(len(fit_t), a.batch, g),
                    batch_size=None, num_workers=0, pin_memory=device.type == 'cuda')
    opt = torch.optim.Adam(net.parameters(), lr=a.lr, eps=ADAM_EPS)
    hist = {k: [] for k in ('train_loss', 'train_acc', 'val_loss', 'val_acc', 'val_macro_f1', 'epoch_seconds')}
    best, best_ep, best_state, wait, stopped, nonfinite = float('inf'), 0, None, 0, False, 0
    for ep in range(1, a.epochs + 1):
        t = time.time()
        net.train()
        # epoch loss = the same (weighted) mean as the batch loss: sum(w_i * l_i) / sum(w_i)
        tl = torch.zeros((), device=device); tw = torch.zeros((), device=device)
        tc = torch.zeros((), device=device, dtype=torch.long); n = 0
        for xb, yb in dl:
            xb, yb = xb.to(device, non_blocking=True), yb.to(device, non_blocking=True)
            opt.zero_grad(set_to_none=True)
            out = net(xb)
            loss = F.cross_entropy(out, yb, weight=w)
            loss.backward()
            opt.step()
            bw = w[yb].sum() if w is not None else float(len(yb))
            tl += loss.detach() * bw; tw += bw; tc += (out.detach().argmax(1) == yb).sum(); n += len(yb)
        vl, vacc, vf1 = evaluate(net, X_t, y_t, va_t, cols, w, device)
        nonfinite += int(not np.isfinite(vl))
        hist['train_loss'].append(round(float(tl / tw), 6)); hist['train_acc'].append(round(float(tc) / n, 6))
        hist['val_loss'].append(round(vl, 6)); hist['val_acc'].append(round(vacc, 6))
        hist['val_macro_f1'].append(round(vf1, 6)); hist['epoch_seconds'].append(round(time.time() - t, 1))
        improved = vl < best                                # Keras EarlyStopping, min_delta 0
        if improved:
            best, best_ep, wait = vl, ep, 0
            best_state = {k: v.detach().cpu().clone() for k, v in net.state_dict().items()}
        else:
            wait += 1
            stopped = wait >= a.patience
        print(f'    epoch {ep:2d}/{a.epochs}  loss={hist["train_loss"][-1]:.4f}  acc={hist["train_acc"][-1]:.4f}  '
              f'val_loss={vl:.4f}  val_acc={vacc:.4f}  val_F1={vf1:.4f}  ({hist["epoch_seconds"][-1]:.0f} s)'
              f'{"  *" if improved else ""}{"  [early stop]" if stopped else ""}', flush=True)
        if stopped:
            break
    if best_state is not None:                              # None only if every validation loss was NaN
        net.load_state_dict(best_state)
    else:
        print('    [warning] no finite validation loss: the last weights are evaluated', flush=True)
        best_ep = len(hist['train_loss'])
    net.eval()
    info = {'epochs_run': len(hist['train_loss']), 'best_epoch': best_ep, 'stopped_early': stopped,
            'val_loss_best': hist['val_loss'][best_ep - 1], 'val_macro_f1_selected': hist['val_macro_f1'][best_ep - 1],
            'val_macro_f1_max': max(hist['val_macro_f1']), 'epochs_with_nonfinite_val_loss': nonfinite,
            'hit_epoch_cap': (not stopped) and len(hist['train_loss']) == a.epochs}
    return hist, info


def timed_predict(net, X_t, te_t, cols, device, repeats):
    """Softmax outputs of the test rows + wall-clock timing: one untimed warm-up chunk, then `repeats` full
    passes (median). A pass = host gather of the standardised rows + transfer + forward + softmax + copy back."""
    net.eval()
    cuda = device.type == 'cuda'
    sync = torch.cuda.synchronize if cuda else (lambda: None)
    n = len(te_t)
    proba = np.empty((n, K), np.float32)

    def one_pass():
        with torch.no_grad():
            for i in range(0, n, PREDICT_CHUNK):
                xb = gather(X_t, te_t[i:i + PREDICT_CHUNK], cols).to(device, non_blocking=True)
                proba[i:i + len(xb)] = torch.softmax(net(xb), 1).cpu().numpy()

    with torch.no_grad():
        net(gather(X_t, te_t[:PREDICT_CHUNK], cols).to(device))
    sync()
    secs = []
    for _ in range(max(1, repeats)):
        sync(); t = time.perf_counter()
        one_pass()
        sync(); secs.append(time.perf_counter() - t)
    lat = []
    with torch.no_grad():
        for j in range(LAT_WARMUP + LAT_CALLS):
            xb = gather(X_t, te_t[j % n:j % n + 1], cols)
            t = time.perf_counter()
            int(net(xb.to(device)).argmax(1).item())         # .item() synchronises
            lat.append(time.perf_counter() - t)
    sec = float(np.median(secs))
    ms = 1000 * np.asarray(lat[LAT_WARMUP:])
    inf = {'seconds': round(sec, 4), 'seconds_repeats': [round(v, 4) for v in secs],
           'seconds_per_1000_flows': round(1000 * sec / max(1, n), 6),
           'flows_per_second': round(n / sec, 1) if sec > 0 else None,
           'latency_one_flow_ms_median': round(float(np.median(ms)), 4),
           'latency_one_flow_ms_p95': round(float(np.percentile(ms, 95)), 4),
           'n_flows': int(n), 'batch': PREDICT_CHUNK, 'repeats': len(secs),
           'warmup': f'one untimed chunk of {PREDICT_CHUNK} flows', 'precision': 'fp32',
           'device': torch.cuda.get_device_name(0) if cuda else 'cpu',
           'what': 'gather of the already standardised rows (CPU) + host-to-device copy + forward + softmax + '
                   'copy back, whole test set; standardisation excluded (done once, in place); single-flow '
                   'latency = transfer + forward + argmax of one row'}
    return proba, inf


# ----------------------------------------------------------------------------- scores
def score(yt, p, proba, st, has_dup, dup):
    r = ppc.metrics(yt, p, st)                              # accuracy, BA, macro-F1, per-class F1 / recall, per group
    ap, auc = {}, {}
    for k, c in enumerate(CLASSES):
        m = yt == k
        ok = bool(m.any() and (~m).any())
        ap[c] = round(float(average_precision_score(m, proba[:, k])), 6) if ok else None
        auc[c] = round(float(roc_auc_score(m, proba[:, k])), 6) if ok else None
    mean = lambda d: float(np.mean([v for v in d.values() if v is not None])) if any(
        v is not None for v in d.values()) else None
    n = np.bincount(yt.astype(np.int64), minlength=K)
    r.update({
        'weighted_f1': float(f1_score(yt, p, labels=LABELS, average='weighted', zero_division=0)),
        'macro_precision': float(precision_score(yt, p, labels=LABELS, average='macro', zero_division=0)),
        'macro_recall': float(recall_score(yt, p, labels=LABELS, average='macro', zero_division=0)),
        'per_class_precision': dict(zip(CLASSES, precision_score(yt, p, labels=LABELS, average=None,
                                                                 zero_division=0).round(4).tolist())),
        'per_class_test_support': dict(zip(CLASSES, n.tolist())),
        'per_class_prevalence': dict(zip(CLASSES, (n / max(1, n.sum())).round(6).tolist())),  # AP of a random ranking
        'per_class_average_precision': ap, 'macro_average_precision': mean(ap),
        'per_class_roc_auc': auc, 'macro_roc_auc': mean(auc),
        'labels': CLASSES,
        'confusion': confusion_matrix(yt, p, labels=LABELS).tolist(),
        'test_duplicates': dup,
        'test_subsets': {'with_train_duplicate': ppc.subset_scores(yt, p, has_dup),
                         'without_train_duplicate': ppc.subset_scores(yt, p, ~has_dup)}})
    return r


def xgb_reference(s, w):
    f = XGB_DIR / f'{s}_{w}.json'
    if not f.exists():
        return None
    with open(f, encoding='utf-8') as fh:
        x = json.load(fh)
    return {'run': x['run'], 'accuracy': x['accuracy'], 'balanced_accuracy': x['balanced_accuracy'],
            'macro_f1': x['macro_f1'], 'fit_seconds': x.get('fit_seconds'),
            'macro_f1_without_train_duplicate': x['test_subsets']['without_train_duplicate'].get('macro_f1'),
            'per_class_f1': x.get('per_class_f1')}


def same_test_rows(te, yt):
    """True when every XGBoost control .npz has the same test rows in the same order (idx) with the same labels
    (y); False if any differs; None when there is no such .npz."""
    same = None
    for f in sorted(XGB_DIR.glob('*.npz')):
        with np.load(f) as z:
            if 'idx' in z.files:
                ok = bool(np.array_equal(z['idx'].astype(np.int64), te)
                          and ('y' not in z.files or np.array_equal(z['y'].astype(np.int64), yt.astype(np.int64))))
                same = ok if same is None else (same and ok)
    return same


def hardware(device):
    info = {'device_used': str(device), 'cpu': platform.processor(), 'logical_cpus': os.cpu_count(),
            'platform': platform.platform()}
    try:                                                    # readable CPU name (read-only registry query)
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as k:
            info['cpu'] = winreg.QueryValueEx(k, 'ProcessorNameString')[0].strip()
    except Exception:
        pass
    try:
        import psutil
        vm = psutil.virtual_memory()
        info.update(ram_total_gb=round(vm.total / 2**30, 1), ram_available_gb_at_start=round(vm.available / 2**30, 1))
    except Exception:
        pass
    info['gpu'] = torch.cuda.get_device_name(0) if device.type == 'cuda' else None
    try:
        q = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader'],
                           capture_output=True, text=True, timeout=15)
        if q.returncode == 0 and q.stdout.strip():
            info['gpu_smi'] = q.stdout.strip().splitlines()[0]
    except Exception:
        pass
    import sklearn
    info['versions'] = {'python': platform.python_version(), 'torch': torch.__version__, 'cuda': torch.version.cuda,
                        'cudnn': torch.backends.cudnn.version(), 'numpy': np.__version__, 'sklearn': sklearn.__version__}
    return info


# ----------------------------------------------------------------------------- summary
def summary():
    """Every finished run in OUT (whatever --sets / --weightings / --seeds say), so that summary.csv never loses
    rows when a later process ran only a subset."""
    runs = []
    for f in sorted(OUT.glob('CNN1D_*.json')):
        with open(f, encoding='utf-8') as fh:
            runs.append(json.load(fh))
    if not runs:
        print('no finished runs yet'); return
    so, wo = list(FSETS), list(WEIGHTINGS)
    runs.sort(key=lambda r: (r.get('variant', 'default') != 'default', r.get('variant', 'default'),
                             so.index(r['feature_set']), wo.index(r['weighting']), r['seed']))
    rows = []
    for r in runs:
        s, w = r['feature_set'], r['weighting']
        x = r.get('xgboost_reference') or xgb_reference(s, w) or {}
        rows.append({'run': r['run'], 'variant': r.get('variant', 'default'),
                     'f0_variant': r.get('f0_variant', r.get('variant', 'default')), 'set': s, 'weighting': w,
                     'seed': r['seed'], 'accuracy': r['accuracy'], 'bal_acc': r['balanced_accuracy'],
                     'macro_f1': r['macro_f1'], 'weighted_f1': r['weighted_f1'],
                     'macro_AP': r.get('macro_average_precision'),
                     'macro_f1_no_dup': r['test_subsets']['without_train_duplicate'].get('macro_f1'),
                     'test_dup_share': r['test_duplicates']['share_any'],
                     'epochs': r['epochs_run'], 'best_epoch': r['best_epoch'], 'stopped_early': r['stopped_early'],
                     'fit_min': r['fit_seconds'] / 60, 'infer_s': r['inference_seconds'],
                     'same_test_rows': r.get('test_rows_identical_to_xgboost_control'),
                     'xgb_accuracy': x.get('accuracy'), 'xgb_bal_acc': x.get('balanced_accuracy'),
                     'xgb_macro_f1': x.get('macro_f1')})
    t = pd.DataFrame(rows)
    pd.set_option('display.width', 250)
    print(f'\n=== published-setting control: Hossain-style 1-D CNN vs XGBoost (stratified random 80/20; '
          f'published 1-D CNN accuracy {PUBLISHED_ACCURACY}) ===')
    print(t.drop(columns=['variant', 'f0_variant']).round(4).to_string(index=False))
    if (t['same_test_rows'] == False).any():                                   # noqa: E712 (None = unknown)
        print('[WARNING] some runs were not evaluated on the XGBoost control test rows (same_test_rows False)')
    key = ['variant', 'set', 'weighting']
    if t.groupby(key)['seed'].nunique().max() > 1:
        agg = t.groupby(key, sort=False).agg(
            n_seeds=('seed', 'nunique'), acc_mean=('accuracy', 'mean'), acc_sd=('accuracy', 'std'),
            acc_min=('accuracy', 'min'), acc_max=('accuracy', 'max'), macro_f1_mean=('macro_f1', 'mean'),
            macro_f1_sd=('macro_f1', 'std'), macro_f1_min=('macro_f1', 'min'), macro_f1_max=('macro_f1', 'max'),
            bal_acc_mean=('bal_acc', 'mean'), bal_acc_sd=('bal_acc', 'std'))
        print('\n=== over model seeds (SD with ddof 1; the data split is always seed 42) ===')
        print(agg.round(4).to_string())
    print('\n=== per-class F1 (CNN) ===')
    print(pd.DataFrame([{'run': r['run'], **r['per_class_f1']} for r in runs]).set_index('run').round(3).to_string())
    print('\n=== per-class average precision (CNN, threshold-free, from the softmax outputs) ===')
    print(pd.DataFrame([{'run': r['run'], **r['per_class_average_precision']} for r in runs])
          .set_index('run').round(3).to_string())
    base = {(b['variant'], b['weighting'], b['seed']): b for _, b in t[t['set'] == 'F0'].iterrows()}
    d = []
    for _, r in t[t['set'] != 'F0'].iterrows():
        b = base.get((r['f0_variant'], r['weighting'], r['seed']))          # F0 of the same settings
        if b is None:
            continue
        dx = lambda c: (r[c] - b[c]) if pd.notna(r[c]) and pd.notna(b[c]) else None
        d.append({'variant': r['variant'], 'effect': f'{r["set"]} - F0', 'weighting': r['weighting'],
                  'seed': r['seed'], 'cnn_d_accuracy': dx('accuracy'), 'cnn_d_macro_f1': dx('macro_f1'),
                  'cnn_d_bal_acc': dx('bal_acc'), 'xgb_d_accuracy': dx('xgb_accuracy'),
                  'xgb_d_macro_f1': dx('xgb_macro_f1'), 'xgb_d_bal_acc': dx('xgb_bal_acc')})
    if d:
        print('\n=== identifier effect (feature set minus F0, same weighting, seed and training settings) ===')
        print(pd.DataFrame(d).round(4).to_string(index=False))
    t.to_csv(OUT / 'summary.csv', index=False)
    print('\n[saved]', OUT / 'summary.csv')


# ----------------------------------------------------------------------------- main
def main():
    global OUT, XGB_DIR
    ap = argparse.ArgumentParser(description='Hossain-style 1-D CNN in the published setting (identifier control)')
    ap.add_argument('--sets', nargs='+', default=['F0', 'FT'], choices=list(FSETS))
    ap.add_argument('--weightings', nargs='+', default=['none'], choices=list(WEIGHTINGS))
    ap.add_argument('--seeds', nargs='+', type=int, default=[SEED],
                    help='model seeds (initialisation, batch order, dropout); the data split is always seed 42')
    ap.add_argument('--order', default=DEFAULTS['order'], choices=list(ORDERS),
                    help='ids-last: flow features, then identifiers (XGBoost control order); ids-first: identifiers '
                         'first (in-place label encoding of the CSV)')
    ap.add_argument('--pad', default=DEFAULTS['pad'], choices=list(PADS),
                    help='full: zero-pad so that every input reaches the dense layer; none: strict valid stack')
    ap.add_argument('--init', default=DEFAULTS['init'], choices=list(INITS))
    ap.add_argument('--epochs', type=int, default=DEFAULTS['epochs'])
    ap.add_argument('--patience', type=int, default=DEFAULTS['patience'])
    ap.add_argument('--batch', type=int, default=DEFAULTS['batch'])
    ap.add_argument('--lr', type=float, default=DEFAULTS['lr'])
    ap.add_argument('--timing-repeats', type=int, default=3, help='full timed inference passes (median reported)')
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N fits (0 = no limit); use 1 in a PowerShell loop: one fit per process')
    ap.add_argument('--device', default=None, help='cuda | cpu (default: cuda when available)')
    ap.add_argument('--plan', action='store_true', help='list the runs and their status, load nothing')
    ap.add_argument('--summary', action='store_true', help='only print the table of finished runs')
    ap.add_argument('--cache', default=None, help=argparse.SUPPRESS)      # testing: other data.parquet
    ap.add_argument('--out', default=None, help=argparse.SUPPRESS)        # testing: other output folder
    ap.add_argument('--xgb-dir', default=None, help=argparse.SUPPRESS)    # testing: other XGBoost results
    a = ap.parse_args()
    if a.cache:
        ppc.CACHE = Path(a.cache)
    if a.out:
        OUT = Path(a.out)
    if a.xgb_dir:
        XGB_DIR = Path(a.xgb_dir)
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return

    jobs = [(s, w, sd) for w in a.weightings for s in a.sets for sd in a.seeds]
    jname = lambda j: run_name(*j, variant_tag(a, j[0]))
    done = lambda j: (OUT / f'{jname(j)}.json').exists()
    todo = [j for j in jobs if not done(j)]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do (order {a.order}, pad '
          f'{a.pad}, init {a.init}, max {a.epochs} epochs, patience {a.patience}, batch {a.batch}, lr {a.lr:g})',
          flush=True)
    if a.plan:
        for j in jobs:
            print(f'  {jname(j):40s} {"done" if done(j) else "to do"}')
        return
    if not todo:
        summary(); return
    if not ppc.CACHE.exists():
        sys.exit(f'[error] {ppc.CACHE} is missing: run  experiments\\published_protocol_control.py --build-only  first')
    device = torch.device(a.device or ('cuda' if torch.cuda.is_available() else 'cpu'))
    if device.type == 'cuda' and not torch.cuda.is_available():
        sys.exit('[error] CUDA is not available (use --device cpu to run on the CPU)')

    batch = todo[:a.max_fits] if a.max_fits > 0 else todo
    extra = [c for c in ppc.ID_COLS if any(c in FSETS[s][0] for s, _, _ in batch)]   # only what is needed
    cols = FEATS + extra
    t0 = time.time()
    X, y, h, sub = ppc.load(cols)                           # float32, column by column, NaN/inf -> 0
    tr, fit, va, te = split_rows(y)
    has_dup, dup = ppc.dup_report(h, y, tr, te)             # duplicates against the whole training part (80%)
    del h; gc.collect()
    yt = y[te].astype(np.int8)
    st = sub[te].astype(str)
    del sub; gc.collect()
    same = same_test_rows(te, yt)
    if same is False:
        print('[WARNING] the test rows differ from the XGBoost control .npz files: data.parquet has changed since '
              'published_protocol_control.py ran, so the CNN and XGBoost results are NOT comparable', flush=True)
    mu, sd = standardise(X, tr)
    scaling = {c: [round(float(m), 6), round(float(s), 6)] for c, m, s in zip(cols, mu, sd)}
    counts = lambda v: {c: int(n) for c, n in zip(CLASSES, np.bincount(v, minlength=K))}
    class_counts = {'all': counts(y), 'train_part': counts(y[tr]), 'fit': counts(y[fit]),
                    'validation': counts(y[va]), 'test': counts(y[te])}
    n_tr = int(len(tr))
    del tr; gc.collect()
    X_t, y_t = torch.from_numpy(X), torch.from_numpy(np.ascontiguousarray(y, dtype=np.int64))   # no copy
    fit_t, va_t, te_t = (torch.from_numpy(v.astype(np.int64)) for v in (fit, va, te))
    data_s = time.time() - t0
    print(f'[data] {len(y):,} flows x {len(cols)} columns ({X.nbytes / 2**30:.2f} GB); fit {len(fit):,}, '
          f'validation {len(va):,}, test {len(te):,}; test rows = XGBoost control: {same}; test flows with an '
          f'exact duplicate in train: {dup["share_any"]:.1%} ({data_s:.0f} s)', flush=True)

    for i, (s, w, seed) in enumerate(batch, 1):
        tag = variant_tag(a, s)
        name = run_name(s, w, seed, tag)
        want = feature_order(s, a.order)
        cidx = [cols.index(c) for c in want]
        csel = None if cidx == list(range(len(cols))) else torch.as_tensor(cidx, dtype=torch.long)
        print(f'\n===== [{len(jobs) - len(todo) + i}/{len(jobs)}] {name}: {len(want)} features, weighting={w}, '
              f'seed={seed} =====', flush=True)
        torch.manual_seed(seed); np.random.seed(seed)
        if device.type == 'cuda':
            torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.benchmark = False
        torch.backends.cudnn.deterministic = True
        cw = compute_class_weight('balanced', classes=np.array(LABELS), y=y[fit]).astype(np.float32) \
            if w == 'balanced' else None
        wt = torch.as_tensor(cw, device=device) if cw is not None else None
        net = HossainCNN1D(len(want), K, init=a.init, pad=a.pad).to(device)
        n_par = int(sum(q.numel() for q in net.parameters()))
        seen = reaching_inputs(len(want) + net.n_pad)
        names = [ppc.ID_NAME.get(c, c) for c in want]
        unseen = [names[q] for q in range(len(want)) if q not in seen]
        if unseen:
            print(f'    [note] inputs that do not reach the dense layer: {unseen}', flush=True)
        if device.type == 'cuda':
            torch.cuda.reset_peak_memory_stats()

        t = time.time()
        hist, info = train(net, X_t, y_t, fit_t, va_t, csel, wt, device, a, seed)
        fit_s = time.time() - t
        proba, inf = timed_predict(net, X_t, te_t, csel, device, a.timing_repeats)
        p = proba.argmax(1).astype(np.int8)

        r = score(yt, p, proba, st, has_dup, dup)
        r.update({
            'run': name, 'variant': tag.lstrip('_') or 'default',
            'f0_variant': variant_tag(a, 'F0').lstrip('_') or 'default',   # the F0 run of the same settings
            'model': 'CNN1D (Hossain-style)', 'feature_set': s, 'features': FSETS[s][1], 'n_features': len(want),
            'weighting': w, 'weighting_desc': WEIGHTINGS[w],
            'class_weights': dict(zip(CLASSES, np.round(cw.astype(float), 4).tolist())) if cw is not None else None,
            'seed': seed,
            'description': 'identifier necessity control in the published setting with the published model family: '
                           'the table, class set, stratified random 80/20 split (seed 42) and feature sets of '
                           'published_protocol_control.py; Hossain-style 1-D CNN; early stopping on a stratified '
                           '10% of the training part',
            'architecture': 'input (n,1) -> Conv1d(1,64,3)+ReLU+MaxPool(2) -> Conv1d(64,128,3)+ReLU+MaxPool(2) -> '
                            'Flatten -> Dense 128+ReLU -> Dropout 0.5 -> Dense 8',
            'feature_order': names, 'order': a.order, 'order_desc': ORDERS[a.order],
            'pad': a.pad, 'pad_desc': PADS[a.pad], 'n_zero_pad': int(net.n_pad),
            'input_length': int(len(want) + net.n_pad), 'inputs_not_reaching_dense': unseen,
            'init': a.init, 'init_desc': INITS[a.init], 'n_parameters': n_par,
            'training': {'optimizer': 'Adam', 'lr': a.lr, 'eps': ADAM_EPS, 'batch_size': a.batch,
                         'max_epochs': a.epochs, 'early_stopping': 'validation loss, min_delta 0',
                         'patience': a.patience, 'restore_best_weights': True,
                         'loss': 'cross-entropy' + (' (class-weighted)' if cw is not None else ''),
                         'amp': False, 'gradient_clipping': None, 'lr_schedule': None,
                         'shuffle': 'new permutation of the fitted rows every epoch',
                         'validation': f'stratified {VAL_FRAC:.0%} of the training part, seed {SEED}'},
            'scaling': 'per-column mean / population SD of the training part (80%), SD 0 -> 1; NaN/inf -> 0 first',
            'scaling_mean_sd_identifier_columns': {c: scaling[c] for c in FSETS[s][0]},
            'split': 'stratified random 80/20, seed 42 (= published_protocol_control.py)',
            'test_rows_identical_to_xgboost_control': same,
            'n_train': n_tr, 'n_fit': int(len(fit)), 'n_val': int(len(va)), 'n_test': int(len(te)),
            'class_counts': class_counts,
            **info, 'history': hist,
            'fit_seconds': round(fit_s, 1),
            'fit_note': 'training + per-epoch validation passes; data loading, scaling and splitting excluded '
                        '(data_prep_seconds, shared by all runs of the process)',
            'seconds_per_epoch': round(fit_s / max(1, info['epochs_run']), 1),
            'data_prep_seconds': round(data_s, 1),
            'peak_gpu_memory_mb': round(torch.cuda.max_memory_allocated() / 2**20, 1) if device.type == 'cuda' else None,
            'inference_seconds': inf['seconds'], 'inference_us_per_flow': round(inf['seconds'] / len(te) * 1e6, 3),
            'inference': inf,
            'hardware': hardware(device),
            'command': ' '.join(sys.argv),
            'xgboost_reference': xgb_reference(s, w)})
        np.savez_compressed(OUT / f'{name}.npz', y=yt, p=p, proba=proba.astype(np.float16), sub=st,
                            idx=te.astype(np.int32))        # before the JSON: the JSON marks the run finished
        write_json(OUT / f'{name}.json', r)
        x = r['xgboost_reference'] or {}
        print(f'[result] {name}: acc={r["accuracy"]:.4f}  bal-acc={r["balanced_accuracy"]:.4f}  '
              f'macro-F1={r["macro_f1"]:.4f}  (no train duplicate: '
              f'{r["test_subsets"]["without_train_duplicate"].get("macro_f1", float("nan")):.4f})  '
              f'epochs={info["epochs_run"]} (best {info["best_epoch"]})  fit {fit_s / 60:.1f} min, '
              f'inference {inf["seconds"]:.1f} s'
              + (f'  | XGBoost acc={x["accuracy"]:.4f} macro-F1={x["macro_f1"]:.4f}' if x else ''), flush=True)
        del net, proba, p, r, hist, info; gc.collect()
        if device.type == 'cuda':
            torch.cuda.empty_cache()
    left = len(todo) - len(batch)
    print(f'\n[left] {left} runs still to do' if left else '\n[DONE] all runs finished', flush=True)
    if not left:
        summary()


if __name__ == '__main__':
    main()
