# -*- coding: utf-8 -*-
r"""
deep_protocol_study.py
======================
Reviewer points expe-07, expe-08, stat-06, disc-14, disc-11, stat-09, expe-09 and expe-17:
more training seeds for the deep models, a fixed-budget protocol next to the paper's early stopping,
stored test probabilities, measured inference time, and two new deep baselines (a tuned MLP and a
re-implementation of the published 1-D CNN).

Data, cleaning and splits are exactly those of deep_split_noise_study.py: the flagged sample of
flagged_loader.load_prepared() (3,626,502 flows, 81 features, NaN/inf -> 0), kept_rows() first,
then splits() on the kept rows (random: stratified 70/15/15 with split seed 42; temporal: 70/15/15
by time inside each of the 16 capture groups). The data split is fixed; only the training seed varies.
  conditions   split random | temporal  x  labels raw | r1          (--splits, --cleaning)

Models (--models; default: the three paper models)
  ResNet1D, GRU, Transformer   the paper's networks, imported unchanged from src/stage3_ml_models.py
                               (_ResNet1DNet, _GRUNet, _TransformerNet), with the settings of their
                               wrapper classes: Adam lr 1e-3 / 1e-3 / 1e-4, batch 512 / 512 / 256.
  MLP            (new)         plain multilayer perceptron on the 81 standardised features; every hidden
                               layer is Linear -> BatchNorm -> ReLU -> Dropout; default hidden sizes
                               256-128-64, dropout 0.2; Adam lr 1e-3, batch 512. The configuration is
                               chosen by --tune (below) and read from mlp_tuning/mlp_config.json.
  CNN1D_Hossain  (new)         re-implementation of the 1-D CNN of Hossain (2025) as described in the
                               related work of the paper: the 81 features as a 1-channel sequence;
                               Conv1d(1,64,k=3)+ReLU+MaxPool(2), Conv1d(64,128,k=3)+ReLU+MaxPool(2),
                               flatten, Dense 128 + ReLU + Dropout(0.5), softmax output over the 8 classes
                               (the softmax is inside the cross-entropy loss / applied at prediction).
                               'valid' convolutions (no padding, the Keras default): 81 -> 79 -> 39 -> 37
                               -> 18, flatten 128 x 18 = 2,304. It follows the published description and is
                               NOT the authors' code; the training settings are this benchmark's
                               (class-weighted loss, Adam lr 1e-3, batch 512, at most 30 epochs).

Training (identical for every model)
  StandardScaler fitted on the training rows (fit_scaler(): the statistics of StandardScaler().fit()
  computed in chunks, bit-identical to fit() but without its float64 copies of the training matrix),
  class-weighted cross-entropy
  (compute_class_weight('balanced') on the training rows, as deep_split_noise_study.run_one), Adam,
  AMP, gradient clipping 1.0, ReduceLROnPlateau(factor 0.5, patience 5), at most --max-epochs 30.
  The loop is a line-by-line copy of src/stage3_ml_models._train_pytorch_model (same batch order,
  same RNG use), extended by the protocol switch and by per-epoch validation macro-F1 / timing records.
  Checked on synthetic data (CPU and GPU): the loop reproduces the weights of _train_pytorch_model exactly,
  and run_one(--protocol earlystop) reproduces deep_split_noise_study.run_one exactly (identical test
  predictions for ResNet1D, GRU and Transformer, random/raw and temporal/r1).
  --protocol earlystop  the paper's protocol: the LR schedule monitors the validation loss; training
                        stops after 10 epochs without a lower validation loss and the weights of the
                        best epoch are restored.
  --protocol fixed      exactly --max-epochs epochs, the FINAL weights are evaluated, and the validation
                        part is not used at all, as for the tree ensembles: the LR schedule monitors the
                        training loss (--fixed-lr train, default). Sensitivity variants: --fixed-lr val keeps
                        the paper's validation-loss schedule and changes only the weight selection (folder
                        fixed_lr-val); --fixed-lr none uses a constant learning rate (fixed_lr-none).
  In both protocols the validation loss, accuracy and macro-F1 are recorded after every epoch (in 'fixed'
  for monitoring only), so the epoch with the lowest validation loss is known in hindsight (disc-14).
  Seeding as in the paper: numpy and torch are seeded with the training seed right before the network is
  built; the DataLoader shuffling draws from the same torch generator.

Seeds (--seeds overrides the defaults for every selected model)
  earlystop  paper models: 7 123 2024. Together with seeds 17 and 42 of results_2026_03_03/deep_split
             (same protocol and code path; poolable) this gives five seeds per cell. A run that exists
             in deep_split is never repeated unless --rerun-existing is given; a rerun is written to the
             new folder and deep_protocol_summary.py pools the deep_split value and reports the difference.
             MLP and CNN1D_Hossain (no earlier runs): 17 42 7 123 2024.
  fixed      17 42 for every model.

MLP tuning (--models MLP --tune; always the earlystop protocol)
  4 configurations: hidden 256-128-64 or 512-256-128 x dropout 0.2 or 0.4, on the random/raw condition
  with seed 42. The configuration with the highest validation macro-F1 (of the weights that early
  stopping selects; ties -> the first in the list above) is written to mlp_tuning/mlp_config.json,
  which every later MLP run reads; MLP runs are skipped until that file exists. The test set is not
  used for the choice. The chosen trial IS the earlystop MLP random/raw seed-42 run (same code path)
  and is copied to earlystop/ instead of being fitted again.

Stored per run
  JSON  metrics() of deep_split_noise_study (accuracy, balanced_accuracy, macro_f1, per_class_f1,
        per_class_recall, per_subattack_recall), attack_macro_f1 (7 attack classes, Benign excluded),
        per_class_precision, confusion (rows = true), per_class_test_support, per_class_prevalence,
        per_class_ap (one-vs-rest average precision from the float32 probabilities), macro_ap,
        attack_macro_ap, macro_ap_float16 (the same from the stored float16 probabilities),
        per_class_roc_auc, macro_roc_auc;
        model, split, cleaning, seed, protocol, lr_monitor, max_epochs, patience, epochs_run,
        best_epoch (epoch whose weights are evaluated), stopped_early, val_best_epoch (lowest validation
        loss, hindsight), val_macro_f1_selected (validation macro-F1 of the evaluated weights),
        history (per epoch: train loss/acc, val loss/acc/macro-F1 (under AMP, as the paper's loop), learning
        rate after the scheduler step, seconds, validation seconds);
        fit_seconds (standardisation + network + training loop incl. the per-epoch validation pass, as
        fit_seconds of deep_split), val_seconds, seconds_per_epoch;
        inference {seconds (median of --timing-repeats passes over the whole test set), seconds_repeats,
        seconds_per_1000_flows, flows_per_second, forward_seconds (without standardisation),
        latency_one_flow_ms_median, batch, precision, device, warm-up, load_before_timing (CPU load, free
        RAM, GPU utilisation and memory in use right before the timed passes; a warning is printed when
        the machine is busy)};
        n_params, arch (optimiser settings, MLP configuration), class_weights, n_train, n_val, n_test,
        train/test class counts, hardware (CPU, RAM, GPU, library versions); for a rerun of a deep_split run
        (--rerun-existing) also deep_split_original (its macro_f1, balanced_accuracy, accuracy, epochs_run,
        n_test and whether they are identical to this run).
  NPZ   y (int8), p (int8, argmax of the logits = the paper's predict()), proba (float16 softmax,
        n_test x 8, columns in CLASSES order), rows (int32 global row positions in the load_prepared()
        sample), sub (capture group, str); the test rows are in splits() order.
  Inference time: the trained network in eval mode on the GPU, fp32 (as the paper's predict()), chunks
  of 8,192 flows (src PREDICT_CHUNK). After one untimed warm-up chunk the whole test set is predicted
  --timing-repeats times: standardisation of the raw features (CPU) + host-to-device copy + forward +
  argmax + softmax + copy back. Single-flow latency: median of 200 batch-1 forward passes (after 10 warm-up calls).

Output: results_2026_03_03/q1_revision/deep_protocol/
  earlystop/<Model>_<split>_<cleaning>_s<seed>.json + .npz    (same names as deep_split: poolable)
  fixed/<Model>_<split>_<cleaning>_s<seed>.json + .npz        (fixed_lr-val/, fixed_lr-none/ for variants;
                                                               a suffix _e<N> when --max-epochs is not 30)
  mlp_tuning/MLP-<config>_random_raw_s42.json + .npz, mlp_tuning/mlp_config.json
  Tables: experiments/deep_protocol_summary.py. results_2026_03_03/deep_split is only read, never written.
Resumable: a run is finished when its JSON exists (npz first, JSON last and atomically). Memory: the
feature matrix is read column by column (~1.2 GB); the training / validation / test rows are copied out
(~1.2 GB) and the full matrix is released before the last fit of a process, so one fit per process
(--max-fits 1) peaks at about 3 GB of RAM (incl. the CUDA runtime). --plan lists the runs and their status without loading data.

Run (PowerShell, from the project folder). Approximate times on the
RTX 5070 laptop GPU, from the fit times of deep_split (35-47 s per epoch for ResNet1D / GRU, 47-59 s for the
Transformer, plus about 1 min to load the data in every process): ResNet1D / GRU up to about 23 min,
Transformer up to about 30 min per 30-epoch run. MLP and CNN1D_Hossain: a short timing on synthetic data
gave about 0.7x (MLP 512-256-128) and 0.9x (CNN) the ResNet1D epoch time, i.e. about 15 and 20 min per
30-epoch run (the per-batch data loading dominates). A loop iteration after all runs are finished only
prints the plan and exits (no data is loaded). Without CUDA the script stops with exit code 2 before
loading data instead of silently training on the CPU (--device cpu is for smoke tests only). Inference
times are most reliable when no other job (e.g. a tree fit) runs; the load right before timing is stored.
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\deep_protocol_study.py --plan
  & $py experiments\deep_protocol_study.py --protocol fixed --plan
  # 1) paper protocol, seeds 7 123 2024 for ResNet1D, GRU, Transformer (36 fits, about 13 h)
  1..36 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol earlystop --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_earlystop.log -Append }
  # 2) fixed 30-epoch protocol, seeds 17 42 for the same models (24 fits, about 10 h)
  1..24 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol fixed --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_fixed.log -Append }
  # 3) MLP tuning (4 fits), then MLP and CNN1D_Hossain: earlystop, 5 seeds (39 fits: the tuning run is reused)
  #    and fixed, seeds 17 42 (16 fits)
  1..4 | ForEach-Object { & $py experiments\deep_protocol_study.py --models MLP --tune --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_mlp_tune.log -Append }
  1..39 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol earlystop --models MLP CNN1D_Hossain --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_new_models.log -Append }
  1..16 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol fixed --models MLP CNN1D_Hossain --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_new_models.log -Append }
  # optional sensitivity: fixed epochs with the paper's validation-loss LR schedule (weight selection only)
  1..24 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol fixed --fixed-lr val --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_fixed_lrval.log -Append }
  # optional: refit the deep_split seeds 17 42 (paper protocol) to store probabilities and inference time for
  # all five seeds (AP, per-class intervals; 24 fits). The summary keeps pooling the deep_split metrics, takes
  # AP / inference time from these reruns and lists rerun - original in rerun_check.csv. Each rerun also prints
  # its difference to the deep_split run: the data, standardisation, seeding and training loop are identical,
  # so a difference of 0 is expected unless GPU kernels are non-deterministic. Quick pipeline check first
  # (the shortest paper run, 13 epochs, about 10 min):
  & $py experiments\deep_protocol_study.py --models ResNet1D --splits temporal --cleaning r1 --seeds 42 --rerun-existing --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_rerun.log -Append
  1..24 | ForEach-Object { & $py experiments\deep_protocol_study.py --protocol earlystop --seeds 17 42 --rerun-existing --max-fits 1 2>&1 | Tee-Object -FilePath deep_protocol_rerun.log -Append }
  # tables (pools deep_split + new runs; can be run at any time)
  & $py experiments\deep_protocol_summary.py 2>&1 | Tee-Object -FilePath deep_protocol_summary.log
"""
import argparse, gc, json, logging, os, platform, shutil, subprocess, sys, time
from pathlib import Path

logging.basicConfig(level=logging.WARNING)      # silences the INFO lines of stage3_ml_models (stderr)

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             roc_auc_score)
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(ROOT / 'src'))
from deep_split_noise_study import kept_rows, metrics, splits  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES  # noqa: E402
import stage3_ml_models as S  # noqa: E402  (paper networks, DEVICE, TRAINING_CONFIG, PREDICT_CHUNK)

sys.stdout.reconfigure(encoding='utf-8')
RES = ROOT / 'results_2026_03_03'
OLD = RES / 'deep_split'                         # paper runs, seeds 17 / 42 (read only)
OUT = RES / 'q1_revision' / 'deep_protocol'
K = len(CLASSES)
LABELS = list(range(K))
ATTACKS = [i for i, c in enumerate(CLASSES) if c != 'Benign']
PAPER_MODELS = ['ResNet1D', 'GRU', 'Transformer']
NEW_MODELS = ['MLP', 'CNN1D_Hossain']
ALL_MODELS = PAPER_MODELS + NEW_MODELS
SPLITS, CLEANING = ['random', 'temporal'], ['raw', 'r1']
PAPER_EPOCHS = 30
PATIENCE = 10                                    # default of _train_pytorch_model (all three paper wrappers)
# learning rates as passed by the wrappers' fit() in src/stage3_ml_models.py (ResNet1DModel, GRUModel:
# default 0.001; TransformerModel: lr=0.0001); batch sizes from config.DL_MODELS (checked in spec())
LR = {'ResNet1D': 1e-3, 'GRU': 1e-3, 'Transformer': 1e-4, 'MLP': 1e-3, 'CNN1D_Hossain': 1e-3}
NEW_BATCH = {'MLP': 512, 'CNN1D_Hossain': 512}
SEEDS_EARLY_PAPER = [7, 123, 2024]               # + 17, 42 of deep_split
SEEDS_EARLY_NEW = [17, 42, 7, 123, 2024]
SEEDS_FIXED = [17, 42]
MLP_GRID = [{'hidden': [256, 128, 64], 'dropout': 0.2}, {'hidden': [256, 128, 64], 'dropout': 0.4},
            {'hidden': [512, 256, 128], 'dropout': 0.2}, {'hidden': [512, 256, 128], 'dropout': 0.4}]
TUNE_SEED, TUNE_SPLIT, TUNE_CLEANING = 42, 'random', 'raw'
VAL_CHUNK = 8192                                 # as in _train_pytorch_model
SCALE_CHUNK = 250_000
LATENCY_CALLS, LATENCY_WARMUP = 200, 10


# ============================================================================ new baselines
class MLPNet(nn.Module):
    """Plain MLP: (Linear -> BatchNorm1d -> ReLU -> Dropout) per hidden layer, then a linear output."""

    def __init__(self, input_dim, n_classes, hidden=(256, 128, 64), dropout=0.2):
        super().__init__()
        layers, d = [], input_dim
        for h in hidden:
            layers += [nn.Linear(d, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(dropout)]
            d = h
        layers.append(nn.Linear(d, n_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class CNN1DHossainNet(nn.Module):
    """1-D CNN after the description of Hossain (2025); not the authors' code (see module docstring)."""

    def __init__(self, input_dim, n_classes):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3), nn.ReLU(), nn.MaxPool1d(2),
            nn.Conv1d(64, 128, kernel_size=3), nn.ReLU(), nn.MaxPool1d(2))
        length = ((input_dim - 2) // 2 - 2) // 2                    # 81 -> 18
        self.classifier = nn.Sequential(
            nn.Flatten(), nn.Linear(128 * length, 128), nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(128, n_classes))                             # softmax: in the loss / at prediction

    def forward(self, x):
        return self.classifier(self.features(x.unsqueeze(1)))


def cfg_tag(cfg):
    return 'h' + '-'.join(str(h) for h in cfg['hidden']) + f'-d{cfg["dropout"]}'


def spec(model, mlp_cfg=None):
    """Optimiser settings and network constructor of one model."""
    if model in PAPER_MODELS:
        batch = int(S.DL_MODELS[model]['batch_size'])               # 512 / 512 / 256
        assert (model, batch) in {('ResNet1D', 512), ('GRU', 512), ('Transformer', 256)}, (model, batch)
    else:
        batch = NEW_BATCH[model]
    cfg = None
    if model == 'ResNet1D':
        build = lambda d: S._ResNet1DNet(d, K, channels=128, n_blocks=S.DL_MODELS['ResNet1D'].get('n_blocks', 3))
    elif model == 'GRU':
        c = S.DL_MODELS['GRU']
        build = lambda d: S._GRUNet(d, K, hidden_size=c.get('hidden_size', 128), n_layers=c.get('n_layers', 2))
    elif model == 'Transformer':
        build = lambda d: S._TransformerNet(d, K)
    elif model == 'MLP':
        cfg = {'hidden': list(mlp_cfg['hidden']), 'dropout': float(mlp_cfg['dropout'])}
        build = lambda d: MLPNet(d, K, hidden=cfg['hidden'], dropout=cfg['dropout'])
    elif model == 'CNN1D_Hossain':
        cfg = {'conv': [[1, 64, 3], [64, 128, 3]], 'padding': 'valid', 'pool': 2, 'dense': 128, 'dropout': 0.5}
        build = lambda d: CNN1DHossainNet(d, K)
    else:
        raise ValueError(model)
    return {'lr': LR[model], 'batch_size': batch, 'config': cfg, 'build': build}


# ============================================================================ training
def _colsum(X, shift=None, square=False):
    """float64 column sums of X (optionally of (X - shift) or (X - shift)**2), chunk by chunk.

    The running total is prepended to every chunk, so the rows are added in exactly the order of
    np.sum(X, axis=0, dtype=np.float64) on the whole array: the result is bit-identical to that one-pass
    sum (checked on synthetic data, numpy 2.1.3) without its full-size float64 temporaries."""
    acc = None
    for i in range(0, len(X), SCALE_CHUNK):
        c = X[i:i + SCALE_CHUNK].astype(np.float64)
        if shift is not None:
            c -= shift
        if square:
            c **= 2
        if acc is not None:
            c = np.vstack([acc[None, :], c])
        acc = c.sum(axis=0)
    return acc


def fit_scaler(X):
    """StandardScaler().fit(X) (the paper wrappers' fit_transform) computed in chunks.

    Same algorithm as sklearn's first (and only) _incremental_mean_and_var pass of fit(): mean = sum / n,
    corrected two-pass variance ((sum of squared deviations) - (sum of deviations)^2 / n) / n, and sklearn's
    own handling of constant features. mean_, var_ and scale_ are bit-identical to fit(X) (checked on
    synthetic data with sklearn 1.8.0), so the standardised features equal those of the paper runs, while the
    peak memory is two float64 chunks instead of a float64 copy of the training matrix."""
    from sklearn.preprocessing._data import _handle_zeros_in_scale, _is_constant_feature
    n = len(X)
    mean = _colsum(X) / np.float64(n)
    corr = _colsum(X, shift=mean)
    var = (_colsum(X, shift=mean, square=True) - corr ** 2 / np.float64(n)) / np.float64(n)
    sc = StandardScaler().fit(X[:2])                     # creates every fitted attribute of this sklearn version
    sc.mean_, sc.var_, sc.n_samples_seen_ = mean, var, np.float64(n)
    sc.scale_ = _handle_zeros_in_scale(np.sqrt(var), copy=False,
                                       constant_mask=_is_constant_feature(var, mean, np.float64(n)))
    return sc


def scale_inplace(sc, X):
    for i in range(0, len(X), SCALE_CHUNK):
        X[i:i + SCALE_CHUNK] = sc.transform(X[i:i + SCALE_CHUNK])
    return X


def macro_f1_from_pred(y, p):
    cm = np.bincount(y * K + p, minlength=K * K).reshape(K, K).astype(float)
    tp, row, col = np.diagonal(cm), cm.sum(1), cm.sum(0)
    with np.errstate(divide='ignore', invalid='ignore'):
        prec = np.where(col > 0, tp / col, 0.0)
        rec = np.where(row > 0, tp / row, 0.0)
        f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0)
    return float(f1.mean())


def train(net, Xtr, ytr, Xva, yva, class_weights, epochs, batch_size, lr, protocol, lr_monitor,
          patience=PATIENCE, verbose=True):
    """src/stage3_ml_models._train_pytorch_model, statement by statement, plus the protocol switch.

    protocol 'earlystop': scheduler.step(val_loss), early stopping with `patience`, best weights restored
                          (identical to _train_pytorch_model).
    protocol 'fixed'    : all `epochs` epochs, final weights; scheduler.step(train_loss | val_loss | none)
                          according to lr_monitor; the validation pass is monitoring only.
    """
    from torch.utils.data import DataLoader, TensorDataset
    dev = S.DEVICE
    use_amp = S.TRAINING_CONFIG.get('use_amp', True) and dev is not None and dev.type == 'cuda'
    clip_norm = S.TRAINING_CONFIG.get('gradient_clip_norm', 1.0)
    net = net.to(dev)
    net.train()
    X_t = torch.from_numpy(Xtr)                                    # shares memory (FloatTensor copies)
    y_t = torch.from_numpy(np.ascontiguousarray(ytr, dtype=np.int64))
    train_loader = DataLoader(TensorDataset(X_t, y_t), batch_size=batch_size, shuffle=True,
                              num_workers=0, pin_memory=(dev.type == 'cuda'))
    X_v = torch.from_numpy(Xva)
    y_v = torch.from_numpy(np.ascontiguousarray(yva, dtype=np.int64))
    yva_np = y_v.numpy()
    criterion = nn.CrossEntropyLoss(weight=torch.FloatTensor(class_weights).to(dev))
    optimizer = torch.optim.Adam(net.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, factor=0.5, patience=5)
    scaler = torch.amp.GradScaler('cuda') if use_amp else None

    best_val_loss, best_state, best_epoch, wait, stopped = float('inf'), None, None, 0, False
    hist = {k: [] for k in ('train_loss', 'train_acc', 'val_loss', 'val_acc', 'val_macro_f1', 'lr_after_epoch',
                            'seconds', 'val_seconds')}
    for epoch in range(epochs):
        t_ep = time.time()
        net.train()
        total_loss, correct, total = 0.0, 0, 0
        for xb, yb in train_loader:
            xb, yb = xb.to(dev, non_blocking=True), yb.to(dev, non_blocking=True)
            optimizer.zero_grad()
            with torch.amp.autocast('cuda', enabled=use_amp):
                logits = net(xb)
                loss = criterion(logits, yb)
            if scaler is not None:
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(net.parameters(), max_norm=clip_norm)
                scaler.step(optimizer)
                scaler.update()
            else:
                loss.backward()
                nn.utils.clip_grad_norm_(net.parameters(), max_norm=clip_norm)
                optimizer.step()
            total_loss += loss.item() * xb.size(0)
            preds = logits.argmax(dim=1)
            correct += (preds == yb).sum().item()
            total += xb.size(0)
        train_loss, train_acc = total_loss / total, correct / total

        t_val = time.time()                                        # validation pass (as the original)
        net.eval()
        vpred = np.empty(len(yva_np), np.int64)
        with torch.no_grad():
            val_loss_sum, val_correct, val_total = 0.0, 0, 0
            for vi in range(0, X_v.size(0), VAL_CHUNK):
                xvb = X_v[vi:vi + VAL_CHUNK].to(dev, non_blocking=True)
                yvb = y_v[vi:vi + VAL_CHUNK].to(dev, non_blocking=True)
                with torch.amp.autocast('cuda', enabled=use_amp):
                    logits_vb = net(xvb)
                    vl = criterion(logits_vb, yvb).item()
                val_loss_sum += vl * xvb.size(0)
                pv = logits_vb.argmax(dim=1)
                val_correct += (pv == yvb).sum().item()
                val_total += xvb.size(0)
                vpred[vi:vi + VAL_CHUNK] = pv.cpu().numpy()
            val_loss = val_loss_sum / val_total
            val_acc = val_correct / val_total
        val_f1 = macro_f1_from_pred(yva_np, vpred)
        val_s = time.time() - t_val

        improved = False
        if protocol == 'earlystop':
            scheduler.step(val_loss)
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_state = {k: v.cpu().clone() for k, v in net.state_dict().items()}
                best_epoch, wait, improved = epoch + 1, 0, True
            else:
                wait += 1
                if wait >= patience:
                    stopped = True
        else:
            if lr_monitor == 'train':
                scheduler.step(train_loss)
            elif lr_monitor == 'val':
                scheduler.step(val_loss)
        for k, v in (('train_loss', train_loss), ('train_acc', train_acc), ('val_loss', val_loss),
                     ('val_acc', val_acc), ('val_macro_f1', val_f1), ('lr_after_epoch', optimizer.param_groups[0]['lr']),
                     ('seconds', time.time() - t_ep), ('val_seconds', val_s)):
            hist[k].append(float(v))
        if verbose:
            print(f'    ep {epoch + 1:02d}/{epochs} loss {train_loss:.4f} acc {train_acc:.4f} | val loss {val_loss:.4f} '
                  f'acc {val_acc:.4f} F1 {val_f1:.4f} | lr {hist["lr_after_epoch"][-1]:.1e} {hist["seconds"][-1]:.0f}s'
                  f'{" *" if improved else ""}{"  [early stop]" if stopped else ""}', flush=True)
        if stopped:
            break

    if protocol == 'earlystop' and best_state is not None:
        net.load_state_dict(best_state)
    else:
        best_epoch = len(hist['train_loss'])                       # final weights are evaluated
    net.eval()
    vb = int(np.argmin(hist['val_loss'])) + 1
    info = {'epochs_run': len(hist['train_loss']), 'best_epoch': best_epoch, 'stopped_early': stopped,
            'val_best_epoch': vb, 'val_loss_min': hist['val_loss'][vb - 1],
            'val_loss_selected': hist['val_loss'][best_epoch - 1],
            'val_macro_f1_selected': hist['val_macro_f1'][best_epoch - 1],
            'val_macro_f1_max': max(hist['val_macro_f1']),
            'val_seconds': float(sum(hist['val_seconds'])), 'amp': use_amp}
    return net, hist, info


# ============================================================================ inference
def load_snapshot():
    """Machine load right before the timed passes: other jobs (e.g. tree fits) inflate inference times, so
    the CPU load, free RAM and the GPU utilisation / memory in use (all processes, incl. this one) are stored
    with every timing."""
    s = {}
    try:
        import psutil
        s['cpu_load_percent'] = float(psutil.cpu_percent(interval=0.5))
        s['ram_available_gb'] = round(psutil.virtual_memory().available / 2**30, 1)
    except Exception:
        pass
    try:
        q = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,memory.used', '--format=csv,noheader,nounits'],
                           capture_output=True, text=True, timeout=15)
        if q.returncode == 0 and q.stdout.strip():
            u, mem = [v.strip() for v in q.stdout.strip().splitlines()[0].split(',')[:2]]
            s['gpu_utilization_percent'], s['gpu_memory_used_mib'] = float(u), float(mem)
    except Exception:
        pass
    return s


def timed_predict(net, sc, Xte, repeats):
    """Probabilities of the whole test set + wall-clock timing (see module docstring)."""
    dev = S.DEVICE
    cuda = dev.type == 'cuda'
    sync = torch.cuda.synchronize if cuda else (lambda: None)
    chunk = int(S.PREDICT_CHUNK)
    net.eval()
    load = load_snapshot()
    if load.get('cpu_load_percent', 0) > 30 or load.get('gpu_utilization_percent', 0) > 10:
        print(f'[warn] machine busy before timing (CPU {load.get("cpu_load_percent")}%, GPU '
              f'{load.get("gpu_utilization_percent")}%): the inference time may be inflated', flush=True)

    def forward_all(Xs, out, pred):
        with torch.no_grad():
            for i in range(0, len(Xs), chunk):
                logits = net(torch.from_numpy(Xs[i:i + chunk]).to(dev))
                pred[i:i + chunk] = logits.argmax(dim=1).cpu().numpy()     # = the paper's predict()
                out[i:i + chunk] = torch.softmax(logits, dim=1).cpu().numpy()

    warm = np.asarray(sc.transform(Xte[:chunk]), np.float32)          # untimed warm-up chunk
    forward_all(warm, np.empty((len(warm), K), np.float32), np.empty(len(warm), np.int64)); sync()
    proba = np.empty((len(Xte), K), np.float32)
    pred = np.empty(len(Xte), np.int64)
    tot, fwd, Xs = [], [], None
    for _ in range(max(1, repeats)):
        Xs = None; gc.collect()
        t0 = time.perf_counter()
        Xs = np.asarray(sc.transform(Xte), np.float32)                 # standardisation is part of inference
        t1 = time.perf_counter()
        forward_all(Xs, proba, pred); sync()
        t2 = time.perf_counter()
        tot.append(t2 - t0); fwd.append(t2 - t1)
    lat = []
    with torch.no_grad():
        for i in range(LATENCY_WARMUP + LATENCY_CALLS):
            j = i % len(Xs)
            t = time.perf_counter()
            int(net(torch.from_numpy(Xs[j:j + 1]).to(dev)).argmax(dim=1).item())   # .item() synchronises
            lat.append(time.perf_counter() - t)
    del Xs; gc.collect()
    sec = float(np.median(tot))
    n = len(Xte)
    inf = {'seconds': round(sec, 4), 'seconds_repeats': [round(v, 4) for v in tot],
           'seconds_per_1000_flows': round(1000 * sec / max(1, n), 6),
           'flows_per_second': round(n / sec, 1) if sec > 0 else None,
           'forward_seconds': round(float(np.median(fwd)), 4),
           'forward_seconds_per_1000_flows': round(1000 * float(np.median(fwd)) / max(1, n), 6),
           'latency_one_flow_ms_median': round(1000 * float(np.median(lat[LATENCY_WARMUP:])), 4),
           'latency_one_flow_ms_p95': round(1000 * float(np.percentile(lat[LATENCY_WARMUP:], 95)), 4),
           'n_flows': int(n), 'batch': chunk, 'repeats': len(tot), 'warmup': f'one untimed chunk of {chunk} flows',
           'load_before_timing': load,
           'precision': 'fp32 (no autocast, as the paper predict())',
           'device': torch.cuda.get_device_name(0) if cuda else 'cpu',
           'what': 'standardisation (CPU) + host-to-device copy + forward + argmax + softmax + copy back, whole test set'}
    return proba, pred, inf


# ============================================================================ scoring / output
def counts(v):
    return dict(zip(CLASSES, np.bincount(v, minlength=K).tolist()))


def per_class_ranking(y, proba):
    ap, auc = {}, {}
    for k in LABELS:
        pos = y == k
        ok = pos.any() and (~pos).any()
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


def _js(o):
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
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(r, f, indent=1, default=_js)
    os.replace(tmp, path)


def with_ext(path, ext):
    """path + ext. Not Path.with_suffix: tuning names contain dots ('...-d0.2_random_raw_s42')."""
    return path.with_name(path.name + ext)


def save(path, r, y_te, p, proba, rows, sub_te):
    # npz first, JSON last and atomically: the JSON marks the run as finished (resume check)
    npz = with_ext(path, '.npz')
    tmp = with_ext(path, '.tmp.npz')
    np.savez_compressed(tmp, y=y_te.astype(np.int8), p=p.astype(np.int8),
                        proba=proba.astype(np.float16), rows=rows.astype(np.int32),
                        sub=np.asarray(sub_te, dtype=str))            # str: loads without pickle
    os.replace(tmp, npz)
    write_json(with_ext(path, '.json'), r)


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
                    ram_available_gb_at_start=round(vm.available / 2**30, 1))
    except Exception:
        pass
    info['gpu'] = torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    try:
        q = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader'],
                           capture_output=True, text=True, timeout=15)
        if q.returncode == 0 and q.stdout.strip():
            info['gpu_smi'] = q.stdout.strip().splitlines()[0]
    except Exception:
        pass
    import sklearn
    info['versions'] = {'python': platform.python_version(), 'torch': torch.__version__,
                        'cuda': torch.version.cuda, 'cudnn': torch.backends.cudnn.version(),
                        'numpy': np.__version__, 'sklearn': sklearn.__version__}
    info['device_used'] = str(S.DEVICE)
    return info


# ============================================================================ plan
def run_dir(protocol, lr_monitor, max_epochs):
    name = protocol
    if protocol == 'fixed' and lr_monitor != 'train':
        name += f'_lr-{lr_monitor}'
    if max_epochs != PAPER_EPOCHS:
        name += f'_e{max_epochs}'
    return OUT / name


def tune_dir(max_epochs):
    return OUT / ('mlp_tuning' + ('' if max_epochs == PAPER_EPOCHS else f'_e{max_epochs}'))


def run_name(m, s, c, sd):
    return f'{m}_{s}_{c}_s{sd}'                 # the deep_split naming


def load_mlp_cfg(max_epochs):
    f = tune_dir(max_epochs) / 'mlp_config.json'
    if not f.exists():
        return None
    with open(f, encoding='utf-8') as fh:
        return json.load(fh)['chosen']


def default_seeds(protocol, model):
    if protocol == 'fixed':
        return SEEDS_FIXED
    return SEEDS_EARLY_PAPER if model in PAPER_MODELS else SEEDS_EARLY_NEW


def plan(a):
    """Jobs in seed-major order; status: done | deep_split | no-config | todo."""
    if a.tune:
        d = tune_dir(a.max_epochs)
        jobs = [dict(model='MLP', seed=TUNE_SEED, split=TUNE_SPLIT, cleaning=TUNE_CLEANING, cfg=c,
                     role='tuning', name=f'MLP-{cfg_tag(c)}_{TUNE_SPLIT}_{TUNE_CLEANING}_s{TUNE_SEED}', dir=d)
                for c in MLP_GRID]
    else:
        d = run_dir(a.protocol, a.lr_monitor, a.max_epochs)
        mlp_cfg = load_mlp_cfg(a.max_epochs) if 'MLP' in a.models else None
        seed_lists = {m: (a.seeds or default_seeds(a.protocol, m)) for m in a.models}
        order = []
        for m in a.models:
            for sd in seed_lists[m]:
                if sd not in order:
                    order.append(sd)
        jobs = [dict(model=m, seed=sd, split=s, cleaning=c, cfg=mlp_cfg if m == 'MLP' else None,
                     role='run', name=run_name(m, s, c, sd), dir=d)
                for sd in order for m in a.models if sd in seed_lists[m] for s in a.splits for c in a.cleaning]
    for j in jobs:
        if (j['dir'] / f'{j["name"]}.json').exists():
            j['status'] = 'done'
        elif (j['role'] == 'run' and a.protocol == 'earlystop' and a.max_epochs == PAPER_EPOCHS
              and j['model'] in PAPER_MODELS and (OLD / f'{j["name"]}.json').exists() and not a.rerun_existing):
            j['status'] = 'deep_split'
        elif j['model'] == 'MLP' and j['cfg'] is None:
            j['status'] = 'no-config'
        else:
            j['status'] = 'todo'
    return jobs


# ============================================================================ data
class Data:
    """load_prepared() once per process; split indices cached per (split, cleaning)."""

    def __init__(self):
        X, meta, flags = load_prepared()                # column by column: peak ~1.6 GB
        self.X = X
        self.meta = meta.reset_index(drop=True)         # RangeIndex: split positions = global row positions
        self.flags = flags
        self.y = self.meta['y'].to_numpy()
        self.sub = self.meta['sub'].astype(str).to_numpy()
        self._splits = {}

    def split(self, s, c):
        if (s, c) not in self._splits:
            rows = kept_rows(self.flags, c)
            tr, va, te = splits(self.meta.iloc[rows].reset_index(drop=True), s)   # positions within `rows`
            self._splits[(s, c)] = (rows[tr], rows[va], rows[te])               # -> global positions
        return self._splits[(s, c)]

    def release_X(self):
        self.X = None
        gc.collect()


# ============================================================================ one run
def run_one(j, D, a, hw, last_fit):
    m, sd, s, c = j['model'], j['seed'], j['split'], j['cleaning']
    protocol = 'earlystop' if j['role'] == 'tuning' else a.protocol
    lr_monitor = 'val' if protocol == 'earlystop' else a.lr_monitor
    sp = spec(m, j['cfg'])
    tr, va, te = D.split(s, c)
    Xtr, Xva, Xte = D.X[tr], D.X[va], D.X[te]            # copies (fancy indexing)
    if last_fit:
        D.release_X()                                    # the full matrix is not needed any more
    y, sub = D.y, D.sub
    ytr, yva, yte = y[tr], y[va], y[te]
    missing = [CLASSES[k] for k in LABELS if not (ytr == k).any()]
    if missing:
        raise RuntimeError(f'{j["name"]}: no training rows for {missing}')
    cw = compute_class_weight('balanced', classes=np.arange(K), y=ytr).astype(np.float32)

    t0 = time.time()                                     # fit time as deep_split: scaler + net + loop
    sc = fit_scaler(Xtr)
    scale_inplace(sc, Xtr); scale_inplace(sc, Xva)
    np.random.seed(sd); torch.manual_seed(sd)            # as run_one + the wrapper's fit()
    net = sp['build'](Xtr.shape[1])
    n_params = int(sum(p.numel() for p in net.parameters()))
    net, hist, info = train(net, Xtr, ytr, Xva, yva, cw, a.max_epochs, sp['batch_size'], sp['lr'],
                            protocol, lr_monitor)
    fit_s = time.time() - t0
    del Xtr, Xva; gc.collect()

    proba, p, inf = timed_predict(net, sc, Xte, a.timing_repeats)       # p: argmax of the logits
    p = p.astype(np.int8)
    del Xte; gc.collect()
    r = score(yte, p, sub[te], proba)
    r.update({'model': m, 'split': s, 'cleaning': c, 'seed': sd, 'protocol': protocol, 'lr_monitor': lr_monitor,
              'role': j['role'], 'split_seed': 42 if s == 'random' else None,
              'max_epochs': a.max_epochs, 'patience': PATIENCE if protocol == 'earlystop' else None,
              'epochs_run': info['epochs_run'], 'best_epoch': info['best_epoch'],
              'stopped_early': info['stopped_early'], 'val_best_epoch': info['val_best_epoch'],
              'val_loss_min': info['val_loss_min'], 'val_loss_selected': info['val_loss_selected'],
              'val_macro_f1_selected': info['val_macro_f1_selected'], 'val_macro_f1_max': info['val_macro_f1_max'],
              'fit_seconds': round(fit_s, 1), 'val_seconds': round(info['val_seconds'], 1),
              'seconds_per_epoch': round(fit_s / max(1, info['epochs_run']), 2),
              'inference': inf, 'n_params': n_params,
              'arch': {'lr': sp['lr'], 'batch_size': sp['batch_size'], 'optimizer': 'Adam',
                       'scheduler': 'ReduceLROnPlateau(factor=0.5, patience=5)', 'lr_monitor': lr_monitor,
                       'amp': info['amp'], 'grad_clip_norm': S.TRAINING_CONFIG.get('gradient_clip_norm', 1.0),
                       'loss': 'cross-entropy, balanced class weights', 'config': sp['config'],
                       'scaler': 'StandardScaler statistics of fit() computed in chunks (bit-identical)'},
              'class_weights': dict(zip(CLASSES, cw.round(6).tolist())),
              'n_train': int(len(tr)), 'n_val': int(len(va)), 'n_test': int(len(te)),
              'train_class_counts': counts(ytr), 'test_class_counts': counts(yte),
              'history': {k: [round(v, 6) for v in vals] for k, vals in hist.items()},
              'hardware': hw, 'script': 'experiments/deep_protocol_study.py',
              'created': time.strftime('%Y-%m-%d %H:%M:%S')})
    if m == 'MLP':
        r['mlp_config'] = {'hidden': sp['config']['hidden'], 'dropout': sp['config']['dropout'],
                           'tag': cfg_tag(sp['config'])}
    old = OLD / f'{j["name"]}.json'
    if j['role'] == 'run' and protocol == 'earlystop' and a.max_epochs == PAPER_EPOCHS and old.exists():
        with open(old, encoding='utf-8') as fh:                  # a rerun of a paper run: record the original
            o = json.load(fh)
        keys = ('macro_f1', 'balanced_accuracy', 'accuracy', 'epochs_run', 'n_test')
        r['deep_split_original'] = {k: o.get(k) for k in keys}
        r['deep_split_original']['identical'] = all(o.get(k) == r[k] for k in keys)
    j['dir'].mkdir(parents=True, exist_ok=True)
    save(j['dir'] / j['name'], r, yte, p, proba, te, sub[te])
    del net, proba; gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return r


# ============================================================================ tuning result
def finalize_tuning(a):
    """Choose the MLP configuration when all trials exist; copy the chosen trial to earlystop/."""
    d = tune_dir(a.max_epochs)
    trials = []
    for c in MLP_GRID:
        f = d / f'MLP-{cfg_tag(c)}_{TUNE_SPLIT}_{TUNE_CLEANING}_s{TUNE_SEED}.json'
        if not f.exists():
            return None
        with open(f, encoding='utf-8') as fh:
            r = json.load(fh)
        trials.append({'tag': cfg_tag(c), 'hidden': c['hidden'], 'dropout': c['dropout'], 'run': f.stem,
                       'val_macro_f1_selected': r['val_macro_f1_selected'], 'best_epoch': r['best_epoch'],
                       'epochs_run': r['epochs_run'], 'val_loss_selected': r['val_loss_selected'],
                       'test_macro_f1_not_used': r['macro_f1']})
    best = max(range(len(trials)), key=lambda i: (trials[i]['val_macro_f1_selected'], -i))
    ch = trials[best]
    out = {'chosen': {'hidden': ch['hidden'], 'dropout': ch['dropout'], 'tag': ch['tag']},
           'criterion': 'validation macro-F1 of the weights selected by early stopping (random/raw, seed 42); '
                        'ties -> first configuration in the grid order; the test set is not used',
           'condition': {'split': TUNE_SPLIT, 'cleaning': TUNE_CLEANING, 'seed': TUNE_SEED,
                         'protocol': 'earlystop', 'max_epochs': a.max_epochs},
           'grid': MLP_GRID, 'trials': trials, 'chosen_run': ch['run'],
           'created': time.strftime('%Y-%m-%d %H:%M:%S')}
    write_json(d / 'mlp_config.json', out)
    dst_dir = run_dir('earlystop', 'val', a.max_epochs)
    dst = dst_dir / run_name('MLP', TUNE_SPLIT, TUNE_CLEANING, TUNE_SEED)
    if not with_ext(dst, '.json').exists():
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(d / f'{ch["run"]}.npz', with_ext(dst, '.npz'))
        with open(d / f'{ch["run"]}.json', encoding='utf-8') as fh:
            r = json.load(fh)
        r.update({'role': 'run', 'from_tuning_trial': f'{d.name}/{ch["run"]}'})
        write_json(with_ext(dst, '.json'), r)
        print(f'[tune] chosen trial copied to {dst_dir.name}/{dst.name}', flush=True)
    print(f'[tune] chosen MLP configuration: {ch["tag"]} (validation macro-F1 {ch["val_macro_f1_selected"]:.4f}); '
          f'written to {d.name}/mlp_config.json', flush=True)
    for t in trials:
        print(f'  {t["tag"]:22s} val-F1={t["val_macro_f1_selected"]:.4f} best epoch={t["best_epoch"]:>2} '
              f'(test macro-F1 {t["test_macro_f1_not_used"]:.4f}, not used)', flush=True)
    return out


# ============================================================================ main
def main():
    global OUT
    ap = argparse.ArgumentParser(description='Deep models: seeds, early stopping vs fixed epochs, probabilities, '
                                             'inference time, MLP and 1-D CNN baselines (see docstring).')
    ap.add_argument('--protocol', choices=['earlystop', 'fixed'], default='earlystop')
    ap.add_argument('--fixed-lr', dest='lr_monitor', choices=['train', 'val', 'none'], default='train',
                    help="fixed protocol only: what ReduceLROnPlateau monitors (default 'train': no validation data)")
    ap.add_argument('--models', nargs='+', choices=ALL_MODELS, default=PAPER_MODELS)
    ap.add_argument('--seeds', nargs='+', type=int, default=None,
                    help='training seeds (default earlystop: 7 123 2024 for the paper models, 17 42 7 123 2024 for '
                         'MLP / CNN1D_Hossain; fixed: 17 42)')
    ap.add_argument('--splits', nargs='+', choices=SPLITS, default=SPLITS)
    ap.add_argument('--cleaning', nargs='+', choices=CLEANING, default=CLEANING)
    ap.add_argument('--max-epochs', type=int, default=PAPER_EPOCHS)
    ap.add_argument('--tune', action='store_true', help='MLP tuning trials (4 configurations, random/raw, seed 42)')
    ap.add_argument('--rerun-existing', action='store_true',
                    help='earlystop: also fit paper-model runs that exist in deep_split (written to the new folder)')
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N fits (0 = no limit); with 1 in a PowerShell loop every fit is a fresh process')
    ap.add_argument('--timing-repeats', type=int, default=3, help='timed passes over the test set (median reported)')
    ap.add_argument('--device', choices=['auto', 'cpu'], default='auto', help='cpu: smoke tests only')
    ap.add_argument('--out-root', default=None, help='output root instead of q1_revision/deep_protocol (tests)')
    ap.add_argument('--plan', action='store_true', help='only list the runs and their status')
    a = ap.parse_args()
    if a.out_root:
        OUT = Path(a.out_root)
    if a.device == 'cpu':
        S.DEVICE = torch.device('cpu')
    if a.tune:
        if a.protocol != 'earlystop':
            print('[note] --tune always uses the earlystop protocol', flush=True)
        a.protocol, a.models = 'earlystop', ['MLP']
    if a.protocol == 'earlystop':
        a.lr_monitor = 'val'

    jobs = plan(a)
    todo = [j for j in jobs if j['status'] == 'todo']
    n = {st: sum(j['status'] == st for j in jobs) for st in ('done', 'deep_split', 'no-config')}
    where = jobs[0]['dir'].relative_to(RES) if jobs and jobs[0]['dir'].is_relative_to(RES) else (jobs[0]['dir'] if jobs else OUT)
    print(f'[plan] {"MLP tuning" if a.tune else "protocol=" + a.protocol + ("" if a.protocol == "earlystop" else f" lr-monitor={a.lr_monitor}")}'
          f' max_epochs={a.max_epochs} -> {where}: {len(jobs)} runs, {n["done"]} finished, '
          f'{n["deep_split"]} in deep_split (pooled, not refitted), {len(todo)} to do'
          + (f', {n["no-config"]} MLP runs wait for --tune' if n['no-config'] else ''), flush=True)
    if n['no-config']:
        print('[skip] MLP: no tuned configuration yet - run first:  --models MLP --tune', flush=True)
    if a.plan:
        for j in jobs:
            print(f'  {j["status"]:10s} {j["name"]}')
        return
    if a.tune and not todo:
        finalize_tuning(a)
        return
    if not todo:
        print('[DONE] all runs finished', flush=True)
        return

    if a.device == 'auto' and (S.DEVICE is None or S.DEVICE.type != 'cuda'):
        # the paper runs and the inference timing are GPU runs: never fall back to hours of CPU training
        print('[ERROR] CUDA is not available (torch.cuda.is_available() is False); no run started. '
              'Check the GPU driver / the MyProject environment, or pass --device cpu for a smoke test.', flush=True)
        sys.exit(2)
    n_here = len(todo) if not a.max_fits else min(a.max_fits, len(todo))
    hw = hardware()
    print(f'[device] {S.DEVICE} {hw.get("gpu") or ""}', flush=True)
    D = Data()
    for i, j in enumerate(todo[:n_here], 1):
        t = time.time()
        print(f'===== [{i}/{n_here}] {j["name"]} | {j["role"]} | protocol={"earlystop" if a.tune else a.protocol}'
              + (f' | MLP {cfg_tag(j["cfg"])}' if j['model'] == 'MLP' else '') + ' =====', flush=True)
        r = run_one(j, D, a, hw, last_fit=(i == n_here))
        inf = r['inference']
        print(f'[result] {j["name"]} macro-F1={r["macro_f1"]:.4f} bal-acc={r["balanced_accuracy"]:.4f} '
              f'macro-AP={"n/a" if r["macro_ap"] is None else format(r["macro_ap"], ".4f")} '
              f'epochs={r["epochs_run"]} best={r["best_epoch"]} '
              f'(val-loss min at {r["val_best_epoch"]}) fit={r["fit_seconds"] / 60:.1f} min '
              f'infer={inf["seconds"]:.2f}s ({inf["seconds_per_1000_flows"] * 1000:.2f} ms/1k flows) '
              f'[{(time.time() - t) / 60:.1f} min]', flush=True)
        o = r.get('deep_split_original')
        if o:
            print(f'[rerun] deep_split original: macro-F1={o["macro_f1"]:.6f} epochs={o["epochs_run"]}; this run '
                  f'{r["macro_f1"]:.6f} epochs={r["epochs_run"]} (difference {r["macro_f1"] - o["macro_f1"]:+.2e}; '
                  f'{"identical" if o["identical"] else "NOT identical"})', flush=True)
    left = len(todo) - n_here
    if a.tune and not left:
        finalize_tuning(a)
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)


if __name__ == '__main__':
    main()
