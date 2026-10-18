# -*- coding: utf-8 -*-
r"""
shared_budget_study.py
======================
Round-2 review (Reviewer 2, point 3): the neural-versus-tree comparison of the paper used unmatched optimisation
effort (only the MLP was tuned), a 30-epoch ceiling, and early stopping on the validation PERIOD that follows the
training period. This study gives every model family the same, predeclared validation budget, draws the
validation set from the training period, raises the epoch ceiling, and reports convergence and how stable the
ranking of the eight models is over training seeds and label conditions.

Data and split: the flagged sample (flagged_loader.load_prepared(), 3,626,502 flows, NaN/inf -> 0), labels raw
or R1 (R1-flagged attack flows removed first), and the paper's temporal split within capture groups
(deep_split_noise_study.splits(..., 'temporal'): first 70% of each group's flows in time order = training period,
last 15% = test; the 15% between them are NOT used). Inside the training period, 15/70 of the flows of every
capture group (stratified by group, seed 42) form the IN-PERIOD VALIDATION set; the rest (55% of each group)
is the training set. Training, validation and test rows are the same for every model, seed and configuration.

Predeclared budget (grid.json, written by --declare and committed to the public repository BEFORE any run; the
script refuses to run when the grid in the code differs from grid.json): four configurations per family, the
first being the paper's setting.
  networks   learning rate {paper, paper / 3} x batch size {paper, 2 x paper}; Adam, class-weighted
             cross-entropy, early stopping on the in-period validation loss (patience 10, best weights restored),
             ReduceLROnPlateau on the validation loss, at most 100 epochs; architectures unchanged
             (ResNet1D, GRU, Transformer of src/stage3_ml_models.py; MLP with the configuration chosen in the
             paper; 1-D CNN of Hossain as re-implemented in deep_protocol_study.py)
  XGBoost    max_depth {8, 12} x learning_rate {0.1, 0.3}        (200 trees, hist, GPU)
  LightGBM   num_leaves {127, 31} x learning_rate {0.1, 0.05}    (300 trees, subsample 0.8, colsample 0.8)
  RF         max_depth {24, 32} x max_features {sqrt, 0.2}       (100 trees, min_samples_leaf 2, max_samples 0.3)
  Selection: the configuration with the highest macro-F1 on the in-period validation set (networks: of the
  early-stopped weights), on the temporal split with RAW labels and seed 42; ties -> the earlier configuration.
  The chosen configuration is used unchanged for the R1 labels. The test set is never used for the choice.
Final runs: chosen configuration x seeds 42, 17, 7 x labels raw, R1 (XGBoost: seed-independent, one run per
label condition; the raw seed-42 run of each family is its tuning run, not refitted).
Fits: tuning 5 x 4 networks + 3 x 4 trees = 32; final networks 5 x (6 - 1) = 25, trees 1 + 2 x 5 = 11.
GPU time (RTX 5070 laptop, from the epoch times of deep_protocol_study.py scaled to 55% of the rows):
about 25-45 s per epoch (Transformer the slowest; batch x2 about 0.6x), early stopping typically after 15-40
epochs: roughly 10-40 min per network fit, 15-30 h for all 45 network fits. Trees: minutes per fit (RF and
LightGBM on the CPU, several GB: one fit per process).

Stored per run (JSON + NPZ, as deep_protocol_study.py): test metrics (score(): macro-F1, balanced accuracy,
per-class F1/precision/recall, confusion, macro-AP), validation macro-F1, configuration, seed, convergence
(epochs_run, best_epoch, stopped_early, hit_ceiling, val_best_epoch, per-epoch history), fit time; NPZ: y, p,
proba (float16), rows (global), sub. Weights: networks <name>.pt (state_dict + standardisation), XGBoost
<name>.xgb.json, LightGBM <name>.lgb.txt; random-forest forests are not stored (hundreds of MB each; refit
from the configuration and seed).
Summary (--summary): tuning.csv, runs.csv, cells.csv (mean, SD, min-max per model and labels), ranking.csv
(rank of every model per seed and labels), ranking_stability.json (Kendall's W over the six rankings, mean
rank, share of rankings with every tree ensemble above every network, best tree - best network per ranking),
convergence.csv, versus_paper.csv (same cells under the paper's protocol, for reference).

Repeated runs (2026-10-18): in the first pass, one R1 in-period validation flow (a DOS flow whose feat_min lies
1.2e5 standard deviations from the training mean) overflowed half precision in the AMP validation pass of the four
networks that read that feature, so the validation loss was NaN in every epoch and the 12 R1 runs of ResNet1D, GRU,
Transformer and MLP stopped after the 10-epoch patience without early stopping on a finite loss (the 1-D CNN, whose
valid convolutions and pooling never reach the last three features, and all raw and tuning runs had finite losses).
deep_protocol_study.train now evaluates such a chunk again in single precision; those 12 runs were moved to
shared_budget/superseded_fp16_overflow/ and run again; --summary refuses a network run with a non-finite
validation loss. Tuning and the configuration choice are unaffected (raw labels, all losses finite).

Output: results_2026_03_03/q1_revision/shared_budget/{grid.json, tuning/, final/, summary/}
Run (PowerShell, from the project folder):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  & $py experiments\shared_budget_study.py --declare            # once, then commit grid.json
  & $py experiments\shared_budget_study.py --plan
  1..20 | ForEach-Object { & $py experiments\shared_budget_study.py --stage tune --families nets --max-fits 1 2>&1 | Tee-Object -FilePath shared_budget.log -Append }
  1..12 | ForEach-Object { & $py experiments\shared_budget_study.py --stage tune --families trees --max-fits 1 2>&1 | Tee-Object -FilePath shared_budget.log -Append }
  1..25 | ForEach-Object { & $py experiments\shared_budget_study.py --stage final --families nets --max-fits 1 2>&1 | Tee-Object -FilePath shared_budget.log -Append }
  1..11 | ForEach-Object { & $py experiments\shared_budget_study.py --stage final --families trees --max-fits 1 2>&1 | Tee-Object -FilePath shared_budget.log -Append }
  & $py experiments\shared_budget_study.py --summary
"""
import argparse, gc, hashlib, json, os, sys, time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deep_protocol_study as D  # noqa: E402  (networks, training loop, scaler, prediction, scoring, saving)
from deep_split_noise_study import kept_rows, splits  # noqa: E402
from flagged_loader import load_prepared  # noqa: E402
from pilot_temporal_split import CLASSES, SEED  # noqa: E402

torch = D.torch
RES = HERE.parent / 'results_2026_03_03'
OUT = RES / 'q1_revision' / 'shared_budget'
K = len(CLASSES)
NETS = ['ResNet1D', 'GRU', 'Transformer', 'MLP', 'CNN1D_Hossain']
TREES = ['XGBoost', 'LightGBM', 'RandomForest']
MAX_EPOCHS, PATIENCE = 100, 10
VAL_FRAC = 0.15 / 0.70                      # of each group's training period
TUNE = {'split': 'temporal', 'cleaning': 'raw', 'seed': 42}
SEEDS = [42, 17, 7]
CLEANINGS = ['raw', 'r1']
PAPER_BATCH = {'ResNet1D': 512, 'GRU': 512, 'Transformer': 256, 'MLP': 512, 'CNN1D_Hossain': 512}


def build_grid():
    g = {}
    for m in NETS:
        lr, b = D.LR[m], PAPER_BATCH[m]
        g[m] = [{'lr': lr, 'batch_size': b}, {'lr': lr, 'batch_size': 2 * b},
                {'lr': lr / 3, 'batch_size': b}, {'lr': lr / 3, 'batch_size': 2 * b}]
    g['XGBoost'] = [{'max_depth': d, 'learning_rate': l} for d in (8, 12) for l in (0.1, 0.3)]
    g['LightGBM'] = [{'num_leaves': n, 'learning_rate': l} for n in (127, 31) for l in (0.1, 0.05)]
    g['RandomForest'] = [{'max_depth': d, 'max_features': f} for d in (24, 32) for f in ('sqrt', 0.2)]
    return g


GRID = build_grid()
SETTINGS = {'split': 'temporal within capture groups (deep_split_noise_study.splits), middle 15% unused',
            'validation': f'in-period: {VAL_FRAC:.6f} of the training period of every capture group, stratified, seed 42',
            'max_epochs': MAX_EPOCHS, 'patience': PATIENCE, 'selection': 'highest in-period validation macro-F1, '
            'temporal split, raw labels, seed 42; ties -> earlier configuration; test set never used',
            'final_seeds': SEEDS, 'labels': CLEANINGS}


def grid_hash():
    return hashlib.sha256(json.dumps({'grid': GRID, 'settings': SETTINGS}, sort_keys=True).encode()).hexdigest()


def cfg_tag(m, cfg):
    if m in NETS:
        return f'lr{cfg["lr"]:.2e}-b{cfg["batch_size"]}'
    return '-'.join(f'{k}{v}' for k, v in cfg.items())


def make_tree(m, cfg, seed):
    if m == 'XGBoost':
        import xgboost as xgb
        return xgb.XGBClassifier(n_estimators=200, max_depth=cfg['max_depth'], learning_rate=cfg['learning_rate'],
                                 tree_method='hist', device='cuda', random_state=SEED, eval_metric='mlogloss')
    if m == 'LightGBM':
        import lightgbm as lgb
        return lgb.LGBMClassifier(n_estimators=300, num_leaves=cfg['num_leaves'], learning_rate=cfg['learning_rate'],
                                  subsample=0.8, subsample_freq=1, colsample_bytree=0.8, random_state=seed,
                                  n_jobs=-1, verbose=-1)
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=100, max_depth=cfg['max_depth'], max_features=cfg['max_features'],
                                  min_samples_leaf=2, max_samples=0.3, n_jobs=2, random_state=seed)


# ============================================================================ jobs
def tune_path(m, i):
    return OUT / 'tuning' / f'{m}_c{i}_{cfg_tag(m, GRID[m][i])}_temporal_raw_s42'


def final_path(m, c, sd):
    return OUT / 'final' / f'{m}_temporal_{c}_s{sd}'


def done(path):
    return D.with_ext(path, '.json').exists()


def chosen(m):
    """Index of the chosen configuration of family m, or None while tuning is incomplete."""
    vals = []
    for i in range(len(GRID[m])):
        p = D.with_ext(tune_path(m, i), '.json')
        if not p.exists():
            return None
        with open(p, encoding='utf-8') as f:
            vals.append(json.load(f)['val_macro_f1'])
    return int(np.argmax(vals))                 # first maximum = earlier configuration on ties


def jobs(stage, families):
    out = []
    fams = (NETS if 'nets' in families else []) + (TREES if 'trees' in families else [])
    if stage in ('tune', 'all'):
        for m in fams:
            for i in range(len(GRID[m])):
                out.append({'role': 'tuning', 'model': m, 'cfg_index': i, 'cleaning': 'raw', 'seed': 42,
                            'path': tune_path(m, i)})
    if stage in ('final', 'all'):
        for c in CLEANINGS:
            for sd in SEEDS:
                for m in fams:
                    if m == 'XGBoost' and sd != SEEDS[0]:
                        continue
                    out.append({'role': 'final', 'model': m, 'cfg_index': None, 'cleaning': c, 'seed': sd,
                                'path': final_path(m, c, sd)})
    return out


def status(j):
    if done(j['path']):
        return 'done'
    if j['role'] == 'final':
        ci = chosen(j['model'])
        if ci is None:
            return 'waiting for tuning'
        if j['cleaning'] == 'raw' and j['seed'] == 42:
            return 'copy of tuning run'
    return 'todo'


# ============================================================================ data
class Data:
    def __init__(self):
        X, meta, flags = load_prepared()
        self.X, self.meta, self.flags = X, meta.reset_index(drop=True), flags
        self.y = self.meta['y'].to_numpy()
        self.sub = self.meta['sub'].astype(str).to_numpy()
        self._sp = {}

    def split(self, c):
        if c not in self._sp:
            from sklearn.model_selection import train_test_split
            rows = kept_rows(self.flags, c)
            mk = self.meta.iloc[rows].reset_index(drop=True)
            tr, _, te = splits(mk, 'temporal')                       # positions within `rows`
            gid = mk['y'].to_numpy() * 64 + mk['sub'].cat.codes.to_numpy()
            fit, va = train_test_split(tr, test_size=VAL_FRAC, stratify=gid[tr], random_state=SEED)
            self._sp[c] = (rows[np.sort(fit)], rows[np.sort(va)], rows[te])
        return self._sp[c]


# ============================================================================ one run
def run_net(j, cfg, data, hw, last):
    m, c, sd = j['model'], j['cleaning'], j['seed']
    tr, va, te = data.split(c)
    Xtr, Xva, Xte = data.X[tr], data.X[va], data.X[te]
    if last:
        data.X = None; gc.collect()
    y, sub = data.y, data.sub
    ytr, yva, yte = y[tr], y[va], y[te]
    cw = D.compute_class_weight('balanced', classes=np.arange(K), y=ytr).astype(np.float32)
    sp = D.spec(m, D.load_mlp_cfg(D.PAPER_EPOCHS) if m == 'MLP' else None)
    t0 = time.time()
    sc = D.fit_scaler(Xtr)
    D.scale_inplace(sc, Xtr); D.scale_inplace(sc, Xva)
    np.random.seed(sd); torch.manual_seed(sd)
    net = sp['build'](Xtr.shape[1])
    n_params = int(sum(p.numel() for p in net.parameters()))
    net, hist, info = D.train(net, Xtr, ytr, Xva, yva, cw, MAX_EPOCHS, cfg['batch_size'], cfg['lr'],
                              'earlystop', 'val', patience=PATIENCE)
    fit_s = time.time() - t0
    del Xtr, Xva; gc.collect()
    proba, p, inf = D.timed_predict(net, sc, Xte, 1)
    p = p.astype(np.int8)
    del Xte; gc.collect()
    r = D.score(yte, p, sub[te], proba)
    r.update({'val_macro_f1': info['val_macro_f1_selected'], 'epochs_run': info['epochs_run'],
              'best_epoch': info['best_epoch'], 'stopped_early': info['stopped_early'],
              'hit_ceiling': (not info['stopped_early']) and info['epochs_run'] == MAX_EPOCHS,
              'val_best_epoch': info['val_best_epoch'], 'val_loss_min': info['val_loss_min'],
              'val_chunks_fp32': info['val_chunks_fp32'],
              'history': {k: [round(v, 6) for v in vals] for k, vals in hist.items()},
              'n_params': n_params, 'fit_seconds': round(fit_s, 1), 'inference': inf,
              'arch': {'config': sp['config'], 'optimizer': 'Adam', 'scheduler': 'ReduceLROnPlateau(0.5, 5) on val loss',
                       'amp': info['amp'], 'loss': 'cross-entropy, balanced class weights'},
              'class_weights': dict(zip(CLASSES, cw.round(6).tolist()))})
    w = D.with_ext(j['path'], '.pt')
    torch.save({'state_dict': {k: v.cpu() for k, v in net.state_dict().items()}, 'model': m, 'config': cfg,
                'arch_config': sp['config'], 'scaler_mean': sc.mean_, 'scaler_scale': sc.scale_,
                'classes': CLASSES, 'features': 'pilot_temporal_split.FEATS (81)'}, w)
    r['weights'] = w.name
    del net; gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return r, yte, p, proba, te


def run_tree(j, cfg, data, hw, last):
    from sklearn.utils.class_weight import compute_sample_weight
    m, c, sd = j['model'], j['cleaning'], j['seed']
    tr, va, te = data.split(c)
    Xtr, Xva, Xte = data.X[tr], data.X[va], data.X[te]
    if last:
        data.X = None; gc.collect()
    y, sub = data.y, data.sub
    present = np.unique(y[tr])
    assert len(present) == K, 'a class has no training rows'
    clf = make_tree(m, cfg, sd)
    t0 = time.time()
    clf.fit(Xtr, y[tr], sample_weight=compute_sample_weight('balanced', y[tr]))
    fit_s = time.time() - t0
    del Xtr; gc.collect()
    pva = np.asarray(clf.predict(Xva)).astype(int).ravel()
    del Xva; gc.collect()
    t1 = time.time()
    proba = np.asarray(clf.predict_proba(Xte), np.float32)
    pred_s = time.time() - t1
    p = proba.argmax(1).astype(np.int8)
    del Xte; gc.collect()
    r = D.score(y[te], p, sub[te], proba)
    r.update({'val_macro_f1': D.macro_f1_from_pred(y[va], pva), 'fit_seconds': round(fit_s, 1),
              'predict_seconds': round(pred_s, 2)})
    if m == 'XGBoost':
        w = D.with_ext(j['path'], '.xgb.json'); clf.save_model(str(w)); r['weights'] = w.name
    elif m == 'LightGBM':
        w = D.with_ext(j['path'], '.lgb.txt'); clf.booster_.save_model(str(w)); r['weights'] = w.name
    else:
        r['weights'] = None
    del clf; gc.collect()
    return r, y[te], p, proba, te


def run_job(j, data, hw, last):
    m = j['model']
    ci = j['cfg_index'] if j['role'] == 'tuning' else chosen(m)
    cfg = GRID[m][ci]
    j['path'].parent.mkdir(parents=True, exist_ok=True)        # the weights are written inside run_net/run_tree
    r, yte, p, proba, te = (run_net if m in NETS else run_tree)(j, cfg, data, hw, last)
    tr, va, _ = data.split(j['cleaning'])
    r.update({'model': m, 'family': 'network' if m in NETS else 'tree ensemble', 'role': j['role'],
              'config_index': ci, 'config': cfg, 'config_tag': cfg_tag(m, cfg), 'split': 'temporal',
              'cleaning': j['cleaning'], 'seed': j['seed'] if m != 'XGBoost' else None,
              'validation': SETTINGS['validation'], 'grid_sha256': grid_hash(),
              'n_train': int(len(tr)), 'n_val': int(len(va)), 'n_test': int(len(te)),
              'hardware': hw, 'script': 'experiments/shared_budget_study.py', 'created': time.strftime('%Y-%m-%d %H:%M:%S')})
    j['path'].parent.mkdir(parents=True, exist_ok=True)
    D.save(j['path'], r, yte, p, proba, te, data.sub[te])
    return r


def copy_tuning_run(j):
    """The raw seed-42 final run is the chosen tuning run (same data, configuration and seed)."""
    import shutil
    m = j['model']
    src = tune_path(m, chosen(m))
    j['path'].parent.mkdir(parents=True, exist_ok=True)
    for ext in ('.npz', '.pt', '.xgb.json', '.lgb.txt'):
        if D.with_ext(src, ext).exists():
            shutil.copyfile(D.with_ext(src, ext), D.with_ext(j['path'], ext))
    with open(D.with_ext(src, '.json'), encoding='utf-8') as f:
        r = json.load(f)
    r.update({'role': 'final', 'copied_from': D.with_ext(src, '.json').name})
    if r.get('weights'):
        r['weights'] = D.with_ext(j['path'], r['weights'][len(src.name):]).name
    D.write_json(D.with_ext(j['path'], '.json'), r)


# ============================================================================ summary
def summary():
    import pandas as pd
    from scipy.stats import rankdata
    S = OUT / 'summary'
    S.mkdir(parents=True, exist_ok=True)
    load = lambda f: json.load(open(f, encoding='utf-8'))
    results = lambda d: [load(f) for f in sorted(d.glob('*.json')) if not f.name.endswith('.xgb.json')]   # not weights
    tune, fin = results(OUT / 'tuning'), results(OUT / 'final')
    bad = [f'{r["role"]} {r["model"]} {r["cleaning"]} s{r["seed"]}' for r in tune + fin
           if r.get('history') and not np.all(np.isfinite(np.asarray(r['history']['val_loss'], float)))]
    if bad:                                     # module docstring, "Repeated runs"
        raise SystemExit(f'network runs with a non-finite validation loss (run them again): {bad}')
    if tune:
        t = pd.DataFrame([{'model': r['model'], 'config_index': r['config_index'], 'config': r['config_tag'],
                           'val_macro_f1': r['val_macro_f1'], 'test_macro_f1': r['macro_f1'],
                           'epochs_run': r.get('epochs_run'), 'best_epoch': r.get('best_epoch'),
                           'hit_ceiling': r.get('hit_ceiling'), 'fit_seconds': r['fit_seconds']} for r in tune])
        t['chosen'] = t.apply(lambda x: chosen(x['model']) == x['config_index'], axis=1)
        t.to_csv(S / 'tuning.csv', index=False)
        print(t.round(4).to_string(index=False))
    if not fin:
        return
    d = pd.DataFrame([{'model': r['model'], 'family': r['family'], 'cleaning': r['cleaning'], 'seed': r['seed'],
                       'config': r['config_tag'], 'macro_f1': r['macro_f1'], 'balanced_accuracy': r['balanced_accuracy'],
                       'macro_ap': r.get('macro_ap'), 'val_macro_f1': r['val_macro_f1'],
                       'epochs_run': r.get('epochs_run'), 'best_epoch': r.get('best_epoch'),
                       'stopped_early': r.get('stopped_early'), 'hit_ceiling': r.get('hit_ceiling'),
                       'val_chunks_fp32': r.get('val_chunks_fp32', 0) if r['model'] in NETS else None,
                       'fit_seconds': r['fit_seconds']} for r in fin])
    d.to_csv(S / 'runs.csv', index=False)
    cells = d.groupby(['model', 'family', 'cleaning']).agg(
        n=('macro_f1', 'size'), macro_f1=('macro_f1', 'mean'), sd=('macro_f1', 'std'), min=('macro_f1', 'min'),
        max=('macro_f1', 'max'), balanced_accuracy=('balanced_accuracy', 'mean'), macro_ap=('macro_ap', 'mean')).reset_index()
    cells.to_csv(S / 'cells.csv', index=False)
    print(cells.round(4).to_string(index=False))
    d.loc[d['family'] == 'network', ['model', 'cleaning', 'seed', 'epochs_run', 'best_epoch', 'stopped_early',
                                     'hit_ceiling', 'val_chunks_fp32']].to_csv(S / 'convergence.csv', index=False)
    # rankings: one per (labels, seed); XGBoost (seed-independent) enters every ranking with its single run
    ranks, stab = [], {}
    for c in CLEANINGS:
        for sd in SEEDS:
            row = {}
            for m in NETS + TREES:
                h = d[(d['model'] == m) & (d['cleaning'] == c) & ((d['seed'] == sd) | d['seed'].isna())]
                if len(h):
                    row[m] = float(h['macro_f1'].iloc[0])
            if len(row) == len(NETS) + len(TREES):
                r = rankdata([-row[m] for m in row], method='average')
                for m, rk in zip(row, r):
                    ranks.append({'cleaning': c, 'seed': sd, 'model': m, 'macro_f1': row[m], 'rank': rk})
                stab[(c, sd)] = row
    if ranks:
        R = pd.DataFrame(ranks)
        R.to_csv(S / 'ranking.csv', index=False)
        M = R.pivot_table(index=['cleaning', 'seed'], columns='model', values='rank')
        m_, n_ = M.shape                                     # m_ rankings (raters), n_ models (objects)
        Rj = M.sum(0)
        W = float(12 * ((Rj - Rj.mean()) ** 2).sum() / (m_ ** 2 * (n_ ** 3 - n_)))
        tree_above = [min(v[t] for t in TREES) > max(v[n] for n in NETS) for v in stab.values()]
        best_gap = [max(v[t] for t in TREES) - max(v[n] for n in NETS) for v in stab.values()]
        out = {'rankings': m_, 'models': n_, 'kendalls_w': round(W, 4),
               'mean_rank': M.mean(0).round(2).sort_values().to_dict(),
               'every_tree_above_every_network': f'{sum(tree_above)} of {len(tree_above)}',
               'best_tree_minus_best_network': {f'{c}/s{sd}': round(g, 4) for (c, sd), g in zip(stab, best_gap)},
               'best_tree_above_best_network': f'{sum(g > 0 for g in best_gap)} of {len(best_gap)}'}
        with open(S / 'ranking_stability.json', 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=1)
        print(json.dumps(out, indent=1))
    # the same cells under the paper's protocol (for reference only: other training rows and validation)
    ref = []
    for m in NETS + TREES:
        for c in CLEANINGS:
            fs = (list((RES / 'q1_revision' / 'deep_protocol' / 'earlystop').glob(f'{m}_temporal_{c}_s*.json'))
                  + list((RES / 'deep_split').glob(f'{m}_temporal_{c}_s*.json'))) if m in NETS else \
                 (list((RES / 'tree_protocol' / 'main').glob(f'{m}_temporal_{c}_s*.json'))
                  + list((RES / 'q1_revision' / 'tree_seeds' / 'runs').glob(f'{m}_temporal_{c}_s*.json')))
            vals = {}
            for f in fs:
                vals.setdefault(f.stem, load(f)['macro_f1'])
            new = d[(d['model'] == m) & (d['cleaning'] == c)]['macro_f1']
            if vals and len(new):
                ref.append({'model': m, 'cleaning': c, 'paper_protocol_mean': round(float(np.mean(list(vals.values()))), 4),
                            'paper_protocol_runs': len(vals), 'shared_budget_mean': round(float(new.mean()), 4),
                            'shared_budget_runs': int(len(new))})
    pd.DataFrame(ref).to_csv(S / 'versus_paper.csv', index=False)


# ============================================================================ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--declare', action='store_true', help='write grid.json (once, before any run)')
    ap.add_argument('--stage', choices=['tune', 'final', 'all'], default='all')
    ap.add_argument('--families', nargs='+', choices=['nets', 'trees'], default=['nets', 'trees'])
    ap.add_argument('--max-fits', type=int, default=0)
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--summary', action='store_true')
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    gfile = OUT / 'grid.json'
    if a.declare:
        if gfile.exists():
            raise SystemExit(f'{gfile} exists already (a declared grid is never rewritten)')
        D.write_json(gfile, {'grid': GRID, 'settings': SETTINGS, 'sha256': grid_hash(),
                             'declared': time.strftime('%Y-%m-%d %H:%M:%S')})
        print('[declared]', gfile, grid_hash()); return
    if a.summary:
        summary(); return
    if not gfile.exists():
        raise SystemExit('no grid.json: run --declare first (and commit it)')
    with open(gfile, encoding='utf-8') as f:
        if json.load(f)['sha256'] != grid_hash():
            raise SystemExit('the grid in the code differs from the declared grid.json')
    js = jobs(a.stage, a.families)
    st = [(j, status(j)) for j in js]
    for s in ('done', 'copy of tuning run', 'waiting for tuning', 'todo'):
        n = sum(x == s for _, x in st)
        if n:
            print(f'[plan] {s}: {n}', flush=True)
    for j, s in st:                                 # copies need no data
        if s == 'copy of tuning run':
            copy_tuning_run(j); print(f'[copy] {j["path"].name}', flush=True)
    todo = [j for j, s in st if s == 'todo']
    if a.plan or not todo:
        if not todo:
            print('[DONE] nothing left in this selection', flush=True)
        return
    if any(j['model'] in NETS for j in todo[:a.max_fits or None]) and not torch.cuda.is_available():
        print('[stop] CUDA is not available; the networks are trained on the GPU only', flush=True)
        raise SystemExit(2)
    hw = D.hardware()
    data = Data()
    n_here = min(len(todo), a.max_fits) if a.max_fits else len(todo)
    for n, j in enumerate(todo[:n_here], 1):
        t0 = time.time()
        r = run_job(j, data, hw, last=(n == n_here))
        print(f'[{n}/{n_here}] {j["role"]:6s} {j["model"]:13s} {r["config_tag"]:24s} {j["cleaning"]:3s} s{j["seed"]:<4} '
              f'val-F1={r["val_macro_f1"]:.4f} test-F1={r["macro_f1"]:.4f} '
              f'{"epochs=" + str(r.get("epochs_run")) if j["model"] in NETS else ""} ({(time.time() - t0) / 60:.1f} min)',
              flush=True)
    left = [j for j in jobs(a.stage, a.families) if status(j) != 'done']
    print(f'[left] {len(left)} runs in this selection', flush=True)


if __name__ == '__main__':
    main()
