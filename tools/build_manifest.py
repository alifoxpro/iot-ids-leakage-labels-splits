# -*- coding: utf-8 -*-
r"""
tools/build_manifest.py -- the versioned manifest of the paper (round-2 review, Reviewer 1, point 5): it links every run,
and through the figure, table and paragraph maps every reported value, to its sample, preprocessing, label mask, split,
model configuration, seed, stored predictions and stored model.

Output (manifest/):
  runs.csv            one line per model run (every result JSON with a macro-F1 under the result folders of the paper, the
                      held-out sub-attack runs, which report recalls only, and the 14 runs of split_pilot/
                      rule_sensitivity.json; the superseded shared-budget runs are not listed): run, folder, script,
                      model, configuration (named by the run, else the fixed settings of its script), training seed,
                      sample, features, preprocessing, class weights, split design (with split seed or cut), training
                      labels, test labels, n_train, n_test, macro-F1, balanced accuracy, accuracy, predictions
                      (release-asset path or 'not stored'), stored model, notes
  analyses.csv        the files of the analyses computed from stored runs (bootstrap, drift, audit, flags), with script
  figures/            the source values of every figure (one JSON per figure, from the figure scripts) and figures.csv:
                      figure, panel, quantity and source files
  paper_map.csv       every paragraph, caption and table of the paper -> the result folders and analyses its values
                      come from (the numbers of each text are listed)
  manifest.json       the git commit, the SHA-256 of the per-flow flag table that defines the sample, and the counts
Usage (from the repository folder; the release assets need not be unzipped):
  python tools/build_manifest.py [--source <working copy with the prediction and model files>]
"""
import csv, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / 'results_2026_03_03'
OUT = ROOT / 'manifest'
FLAGS = RES / 'q1_revision' / 'export_flags' / 'flow_flags.csv.gz'
SAMPLE = 'flagged sample: 3,626,502 flows of CIC IoT-DIAD 2024 (export_flags/flow_flags.csv.gz)'
ZERO = 'NaN/inf -> 0'
MEDIAN = 'NaN/inf -> median of the training rows'
STD = '; networks: standardised with training statistics'
SEED42 = '42 (random_state = SEED of pilot_temporal_split.py)'
# model settings of runs whose result file names no configuration (experiments/extra_baselines.make, used by every tree
# study, and pilot_temporal_split.fit_eval; networks: deep_protocol_study.spec, the paper settings of src/stage3)
TREE_CFG = {'XGBoost': '200 trees, max_depth 8, learning_rate 0.1, hist',
            'LightGBM': '300 trees, 127 leaves, learning_rate 0.1, subsample 0.8, colsample_bytree 0.8',
            'RandomForest': '100 trees, max_depth 24, max_features sqrt, min_samples_leaf 2, max_samples 0.3'}
NET_CFG = {'ResNet1D': 'Adam lr 1e-3, batch 512', 'GRU': 'Adam lr 1e-3, batch 512',
           'Transformer': 'Adam lr 1e-4, batch 256', 'MLP': 'Adam lr 1e-3, batch 512',
           'CNN1D_Hossain': 'Adam lr 1e-3, batch 512', 'CNN1D': 'Adam lr 1e-3, batch 512'}
SYM = {'sym': 'R1 applied to every class (symmetric R1)', 'relabel': 'R1-flagged flows relabelled Benign'}

# folder (relative to results_2026_03_03) -> defaults of its runs
FOLDERS = {
    'deep_split': dict(script='experiments/deep_split_noise_study.py', preprocessing=ZERO + STD),
    'extra_baselines': dict(script='experiments/extra_baselines.py', preprocessing=ZERO, seed=SEED42),
    'tree_protocol/main': dict(script='experiments/tree_protocol_study.py', preprocessing=ZERO),
    'tree_protocol/decomp': dict(script='experiments/tree_protocol_study.py', preprocessing=ZERO),
    'identifier_leakage_v2': dict(script='experiments/identifier_leakage.py', preprocessing=ZERO, model='XGBoost',
                                  seed=SEED42),
    'q1_revision/cicids2017': dict(script='experiments/cicids2017_replication.py', preprocessing=ZERO, seed=SEED42,
                                   sample='CICIDS2017 labelled flows, de-duplicated within each class (2,199,736 flows)'),
    'q1_revision/cleaning_train_only': dict(script='experiments/cleaning_train_only.py', preprocessing=ZERO),
    'q1_revision/day_disjoint': dict(script='experiments/day_disjoint_split.py', preprocessing=ZERO),
    'q1_revision/deep_protocol/earlystop': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/deep_protocol/fixed': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/deep_protocol/mlp_tuning': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/leave_one_subattack_out': dict(script='experiments/leave_one_subattack_out.py', preprocessing=ZERO,
                                                seed=SEED42),
    'q1_revision/published_control': dict(script='experiments/published_protocol_control.py', preprocessing=ZERO,
                                          seed=SEED42,
                                          sample='approximated published setting: 3,243,755 flows, eight classes of '
                                                 'Hossain (2025), no de-duplication'),
    'q1_revision/published_deep': dict(script='experiments/published_deep_control.py', preprocessing=ZERO + STD,
                                       sample='approximated published setting: 3,243,755 flows, eight classes of '
                                              'Hossain (2025), no de-duplication'),
    'q1_revision/r3_train_reference': dict(script='experiments/r3_train_reference.py', preprocessing=ZERO),
    'q1_revision/rolling_origin': dict(script='experiments/rolling_origin.py', preprocessing=ZERO),
    'q1_revision/split_replication/splits': dict(script='experiments/split_replication.py', preprocessing=ZERO),
    'q1_revision/split_replication/weights': dict(script='experiments/split_replication.py', preprocessing=ZERO),
    'q1_revision/symmetric_r1': dict(script='experiments/symmetric_r1.py', preprocessing=ZERO),
    'q1_revision/tree_seeds/runs': dict(script='experiments/tree_seeds_proba.py', preprocessing=ZERO),
    'q1_revision/variant_seeds': dict(script='experiments/variant_seeds.py', preprocessing=MEDIAN),
    'q1_revision/shared_budget/tuning': dict(script='experiments/shared_budget_study.py', preprocessing=ZERO + STD,
                                             seed=SEED42),           # XGBoost rows: seed-independent, random_state 42
    'q1_revision/shared_budget/final': dict(script='experiments/shared_budget_study.py', preprocessing=ZERO + STD,
                                            seed=SEED42),
}
ANALYSES = [
    ('split_pilot', 'experiments/pilot_temporal_split.py, temporal_split_by_subattack.py, diagnose_icmp_confusion.py, '
                    'inspect_attack_ips.py, relabel_background.py, rule_sensitivity.py, temporal_drift_analysis.py, '
                    'protocol_packet_share.py', 'XGBoost pilot and cleaning variants (training-median imputation), '
                    'per-capture diagnostics, rule extent, drift'),
    ('tree_protocol/bootstrap.json', 'experiments/bootstrap_ci.py', 'stratified bootstrap intervals, paired tests'),
    ('q1_revision/analyses', 'experiments/revision_analyses.py', 'attack-class macro-F1, predictions on R1-flagged flows, '
                             'block bootstrap, paired tests, per-class precision/recall, drift-loss association'),
    ('q1_revision/analyses2', 'experiments/revision_analyses2.py', 'capture-level and packet-weighted detection, seed '
                              'means with intervals, Wilson intervals'),
    ('q1_revision/bootstrap_family', 'experiments/bootstrap_family.py', 'the 40 comparisons of Section 5.4, paired block '
                                     'bootstrap with automatic block length, leave one capture group out'),
    ('q1_revision/train_only_bootstrap', 'experiments/train_only_bootstrap.py', 'intervals of the training-only cleaning'),
    ('q1_revision/drift_calibration', 'experiments/drift_calibration.py', 'within-training drift reference'),
    ('q1_revision/rule_validation', 'experiments/rule_validation.py', 'signature checks (first captures)'),
    ('q1_revision/rule_validation2', 'experiments/rule_validation2.py, experiments/audit_design.py',
     'signature checks of all captures, R1 audit, 472-flow audit sample, language-model audit, sampling design'),
    ('q1_revision/export_flags', 'experiments/export_flags.py', 'per-flow R1-R3 flags and split assignments'),
    ('q1_revision/deep_protocol/summary', 'experiments/deep_protocol_summary.py', 'tables of the deep protocol study'),
    ('q1_revision/tree_seeds', 'experiments/tree_seeds_summary.py', 'tables of the tree-ensemble seeds'),
]


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def first(r, *keys, default=''):
    for k in keys:
        if r.get(k) not in (None, ''):
            return r[k]
    return default


# feature-set codes of the identifier controls (published_protocol_control.FSETS, cicids2017_replication.FSET_DESC),
# for result files that name the code without its description
FSET_DESC = {'cicids2017': {'F0': '77 flow features', 'F78': '77 flow features + Destination Port',
                            'FT': '77 flow features + Destination Port + Timestamp',
                            'FA': '77 flow features + all seven identifier columns'},
             'default': {'F0': '81 flow features', 'FT': '81 flow features + Timestamp',
                         'FA': '81 flow features + all seven identifier columns'}}


def features_of(r, folder):
    """'code: description' of a run's features ('81 flow features' when the result file names none)."""
    fs = str(first(r, 'feature_set', default=''))
    desc = r['features'] if isinstance(r.get('features'), str) else ''
    if fs and not desc:
        desc = FSET_DESC['cicids2017' if 'cicids2017' in folder else 'default'].get(fs, '')
    if fs and desc and not desc.startswith(fs):
        return f'{fs}: {desc}'
    return fs or desc or '81 flow features'


def labels(r, folder):
    if 'train_variant' in r:
        return r['train_variant'], f'test rows not flagged by {r.get("test_set", "")}'
    if 'train_cleaning' in r:
        return r['train_cleaning'], r.get('test_cleaning', r['train_cleaning'])
    if r.get('condition') in SYM:                       # symmetric_r1: training and test labels alike
        return SYM[r['condition']], SYM[r['condition']]
    if isinstance(r.get('labels'), str):                # leave_one_subattack_out (raw / r1)
        return r['labels'], r['labels']
    if folder == 'q1_revision/published_deep':          # 'variant' is an input layout there, not a label mask
        return 'raw (folder labels)', 'raw (folder labels)'
    if 'variant' in r and 'label' in r:                 # variant_seeds: rule variant, cleaned jointly
        v = f'{r["label"]} ({r["variant"]})'
        return v, v
    c = first(r, 'cleaning', 'variant', default='raw')
    return c, c


def configuration(r, model):
    """Model settings: the configuration named by the run, else the fixed settings of its script."""
    cfg = first(r, 'config_tag', default='')
    if not cfg and model in TREE_CFG:
        cfg = TREE_CFG[model]
    if not cfg and model in NET_CFG:
        epochs = first(r, 'max_epochs', default='')
        cfg = NET_CFG[model] + '; ' + (r.get('protocol') or 'earlystop') + (f', at most {epochs} epochs' if epochs else '')
    elif r.get('protocol'):
        cfg += '; ' + r['protocol']
    if isinstance(r.get('mlp_config'), dict):
        cfg = (cfg + '; ' if cfg else '') + r['mlp_config'].get('tag', '')
    if r.get('variant') in ('default', 'nopad', 'idsfirst'):          # published_deep input layouts
        cfg = (cfg + '; ' if cfg else '') + f'input layout {r["variant"]}'
    return cfg


def class_weights(r):
    """'balanced', 'none' or 'sqrt' (never the name of a stored model file, which some runs keep under 'weights')."""
    w = first(r, 'weighting', default='')
    if not w:
        v = r.get('weights')
        w = v if isinstance(v, str) and not v.endswith(('.pt', '.json', '.txt')) else 'balanced'
    return w


def split_of(r, folder):
    s = first(r, 'design', 'split', default='')
    extra = []
    if r.get('split_seed') not in (None, ''):
        extra.append(f'split seed {r["split_seed"]}')
    if r.get('split_desc'):
        extra.append(str(r['split_desc']))
    if isinstance(r.get('design_definition'), dict):
        d = r['design_definition']
        extra.append(f'train {d.get("train")} / test {d.get("test")}')
    if isinstance(r.get('validation'), str) and r['validation'].startswith('in-period'):     # shared budget
        extra.append(f'validation {r["validation"]}')
    return '; '.join([str(s)] + extra)


SRC = ROOT          # folder that holds the large files (--source): the predictions and models are release assets


def stored(js):
    rel = lambda p: p.relative_to(ROOT).as_posix()
    base = SRC / js.relative_to(ROOT).with_suffix('')
    pred = SRC / js.relative_to(ROOT).with_suffix('.npz')
    w = [p for p in (base.with_name(base.name + '.pt'), base.with_name(base.name + '.xgb.json'),
                     base.with_name(base.name + '.lgb.txt')) if p.exists()]
    rel = lambda p: p.relative_to(SRC).as_posix()
    return (('release asset: ' + rel(pred)) if pred.exists() else 'not stored',
            ('release asset: ' + rel(w[0])) if w else 'not stored (refit from the script, configuration and seed)')


def main():
    global SRC
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', default=str(ROOT), help='folder with the large files (default: this repository)')
    SRC = Path(ap.parse_args().source).resolve()
    OUT.mkdir(exist_ok=True)
    rows = []
    for folder, d in FOLDERS.items():
        fo = RES / folder
        if not fo.exists():
            continue
        for js in sorted(fo.glob('*.json')):
            if js.name.endswith('.xgb.json') or js.name.startswith('summary'):
                continue
            try:
                r = json.loads(js.read_text(encoding='utf-8'))
            except Exception:
                continue
            if not isinstance(r, dict):
                continue
            notes = ''
            if 'macro_f1' not in r:
                if 'recall_unseen' not in r:                # summaries and diagnostics, not model runs
                    continue
                notes = (f'held-out sub-attack {r.get("held_out_class")} / {r.get("held_out_subattack")}: recall '
                         f'{r["recall_seen"]} when seen in training, {r["recall_unseen"]} when held out (no macro-F1)')
            tr, te = labels(r, folder)
            pred, model_file = stored(js)
            model = first(r, 'model', default=d.get('model', ''))
            seed = first(r, 'seed', 'model_seed', default=d.get('seed', ''))
            if model == 'XGBoost' and 'seed' not in r:
                notes = (notes + '; ' if notes else '') + 'XGBoost: training does not depend on the seed'
            rows.append({
                'run': js.relative_to(RES).with_suffix('').as_posix(), 'folder': folder, 'script': d['script'],
                'model': model, 'configuration': configuration(r, model),
                'training_seed': seed, 'sample': d.get('sample', SAMPLE),
                'features': features_of(r, folder),
                'preprocessing': d['preprocessing'], 'class_weights': class_weights(r),
                'split': split_of(r, folder), 'training_labels': tr, 'test_labels': te,
                'n_train': first(r, 'n_train', default=''), 'n_test': first(r, 'n_test', default=''),
                'macro_f1': r.get('macro_f1'), 'balanced_accuracy': r.get('balanced_accuracy'),
                'accuracy': r.get('accuracy'), 'predictions': pred, 'stored_model': model_file, 'notes': notes})
    # the 14 XGBoost runs of the rule-sensitivity pilot are stored inside one file (variant -> split design)
    rs = RES / 'split_pilot' / 'rule_sensitivity.json'
    if rs.exists():
        designs = {'A_random': 'random 70/15/15, stratified by class (split seed 42)',
                   'D_temporal_subattack': 'temporal 70/15/15 within capture groups'}
        for variant, parts in json.loads(rs.read_text(encoding='utf-8')).items():
            for dsg, m in parts.items():
                if dsg not in designs:
                    continue
                rows.append({
                    'run': f'split_pilot/rule_sensitivity#{variant}/{dsg}', 'folder': 'split_pilot',
                    'script': 'experiments/rule_sensitivity.py', 'model': 'XGBoost',
                    'configuration': TREE_CFG['XGBoost'] + ' (pilot_temporal_split.fit_eval)', 'training_seed': SEED42,
                    'sample': SAMPLE, 'features': '81 flow features', 'preprocessing': MEDIAN, 'class_weights': 'balanced',
                    'split': designs[dsg], 'training_labels': f'rule variant {variant} (flagged rows removed before the split)',
                    'test_labels': f'rule variant {variant}', 'n_train': m.get('n_train', ''), 'n_test': m.get('n_test', ''),
                    'macro_f1': m.get('macro_f1'), 'balanced_accuracy': m.get('balanced_accuracy'),
                    'accuracy': m.get('accuracy'), 'predictions': 'not stored',
                    'stored_model': 'not stored (refit from the script, configuration and seed)',
                    'notes': 'XGBoost: training does not depend on the seed'})
    with open(OUT / 'runs.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    with open(OUT / 'analyses.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['path', 'script', 'content'])
        for p, s, c in ANALYSES:
            if (RES / p).exists():
                w.writerow([f'results_2026_03_03/{p}', s, c])
    # figures: sanitised copies of the source values written by the figure scripts (if present). Round 2: the numeric
    # panels of the former Figs. 5a-c and 6a are printed as Tables 6 and 5 (same values files); the dot plots of
    # Fig. 5 and the held-out sub-attacks of Fig. 6 stay figures
    def printed_as(fid, part):
        if fid == 'Fig. 3':                  # the tree settings are no longer drawn: text of Section 4.2
            return {'trees': 'Section 4.2 (text; formerly drawn in Fig. 3)'}.get(part, fid)
        if fid == 'Fig. 5':
            return {'levels': 'Table 6 (former Fig. 5a-c)', 'text': 'Fig. 5; Table 6'}.get(part, fid)
        if fid == 'Fig. 6':
            return {'held_out': fid, 'text': 'Fig. 6; Table 5'}.get(part, 'Table 5 (former Fig. 6a)')
        return fid
    figrows = []
    vals = ROOT / 'figures' / 'values'
    # one file per figure; the glob alone is case-insensitive on Windows and would also take mid_figure_values.json
    for src in sorted(p for p in vals.glob('mid_F*_values.json') if re.fullmatch(r'mid_F\d_values\.json', p.name)) \
            if vals.exists() else []:
        v = json.loads(src.read_text(encoding='utf-8'))
        fig = v.get('figure')
        fid = fig.get('printed', src.stem) if isinstance(fig, dict) else str(v.get('printed_as') or fig or src.stem)
        vf = src.relative_to(ROOT).as_posix()
        if v.get('sources'):
            for k, s in v['sources'].items():
                figrows.append({'figure': printed_as(fid, k), 'part': k, 'source': s, 'values_file': vf})
        else:                                           # no 'sources' key: the result folders its values cite
            cited = sorted({p.rsplit('/', 1)[0] for p in re.findall(r'results_2026_03_03/[\w./-]+', json.dumps(v))})
            for p in cited or ['study design: counts from the result folders listed in paper_map.csv']:
                figrows.append({'figure': fid, 'part': 'values from', 'source': p, 'values_file': vf})
    if figrows:
        with open(OUT / 'figures.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(figrows[0])); w.writeheader(); w.writerows(figrows)
    try:
        commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except Exception:
        commit = ''
    meta = {'version': 'v2.0', 'commit_at_build': commit, 'sample_definition': 'results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz',
            'sample_sha256': sha256(FLAGS) if FLAGS.exists() else None, 'runs': len(rows),
            'runs_with_predictions': sum(r['predictions'] != 'not stored' for r in rows),
            'runs_with_stored_model': sum(not r['stored_model'].startswith('not stored') for r in rows),
            'files': ['runs.csv', 'analyses.csv', 'figures.csv', 'paper_map.csv']}
    (OUT / 'manifest.json').write_text(json.dumps(meta, indent=1), encoding='utf-8')
    print(f'[manifest] {len(rows)} runs ({meta["runs_with_predictions"]} with predictions, '
          f'{meta["runs_with_stored_model"]} with a stored model), {len(figrows)} figure sources -> {OUT}')


if __name__ == '__main__':
    main()
