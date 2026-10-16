# -*- coding: utf-8 -*-
r"""
tools/build_manifest.py -- the versioned manifest of the paper (round-2 review, Reviewer 1, point 5): it links every run,
and through the figure, table and paragraph maps every reported value, to its sample, preprocessing, label mask, split,
model configuration, seed, stored predictions and stored model.

Output (manifest/):
  runs.csv            one line per model run (every result JSON with a macro-F1 under the result folders of the paper):
                      run, folder, script, model, configuration, training seed, sample, features, preprocessing, class
                      weights, split design (with split seed or cut), training labels, test labels, n_train, n_test,
                      macro-F1, balanced accuracy, accuracy, predictions (release-asset path or 'not stored'), stored model
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

# folder (relative to results_2026_03_03) -> defaults of its runs
FOLDERS = {
    'deep_split': dict(script='experiments/deep_split_noise_study.py', preprocessing=ZERO + STD),
    'extra_baselines': dict(script='experiments/extra_baselines.py', preprocessing=ZERO),
    'tree_protocol/main': dict(script='experiments/tree_protocol_study.py', preprocessing=ZERO),
    'tree_protocol/decomp': dict(script='experiments/tree_protocol_study.py', preprocessing=ZERO),
    'identifier_leakage_v2': dict(script='experiments/identifier_leakage.py', preprocessing=ZERO, model='XGBoost'),
    'q1_revision/cicids2017': dict(script='experiments/cicids2017_replication.py', preprocessing=ZERO,
                                   sample='CICIDS2017 labelled flows, de-duplicated within each class (2,199,736 flows)'),
    'q1_revision/cleaning_train_only': dict(script='experiments/cleaning_train_only.py', preprocessing=ZERO),
    'q1_revision/day_disjoint': dict(script='experiments/day_disjoint_split.py', preprocessing=ZERO),
    'q1_revision/deep_protocol/earlystop': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/deep_protocol/fixed': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/deep_protocol/mlp_tuning': dict(script='experiments/deep_protocol_study.py', preprocessing=ZERO + STD),
    'q1_revision/leave_one_subattack_out': dict(script='experiments/leave_one_subattack_out.py', preprocessing=ZERO),
    'q1_revision/published_control': dict(script='experiments/published_protocol_control.py', preprocessing=ZERO,
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
    'q1_revision/shared_budget/tuning': dict(script='experiments/shared_budget_study.py', preprocessing=ZERO + STD),
    'q1_revision/shared_budget/final': dict(script='experiments/shared_budget_study.py', preprocessing=ZERO + STD),
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


def labels(r, folder):
    if 'train_variant' in r:
        return r['train_variant'], f'test rows not flagged by {r.get("test_set", "")}'.replace('by R1', 'by R1')
    if 'train_cleaning' in r:
        return r['train_cleaning'], r.get('test_cleaning', r['train_cleaning'])
    c = first(r, 'cleaning', 'variant', default='raw')
    return c, c


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
            if not isinstance(r, dict) or 'macro_f1' not in r:
                continue
            tr, te = labels(r, folder)
            pred, model_file = stored(js)
            cfg = first(r, 'config_tag', 'protocol', default='')
            if isinstance(r.get('mlp_config'), dict):
                cfg = (cfg + '; ' if cfg else '') + r['mlp_config'].get('tag', '')
            rows.append({
                'run': js.relative_to(RES).with_suffix('').as_posix(), 'folder': folder, 'script': d['script'],
                'model': first(r, 'model', default=d.get('model', '')), 'configuration': cfg,
                'training_seed': first(r, 'seed', default=''), 'sample': d.get('sample', SAMPLE),
                'features': first(r, 'feature_set', default='81 flow features'),
                'preprocessing': d['preprocessing'], 'class_weights': first(r, 'weights', default='balanced'),
                'split': split_of(r, folder), 'training_labels': tr, 'test_labels': te,
                'n_train': first(r, 'n_train', default=''), 'n_test': first(r, 'n_test', default=''),
                'macro_f1': r.get('macro_f1'), 'balanced_accuracy': r.get('balanced_accuracy'),
                'accuracy': r.get('accuracy'), 'predictions': pred, 'stored_model': model_file})
    with open(OUT / 'runs.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    with open(OUT / 'analyses.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['path', 'script', 'content'])
        for p, s, c in ANALYSES:
            if (RES / p).exists():
                w.writerow([f'results_2026_03_03/{p}', s, c])
    # figures: sanitised copies of the source values written by the figure scripts (if present)
    figrows = []
    for src in sorted((ROOT / 'figures' / 'values').glob('mid_F*_values.json')) if (ROOT / 'figures' / 'values').exists() else []:
        v = json.loads(src.read_text(encoding='utf-8'))
        if not isinstance(v.get('figure'), dict):
            continue
        fid = v['figure'].get('printed', src.stem)
        for k, s in (v.get('sources') or {}).items():
            figrows.append({'figure': fid, 'part': k, 'source': s, 'values_file': src.relative_to(ROOT).as_posix()})
    if figrows:
        with open(OUT / 'figures.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(figrows[0])); w.writeheader(); w.writerows(figrows)
    try:
        commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except Exception:
        commit = ''
    meta = {'commit_at_build': commit, 'sample_definition': 'results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz',
            'sample_sha256': sha256(FLAGS) if FLAGS.exists() else None, 'runs': len(rows),
            'runs_with_predictions': sum(r['predictions'] != 'not stored' for r in rows),
            'runs_with_stored_model': sum(not r['stored_model'].startswith('not stored') for r in rows),
            'files': ['runs.csv', 'analyses.csv', 'figures.csv', 'paper_map.csv']}
    (OUT / 'manifest.json').write_text(json.dumps(meta, indent=1), encoding='utf-8')
    print(f'[manifest] {len(rows)} runs ({meta["runs_with_predictions"]} with predictions, '
          f'{meta["runs_with_stored_model"]} with a stored model), {len(figrows)} figure sources -> {OUT}')


if __name__ == '__main__':
    main()
