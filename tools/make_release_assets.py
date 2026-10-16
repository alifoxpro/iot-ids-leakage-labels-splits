# -*- coding: utf-8 -*-
"""
tools/make_release_assets.py -- pack the large result files that git does not version (stored test predictions
*.npz, cached arrays *.npy, model weights *.pt / *.pth / *.pkl) into zip files for a GitHub Release (archived with
a DOI on acceptance of the paper). Every zip stays below GitHub's 2 GB limit per release asset; a manifest
lists every packed file with its size and SHA-256.

Usage (from the project folder):
    python tools/make_release_assets.py --dry-run          # list what would be packed, per asset
    python tools/make_release_assets.py                    # write dist/release_assets/*.zip + MANIFEST.json
Options: --folders q1_revision tree_protocol ... (result folders under results_2026_03_03/; default: the folders of
the study), --max-gb 1.9, --source <folder> (the project folder whose results_2026_03_03/ holds the large files, for
example the working copy in which the experiments were run; default: this repository).
Paths inside the zip files and the manifest are relative to that folder, so they match the layout of this repository.
The cached data samples (*.parquet, e.g. split_pilot/flagged_data.parquet) are not packed: they are derived from the
public CSVs and are rebuilt by the scripts; results_2026_03_03/q1_revision/export_flags/flow_flags.csv.gz (in git)
identifies every flow of the sample.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'dist' / 'release_assets'
PATTERNS = ('*.npz', '*.npy', '*.pt', '*.pth', '*.pkl', '*.xgb.json', '*.lgb.txt')   # + round-2 tree models
IJIES = ['q1_revision', 'tree_protocol', 'deep_split', 'extra_baselines', 'identifier_leakage_v2', 'split_pilot']

ap = argparse.ArgumentParser()
ap.add_argument('--folders', nargs='+', default=IJIES)
ap.add_argument('--max-gb', type=float, default=1.9)
ap.add_argument('--dry-run', action='store_true')
ap.add_argument('--source', default=str(ROOT))
a = ap.parse_args()
SRC = Path(a.source).resolve()
RES = SRC / 'results_2026_03_03'
limit = int(a.max_gb * 1e9)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


assets = []                                         # (asset name, [files])
for folder in a.folders:
    files = sorted({p for pat in PATTERNS for p in (RES / folder).rglob(pat) if p.is_file()})
    part, size, k = [], 0, 1
    for f in files:
        if part and size + f.stat().st_size > limit:
            assets.append((f'{folder}_part{k}', part)); part, size, k = [], 0, k + 1
        part.append(f); size += f.stat().st_size
    if part:
        assets.append((folder if k == 1 else f'{folder}_part{k}', part))

total = 0
for name, files in assets:
    s = sum(f.stat().st_size for f in files)
    total += s
    print(f'{name}.zip: {len(files)} files, {s / 1e9:.2f} GB')
print(f'total: {sum(len(f) for _, f in assets)} files, {total / 1e9:.2f} GB in {len(assets)} assets')
if a.dry_run:
    raise SystemExit
OUT.mkdir(parents=True, exist_ok=True)
manifest = {'source': 'results_2026_03_03', 'assets': {}}
for name, files in assets:
    zp = OUT / f'{name}.zip'
    with zipfile.ZipFile(zp, 'w', zipfile.ZIP_STORED) as z:          # npz/pt are already compressed
        for f in files:
            z.write(f, f.relative_to(SRC).as_posix())
    manifest['assets'][zp.name] = {'sha256': sha256(zp), 'files': [
        {'path': f.relative_to(SRC).as_posix(), 'bytes': f.stat().st_size, 'sha256': sha256(f)} for f in files]}
    print('wrote', zp)
(OUT / 'MANIFEST.json').write_text(json.dumps(manifest, indent=1), encoding='utf-8')
print('wrote', OUT / 'MANIFEST.json')
