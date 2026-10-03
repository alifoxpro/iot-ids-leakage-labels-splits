# -*- coding: utf-8 -*-
"""
flagged_loader.py
=================
Shared loader for the label-noise experiments. Reads the CIC IoT-DIAD 2024 flow CSVs
once (same sample and caps as the split pilot), computes the three background rules
of relabel_background.py for every flow, and caches the result to
results_2026_03_03/split_pilot/flagged_data.parquet.

Columns kept: 81 model features, y (class index), sub (capture group), ts (time),
r1_external, r2_service, r3_benign_pair (bool flags; always False for Benign),
Src IP, Dst IP, Dst Port, Protocol (for drift analysis only - never model features).

Usage:  from flagged_loader import get_flagged;  df = get_flagged()
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pilot_temporal_split import CAP, CLASSES, OUT, RAW, SAMPLE_FRAC, SEED, TS_FMT  # noqa: E402
from relabel_background import (DNS_ATTACK, SERVICE_PORTS, capture_groups,  # noqa: E402
                                internal, pair_key)

CACHE = OUT / 'flagged_data.parquet'
IDS = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol']
FLAGS = ['r1_external', 'r2_service', 'r3_benign_pair']


def _read(files, frac):
    parts = []
    for f in files:
        for ch in pd.read_csv(f, usecols=RAW + IDS + ['Timestamp'], chunksize=400_000, low_memory=False):
            if frac < 1.0:
                ch = ch.sample(frac=frac, random_state=SEED)
            for c in RAW:
                ch[c] = pd.to_numeric(ch[c], errors='coerce').astype(np.float32)
            parts.append(ch)
    return pd.concat(parts, ignore_index=True)


def _build():
    benign_pairs, frames = set(), []
    for cls in CLASSES:                       # Benign is first, so its pairs exist before attacks
        parts = []
        for sub, files in capture_groups(cls):
            df = _read(files, SAMPLE_FRAC.get(cls, 1.0))
            df[RAW] = df[RAW].replace([np.inf, -np.inf], np.nan)
            df['ts'] = pd.to_datetime(df['Timestamp'], format=TS_FMT, errors='coerce')
            df['sub'] = sub
            key = pair_key(df['Src IP'], df['Dst IP'])
            if cls == 'Benign':
                benign_pairs = set(key)
                for f in FLAGS:
                    df[f] = False
            else:
                df['r1_external'] = ~(internal(df['Src IP']) & internal(df['Dst IP']))
                svc = df['Src Port'].isin(SERVICE_PORTS) | df['Dst Port'].isin(SERVICE_PORTS)
                if sub == DNS_ATTACK:
                    svc = svc & ~((df['Src Port'] == 53) | (df['Dst Port'] == 53))
                df['r2_service'] = svc.to_numpy()
                df['r3_benign_pair'] = pd.Series(key).isin(benign_pairs).to_numpy()
            parts.append(df.drop(columns=['Timestamp', 'Src Port']))
        df = pd.concat(parts, ignore_index=True)
        df = df.sort_values('ts', kind='stable').drop_duplicates(subset=RAW, keep='first')
        if cls in CAP and len(df) > CAP[cls]:
            df = df.sample(CAP[cls], random_state=SEED).sort_values('ts', kind='stable')
        df['y'] = CLASSES.index(cls)
        print(f'  {cls:11s} flows={len(df):>9,}', flush=True)
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    v = df[RAW].to_numpy(np.float32)
    df['feat_mean'] = np.nanmean(v, 1); df['feat_std'] = np.nanstd(v, 1)
    df['feat_min'] = np.nanmin(v, 1); df['feat_max'] = np.nanmax(v, 1)
    df['feat_range'] = df['feat_max'] - df['feat_min']
    for c in ('Src IP', 'Dst IP'):
        df[c] = df[c].astype(str)
    return df


def load_prepared():
    """Same result as deep_split_noise_study.prepare(get_flagged(columns=NEEDED)), with a far
    lower peak: the 81 features are read one parquet column at a time straight into a
    preallocated float32 matrix, so no arrow table or pandas frame of all features is built.
    Peak is about the size of X (~1.2 GB) instead of ~3.5 GB."""
    import pyarrow.parquet as pq
    from pilot_temporal_split import FEATS
    if not CACHE.exists():                    # first run: build and cache, then read back lean
        get_flagged(columns=['y'])
    print(f'[loader] cached {CACHE.name} (column by column)', flush=True)
    pf = pq.ParquetFile(CACHE)
    X = np.empty((pf.metadata.num_rows, len(FEATS)), np.float32)
    for j, c in enumerate(FEATS):             # nan/inf -> 0 per column: no full-size temporaries
        v = pf.read(columns=[c], use_threads=False).column(0).to_numpy().astype(np.float32, copy=False)
        X[:, j] = np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)   # models scale internally
    del v
    meta = pf.read(columns=['y', 'sub', 'ts']).to_pandas()
    meta['sub'] = meta['sub'].astype('category')
    flags = {c: pf.read(columns=[c]).column(0).to_numpy() for c in FLAGS}
    return X, meta, flags


def get_flagged(columns=None):
    """columns=None loads everything; pass a list to load only what is needed (saves RAM)."""
    if CACHE.exists():
        print(f'[loader] cached {CACHE.name}')
        return pd.read_parquet(CACHE, columns=columns)
    print('[loader] first run: reading CSVs (slow), then caching')
    df = _build()
    OUT.mkdir(parents=True, exist_ok=True)
    df.to_parquet(CACHE, index=False)
    return df if columns is None else df[columns]
