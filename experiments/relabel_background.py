# -*- coding: utf-8 -*-
"""
relabel_background.py
=====================
Approximate removal of background traffic from the attack captures of
CIC IoT-DIAD 2024 (flow-based version, labels = pcap folder names).

A flow inside an attack capture is marked as background if any rule holds:
  R1 external   one endpoint is outside the testbed (192.168.137.0/24) and outside
                the CIC lab range 205.174.165.0/24 - the official page states that
                "all attacks are executed by malicious IoT devices targeting other
                IoT devices"
  R2 service    DNS 53 (except in DNS Spoofing, where DNS is the attack), DHCP 67/68,
                NTP 123, NetBIOS 137/138, SSDP 1900, mDNS 5353
  R3 benign     the unordered IP pair also occurs in the Benign captures
Benign captures are left unchanged. Background flows are DROPPED (not relabelled as
Benign), because the rules are approximate.

Then class-weighted XGBoost is compared on the same sample (DOS/DDOS capped as in
the split pilot) before and after cleaning, under
  A  random stratified split
  D  temporal split inside each sub-attack (every sub-attack seen in training)

Outputs (results_2026_03_03/split_pilot/):
  relabel_summary.json   flows removed per capture group and per rule, and the scores
  clean_data.parquet     cleaned sample (features, label, sub-attack, time) for reuse
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\relabel_background.py
"""
import glob, ipaddress, json, sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pilot_temporal_split import (CAP, CLASSES, DATA, FEATS, OUT, RAW, SAMPLE_FRAC,  # noqa: E402
                                  SEED, TS_FMT, fit_eval)
from temporal_split_by_subattack import subattack_temporal_idx  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
IDS = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port']
TESTBED = [ipaddress.ip_network('192.168.137.0/24'), ipaddress.ip_network('205.174.165.0/24')]
SERVICE_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353}
DNS_ATTACK = 'DNS Spoofing'


def internal(ip_series):
    """Vectorised test: is each IP inside the testbed networks? (cached per unique IP)"""
    uniq = pd.unique(ip_series)
    ok = {}
    for ip in uniq:
        try:
            a = ipaddress.ip_address(ip)
            ok[ip] = any(a in n for n in TESTBED)
        except ValueError:
            ok[ip] = False
    return ip_series.map(ok).to_numpy()


def pair_key(a, b):
    a, b = a.astype(str), b.astype(str)
    return (a.where(a < b, b) + '|' + b.where(a < b, a)).to_numpy()


def read_group(files, frac):
    parts = []
    for f in files:
        for ch in pd.read_csv(f, usecols=RAW + IDS + ['Timestamp'], chunksize=400_000, low_memory=False):
            if frac < 1.0:
                ch = ch.sample(frac=frac, random_state=SEED)
            for c in RAW:
                ch[c] = pd.to_numeric(ch[c], errors='coerce').astype(np.float32)
            parts.append(ch)
    return pd.concat(parts, ignore_index=True)


def capture_groups(cls):
    d = DATA / cls
    subs = sorted(p for p in d.iterdir() if p.is_dir())
    for g in (subs or [d]):
        files = [f for f in sorted(glob.glob(str(g / '*.csv')))
                 if 'Timestamp' in pd.read_csv(f, nrows=0).columns]   # skip empty stubs
        if files:
            yield (g.name if subs else cls), files


def load_with_rules():
    benign_pairs = None
    frames, summary = [], {}
    for cls in CLASSES:
        n_cls_before = 0
        cls_frames = []
        for sub, files in capture_groups(cls):
            df = read_group(files, SAMPLE_FRAC.get(cls, 1.0))
            df[RAW] = df[RAW].replace([np.inf, -np.inf], np.nan)
            df['ts'] = pd.to_datetime(df['Timestamp'], format=TS_FMT, errors='coerce')
            df['sub'] = sub
            key = pair_key(df['Src IP'], df['Dst IP'])
            if cls == 'Benign':
                benign_pairs = set(key)
                bg = np.zeros(len(df), bool); r1 = r2 = r3 = bg
            else:
                r1 = ~(internal(df['Src IP']) & internal(df['Dst IP']))
                ports = df['Src Port'].isin(SERVICE_PORTS) | df['Dst Port'].isin(SERVICE_PORTS)
                if sub == DNS_ATTACK:                 # DNS is the attack itself here
                    ports = ports & ~((df['Src Port'] == 53) | (df['Dst Port'] == 53))
                r2 = ports.to_numpy()
                r3 = pd.Series(key).isin(benign_pairs).to_numpy()
                bg = r1 | r2 | r3
            n = len(df)
            summary[f'{cls} / {sub}'] = {
                'flows_read': int(n), 'background_fraction': round(float(bg.mean()), 4),
                'R1_external': round(float(r1.mean()), 4), 'R2_service': round(float(r2.mean()), 4),
                'R3_benign_pair': round(float(r3.mean()), 4), 'kept': int((~bg).sum())}
            df['bg'] = bg
            cls_frames.append(df.drop(columns=IDS + ['Timestamp']))
            n_cls_before += n
        df = pd.concat(cls_frames, ignore_index=True)
        df = df.sort_values('ts', kind='stable').drop_duplicates(subset=RAW + ['bg'], keep='first')
        if cls in CAP and len(df) > CAP[cls]:
            df = df.sample(CAP[cls], random_state=SEED).sort_values('ts', kind='stable')
        df['y'] = CLASSES.index(cls)
        print(f'  {cls:11s} read={n_cls_before:>10,}  sample={len(df):>9,}  background={df["bg"].mean():6.1%}', flush=True)
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    v = df[RAW].to_numpy(np.float32)
    df['feat_mean'] = np.nanmean(v, 1); df['feat_std'] = np.nanstd(v, 1)
    df['feat_min'] = np.nanmin(v, 1); df['feat_max'] = np.nanmax(v, 1)
    df['feat_range'] = df['feat_max'] - df['feat_min']
    return df, summary


def run_splits(df, tag):
    df = df.reset_index(drop=True)
    X, y = df[FEATS].to_numpy(np.float32), df['y'].to_numpy()
    out = {}
    tr, te = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=SEED)
    tr, _ = train_test_split(tr, test_size=0.15 / 0.85, stratify=y[tr], random_state=SEED)
    out['A_random'], _ = fit_eval(X[tr], y[tr], X[te], y[te], f'{tag} A random')
    tr, _, te = subattack_temporal_idx(df)
    out['D_temporal_subattack'], _ = fit_eval(X[tr], y[tr], X[te], y[te], f'{tag} D temporal/sub-attack')
    out['n_flows'] = int(len(df))
    out['class_counts'] = {CLASSES[k]: int(v) for k, v in pd.Series(y).value_counts().sort_index().items()}
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print('[1] reading captures with identifier columns and applying the rules')
    df, summary = load_with_rules()

    print('\n=== background share per capture group (before de-duplication/caps) ===')
    print(f'  {"group":38s} {"read":>10s} {"backgr.":>8s} {"R1 ext":>7s} {"R2 svc":>7s} {"R3 benign":>9s} {"kept":>9s}')
    for g, s in summary.items():
        print(f'  {g:38s} {s["flows_read"]:>10,} {s["background_fraction"]:>8.1%} {s["R1_external"]:>7.1%} '
              f'{s["R2_service"]:>7.1%} {s["R3_benign_pair"]:>9.1%} {s["kept"]:>9,}')

    res = {'rules': {'testbed': [str(n) for n in TESTBED], 'service_ports': sorted(SERVICE_PORTS),
                     'dns_exception': DNS_ATTACK}, 'per_group': summary}
    print('\n[2] before cleaning (all flows)')
    res['before'] = run_splits(df, 'BEFORE')
    print('\n[3] after cleaning (background dropped from attack classes)')
    clean = df[~df['bg']]
    res['after'] = run_splits(clean, 'AFTER')
    clean.drop(columns='bg').to_parquet(OUT / 'clean_data.parquet', index=False)

    print('\n=== summary ===')
    print(f'  {"":24s} {"random: macro-F1 / bal-acc":>28s} {"temporal: macro-F1 / bal-acc":>30s}')
    for k in ('before', 'after'):
        a, d = res[k]['A_random'], res[k]['D_temporal_subattack']
        print(f'  {k:24s} {a["macro_f1"]:>14.3f} / {a["balanced_accuracy"]:.3f} {d["macro_f1"]:>16.3f} / {d["balanced_accuracy"]:.3f}')
    print('\n  per-class F1 (random | temporal), before -> after:')
    for c in CLASSES:
        b = res['before']; a = res['after']
        print(f'  {c:11s} {b["A_random"]["per_class_f1"][c]:.3f} | {b["D_temporal_subattack"]["per_class_f1"][c]:.3f}'
              f'   ->   {a["A_random"]["per_class_f1"][c]:.3f} | {a["D_temporal_subattack"]["per_class_f1"][c]:.3f}'
              f'   (n after = {a["class_counts"].get(c, 0):,})')

    json.dump(res, open(OUT / 'relabel_summary.json', 'w'), indent=2, default=str)
    print('\n[DONE]', OUT / 'relabel_summary.json')


if __name__ == '__main__':
    main()
