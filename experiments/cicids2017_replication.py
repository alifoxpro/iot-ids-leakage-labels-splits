# -*- coding: utf-8 -*-
r"""
cicids2017_replication.py
=========================
Reviewer point narr-03: repeat the core analyses of the paper on a second folder/CICFlowMeter-based
dataset that the paper already cites, CICIDS2017 (Sharafaldin et al., 2018), using the generated
labelled flows ("TrafficLabelling" release) in data/cic-ids-2017/labelled-flows/*.csv.

Data (one pass over the eight CSV files, chunk-wise, float32; cached on the first run)
  files      Monday, Tuesday, Wednesday, Thursday morning (web attacks) and afternoon (infiltration),
             Friday morning (bot) and afternoon (port scan, DDoS); 85 columns each (header names carry
             leading spaces and are stripped; the duplicated "Fwd Header Length" column becomes
             "Fwd Header Length.1", as in the MachineLearningCVE release); read with latin-1 because the
             web-attack labels contain byte 0x96 (cp1252 en dash). Rows without a label (the ~288k empty
             trailing rows of the Thursday-morning file) are dropped.
  features   F0 = the 77 CICFlowMeter statistics between Timestamp and Label (no identifier column, the
             convention of this project); F78 = F0 + Destination Port = the 78 features of the widely
             used MachineLearningCVE release. inf -> NaN when read, NaN -> 0 before training
             (deep_split_noise_study.prepare). No row statistics are added.
  identifiers Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp.
             Text columns (Flow ID, addresses, Timestamp as raw text) are label-encoded over the whole
             de-duplicated table, before any split, in sorted order (pd.factorize(sort=True) /
             sklearn LabelEncoder order, as in published_protocol_control.py); ports and protocol are
             numeric.
  time       the Timestamp text is "d/m/yyyy h:mm" (Monday: "dd/mm/yyyy hh:mm:ss") on a 12-hour clock
             WITHOUT AM/PM (afternoon flows read "1:00".."5:59"). The capture ran from about 08:40 to
             17:10, so hours 1-7 are read as 13-19 h; hours 8-12 are kept. The file's weekday is used as
             the capture day; every file's parsed range and the rows off the expected date are in
             data_summary.json.
  labels     class mapping (common practice): the three "Web Attack - Brute Force / XSS / Sql Injection"
             labels are grouped into one class "Web Attack"; every other label is its own class. After
             de-duplication, classes with fewer than 100 flows are dropped (expected: Heartbleed and
             Infiltration). BENIGN is class 0, the other kept classes follow in alphabetical order.
             The full mapping and the flow counts before and after de-duplication are in data_summary.json.
  de-dup     as in this project (flagged_loader / pilot_temporal_split.load): inside each class, flows
             are put in time order (stable, so file order breaks ties) and exact duplicates of the 77
             flow features (NaN == NaN, -0 == +0; 64-bit row hash as in published_protocol_control)
             are dropped, keeping the earliest flow. Row order of the cache = class order, then time.

Analyses
  (1) identifier columns - stratified random 80/20 split (seed 42, train_test_split as in
      published_protocol_control.py); feature sets
        F0   77 flow features (identifier-free)
        F78  F0 + Destination Port (the standard 78-feature set)
        FT   F78 + Timestamp (raw text, label-encoded in sorted text order)
        FA   F78 + Flow ID, Source IP, Source Port, Destination IP, Protocol, Timestamp (all 7 identifiers)
      reported: accuracy, balanced accuracy, macro-F1 (+ per class), gain share and rank of every
      identifier column.
  (2) split design - random stratified 70/15/15 (deep_split_noise_study.splits(meta, 'random'), seed 42)
      versus the chronological split within capture groups of paper Section 4.2 (subattack_temporal_idx
      through splits(meta, 'temporal')): inside each (day, original label) group the flows are ordered by
      time; the first 70% train, the last 15% test, the middle 15% is not used (no tuning). Groups:
      BENIGN x 5 days, each attack label on its day, and the three web-attack labels separately (so, as in
      the temporal split within capture groups of the paper, every sub-attack is present in training).
      Feature sets F0 and F78. Reported: macro-F1, per-class recall/F1/precision, recall per (class, group),
      train/test time window of every group. Timestamps have minute resolution except on Monday, so flows of
      the boundary minute can fall on both sides (ties keep the source-file order); their number is reported
      per group (n_test_not_after_train_end) and overall (test_share_not_after_train_end_of_group).
  (3) protocol-0 compression (as protocol_packet_share.py) - per label, the share of flows and of packets
      (Total Fwd Packets + Total Backward Packets) of every Protocol value, the largest protocol-0 flow
      and the protocol-0 flows with a non-zero port; for all labelled rows (no de-duplication, as in
      protocol_packet_share.py) and for the de-duplicated table. Written during the build.
  R1 analogue - per label, the share of flows with at least one endpoint outside the documented
      CICIDS2017 victim / attacker networks 192.168.10.0/24 and 205.174.165.0/24 (the rule R1 of
      relabel_background.py). Attack traffic enters the victim LAN through the firewall's NAT address
      172.16.0.1, so a second variant also counts 172.16.0.1 as inside. Also reported: flows with both
      endpoints outside, flows with a non-IPv4 endpoint, flows with a documented attacker endpoint
      (205.174.165.69/70/71/73 or the NAT address 172.16.0.1), and the five most frequent outside
      endpoints per label. R2 / R3 analogues of relabel_background.py on the attack-labelled flows (null
      for BENIGN): R2 = a service port (SERVICE_PORTS) at either end, R3 = the unordered address pair also
      occurs in a BENIGN flow; and the union R1 | R2 | R3 ('any rule'). Written during the build; the
      per-flow flags (outside_strict, outside_nat, r2_service, r3_benign_pair) are kept in the cache.
      CICIDS2017 labels were assigned from attacker addresses and time windows, so these shares are the
      contrast to the folder labels of CIC IoT-DIAD 2024.
Model: XGBoost of extra_baselines.make (seed 42), balanced sample weights computed on the training part,
on the GPU; if the GPU fit fails (no CUDA device, out of memory) the same fit is repeated on the CPU
(n_jobs=--cpu-jobs). The device actually used is stored in every run JSON.

Output: results_2026_03_03/q1_revision/cicids2017/
  data.parquet          compact de-duplicated table: 77 features, Destination/Source Port, Protocol,
                        le_* codes, y, label, group, day, file, file_row (0-based data row in the source
                        CSV), ts, src_ip, dst_ip, outside_strict, outside_nat, r2_service,
                        r3_benign_pair, raw_hash
  data_summary.json     files, rows, timestamp checks, class mapping, counts before/after de-dup,
                        classes, groups, cross-class duplicate share, distinct identifier values,
                        rule shares of the de-duplicated attack flows
  protocol_share.json   analysis (3)
  r1_analogue.json      R1 analogue (and R2 / R3 / any-rule shares) per label, class and file
  <run>.json / .npz     one per fit: identifiers_F0, identifiers_F78, identifiers_FT, identifiers_FA,
                        split_random_F0, split_temporal_F0, split_random_F78, split_temporal_F78;
                        npz = y, p (int8), proba (float16, test x classes), sub (group), idx (cache row)
  summary.json / summary.csv   tables of the finished runs, effects, and the matching CIC IoT-DIAD 2024
                        reference values of this project (read from their JSON files when present)
Resumable: the cache is built once; a run is finished once its JSON exists (written last, atomically).

Run (PowerShell, from the project root):
  $py = "C:\Users\lenovo\.conda\envs\MyProject\python.exe"
  cd "<project folder>"
  & $py experiments\cicids2017_replication.py --build-only 2>&1 | Tee-Object -FilePath cicids2017_build.log
  for ($i = 0; $i -lt 8; $i++) { & $py experiments\cicids2017_replication.py --max-fits 1 2>&1 | Tee-Object -FilePath cicids2017_fits.log -Append }
  & $py experiments\cicids2017_replication.py --summary 2>&1 | Tee-Object -FilePath cicids2017_summary.log
Same steps with the run-package helpers (memory wait, logs in runs\logs\):
  . .\runs\_common.ps1
  Invoke-Step cicids2017 @('experiments\cicids2017_replication.py', '--build-only') 4
  Invoke-Loop cicids2017 @('experiments\cicids2017_replication.py', '--max-fits', '1') 8 3
  Invoke-Step cicids2017 @('experiments\cicids2017_replication.py', '--summary') 1
Memory: the build keeps the labelled rows as float32 / arrow columns (about 2.8M rows; peak about 2 GB); a fit
reads only the needed parquet columns (peak about 1-1.5 GB RAM; GPU about 1 GB).
Smoke test (tiny copies of the CSVs, no effect on the real results):
  & $py experiments\cicids2017_replication.py --data-dir <folder with small CSVs> --out <scratch folder> --min-flows 20
Options: --study identifiers|split|all (default all), --device auto|cuda|cpu (default auto = GPU with CPU
fallback), --cpu-jobs 4, --min-flows 100; --data-dir/--out/--nrows only for smoke tests on small files
(--nrows or --data-dir without --out is refused, and a cache built with another --min-flows is not reused).
"""
import argparse, gc, ipaddress, json, os, re, sys, time, warnings
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import deep_split_noise_study as dsn  # noqa: E402  (splits(), metrics(); CLASSES is set below)
from extra_baselines import make  # noqa: E402
from pilot_temporal_split import SEED  # noqa: E402
from relabel_background import SERVICE_PORTS  # noqa: E402  (rule R2 ports)

sys.stdout.reconfigure(encoding='utf-8')
warnings.filterwarnings('ignore', category=FutureWarning)   # pandas groupby(observed=...) notices

DATA = ROOT / 'data' / 'cic-ids-2017' / 'labelled-flows'
OUT = ROOT / 'results_2026_03_03' / 'q1_revision' / 'cicids2017'
RES = ROOT / 'results_2026_03_03'
FILES = [('Monday', 'Monday-WorkingHours.pcap_ISCX.csv'),                     # chronological order
         ('Tuesday', 'Tuesday-WorkingHours.pcap_ISCX.csv'),
         ('Wednesday', 'Wednesday-workingHours.pcap_ISCX.csv'),
         ('Thursday', 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'),
         ('Thursday', 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'),
         ('Friday', 'Friday-WorkingHours-Morning.pcap_ISCX.csv'),
         ('Friday', 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'),
         ('Friday', 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')]
DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
DATES = dict(zip(DAYS, ['2017-07-03', '2017-07-04', '2017-07-05', '2017-07-06', '2017-07-07']))
ID7 = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp']
STR_IDS = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']              # text -> label-encoded
NUM_IDS = ['Destination Port', 'Source Port', 'Protocol']                      # numeric
LE = {'Flow ID': 'le_flow_id', 'Source IP': 'le_src_ip', 'Destination IP': 'le_dst_ip',
      'Timestamp': 'le_timestamp'}
PKTS = ['Total Fwd Packets', 'Total Backward Packets']
NETS_STRICT = ['192.168.10.0/24', '205.174.165.0/24']      # documented victim and attacker networks
NETS_NAT = NETS_STRICT + ['172.16.0.1/32']                 # + the firewall's inside (NAT) address
ATTACKERS = ['205.174.165.69', '205.174.165.70', '205.174.165.71', '205.174.165.73', '172.16.0.1']
TS_RE = r'^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$'
CHUNK, BATCH = 100_000, 250_000                          # CSV rows per chunk, parquet rows per batch
FSET_DESC = {
    'F0': '77 CICFlowMeter flow features (no identifier column)',
    'F78': 'F0 + Destination Port (the 78 features of the MachineLearningCVE release)',
    'FT': 'F78 + Timestamp (raw text, label-encoded in sorted text order over the whole table)',
    'FA': 'F78 + Flow ID, Source IP, Source Port, Destination IP, Protocol, Timestamp (all seven identifiers; '
          'text columns label-encoded in sorted order, ports and protocol numeric)'}
EXTRA = {'F0': [], 'F78': ['Destination Port'], 'FT': ['Destination Port', 'le_timestamp'],
         'FA': ['Destination Port', 'le_flow_id', 'le_src_ip', 'Source Port', 'le_dst_ip', 'Protocol',
                'le_timestamp']}
ID_NAME = {'Destination Port': 'Destination Port', 'Source Port': 'Source Port', 'Protocol': 'Protocol',
           **{v: k for k, v in LE.items()}}
JOBS = ([dict(name=f'identifiers_{f}', study='identifiers', split='random80', fset=f)
         for f in ('F0', 'F78', 'FT', 'FA')]
        + [dict(name=f'split_{s}_{f}', study='split', split=s, fset=f)
           for f in ('F0', 'F78') for s in ('random', 'temporal')])
SPLIT_DESC = {'random80': 'stratified random 80/20, seed 42',
              'random': 'stratified random 70/15/15, seed 42 (validation part unused)',
              'temporal': 'temporal split within capture groups (paper Section 4.2): inside each (day, original label) group, flows in time order; first 70% '
                          'train, last 15% test (middle 15% unused)'}


# ============================================================================ helpers
def write_json(path, obj):
    """Atomic write: an interrupted process never leaves a truncated JSON (the JSON marks a run finished)."""
    tmp = Path(str(path) + '.part')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1, default=str)
    os.replace(tmp, path)


def norm_label(s):
    """'Web Attack \x96 Brute Force' -> 'Web Attack - Brute Force'; strip and collapse spaces."""
    s = re.sub(r'[^\x20-\x7e]+', '-', str(s).strip())
    return re.sub(r'\s+', ' ', s)


def to_class(label):
    return 'Web Attack' if label.startswith('Web Attack') else label


def group_name(day, label):
    """Temporal-split group: the day, plus the sub-label for grouped classes ('Thursday / XSS')."""
    c = to_class(label)
    return day if label == c else f'{day} / {label[len(c):].strip(" -")}'


def parse_ts(s):
    """Stripped timestamp strings -> datetime64[ns] (NaT if unparsed), number of rows read as p.m."""
    codes, uniq = pd.factorize(s)
    p = pd.Series(np.asarray(uniq, dtype=object)).str.extract(TS_RE)
    ok = p[[0, 1, 2, 3, 4]].notna().all(axis=1).to_numpy()
    t = np.full(len(uniq), np.datetime64('NaT'), 'datetime64[ns]')
    pm = np.zeros(len(uniq), bool)
    if ok.any():
        q = p[ok].fillna({5: '0'}).astype(int)
        hour = q[3].to_numpy()
        pm[ok] = (hour >= 1) & (hour <= 7)                  # 12-hour clock without AM/PM
        q[3] = np.where(pm[ok], hour + 12, hour)
        t[ok] = pd.to_datetime(pd.DataFrame({'year': q[2], 'month': q[1], 'day': q[0], 'hour': q[3],
                                             'minute': q[4], 'second': q[5]}),
                               errors='coerce').to_numpy('datetime64[ns]')
    out = np.full(len(codes), np.datetime64('NaT'), 'datetime64[ns]')
    m = codes >= 0
    out[m] = t[codes[m]]
    return out, int(pm[codes[m]].sum())


def row_hash(cols):
    """64-bit key of the flow features of each row (NaN == NaN, -0 == +0), as published_protocol_control._raw_hash."""
    h = np.zeros(len(cols[0]), np.uint64)
    for v in cols:
        v = v + np.float32(0)                                # copy; -0.0 -> +0.0
        v[np.isnan(v)] = np.nan                              # a single NaN bit pattern
        h = (h * np.uint64(1099511628211)) ^ pd.util.hash_array(v)
    return h


def header(path):
    return [c.strip() for c in pd.read_csv(path, nrows=0, encoding='latin-1').columns]


def ip_flags(uniq):
    """Per distinct address: inside strict networks, inside incl. NAT address, IPv4, documented attacker."""
    strict = [ipaddress.ip_network(n) for n in NETS_STRICT]
    nat = [ipaddress.ip_network(n) for n in NETS_NAT]
    att = set(ATTACKERS)
    f = np.zeros((len(uniq), 4), bool)
    for i, ip in enumerate(uniq):
        try:
            a = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            continue
        f[i] = [any(a in n for n in strict), any(a in n for n in nat), a.version == 4, ip in att]
    return f


# ============================================================================ build
def read_all(data_dir, nrows):
    """One chunked pass over the eight CSV files; numeric columns float32, text columns as arrow strings."""
    import pyarrow as pa
    hdr0 = header(data_dir / FILES[0][1])
    if hdr0[:7] != ID7 or hdr0[-1] != 'Label' or len(hdr0) != 85:
        raise RuntimeError(f'unexpected header in {FILES[0][1]}: {hdr0[:8]} ... {hdr0[-2:]}')
    f0 = hdr0[7:-1]
    num = {c: [] for c in f0 + NUM_IDS}
    txt = {c: [] for c in STR_IDS}
    lab, ts, fidx, rown = [], [], [], []
    labels, files_info = [], []
    for fi, (day, fname) in enumerate(FILES):
        path = data_dir / fname
        if header(path) != hdr0:
            raise RuntimeError(f'header of {fname} differs from {FILES[0][1]}')
        info = {'file': fname, 'day': day, 'rows_read': 0, 'rows_without_label': 0, 'rows_repeated_header': 0,
                'rows_kept': 0,
                'rows_read_as_pm': 0, 'rows_unparsed_ts': 0, 'rows_off_expected_date': 0, 'labels': {}}
        tmin, tmax, offset, t0 = None, None, 0, time.time()
        for ch in pd.read_csv(path, encoding='latin-1', chunksize=CHUNK, low_memory=False, nrows=nrows):
            ch.columns = hdr0
            m = len(ch)
            lb = ch['Label'].astype('string').fillna('').str.strip()
            hdr = (lb == 'Label').to_numpy(bool)                    # repeated header line (defensive)
            ok = (lb != '').to_numpy(bool) & ~hdr
            rows = np.arange(offset, offset + m, dtype=np.int32)[ok]
            offset += m
            info['rows_read'] += m
            info['rows_without_label'] += int((~ok & ~hdr).sum())
            info['rows_repeated_header'] += int(hdr.sum())
            if not ok.any():
                continue
            ch, lb = ch.loc[ok], lb[ok]
            codes, uniq = pd.factorize(lb)
            gl = []
            for u in uniq:
                u = norm_label(u)
                if u not in labels:
                    labels.append(u)
                gl.append(labels.index(u))
            lcode = np.asarray(gl, np.int16)[codes]
            for k, n in zip(*np.unique(lcode, return_counts=True)):
                info['labels'][labels[k]] = info['labels'].get(labels[k], 0) + int(n)
            for c in num:
                v = pd.to_numeric(ch[c], errors='coerce').to_numpy(np.float32)
                v[np.isinf(v)] = np.nan                       # inf -> NaN, as flagged_loader
                num[c].append(v)
            for c in STR_IDS:
                s = ch[c].astype('string').str.strip()
                txt[c].append(pa.array(s.to_numpy(dtype=object, na_value=None), type=pa.string()))
            t, n_pm = parse_ts(ch['Timestamp'].astype('string').str.strip())
            info['rows_read_as_pm'] += n_pm
            bad = np.isnat(t)
            info['rows_unparsed_ts'] += int(bad.sum())
            if (~bad).any():
                tt = t[~bad]
                tmin = tt.min() if tmin is None else min(tmin, tt.min())
                tmax = tt.max() if tmax is None else max(tmax, tt.max())
                info['rows_off_expected_date'] += int((tt.astype('datetime64[D]')
                                                       != np.datetime64(DATES[day])).sum())
            lab.append(lcode); ts.append(t); rown.append(rows)
            fidx.append(np.full(len(lcode), fi, np.int8))
            info['rows_kept'] += len(lcode)
        info['ts_min'], info['ts_max'] = str(tmin), str(tmax)
        files_info.append(info)
        print(f'  {fname:62s} rows={info["rows_read"]:>9,} unlabelled={info["rows_without_label"]:>7,} '
              f'ts {str(tmin)[:16]} -> {str(tmax)[:16]}  labels={info["labels"]}  '
              f'({time.time() - t0:.0f} s)', flush=True)
    cat = lambda lst: (np.concatenate(lst), lst.clear())[0]          # free the chunks column by column
    pcat = lambda lst: (pa.concat_arrays(lst), lst.clear())[0]
    arrays = {'num': {c: cat(v) for c, v in num.items()}, 'txt': {c: pcat(v) for c, v in txt.items()},
              'lab': cat(lab), 'ts': cat(ts), 'fidx': cat(fidx), 'rown': cat(rown)}
    return f0, labels, files_info, arrays


def label_encode(arr, take=None):
    """Codes of the sorted distinct values (LabelEncoder / pd.factorize(sort=True) order); null -> -1."""
    import pyarrow as pa
    import pyarrow.compute as pc
    if take is not None:
        arr = arr.take(pa.array(take))
    u = pc.drop_null(pc.unique(arr))
    u = u.take(pc.array_sort_indices(u))
    return pc.index_in(arr, value_set=u).fill_null(-1).to_numpy(zero_copy_only=False).astype(np.int32), u


def rank_codes(codes):
    """Re-code integer codes that already follow the sorted text order to 0..k-1 over the values present
    (= label encoding of the underlying strings restricted to these rows); -1 (null) stays -1."""
    u, inv = np.unique(codes, return_inverse=True)
    return (inv - int(u[0] < 0)).astype(np.int32), int((u >= 0).sum())


def describe(rows, key, names, A, ipf, src, dst, ip_uniq, rules):
    """Protocol-0 compression and R1 (plus R2 / R3) analogue per group; rows = positions in the raw arrays;
    rules = full-length bool arrays r2, r3 (False for BENIGN, as in flagged_loader) and benign."""
    g = key[rows]
    proto = np.nan_to_num(A['num']['Protocol'][rows], nan=-1).astype(np.int64)
    pk = (np.nan_to_num(A['num'][PKTS[0]][rows]).astype(np.float64)
          + np.nan_to_num(A['num'][PKTS[1]][rows]).astype(np.float64))
    port = (np.nan_to_num(A['num']['Source Port'][rows]) != 0) | (np.nan_to_num(A['num']['Destination Port'][rows]) != 0)
    s, d = src[rows], dst[rows]
    fs = lambda col, c: np.where(c >= 0, ipf[np.maximum(c, 0), col], False)
    ins_s, ins_n = (fs(0, s) & fs(0, d)), (fs(1, s) & fs(1, d))
    both_s, both_n = (~fs(0, s) & ~fs(0, d)), (~fs(1, s) & ~fs(1, d))
    v4 = fs(2, s) & fs(2, d)
    att = fs(3, s) | fs(3, d)
    out_n_src, out_n_dst = ~fs(1, s), ~fs(1, d)          # outside the with_nat networks
    r2, r3, att_row = rules['r2'][rows], rules['r3'][rows], ~rules['benign'][rows]
    any_s, any_n = (~ins_s | r2 | r3), (~ins_n | r2 | r3)
    prot, r1 = {}, {}
    df = pd.DataFrame({'g': g, 'p': proto, 'n': pk})
    fl = df.groupby(['g', 'p']).size()
    pks = df.groupby(['g', 'p'])['n'].sum()
    for k in np.unique(g):
        m = g == k
        F, P = int(m.sum()), float(pk[m].sum())
        z = m & (proto == 0)
        prot[names[k]] = {
            'flows': F, 'packets': int(P),
            'flow_share': {str(p): round(int(v) / F, 4) for p, v in fl.loc[k].items()},
            'packet_share': {str(p): round(float(v) / P, 4) if P else None for p, v in pks.loc[k].items()},
            'largest_proto0_flow_packets': int(pk[z].max()) if z.any() else 0,
            'proto0_flows_with_nonzero_port': int((z & port).sum())}
        cnt = np.bincount(np.concatenate([s[m & out_n_src & (s >= 0)], d[m & out_n_dst & (d >= 0)]]),
                          minlength=len(ip_uniq))
        top = np.argsort(-cnt, kind='stable')[:5]
        ma = m & att_row                                     # the rules apply to attack-labelled flows only
        sh = (lambda v: round(float(v[ma].mean()), 4)) if ma.any() else (lambda v: None)
        r1[names[k]] = {
            'flows': F,
            'share_any_endpoint_outside_strict': round(float((~ins_s[m]).mean()), 4),
            'share_both_endpoints_outside_strict': round(float(both_s[m].mean()), 4),
            'share_any_endpoint_outside_with_nat': round(float((~ins_n[m]).mean()), 4),
            'share_both_endpoints_outside_with_nat': round(float(both_n[m].mean()), 4),
            'share_non_ipv4_endpoint': round(float((~v4[m]).mean()), 4),
            'share_documented_attacker_endpoint': round(float(att[m].mean()), 4),
            'r2_share_service_port': sh(r2), 'r3_share_benign_pair': sh(r3),
            'any_rule_share_strict': sh(any_s), 'any_rule_share_with_nat': sh(any_n),
            'top_outside_endpoints_with_nat': {str(ip_uniq[i]): int(cnt[i]) for i in top if cnt[i] > 0}}
    return prot, r1


def build(data_dir, nrows, min_flows):
    import pyarrow as pa
    import pyarrow.parquet as pq
    print(f'[build] reading {len(FILES)} CSV files from {data_dir} (first run only)', flush=True)
    f0, labels, files_info, A = read_all(data_dir, nrows)
    n = len(A['lab'])
    lab, ts, fidx = A['lab'], A['ts'], A['fidx']
    print(f'[build] {n:,} labelled flows, {len(labels)} labels; hashing and de-duplicating', flush=True)

    # ---- classes, de-duplication inside each class (time order, keep the earliest)
    cls_of = [to_class(l) for l in labels]
    all_cls = (['BENIGN'] if 'BENIGN' in cls_of else []) + sorted(set(cls_of) - {'BENIGN'})
    lab2cls = np.array([all_cls.index(c) for c in cls_of], np.int16)
    craw = lab2cls[lab]
    h = row_hash([A['num'][c] for c in f0])
    tsk = ts.view('i8').copy()
    tsk[np.isnat(ts)] = np.iinfo(np.int64).max                # unparsed times last (pandas sort_values)
    order = np.lexsort((np.arange(n), tsk, craw))             # class, then time, then file order
    del tsk
    dup = pd.DataFrame({'c': craw[order], 'h': h[order]}).duplicated(keep='first').to_numpy()
    keep = order[~dup]                                        # de-duplicated rows of every class, ordered
    del order, dup; gc.collect()
    n_raw_l = np.bincount(lab, minlength=len(labels))
    dd_l = np.bincount(lab[keep], minlength=len(labels))      # per label, incl. the classes dropped below
    n_raw_c = np.bincount(craw, minlength=len(all_cls))
    n_dd_c = np.bincount(craw[keep], minlength=len(all_cls))
    kept_c = [k for k in range(len(all_cls)) if n_dd_c[k] >= min_flows]
    CLASSES = [all_cls[k] for k in kept_c]
    keep = keep[np.isin(craw[keep], kept_c)]                  # order preserved: class, then time
    newc = np.full(len(all_cls), -1, np.int8)
    newc[kept_c] = np.arange(len(kept_c))
    y = newc[craw[keep]]
    print(f'[build] kept {len(keep):,} de-duplicated flows in {len(CLASSES)} classes: '
          + ', '.join(f'{c}={int((y == i).sum()):,}' for i, c in enumerate(CLASSES)), flush=True)

    # ---- addresses: distinct values over all rows, per-address flags
    ip_codes, ip_uniq = label_encode(pa.concat_arrays([A['txt'].pop('Source IP'), A['txt'].pop('Destination IP')]))
    src, dst = ip_codes[:n], ip_codes[n:]                     # codes in sorted text order of all addresses
    del ip_codes; gc.collect()
    ip_list = ip_uniq.to_pylist()
    ipf = ip_flags(ip_list)
    outside_strict = ~(np.where(src >= 0, ipf[np.maximum(src, 0), 0], False)
                       & np.where(dst >= 0, ipf[np.maximum(dst, 0), 0], False))
    outside_nat = ~(np.where(src >= 0, ipf[np.maximum(src, 0), 1], False)
                    & np.where(dst >= 0, ipf[np.maximum(dst, 0), 1], False))
    # R2 / R3 analogues (relabel_background.py; attack-labelled flows only, False for BENIGN):
    # R2 = a service port (SERVICE_PORTS) at either end; R3 = the unordered address pair occurs in BENIGN
    benign = lab == labels.index('BENIGN') if 'BENIGN' in labels else np.zeros(n, bool)
    svc = np.array(sorted(SERVICE_PORTS), np.float32)
    r2 = (np.isin(A['num']['Source Port'], svc) | np.isin(A['num']['Destination Port'], svc)) & ~benign
    lo, hi = np.minimum(src, dst).astype(np.int64) + 1, np.maximum(src, dst).astype(np.int64) + 1  # null -> 0
    pair = lo * (len(ip_uniq) + 1) + hi
    del lo, hi
    r3 = np.isin(pair, np.unique(pair[benign])) & ~benign
    del pair; gc.collect()
    rules = {'r2': r2, 'r3': r3, 'benign': benign}

    # ---- descriptive analyses: protocol-0 compression (3) and R1 (R2, R3) analogue
    print('[build] protocol shares and R1 / R2 / R3 analogues', flush=True)
    allr = np.arange(n)
    fl_key = fidx.astype(np.int64) * len(labels) + lab
    fl_names = {int(k): f'{FILES[k // len(labels)][1]} | {labels[k % len(labels)]}' for k in np.unique(fl_key)}
    ymap = np.full(n, -1, np.int64)
    ymap[keep] = y
    p_lab, r_lab = describe(allr, lab.astype(np.int64), labels, A, ipf, src, dst, ip_list, rules)
    p_cls, r_cls = describe(allr, craw.astype(np.int64), all_cls, A, ipf, src, dst, ip_list, rules)
    p_fl, r_fl = describe(allr, fl_key, fl_names, A, ipf, src, dst, ip_list, rules)
    p_dl, r_dl = describe(keep, lab.astype(np.int64), labels, A, ipf, src, dst, ip_list, rules)
    p_dc, r_dc = describe(keep, ymap, CLASSES, A, ipf, src, dst, ip_list, rules)
    common = {'dataset': 'CICIDS2017 (TrafficLabelling / labelled flows)', 'files': [f for _, f in FILES]}
    write_json(OUT / 'protocol_share.json', {
        **common,
        'definition': 'per group: share of flows and of packets (Total Fwd Packets + Total Backward Packets) '
                      'of every Protocol value; largest protocol-0 flow (packets); protocol-0 flows with a '
                      'non-zero source or destination port (as protocol_packet_share.py)',
        'all_rows': {'description': 'every labelled row of the eight CSV files, no de-duplication',
                     'per_label': p_lab, 'per_class': p_cls, 'per_file_and_label': p_fl},
        'deduplicated': {'description': 'the de-duplicated table of the experiments (kept classes only)',
                         'per_label': p_dl, 'per_class': p_dc}})
    write_json(OUT / 'r1_analogue.json', {
        **common,
        'definition': 'R1 analogue (rule R1 of relabel_background.py): a flow with at least one endpoint outside '
                      'the documented networks. strict = outside ' + ' and '.join(NETS_STRICT)
                      + '; with_nat = the firewall inside (NAT) address 172.16.0.1, through which the attacks '
                        'enter the victim LAN, also counts as inside. documented_attacker = an endpoint in '
                      + ', '.join(ATTACKERS) + '. top_outside_endpoints_with_nat = the five most frequent '
                        'endpoint addresses outside the with_nat networks. R2 / R3 analogues (attack-labelled '
                        'flows only, null for BENIGN): r2 = source or destination port in '
                      + str(sorted(SERVICE_PORTS)) + ' (relabel_background.SERVICE_PORTS); r3 = the unordered '
                        'address pair also occurs in a BENIGN flow (any day, all rows); any_rule = R1 | R2 | R3 '
                        'with the strict or the with_nat R1.',
        'networks_strict': NETS_STRICT, 'networks_with_nat': NETS_NAT, 'documented_attacker_addresses': ATTACKERS,
        'service_ports_r2': sorted(SERVICE_PORTS),
        'all_rows': {'per_label': r_lab, 'per_class': r_cls, 'per_file_and_label': r_fl},
        'deduplicated': {'per_label': r_dl, 'per_class': r_dc}})
    del p_lab, r_lab, p_cls, r_cls, p_fl, r_fl, p_dl, r_dl, p_dc, r_dc, allr, fl_key, ymap; gc.collect()

    # ---- label encoding of the text identifiers over the whole de-duplicated table (before any split)
    le, n_distinct = {}, {}
    for c in ('Flow ID', 'Timestamp'):
        le[c], u = label_encode(A['txt'].pop(c), keep)
        n_distinct[c] = int(len(u))
        del u; gc.collect()
    le['Source IP'], n_distinct['Source IP'] = rank_codes(src[keep])        # same codes as label_encode of
    le['Destination IP'], n_distinct['Destination IP'] = rank_codes(dst[keep])  # the address text, cheaper
    for c in NUM_IDS:
        n_distinct[c] = int(pd.unique(A['num'][c][keep]).size)

    # ---- temporal groups (day, original label)
    day_of_file = np.array([DAYS.index(d) for d, _ in FILES], np.int64)
    gkey = day_of_file[fidx] * len(labels) + lab
    gk_u, gcode = np.unique(gkey, return_inverse=True)
    gnames = [group_name(DAYS[k // len(labels)], labels[k % len(labels)]) for k in gk_u]
    # several (day, label) keys share a name ('Friday' for BENIGN, Bot, DDoS, PortScan): the split groups by
    # (y, sub), so the name only has to be unique inside a class; the parquet dictionary gets unique values
    gnames, gmap = np.unique(np.asarray(gnames, dtype=object).astype(str), return_inverse=True)
    gnames, gcode = gnames.tolist(), gmap[gcode].astype(np.int64)

    # ---- summary (written before the cache: a finished cache always has its summary)
    hy = pd.DataFrame({'h': h[keep], 'y': y}).drop_duplicates()
    multi = hy.loc[hy['h'].duplicated(keep=False), 'h'].unique()
    cross = float(np.isin(h[keep], multi).mean())
    del hy, multi
    grp_counts = pd.Series(np.asarray(gnames)[gcode[keep]]).groupby(y).value_counts()
    ka = keep[~benign[keep]]                                  # de-duplicated attack-labelled flows
    summ = {
        'dataset': 'CICIDS2017, generated labelled flows (TrafficLabelling), ' + str(data_dir),
        'smoke_test_nrows_per_file': nrows,
        'files': files_info,
        'timestamp_rule': 'text d/m/yyyy h:mm[:ss] on a 12-hour clock without AM/PM; hours 1-7 read as 13-19 h',
        'features': {'F0': f0, 'n_F0': len(f0), 'F78': ['Destination Port'] + f0, 'identifiers': ID7,
                     'feature_sets': FSET_DESC},
        'deduplication': 'inside each class: time order (stable), exact duplicates of the 77 F0 features '
                         '(NaN == NaN, -0 == +0, 64-bit row hash) removed, earliest flow kept',
        'min_flows_per_class': min_flows,
        'labels': {l: {'class': cls_of[i] if cls_of[i] in CLASSES else f'dropped ({cls_of[i]}: fewer than '
                                                                      f'{min_flows} flows after de-duplication)',
                       'flows_all_rows': int(n_raw_l[i]), 'flows_deduplicated': int(dd_l[i]),
                       'duplicate_share': round(1 - int(dd_l[i]) / max(int(n_raw_l[i]), 1), 4)}
                   for i, l in enumerate(labels)},
        'class_mapping': {l: (cls_of[i] if cls_of[i] in CLASSES else None) for i, l in enumerate(labels)},
        'classes_before_threshold': {c: {'flows_all_rows': int(n_raw_c[k]), 'flows_deduplicated': int(n_dd_c[k]),
                                         'kept': c in CLASSES} for k, c in enumerate(all_cls)},
        'classes': CLASSES,
        'class_counts': {c: int(v) for c, v in zip(CLASSES, np.bincount(y, minlength=len(CLASSES)))},
        'n_flows': int(len(keep)),
        'temporal_groups': {f'{CLASSES[int(k)]} / {g}': int(v) for (k, g), v in grp_counts.items()},
        'rows_whose_feature_vector_occurs_under_another_class': round(cross, 4),
        'distinct_values': n_distinct,
        'rows_with_unparsed_timestamp': int(np.isnat(ts[keep]).sum()),
        'r1_outside_share_deduplicated': {'strict': round(float(outside_strict[keep].mean()), 4),
                                          'with_nat': round(float(outside_nat[keep].mean()), 4)},
        'rule_shares_deduplicated_attack_flows': {
            k: (round(float(v[ka].mean()), 4) if len(ka) else None)
            for k, v in (('r1_strict', outside_strict), ('r1_with_nat', outside_nat), ('r2_service_port', r2),
                         ('r3_benign_pair', r3), ('any_rule_with_nat', outside_nat | r2 | r3))}}
    write_json(OUT / 'data_summary.json', summ)

    # ---- compact cache, written in row batches (no second full copy of the table)
    print(f'[build] writing {OUT / "data.parquet"}', flush=True)
    dct = lambda codes, names: pa.DictionaryArray.from_arrays(
        pa.array(codes.astype(np.int32), mask=codes < 0), pa.array(list(names), pa.string()))
    ip_dict = pa.array(ip_list, pa.string())
    file_names = [f for _, f in FILES]
    tmp = OUT / 'data.tmp.parquet'
    writer = None
    try:
        for i in range(0, len(keep), BATCH):
            sel = keep[i:i + BATCH]
            cols = {c: pa.array(A['num'][c][sel]) for c in f0 + NUM_IDS}
            cols.update({LE[c]: pa.array(le[c][i:i + BATCH]) for c in STR_IDS})
            cols.update({
                'y': pa.array(y[i:i + BATCH]),
                'label': dct(lab[sel], labels),
                'group': dct(gcode[sel], gnames),
                'day': dct(day_of_file[fidx[sel]], DAYS),
                'file': dct(fidx[sel].astype(np.int32), file_names),
                'file_row': pa.array(A['rown'][sel]),
                'ts': pa.array(ts[sel]),
                'src_ip': pa.DictionaryArray.from_arrays(pa.array(src[sel], mask=src[sel] < 0), ip_dict),
                'dst_ip': pa.DictionaryArray.from_arrays(pa.array(dst[sel], mask=dst[sel] < 0), ip_dict),
                'outside_strict': pa.array(outside_strict[sel]),
                'outside_nat': pa.array(outside_nat[sel]),
                'r2_service': pa.array(r2[sel]),
                'r3_benign_pair': pa.array(r3[sel]),
                'raw_hash': pa.array(h[sel])})
            t = pa.table(cols)
            if writer is None:
                writer = pq.ParquetWriter(tmp, t.schema, compression='zstd')
            writer.write_table(t)
            del t, cols
        writer.close()
    except BaseException:
        if writer is not None:
            writer.close()
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, OUT / 'data.parquet')
    print(f'[build] done: {len(keep):,} flows, {len(CLASSES)} classes; cross-class duplicate share {cross:.2%}',
          flush=True)
    del A, h, keep, y; gc.collect()


# ============================================================================ experiment
def load_meta():
    """Small per-row columns: y, sub (temporal group, categorical), ts, and the 64-bit feature hash."""
    import pyarrow.parquet as pq
    pf = pq.ParquetFile(OUT / 'data.parquet')
    meta = pf.read(columns=['y', 'group', 'ts']).to_pandas().rename(columns={'group': 'sub'})
    meta['sub'] = meta['sub'].astype('category')
    h = pf.read(columns=['raw_hash']).column(0).to_numpy()
    return meta, h


def load_xy(cols, tr, te):
    """X[tr] and X[te] of `cols` (float32, NaN/inf -> 0 as deep_split_noise_study.prepare), filled one parquet
    column at a time: the full matrix is never built, so the peak is about the size of X[tr] + X[te]."""
    import pyarrow.parquet as pq
    pf = pq.ParquetFile(OUT / 'data.parquet')
    Xtr = np.empty((len(tr), len(cols)), np.float32)
    Xte = np.empty((len(te), len(cols)), np.float32)
    for j, c in enumerate(cols):
        v = pf.read(columns=[c], use_threads=False).column(0).to_numpy().astype(np.float32, copy=False)
        Xtr[:, j] = v[tr]
        Xte[:, j] = v[te]
    del v
    for M in (Xtr, Xte):
        np.nan_to_num(M, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return Xtr, Xte


def fit_xgb(Xtr, ytr, device, cpu_jobs):
    """XGBoost of extra_baselines.make with balanced weights; GPU first, CPU fallback when the GPU fit fails."""
    from sklearn.utils.class_weight import compute_sample_weight
    w = compute_sample_weight('balanced', ytr)
    devs = {'auto': ['cuda', 'cpu'], 'cuda': ['cuda'], 'cpu': ['cpu']}[device]
    for d in devs:
        clf = make('XGBoost')
        if d == 'cpu':
            clf.set_params(device='cpu', n_jobs=cpu_jobs)
        try:
            t = time.time()
            clf.fit(Xtr, ytr, sample_weight=w)
            try:
                used = json.loads(clf.get_booster().save_config())['learner']['generic_param'].get('device', d)
            except Exception:                                  # config layout differs between versions
                used = d
            return clf, used, time.time() - t
        except Exception as e:
            if d == devs[-1]:
                raise
            print(f'[device] {d} fit failed ({type(e).__name__}: {str(e)[:160]}); repeating on the CPU', flush=True)
            del clf; gc.collect()


def score(CLASSES, yt, p, proba, st):
    from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score
    labels = list(range(len(CLASSES)))
    attacks = [i for i, c in enumerate(CLASSES) if c != 'BENIGN']
    r = dsn.metrics(yt, p, st)                                # accuracy, BA, macro-F1, per class, per group
    r['attack_macro_f1'] = float(f1_score(yt, p, average='macro', labels=attacks, zero_division=0))
    r['weighted_f1'] = float(f1_score(yt, p, average='weighted', labels=labels, zero_division=0))
    r['per_class_precision'] = dict(zip(CLASSES, precision_score(yt, p, average=None, labels=labels,
                                                                 zero_division=0).round(4).tolist()))
    ap = {c: (round(float(average_precision_score(yt == k, proba[:, k])), 4) if (yt == k).any() else None)
          for k, c in enumerate(CLASSES)}
    r['per_class_average_precision'] = ap
    r['macro_average_precision'] = float(np.mean([v for v in ap.values() if v is not None]))
    r['per_class_n_test'] = {c: int((yt == k).sum()) for k, c in enumerate(CLASSES)}
    r['per_subattack_n_test'] = {f'{CLASSES[c]} / {s}': int(((yt == c) & (st == s)).sum())
                                 for c, s in sorted(set(zip(yt.tolist(), st.tolist())))}
    r['confusion'] = confusion_matrix(yt, p, labels=labels).tolist()
    return r


def group_windows(CLASSES, meta, tr, te):
    """Per temporal group: sizes and time windows of the training and test parts, plus the test flows whose
    timestamp is not later than the last training timestamp of their group. Most files give only minutes, so
    flows of the boundary minute can fall on both sides (ties keep the cache row order = source-file order)."""
    out, train_end = {}, {}
    for part, idx in (('train', tr), ('test', te)):
        g = meta.iloc[idx].groupby(['y', 'sub'], observed=True)['ts'].agg(['size', 'min', 'max'])
        for (k, s), row in g.iterrows():
            d = out.setdefault(f'{CLASSES[int(k)]} / {s}', {})
            d.update({f'n_{part}': int(row['size']), f'{part}_start': str(row['min']), f'{part}_end': str(row['max'])})
            if part == 'train':
                train_end[(int(k), str(s))] = row['max']
    yt, st, tt = meta['y'].to_numpy()[te], meta['sub'].astype(str).to_numpy()[te], meta['ts'].to_numpy()[te]
    lim = np.array([train_end.get((int(k), s), np.datetime64('NaT')) for k, s in zip(yt, st)], 'datetime64[ns]')
    tie = ~np.isnat(lim) & ~np.isnat(tt) & (tt <= lim)
    for (k, s), n in pd.Series(tie).groupby([yt, st]).sum().items():
        out.setdefault(f'{CLASSES[int(k)]} / {s}', {})['n_test_not_after_train_end'] = int(n)
    return out, int(tie.sum())


def run(a, summ):
    CLASSES = summ['classes']
    dsn.CLASSES = CLASSES               # dsn.metrics() takes the class names from its module-level CLASSES
    f0 = summ['features']['F0']
    jobs = [j for j in JOBS if a.study in ('all', j['study'])]
    todo = [j for j in jobs if not (OUT / f'{j["name"]}.json').exists()]
    print(f'[plan] {len(jobs)} runs, {len(jobs) - len(todo)} finished, {len(todo)} to do', flush=True)
    if not todo:
        return True
    batch = todo[:a.max_fits] if a.max_fits else todo
    meta, h = load_meta()
    y = meta['y'].to_numpy().astype(np.int64)
    sub = meta['sub'].astype(str).to_numpy()
    print(f'[data] {len(y):,} flows, {len(CLASSES)} classes', flush=True)
    for i, j in enumerate(batch, 1):
        if j['split'] == 'random80':
            from sklearn.model_selection import train_test_split
            tr, te = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=SEED)
            n_val = 0
        else:
            tr, va, te = dsn.splits(meta, j['split'])        # random 70/15/15 | the temporal split within capture groups (paper Section 4.2)
            tr, va, te = np.asarray(tr), np.asarray(va), np.asarray(te)
            n_val = len(va)
            del va
        names = f0 + EXTRA[j['fset']]
        Xtr, Xte = load_xy(names, tr, te)                     # rows in the order of tr / te, as X[tr] / X[te]
        print(f'[fit] {j["name"]}: train {len(tr):,} x {len(names)}, test {len(te):,}', flush=True)
        clf, dev, fit_s = fit_xgb(Xtr, y[tr], a.device, a.cpu_jobs)
        del Xtr; gc.collect()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')                   # device-mismatch notice of GPU models on numpy input
            proba = np.asarray(clf.predict_proba(Xte), np.float32)
        del Xte
        p = proba.argmax(1).astype(np.int8)                   # = XGBClassifier.predict for multi:softprob
        yt, st = y[te], sub[te]
        r = score(CLASSES, yt, p, proba, st)
        imp = np.asarray(clf.feature_importances_, float)
        order = np.argsort(-imp)
        rank = np.empty(len(imp), int); rank[order] = np.arange(1, len(imp) + 1)
        prm = clf.get_params()
        dup_any = np.isin(h[te], h[tr])
        r.update({
            'run': j['name'], 'study': j['study'], 'dataset': 'CICIDS2017 (labelled flows, de-duplicated)',
            'feature_set': j['fset'], 'features': FSET_DESC[j['fset']], 'n_features': int(len(names)),
            'split': j['split'], 'split_desc': SPLIT_DESC[j['split']],
            'model': 'XGBoost', 'weighting': "compute_sample_weight('balanced', y_train)",
            'model_params': {k: prm.get(k) for k in ('n_estimators', 'max_depth', 'learning_rate', 'tree_method',
                                                     'random_state')},
            'device_requested': a.device, 'device_used': dev,
            'classes': CLASSES, 'n_train': int(len(tr)), 'n_val_unused': int(n_val), 'n_test': int(len(te)),
            'class_counts_train': {c: int(v) for c, v in zip(CLASSES, np.bincount(y[tr], minlength=len(CLASSES)))},
            'fit_seconds': round(fit_s, 1),
            'test_share_with_identical_train_vector_any_class': round(float(dup_any.mean()), 4),
            'test_duplicate_definition': 'test flows whose 77 F0 values (raw_hash) occur in a training flow of any '
                                         'class; duplicates inside a class were removed before the split, so '
                                         'these are cross-class duplicates',
            'importance_gain_top15': {names[q]: round(float(imp[q]), 4) for q in order[:15]},
            'identifier_importance': {ID_NAME[names[q]]: {'gain_share': round(float(imp[q]), 4), 'rank': int(rank[q])}
                                      for q in range(len(f0), len(names))}})
        if j['split'] == 'temporal':
            r['groups'], n_tie = group_windows(CLASSES, meta, tr, te)
            r['test_share_not_after_train_end_of_group'] = round(n_tie / max(len(te), 1), 4)
        np.savez_compressed(OUT / f'{j["name"]}.npz', y=yt.astype(np.int8), p=p, proba=proba.astype(np.float16),
                            sub=st.astype(str), idx=te.astype(np.int32))   # before the JSON: JSON = run complete
        write_json(OUT / f'{j["name"]}.json', r)
        print(f'[{len(jobs) - len(todo) + i}/{len(jobs)}] {j["name"]:22s} acc={r["accuracy"]:.4f}  '
              f'bal-acc={r["balanced_accuracy"]:.4f}  macro-F1={r["macro_f1"]:.4f}  '
              f'attack-F1={r["attack_macro_f1"]:.4f}  ({dev}, {fit_s / 60:.1f} min)', flush=True)
        del clf, proba, p, dup_any, tr, te; gc.collect()
    left = len(todo) - len(batch)
    print(f'[left] {left} runs still to do' if left else '[DONE] all runs finished', flush=True)
    return not left


# ============================================================================ summary
REFS = {   # matching CIC IoT-DIAD 2024 results of this project (read when present)
    'identifier_leakage_v2 (de-duplicated, 8 folder classes, random 80/20, balanced XGBoost)': {
        'F0 81 flow features': 'identifier_leakage_v2/random_F0.json',
        'F1 + destination port, protocol': 'identifier_leakage_v2/random_F1.json',
        'F3 + timestamp (seconds)': 'identifier_leakage_v2/random_F3.json',
        'F4 + five identifiers': 'identifier_leakage_v2/random_F4.json'},
    'published_control (no de-duplication, published class set, random 80/20, balanced XGBoost)': {
        'F0': 'q1_revision/published_control/F0_balanced.json',
        'FT (+ label-encoded timestamp)': 'q1_revision/published_control/FT_balanced.json',
        'FA (+ all seven identifiers)': 'q1_revision/published_control/FA_balanced.json'},
    'tree_protocol (raw labels, XGBoost seed 42, 81 features)': {
        'random 70/15/15': 'tree_protocol/main/XGBoost_random_raw_s42.json',
        'temporal (within capture groups, paper Section 4.2)': 'tree_protocol/main/XGBoost_temporal_raw_s42.json'}}


def summary():
    rows = [json.load(open(OUT / f'{j["name"]}.json', encoding='utf-8')) for j in JOBS
            if (OUT / f'{j["name"]}.json').exists()]
    res = {}
    if rows:
        pd.set_option('display.width', 200)
        t = pd.DataFrame([{'run': r['run'], 'split': r['split'], 'set': r['feature_set'], 'accuracy': r['accuracy'],
                           'bal_acc': r['balanced_accuracy'], 'macro_f1': r['macro_f1'],
                           'attack_f1': r['attack_macro_f1'], 'macro_ap': r['macro_average_precision'],
                           'test_dup': r['test_share_with_identical_train_vector_any_class'],
                           'test_ties': r.get('test_share_not_after_train_end_of_group'),
                           'n_train': r['n_train'], 'n_test': r['n_test'], 'device': r['device_used'],
                           'fit_min': r['fit_seconds'] / 60} for r in rows])
        print('\n=== CICIDS2017 replication (XGBoost, balanced weights) ===')
        print(t.round(4).to_string(index=False))
        t.to_csv(OUT / 'summary.csv', index=False)
        by = {r['run']: r for r in rows}
        res['runs'] = t.round(4).to_dict('records')
        eff = {}
        for a_, b_ in (('F78', 'F0'), ('FT', 'F78'), ('FA', 'F78'), ('FA', 'F0')):
            ra, rb = by.get(f'identifiers_{a_}'), by.get(f'identifiers_{b_}')
            if ra and rb:
                eff[f'identifiers {a_} - {b_}'] = {m: round(ra[m] - rb[m], 4)
                                                   for m in ('accuracy', 'balanced_accuracy', 'macro_f1')}
        for f in ('F0', 'F78'):
            ra, rb = by.get(f'split_random_{f}'), by.get(f'split_temporal_{f}')
            if ra and rb:
                eff[f'split random - temporal ({f})'] = {m: round(ra[m] - rb[m], 4)
                                                         for m in ('accuracy', 'balanced_accuracy', 'macro_f1',
                                                                   'attack_macro_f1')}
                print(f'\n=== per-class recall / F1, random vs temporal ({f}) ===')
                pc = pd.DataFrame({'recall_random': ra['per_class_recall'], 'recall_temporal': rb['per_class_recall'],
                                   'f1_random': ra['per_class_f1'], 'f1_temporal': rb['per_class_f1'],
                                   'n_test_temporal': rb['per_class_n_test']})
                print(pc.round(3).to_string())
                res[f'per_class_{f}'] = pc.round(4).to_dict('index')
        res['effects'] = eff
        if eff:
            print('\n=== effects ===')
            for k, v in eff.items():
                print(f'  {k:34s} ' + '  '.join(f'{m}={x:+.4f}' for m, x in v.items()))
        ids = [(r['run'], r['identifier_importance']) for r in rows if r['identifier_importance']]
        if ids:
            print('\n=== identifier gain share (rank) ===')
            for n_, d in ids:
                print(f'  {n_:22s} ' + ', '.join(f'{k}={v["gain_share"]:.3f} (#{v["rank"]})' for k, v in d.items()))
    else:
        print('no finished runs yet')
    ref = {}
    for block, files in REFS.items():
        for k, rel in files.items():
            f = RES / rel
            if f.exists():
                r = json.load(open(f, encoding='utf-8'))
                ref.setdefault(block, {})[k] = {m: round(float(r[m]), 4) for m in
                                                ('accuracy', 'balanced_accuracy', 'macro_f1') if m in r}
    res['reference_cic_iot_diad_2024'] = ref
    if ref:
        print('\n=== CIC IoT-DIAD 2024 reference (this project) ===')
        for block, d in ref.items():
            print(f'  {block}')
            for k, v in d.items():
                print(f'    {k:36s} ' + '  '.join(f'{m}={x:.4f}' for m, x in v.items()))
    for fn, key in (('r1_analogue.json', 'r1'), ('protocol_share.json', 'proto')):
        if (OUT / fn).exists():
            d = json.load(open(OUT / fn, encoding='utf-8'))['all_rows']['per_label']
            if key == 'r1':
                keys = ('flows', 'share_any_endpoint_outside_strict', 'share_any_endpoint_outside_with_nat',
                        'share_documented_attacker_endpoint', 'r2_share_service_port', 'r3_share_benign_pair',
                        'any_rule_share_with_nat')
                res['r1_analogue_all_rows'] = {l: {k: v.get(k) for k in keys} for l, v in d.items()}
                num = lambda x: f'{x:.3f}' if isinstance(x, (int, float)) else '  -  '
                print('\n=== rule analogues (all rows): R1 strict | R1 with NAT | attacker endpoint | R2 | R3 | '
                      'any (R1 with NAT) ===')
                for l, v in d.items():
                    print(f'  {l:28s} flows={v["flows"]:>9,}  ' + ' | '.join(num(v.get(k)) for k in keys[1:]))
            else:
                res['protocol0_all_rows'] = {l: {'flow_share_proto0': v['flow_share'].get('0', 0.0),
                                                 'packet_share_proto0': v['packet_share'].get('0', 0.0),
                                                 'largest_proto0_flow_packets': v['largest_proto0_flow_packets']}
                                             for l, v in d.items()}
                print('\n=== protocol 0 (all rows): share of flows | share of packets | largest flow ===')
                num = lambda x: f'{x:.4f}' if isinstance(x, (int, float)) else 'n/a'
                for l, v in res['protocol0_all_rows'].items():
                    print(f'  {l:28s} {num(v["flow_share_proto0"])} | {num(v["packet_share_proto0"])} | '
                          f'{v["largest_proto0_flow_packets"]:,}')
    write_json(OUT / 'summary.json', res)
    print('\n[saved]', OUT / 'summary.json')


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-fits', type=int, default=0,
                    help='stop after N model fits (0 = no limit); use 1 inside a PowerShell loop (fresh process per fit)')
    ap.add_argument('--study', choices=['all', 'identifiers', 'split'], default='all')
    ap.add_argument('--device', choices=['auto', 'cuda', 'cpu'], default='auto',
                    help='auto = GPU, repeated on the CPU if the GPU fit fails')
    ap.add_argument('--cpu-jobs', type=int, default=4)
    ap.add_argument('--min-flows', type=int, default=100, help='drop classes with fewer flows after de-duplication')
    ap.add_argument('--build-only', action='store_true', help='only build the cache and the descriptive JSONs')
    ap.add_argument('--summary', action='store_true', help='only print the tables of finished runs')
    ap.add_argument('--data-dir', default=str(DATA), help='(smoke tests) folder with the eight CSV files')
    ap.add_argument('--out', default=None, help='(smoke tests) output folder instead of q1_revision/cicids2017')
    ap.add_argument('--nrows', type=int, default=None, help='(smoke tests) read only the first N rows of each file')
    a = ap.parse_args()
    smoke = a.nrows is not None or Path(a.data_dir).resolve() != DATA.resolve()
    if a.out:
        OUT = Path(a.out)
    elif smoke:        # a partial cache in the real folder would be reused silently by every later run
        ap.error('--nrows / --data-dir are for smoke tests: add --out <scratch folder>')
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summary:
        summary(); return
    if not (OUT / 'data.parquet').exists():
        build(Path(a.data_dir), a.nrows, a.min_flows)
    summ = json.load(open(OUT / 'data_summary.json', encoding='utf-8'))
    if summ.get('min_flows_per_class') != a.min_flows:
        sys.exit(f'[stop] the cache in {OUT} was built with --min-flows {summ.get("min_flows_per_class")}, not '
                 f'{a.min_flows}: pass the same value, or delete data.parquet to rebuild')
    if not a.out and summ.get('smoke_test_nrows_per_file'):
        sys.exit(f'[stop] {OUT / "data.parquet"} was built from the first {summ["smoke_test_nrows_per_file"]} rows '
                 f'of each file (smoke test): delete it and rebuild from the full CSV files')
    if a.build_only:
        return
    if run(a, summ):
        summary()


if __name__ == '__main__':
    main()
