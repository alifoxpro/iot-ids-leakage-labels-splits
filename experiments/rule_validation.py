# -*- coding: utf-8 -*-
"""
rule_validation.py
==================
Signature-based PARTIAL validation of the background rules R1-R3 (relabel_background.py,
flagged_loader.py). Reviewer question: do the rules remove genuine attack traffic, and how
much attack traffic is left after cleaning? The packet-level release of CIC IoT-DIAD 2024
(with MAC-level ground truth) is not available locally, so attack-related flows are
identified here from the flow CSVs alone, WITHOUT using R1-R3, and the rules are then scored
against this partial ground truth.

Captures (ALL flows of the raw CSVs - no sampling, no de-duplication, no caps):
  BruteForce, Web-Based / Sqlinjection, XSS, Uploading Attack, Spoofing / DNS Spoofing, ARP Spoofing
Columns read: Src IP, Dst IP, Src Port, Dst Port, Protocol, Timestamp, Total Fwd Packet,
Total Bwd packets, Flow Duration.

Step 1 - attack signature (direction-robust: the service port may sit on either side, because
         CICFlowMeter orients a flow by the first packet it sees)
  BruteForce  TCP flows on port 22 or 23 (SSH / Telnet)
  Web         TCP flows on port 80 or 8080 (HTTP)
  DNS         UDP flows on port 53 that involve a "rogue responder": a testbed address other
              than the gateway 192.168.137.1 that is on the port-53 side of >= 5 UDP flows
              in which it SENDS packets (Total Bwd packets > 0 when it is the destination;
              as the source it sent the first packet), i.e. it answers DNS (in the testbed
              the devices resolve through the gateway or Internet resolvers). The same heuristic is applied to the Benign captures as a
              false-positive baseline (flow-direction flips can create such flows there too).
  ARP         protocol-0 flows between the pseudo-addresses 8.6.0.1 and 8.0.6.4: CICFlowMeter
              parses ARP frames as IPv4, so "source" = EtherType 0x0806 + hardware type 0x0001
              and "destination" = protocol type 0x0800 + address lengths 6/4. These bytes are
              the same in EVERY ARP frame, so all ARP frames of a flow-timeout window (normal
              and spoofed) collapse into one pseudo-flow - they also occur in Benign.
              Plus, if identifiable, the spoofing host: the testbed host (not the gateway) that
              sends protocol-0 flows (ICMP; CICFlowMeter reports ICMP as protocol 0) to the most
              distinct testbed hosts - a man-in-the-middle host that forwards the victims'
              packets emits ICMP redirects (and host-discovery pings). Accepted only if its
              fan-out is >= 3 hosts and >= 2x the runner-up.
Step 2 - attackers and victims (BruteForce, Web, DNS)
  Only signature flows whose two endpoints are testbed/lab addresses (192.168.137.0/24,
  205.174.165.0/24) are used: the dataset page states that malicious IoT devices attack IoT
  devices, while web/DNS traffic to Internet hosts is ordinary device traffic (e.g. the SQLi
  capture's largest port-80 pair is the largest pair of the Benign captures).
  Attackers = smallest set of client-side addresses (DNS: the rogue responders) that covers
  >= 80 % of these flows; victims = smallest set of server-side addresses (DNS: counterparts)
  that covers >= 80 % of the attackers' signature flows (at most 10 addresses each).
Step 3 - attack-related flows, two definitions
  signature        the signature flows between attackers and victims (ARP: the pseudo-flows)
  attacker_victim  EVERY flow between an attacker and a victim, any port/protocol    <- main
                   (ARP: the pseudo-flows plus every flow of the spoofing host)
Step 4 - the rules, exactly as in relabel_background.py / flagged_loader.py
  R1 external endpoint (internal()), R2 service ports (DNS exception for DNS Spoofing),
  R3 IP pair seen in Benign (pair set from ALL Benign flows), any = R1|R2|R3 ('all' cleaning).

Reported per capture, definition and rule (R1, R2, R3, any):
  false_removal_rate    attack-related flows flagged / attack-related flows
  flagged_attack_share  attack-related share of the flagged flows
  kept_attack_share     attack-related share of the kept flows (purity of what remains)
  counts, packet-weighted false-removal rate, the flows responsible for false removals,
  the raw signature breakdown (all signature flows incl. those with an Internet endpoint -
  the only partly independent evidence on R1), top destination hosts, the attack time window,
  a Benign baseline of every signature/heuristic (attackers_also_derived_in_benign lists the
  derived attackers that the same heuristic also picks in Benign - suspect), and the number of
  flows of each derived address in every capture and in Benign.
Benign CSVs: the pair set for R3 uses only the IP columns; ports, protocol and packet counts
are read as well, only for the signature false-positive baseline (~0.4 M rows, small).

Heuristic assumptions (stored in the JSON under "assumptions"):
  * flow level only; "attack-related" is a partial, heuristic ground truth;
  * flows not linked to an identified attacker are UNCONFIRMED, not proven background, so
    kept_attack_share and flagged_attack_share are lower bounds;
  * all traffic between an attacker and a victim is attributed to the attack (it may contain
    some background between the same two devices - compare with the 'signature' definition);
  * R1 is not tested independently for BruteForce/Web/DNS (step 2 uses the same address
    ranges); see signature_raw and the ARP pseudo-flows instead;
  * rates are on raw flows (before the de-duplication and caps of flagged_loader.py).

Output: results_2026_03_03/q1_revision/rule_validation/rule_validation.json
Skipped if it exists (--force recomputes). Reads only small CSVs, trains no model (~1-2 min).
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\rule_validation.py
"""
import argparse, gc, json, os, sys, time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import TS_FMT  # noqa: E402
from relabel_background import (DNS_ATTACK, SERVICE_PORTS, TESTBED, capture_groups,  # noqa: E402
                                internal, pair_key)

sys.stdout.reconfigure(encoding='utf-8')
OUT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'rule_validation'
COLS = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp',
        'Total Fwd Packet', 'Total Bwd packets', 'Flow Duration']
BENIGN_COLS = [c for c in COLS if c != 'Timestamp']
CAPTURES = [('BruteForce', 'BruteForce', 'bruteforce'),          # (class folder, capture group, signature)
            ('Web-Based', 'Sqlinjection', 'web'),
            ('Web-Based', 'XSS', 'web'),
            ('Web-Based', 'Uploading Attack', 'web'),
            ('Spoofing', 'DNS Spoofing', 'dns'),
            ('Spoofing', 'ARP Spoofing', 'arp')]
PORTS = {'bruteforce': [22, 23], 'web': [80, 8080]}
TCP, UDP, PROTO0 = 6, 17, 0
PROTO_NAME = {0: 'proto0', 6: 'TCP', 17: 'UDP'}
GATEWAY = '192.168.137.1'
ARP_PSEUDO = ('8.6.0.1', '8.0.6.4')
COVER, MAX_HOSTS = 0.80, 10              # attacker / victim sets: >= 80 % coverage, at most 10 addresses
MIN_RESPONDER_FLOWS = 5                  # DNS: a rogue responder answers >= 5 UDP/53 flows
ARP_MIN_FANOUT, ARP_MIN_RATIO = 3, 2.0   # ARP host: ICMP to >= 3 testbed hosts and >= 2x the runner-up
RULES = ['R1_external', 'R2_service', 'R3_benign_pair', 'any']
DEFS = ['signature', 'attacker_victim']
ASSUMPTIONS = [
    'Flow-level evidence only: the packet-level release with MAC-level ground truth is not available; '
    '"attack-related" is a partial, heuristic ground truth derived without R1-R3.',
    'Service ports are matched on either side of a flow because CICFlowMeter orients a flow by its first '
    'packet; the endpoint on the service-port side is the server (victim for BruteForce/Web, responder for DNS).',
    'Attackers and victims (BruteForce, Web, DNS) are derived only from signature flows with both endpoints in '
    '192.168.137.0/24 or 205.174.165.0/24, following the dataset statement that malicious IoT devices attack IoT '
    'devices. R1 is therefore not tested independently for these captures; signature_raw reports how the rules '
    'treat all signature flows, including those with an Internet endpoint.',
    f'Attackers = smallest set of client-side addresses covering >= {COVER:.0%} of the testbed signature flows; '
    f'victims = smallest set of server-side addresses covering >= {COVER:.0%} of the attackers\' signature flows '
    f'(at most {MAX_HOSTS} addresses each).',
    'Every flow between an attacker and a victim (any port or protocol) is attack-related in the main '
    'definition (attacker_victim); it may include background between the same two devices, so the narrower '
    '"signature" definition is reported as well.',
    f'DNS Spoofing: a rogue responder is a testbed address other than the gateway {GATEWAY} on the port-53 side '
    f'of >= {MIN_RESPONDER_FLOWS} UDP flows in which it sends packets (Total Bwd packets > 0 when it is the '
    'destination; as the source it sent the first packet), i.e. it answers DNS queries. Spoofed replies that '
    'carry the IP address of the real resolver (gateway or Internet) cannot be separated at flow level and are '
    'not captured. Flow-direction flips can produce such flows in normal traffic; the '
    'same heuristic applied to the Benign captures is reported as a false-positive baseline.',
    'ARP Spoofing: 8.6.0.1 / 8.0.6.4 are ARP header bytes read as IPv4 addresses (0x0806 0x0001 / 0x0800 0x06 '
    '0x04). All ARP frames of a flow-timeout window (normal and spoofed) share one pseudo-flow, which also occurs '
    'in Benign, so the attacker cannot be read from it. The spoofing host is taken as the testbed host (not the '
    f'gateway) with the largest protocol-0 (ICMP) fan-out to other testbed hosts (ICMP redirects of a forwarding '
    f'man-in-the-middle host), accepted if the fan-out is >= {ARP_MIN_FANOUT} and >= {ARP_MIN_RATIO:g}x the '
    'runner-up; all its flows are then attack-related.',
    'Flows not linked to an identified attacker are unconfirmed, not proven background: kept_attack_share and '
    'flagged_attack_share are lower bounds of the true attack shares.',
    'Rates are computed on the raw flows of each capture (before the de-duplication and DOS/DDOS caps of '
    'flagged_loader.py), so they can differ slightly from the flag rates in flagged_data.parquet.',
    'Flow Duration is in microseconds (CICFlowMeter); packets = Total Fwd Packet + Total Bwd packets.',
]


# ----------------------------------------------------------------------------- helpers
def _r(x, n, k=4):
    return round(float(x) / float(n), k) if n else None


def _pct(x):
    return '   n/a' if x is None else f'{x:6.1%}'


def _json(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return str(o)


def isin(arr, vals):
    """Hash-based membership test on an object array (empty vals -> all False)."""
    if len(vals) == 0:
        return np.zeros(len(arr), bool)
    return pd.Series(arr, dtype=object).isin(list(vals)).to_numpy()


def between(src, dst, a, v):
    """Flows between an address in a and an address in v, either direction."""
    return (isin(src, a) & isin(dst, v)) | (isin(src, v) & isin(dst, a))


def cover(values, share=COVER, cap=MAX_HOSTS):
    """Smallest set of the most frequent values that covers >= share of the entries (at most cap)."""
    vc = pd.Series(values, dtype=object).value_counts()
    if vc.empty:
        return []
    k = int(np.searchsorted((vc.cumsum() / vc.sum()).to_numpy(), share - 1e-9)) + 1
    return [str(v) for v in vc.index[:min(k, cap)]]


def top(values, n=10, testbed=False):
    vals = pd.Series(values, dtype=object)
    vc = vals.value_counts().head(n)
    out = [{'value': str(k), 'flows': int(c), 'share': _r(c, len(vals))} for k, c in vc.items()]
    if testbed and out:
        flag = internal(pd.Series([o['value'] for o in out])).astype(bool)
        for o, f in zip(out, flag):
            o['testbed'] = bool(f)
    return out


def host_counts(src, dst):
    c = Counter(pd.Series(src, dtype=object).value_counts().to_dict())
    c.update(pd.Series(dst, dtype=object).value_counts().to_dict())
    return c


def _clean(ch):
    for c in ('Src IP', 'Dst IP'):
        ch[c] = ch[c].astype(str)
    for c in ('Src Port', 'Dst Port', 'Protocol'):
        ch[c] = pd.to_numeric(ch[c], errors='coerce').fillna(-1).astype(np.int64)
    fwd = pd.to_numeric(ch['Total Fwd Packet'], errors='coerce').fillna(0)
    bwd = pd.to_numeric(ch['Total Bwd packets'], errors='coerce').fillna(0)
    ch['pk'] = (fwd + bwd).astype(np.float64)
    ch['bwd'] = bwd.astype(np.float32)          # DNS: did the destination (port-53 side) answer?
    ch['dur'] = pd.to_numeric(ch['Flow Duration'], errors='coerce').fillna(0).astype(np.float64)
    return ch.drop(columns=['Total Fwd Packet', 'Total Bwd packets', 'Flow Duration'])


def load(files, cols):
    parts = [_clean(ch) for f in files
             for ch in pd.read_csv(f, usecols=cols, chunksize=400_000, low_memory=False)]
    return pd.concat(parts, ignore_index=True)


def pseudo_rate(mask, pk, dur):
    n, p, d = int(mask.sum()), float(pk[mask].sum()), float(dur[mask].sum()) / 1e6
    return {'flows': n, 'packets': int(p), 'packets_per_flow': round(p / n, 1) if n else None,
            'duration_s': round(d, 1), 'packets_per_second': round(p / d, 3) if d > 0 else None}


# ----------------------------------------------------------------------------- rules (as flagged_loader.py)
def rule_flags(df, sub, benign_pairs):
    int_s = internal(df['Src IP']).astype(bool)
    int_d = internal(df['Dst IP']).astype(bool)
    r1 = ~(int_s & int_d)
    svc = df['Src Port'].isin(SERVICE_PORTS) | df['Dst Port'].isin(SERVICE_PORTS)
    if sub == DNS_ATTACK:                                   # DNS is the attack itself here
        svc = svc & ~((df['Src Port'] == 53) | (df['Dst Port'] == 53))
    r2 = svc.to_numpy()
    r3 = pd.Series(pair_key(df['Src IP'], df['Dst IP'])).isin(benign_pairs).to_numpy()
    return {'R1_external': r1, 'R2_service': r2, 'R3_benign_pair': r3, 'any': r1 | r2 | r3}, int_s, int_d


# ----------------------------------------------------------------------------- signatures (independent of R1-R3)
def identify(kind, df, int_s, int_d):
    """Signature flows, attackers, victims and the two attack-related masks of one capture."""
    src, dst = df['Src IP'].to_numpy(), df['Dst IP'].to_numpy()
    sp, dp, proto = df['Src Port'].to_numpy(), df['Dst Port'].to_numpy(), df['Protocol'].to_numpy()
    both = int_s & int_d
    extra, server, client = {}, None, None
    if kind in PORTS:
        on_dst = np.isin(dp, PORTS[kind])
        raw = (proto == TCP) & (on_dst | np.isin(sp, PORTS[kind]))
        server, client = np.where(on_dst, dst, src), np.where(on_dst, src, dst)
        cand = raw & both
        att = cover(client[cand])
        cand_a = cand & isin(client, att)
        vic = cover(server[cand_a])
        sig = cand_a & isin(server, vic)
        av = between(src, dst, att, vic)
        extra = {'signature_testbed_flows': int(cand.sum()),
                 'attacker_coverage': _r(cand_a.sum(), cand.sum()),
                 'victim_coverage': _r(sig.sum(), cand_a.sum())}
    elif kind == 'dns':
        on_dst = dp == 53
        raw = (proto == UDP) & (on_dst | (sp == 53))
        server, client = np.where(on_dst, dst, src), np.where(on_dst, src, dst)
        # the port-53 side must SEND packets: backward packets when it is the destination; when it is
        # the source (flow starts with its port-53 packet) it sent the first packet by definition
        answers = np.where(on_dst, df['bwd'].to_numpy() > 0, True)
        role = raw & answers & np.where(on_dst, int_d, int_s) & (server != GATEWAY)  # testbed host answering DNS
        n_role = pd.Series(server[role], dtype=object).value_counts()
        eligible = [str(h) for h in n_role.index[n_role >= MIN_RESPONDER_FLOWS]]
        role_ok = role & isin(server, eligible)
        att = cover(server[role_ok])
        inv_s = isin(src, att)
        cand = raw & both & (inv_s | isin(dst, att))
        other = np.where(inv_s, dst, src)
        vic = cover(other[cand])
        sig = cand & isin(other, vic)
        av = between(src, dst, att, vic)
        extra = {'responder_candidates': top(server[role], n=10),
                 'responder_role_flows': int(role.sum()),
                 'port53_testbed_server_flows_without_answer':
                     int((raw & ~answers & np.where(on_dst, int_d, int_s) & (server != GATEWAY)).sum()),
                 'eligible_responders': eligible,
                 'responder_coverage': _r(isin(server[role_ok], att).sum(), role_ok.sum()),
                 'signature_testbed_flows': int(cand.sum()),
                 'victim_coverage': _r(sig.sum(), cand.sum())}
    elif kind == 'arp':
        a, b = ARP_PSEUDO
        raw = (proto == PROTO0) & (((src == a) & (dst == b)) | ((src == b) & (dst == a)))
        bcast = pd.Series(dst, dtype=object).str.endswith('.255', na=False).to_numpy(bool)
        p0 = (proto == PROTO0) & both & (src != GATEWAY) & (dst != GATEWAY) & ~bcast
        fan = (pd.DataFrame({'s': src[p0], 'd': dst[p0]}).drop_duplicates()
               .groupby('s').size().sort_values(ascending=False, kind='stable'))   # ties: address order
        first = int(fan.iloc[0]) if len(fan) else 0
        second = int(fan.iloc[1]) if len(fan) > 1 else 0
        host = str(fan.index[0]) if first >= ARP_MIN_FANOUT and first >= ARP_MIN_RATIO * second else None
        att = [host] if host else []
        host_flows = ((src == host) | (dst == host)) if host else np.zeros(len(src), bool)
        vic = sorted({str(d) for d in dst[p0 & (src == host)]}) if host else []
        sig, av = raw, raw | host_flows
        pk, dur = df['pk'].to_numpy(), df['dur'].to_numpy()
        ext = (proto == PROTO0) & ~both & ~raw
        extra = {'icmp_fanout_top': [{'host': str(h), 'distinct_testbed_targets': int(c)}
                                     for h, c in fan.head(5).items()],
                 'spoofing_host': host,
                 'spoofing_host_identified': host is not None,
                 'spoofing_host_flows': int(host_flows.sum()),
                 'icmp_targets_of_host': vic,
                 'pseudo_flow_rate': pseudo_rate(raw, pk, dur),
                 'other_proto0_pairs_with_non_testbed_endpoint':
                     top(pair_key(pd.Series(src[ext]), pd.Series(dst[ext])), n=5)}
    else:
        raise ValueError(kind)
    return {'raw': raw, 'both': both, 'server': server, 'client': client, 'sig': sig, 'av': av,
            'attackers': att, 'victims': vic, 'extra': extra}


# ----------------------------------------------------------------------------- scoring
def score(att, flags, pk):
    a, pa = int(att.sum()), float(pk[att].sum())
    out = {}
    for r, f in flags.items():
        af, nf = int((att & f).sum()), int(f.sum())
        nk, ak = len(f) - nf, a - af
        out[r] = {'flagged': nf, 'kept': nk, 'attack_flagged': af, 'attack_kept': ak,
                  'false_removal_rate': _r(af, a), 'flagged_attack_share': _r(af, nf),
                  'kept_attack_share': _r(ak, nk),
                  'packet_false_removal_rate': _r(float(pk[att & f].sum()), pa)}
    return out


def examples(df, mask, k=3):
    """The IP pairs that account for most flows of a mask, with their main protocol/port."""
    if not mask.any():
        return []
    s = df.loc[mask, ['Src IP', 'Dst IP', 'Protocol', 'Src Port', 'Dst Port']]
    key = pd.Series(pair_key(s['Src IP'], s['Dst IP']), index=s.index)
    tag = (s['Protocol'].map(PROTO_NAME).fillna(s['Protocol'].astype(str)) + '/'
           + np.minimum(s['Src Port'], s['Dst Port']).astype(str))
    return [{'pair': p, 'flows': int(c), 'main_proto_port': str(tag[key == p].value_counts().index[0])}
            for p, c in key.value_counts().head(k).items()]


def raw_block(df, idn, flags):
    raw, both = idn['raw'], idn['both']
    src, dst = df['Src IP'].to_numpy(), df['Dst IP'].to_numpy()
    nr, ni, ne = int(raw.sum()), int((raw & both).sum()), int((raw & ~both).sum())
    blk = {'flows': nr, 'share_of_capture': _r(nr, len(raw)),
           'testbed_pairs': ni, 'with_non_testbed_endpoint': ne,
           'flag_share': {r: _r((raw & f).sum(), nr) for r, f in flags.items()},
           'flag_share_testbed_pairs': {r: _r((raw & both & f).sum(), ni) for r, f in flags.items()},
           'flag_share_non_testbed_pairs': {r: _r((raw & ~both & f).sum(), ne) for r, f in flags.items()},
           'top_pairs': top(pair_key(pd.Series(src[raw]), pd.Series(dst[raw])), n=8)}
    if idn['server'] is not None:          # service-port side = destination of the request
        blk['top_destination_hosts'] = top(idn['server'][raw], n=10, testbed=True)
        blk['top_source_hosts'] = top(idn['client'][raw], n=10, testbed=True)
    return blk


def time_block(ts, sig, av):
    t = ts.to_numpy()
    ok = ~pd.isna(t)
    out = {'capture_start': str(ts.min()), 'capture_end': str(ts.max()), 'unparsed_timestamps': int((~ok).sum())}
    s = sig & ok
    if s.any():
        lo, hi = t[s].min(), t[s].max()
        inw = ok & (t >= lo) & (t <= hi)
        out.update({'signature_start': str(pd.Timestamp(lo)), 'signature_end': str(pd.Timestamp(hi)),
                    'signature_window_minutes': round(float((hi - lo) / np.timedelta64(1, 'm')), 1),
                    'share_of_flows_in_window': _r(inw.sum(), ok.sum()),
                    'share_of_attack_related_in_window': _r((inw & av).sum(), (av & ok).sum())})
    return out


# ----------------------------------------------------------------------------- Benign
def read_benign():
    """R3 pair set (IP columns) + the same signature heuristics on Benign (false-positive baseline)."""
    files = [f for _, fs in capture_groups('Benign') for f in fs]
    df = load(files, BENIGN_COLS)
    pairs = set(pair_key(df['Src IP'], df['Dst IP']))
    hosts = host_counts(df['Src IP'].to_numpy(), df['Dst IP'].to_numpy())
    int_s = internal(df['Src IP']).astype(bool)
    int_d = internal(df['Dst IP']).astype(bool)
    n = len(df)
    base = {'files': [Path(f).name for f in files], 'flows': n, 'distinct_ip_pairs': len(pairs)}
    for kind in ('bruteforce', 'web', 'dns', 'arp'):
        idn = identify(kind, df, int_s, int_d)
        base[kind] = {'signature_raw_flows': int(idn['raw'].sum()), 'signature_raw_share': _r(idn['raw'].sum(), n),
                      'signature_raw_testbed_pairs': int((idn['raw'] & idn['both']).sum()),
                      'would_be_attackers': idn['attackers'], 'would_be_victims': idn['victims'],
                      'signature_flows': int(idn['sig'].sum()),
                      'attacker_victim_flows': int(idn['av'].sum()),
                      'attacker_victim_share': _r(idn['av'].sum(), n), **idn['extra']}
        if idn['server'] is not None:
            base[kind]['top_destination_hosts'] = top(idn['server'][idn['raw']], n=5, testbed=True)
        del idn
    del df, int_s, int_d; gc.collect()
    return pairs, hosts, base


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--force', action='store_true', help='recompute although the JSON exists')
    a = ap.parse_args()
    path = OUT / 'rule_validation.json'
    if path.exists() and not a.force:
        print(f'[skip] {path} exists (use --force to recompute)', flush=True)
        return
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    print('[1] Benign: IP-pair set for R3 and signature false-positive baseline', flush=True)
    benign_pairs, benign_hosts, baseline = read_benign()
    print(f'    {baseline["flows"]:,} flows, {len(benign_pairs):,} distinct IP pairs ({time.time() - t0:.0f} s)',
          flush=True)
    for kind in ('bruteforce', 'web', 'dns', 'arp'):
        b = baseline[kind]
        print(f'    baseline {kind:10s} raw signature={b["signature_raw_flows"]:>7,} ({_pct(b["signature_raw_share"])})'
              f'  heuristic would mark {b["attacker_victim_flows"]:>6,} flows'
              f'  attackers={b["would_be_attackers"]}', flush=True)

    res = {'purpose': 'Signature-based partial validation of background rules R1-R3 (flow CSVs only).',
           'assumptions': ASSUMPTIONS,
           'parameters': {'service_ports_signature': PORTS, 'dns_port': 53, 'gateway': GATEWAY,
                          'arp_pseudo_addresses': list(ARP_PSEUDO), 'cover': COVER, 'max_hosts': MAX_HOSTS,
                          'min_responder_flows': MIN_RESPONDER_FLOWS, 'arp_min_fanout': ARP_MIN_FANOUT,
                          'arp_min_ratio': ARP_MIN_RATIO, 'main_definition': 'attacker_victim'},
           'rules': {'testbed': [str(n) for n in TESTBED], 'service_ports': sorted(SERVICE_PORTS),
                     'dns_exception': DNS_ATTACK, 'benign_pairs': len(benign_pairs),
                     'any': 'R1 | R2 | R3 (the "all" cleaning condition)'},
           'benign_baseline': baseline, 'captures': {}, 'summary': {}}
    hosts = {'Benign': benign_hosts}

    print('[2] attack captures', flush=True)
    for i, (cls, sub, kind) in enumerate(CAPTURES, 1):
        name = f'{cls} / {sub}' if sub != cls else cls
        files = dict(capture_groups(cls)).get(sub)
        if not files:
            print(f'[{i}/{len(CAPTURES)}] {name}: no CSV found - skipped', flush=True)
            continue
        t = time.time()
        df = load(files, COLS)
        n = len(df)
        flags, int_s, int_d = rule_flags(df, sub, benign_pairs)
        idn = identify(kind, df, int_s, int_d)
        pk, dur = df['pk'].to_numpy(), df['dur'].to_numpy()
        ts = pd.to_datetime(df['Timestamp'], format=TS_FMT, errors='coerce')
        hosts[name] = host_counts(df['Src IP'].to_numpy(), df['Dst IP'].to_numpy())

        entry = {'class': cls, 'capture_group': sub, 'signature_kind': kind,
                 'files': [Path(f).name for f in files], 'flows': n, 'packets': int(pk.sum()),
                 'attackers': idn['attackers'], 'victims': idn['victims'],
                 # same heuristic on Benign: an attacker that is also a would-be attacker/responder there is suspect
                 'attackers_also_derived_in_benign':
                     sorted(set(idn['attackers']) & set(baseline[kind]['would_be_attackers'])),
                 **idn['extra'],
                 'rule_flag_share': {r: _r(f.sum(), n) for r, f in flags.items()},
                 'signature_raw': raw_block(df, idn, flags),
                 'time': time_block(ts, idn['sig'], idn['av']),
                 'definitions': {}}
        for d, m in (('signature', idn['sig']), ('attacker_victim', idn['av'])):
            na = int(m.sum())
            entry['definitions'][d] = {
                'attack_related': na, 'attack_share_before_cleaning': _r(na, n),
                'packet_share_before_cleaning': _r(pk[m].sum(), pk.sum()),
                'median_duration_s': round(float(np.median(dur[m])) / 1e6, 3) if na else None,
                'median_duration_s_other_flows': round(float(np.median(dur[~m])) / 1e6, 3) if na < n else None,
                'rules': score(m, flags, pk),
                'false_removal_by_pair': {r: examples(df, m & flags[r]) for r in RULES}}
        if kind == 'arp':
            entry['pseudo_flow_rate_benign'] = baseline['arp']['pseudo_flow_rate']
        res['captures'][name] = entry
        res['summary'][name] = {
            d: {'flows': n, 'attack_related': entry['definitions'][d]['attack_related'],
                'attack_share_before_cleaning': entry['definitions'][d]['attack_share_before_cleaning'],
                'false_removal_rate': {r: v['false_removal_rate'] for r, v in entry['definitions'][d]['rules'].items()},
                'flagged_attack_share': {r: v['flagged_attack_share'] for r, v in entry['definitions'][d]['rules'].items()},
                'kept_attack_share': {r: v['kept_attack_share'] for r, v in entry['definitions'][d]['rules'].items()}}
            for d in DEFS}

        s = res['summary'][name]['attacker_victim']
        fr, ks = s['false_removal_rate'], s['kept_attack_share']
        print(f'[{i}/{len(CAPTURES)}] {name:30s} flows={n:>7,}  attack-related={s["attack_related"]:>6,} '
              f'({_pct(s["attack_share_before_cleaning"])})  false-removal R1={_pct(fr["R1_external"])} '
              f'R2={_pct(fr["R2_service"])} R3={_pct(fr["R3_benign_pair"])} any={_pct(fr["any"])}  '
              f'kept purity R1={_pct(ks["R1_external"])} any={_pct(ks["any"])}  '
              f'attackers={idn["attackers"]} victims={idn["victims"][:4]}{"..." if len(idn["victims"]) > 4 else ""} '
              f'({time.time() - t:.0f} s)', flush=True)
        del df, flags, int_s, int_d, idn, pk, dur, ts
        gc.collect()

    addrs = sorted({str(x) for e in res['captures'].values() for x in e['attackers'] + list(e['victims'])})
    res['address_presence'] = {x: {c: int(h.get(x, 0)) for c, h in hosts.items()} for x in addrs}

    print('\n=== main definition (attacker_victim): false-removal rate | purity of kept flows ===')
    print(f'  {"capture":30s} {"attack":>7s} {"share":>7s} | {"R1":>6s} {"R2":>6s} {"R3":>6s} {"any":>6s} | '
          f'{"purity kept: R1":>15s} {"any":>6s}')
    for name, sm in res['summary'].items():
        s = sm['attacker_victim']
        fr, ks = s['false_removal_rate'], s['kept_attack_share']
        print(f'  {name:30s} {s["attack_related"]:>7,} {_pct(s["attack_share_before_cleaning"])} | '
              f'{_pct(fr["R1_external"])} {_pct(fr["R2_service"])} {_pct(fr["R3_benign_pair"])} {_pct(fr["any"])} | '
              f'{_pct(ks["R1_external"]):>15s} {_pct(ks["any"])}')
    print('  (attack-related flows not linked to an identified attacker are unconfirmed: purity is a lower bound)')

    tmp = path.with_suffix('.json.tmp')          # atomic: an interrupted write never leaves a JSON that is skipped
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(res, fh, indent=1, default=_json)
    os.replace(tmp, path)
    print(f'\n[DONE] {path}  ({time.time() - t0:.0f} s)', flush=True)


if __name__ == '__main__':
    main()
