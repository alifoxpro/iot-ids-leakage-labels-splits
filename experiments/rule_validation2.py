# -*- coding: utf-8 -*-
"""
rule_validation2.py
===================
Second validation of the background rules R1-R3 (reviewer points meth-02 and nove-03). It extends
rule_validation.py (six small captures) to EVERY attack capture, audits the R1-flagged flows, and
draws a stratified random sample for a manual audit. Flow CSVs only; the packet-level (MAC) check
is experiments/pcap_validation.py. No model is trained.

Part 1  signature-based validation (as rule_validation.py: attack-related flows are identified
        WITHOUT R1-R3, then the rules are scored against them)
  bruteforce / web / dns / arp   the signatures of rule_validation.py, reused unchanged (its
                                 identify()); also used for DoS and DDoS HTTP Flood (web: TCP 80/8080
                                 between testbed hosts, attackers = client side, victims = server side)
  The flood predicates are direction-agnostic (hi / lo = larger / smaller of the forward and backward
  packet counts; flag counts of CICFlowMeter cover both directions), because CICFlowMeter orients a
  flow by the first packet it sees and a victim's SYN-ACK or reply can come first (observed in the
  DoS SYN capture: victim:49153 -> attacker flows with 1 forward and 10 backward packets).
  syn          DoS SYN Flood: TCP flows dominated by SYN without a completed handshake: SYN Flag Count
               >= 1 and >= half of hi, no payload in either direction, ACK Flag Count <= lo (the
               initiator never ACKs; ACKs can only come from the victim's SYN-ACK / RST-ACK)
  udp          DoS/DDoS UDP Flood: one-directional UDP flows (lo = 0) with >= 10 packets that are high-rate
               per flow (>= 100 packets/s) or per victim endpoint (the receiving host:port gets >= 100 such
               flows starting within one second: the DoS UDP captures consist of thousands of ~20-packet
               flows from distinct source ports that start in the same second, ~0.15 packets/s each)
  ackfrag      DDoS ACK Fragmentation: TCP ACK flows without SYN that carry payload and get at most one
               packet or half as many packets back (lo <= 1 or 2 lo <= hi), plus protocol-0 flows
               (fragments without a transport header) with hi >= 10 and lo <= hi / 10
  proto0flood  DDoS ICMP Flood, DDoS ICMP Fragmentation, Mirai GRE flood: protocol-0 flows (not the
               ARP pseudo-flow) with >= 1,000 packets (sensitivity: 100 / 1,000 / 10,000)
  mirai_scan   Mirai: TCP flows to port 23/2323 from a testbed host that contacts >= 20 distinct
               addresses on these ports (Telnet scanning; targets may be Internet addresses)
  recon        Recon: testbed hosts (not the gateway) that open TCP/UDP flows to >= 50 distinct
               destination ports or >= 30 distinct testbed hosts (vertical / horizontal scanning)
  Flood kinds (syn, udp, ackfrag, proto0flood): sender = the side with more packets, receiver = the
  other side. Victim hosts = testbed unicast receivers covering >= 80 % of the predicate packets of
  the flows with fwd != bwd (<= 20 hosts); a tie flow (fwd == bwd) is oriented towards a victim host
  if exactly one side is one. Victim endpoints (host:port) = the receiver endpoints of the predicate
  flows to victim hosts covering >= 80 % of their packets (<= 20); if such a set exists the
  signature is the predicate flows to a victim endpoint (level host:port), otherwise to a victim host
  (level host, e.g. random destination ports). Attackers = senders covering >= 80 % of the signature
  packets (<= 50). If no such attacker set exists (e.g. spoofed sources), attacker_victim =
  signature; otherwise attacker_victim = signature + every flow between an attacker and a victim.
  Three nested definitions of attack-related flows are scored:
    signature        the signature flows only
    attacker_victim  + every flow between an identified attacker and a victim (any port/protocol)  <- main
    attacker_any     + every flow of an identified attacker (any peer): an UPPER bound that also
                     covers attacks on other ports / hosts (e.g. DoS HTTP flood to port 8009) but
                     includes the attacker device's own background (DNS, NTP, cloud)
  Reported per capture and definition for R1, R2, R3 and any: false-removal rate (flows and
  packets), flagged / kept attack share (flows and packets), the Benign baseline of every signature
  (same heuristic on the Benign captures), derived addresses that the heuristic would also pick in
  Benign, and the address presence in every capture.
Part 2  R1 audit (every attack capture)
  share of R1-flagged flows whose external endpoint(s) also occur in the Benign captures (address;
  address + port), with the IP pair in Benign (= R3) and on a service port (= R2); top external
  addresses / address:ports / ports / internal endpoints with counts, packets and Benign flow counts;
  external addresses NOT seen in Benign; spoofed-source check: flows whose external SOURCE address
  is routable IPv4, occurs in exactly one flow of the capture, has no reply packet and never occurs
  in Benign (count, share of R1 flows, of external-source flows, packet share; single-flow IPv6 /
  link-local sources are counted separately, not as spoofed).
  ARP Spoofing: R1 flows of the ARP victims (ICMP-redirect targets of the spoofing host), inside the
  poisoning window, external address / pair in Benign. DNS Spoofing: flows to external resolvers,
  answered, "extra answer" flows (more resolver packets than queries: a forged and a genuine answer
  to the same query share one flow) with the Benign baseline of that indicator, inside the
  rogue-responder window.
Part 3  audit sample: for every attack class and every rule (R1, R2, R3, any) 20 flagged and 20 kept
  raw flows (fewer if the stratum is smaller), simple random sample per stratum with seed 42 (bottom-k
  of a deterministic hash of file + row, so the per-capture candidates merge exactly into the class
  sample). audit_sample.csv holds every identifier column, key features, the rule flags and the
  heuristic labels; audit_template.md (with rule flags and heuristic labels) and audit_template_blind.md
  (without them - recommended, so that the decision does not anchor on the rule being validated) are
  the tables in which the author records the decision (attack / background / unclear) per sampled
  flow; --score-audit turns either one into rule precision and kept-attack share per class (Wilson
  95 % CIs) and a weighted false-removal estimate. Audit files that already hold decisions are never
  overwritten by a later merge (the regenerated set goes to *.regenerated.*).

Rates are on raw flows (before the de-duplication and caps of flagged_loader.py), as in
rule_validation.py; the rules are recomputed exactly as flagged_loader.py computes them (R3 pair set
from all Benign flows); the six captures of rule_validation.py are recomputed with the same code.
Outputs (results_2026_03_03/q1_revision/rule_validation2/):
  captures/<capture>.json, captures/<capture>_sample.csv   one capture (resumable unit)
  benign_baseline.json          every signature applied to the Benign captures
  rule_validation2.json         merged: summaries, R1 audit, address presence, assumptions
  summary_false_removal.csv     capture x kind x definition x rule
  summary_r1_audit.csv          capture: R1 share, external endpoint in Benign, spoofed sources
  audit_sample.csv, audit_template.md, audit_template_blind.md, audit_strata_counts.json,
  audit_scores.json/.csv (after --score-audit)
Resumable: a capture whose JSON exists is skipped (--force recomputes); a JSON made with another
--max-rows (a test run) is recomputed and never merged into the full results. The merge runs when every
capture is done (--merge forces it, marking missing captures). Identifiers are integer-coded
(~60 bytes per flow): DoS SYN Flood (~4.3 GB of CSV) needs ~1-1.5 GB RAM and a few minutes to read;
all 15 captures take roughly 15-30 min. '--max-captures 1' processes one capture per process.
Run (PowerShell, from the project root):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\rule_validation2.py --self-test 2>&1 | Tee-Object -FilePath rule_validation2.log
  & $py experiments\\rule_validation2.py 2>&1 | Tee-Object -FilePath rule_validation2.log -Append
  # alternative with the lowest peak memory: one capture per process, then the merge
  1..15 | ForEach-Object { & $py experiments\\rule_validation2.py --max-captures 1 2>&1 | Tee-Object -FilePath rule_validation2.log -Append }
  & $py experiments\\rule_validation2.py --merge 2>&1 | Tee-Object -FilePath rule_validation2.log -Append
  # after filling the Decision column of audit_template_blind.md (or audit_template.md, or audit_decision in
  # audit_sample.csv):
  & $py experiments\\rule_validation2.py --score-audit results_2026_03_03\\q1_revision\\rule_validation2\\audit_template_blind.md 2>&1 | Tee-Object -FilePath rule_validation2_audit.log
"""
import argparse, gc, ipaddress, json, math, os, re, sys, time, zlib
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import CLASSES, DATA, SEED, TS_FMT  # noqa: E402
from relabel_background import DNS_ATTACK, SERVICE_PORTS, capture_groups, internal  # noqa: E402
import rule_validation as rv  # noqa: E402  (identify(), score(), cover(), constants of the first validation)

sys.stdout.reconfigure(encoding='utf-8')
OUT_DEFAULT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'rule_validation2'
BASE_COLS = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration',
             'Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet',
             'Total Length of Bwd Packet', 'SYN Flag Count', 'ACK Flag Count']
ID_COLS = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
KEY_FEATURES = ['Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet',
                'Total Length of Bwd Packet', 'Flow Bytes/s', 'Flow Packets/s', 'SYN Flag Count',
                'ACK Flag Count', 'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'Down/Up Ratio',
                'Average Packet Size']
READ_COLS = list(dict.fromkeys(BASE_COLS + ID_COLS + KEY_FEATURES))
CHUNK = 400_000
TCP, UDP, PROTO0 = rv.TCP, rv.UDP, rv.PROTO0
GATEWAY, ARP_PSEUDO, COVER, MAX_HOSTS = rv.GATEWAY, rv.ARP_PSEUDO, rv.COVER, rv.MAX_HOSTS
FLOOD_MIN_PKTS = 10                        # udp / ackfrag: a flood flow carries >= 10 packets (hi)
FLOOD_MIN_RATE = 100.0                     # udp: >= 100 packets/s per flow ("high-rate") ...
UDP_BURST_FLOWS = 100                      # ... or >= 100 such flows to one endpoint starting in one second
HEAVY_PKTS, HEAVY_SENS = 1000, (100, 1000, 10000)   # proto0flood: "very many packets"
VICTIM_CAP, ATTACKER_CAP = 20, 50          # floods: victims <= 20 hosts, attackers (bots) <= 50 hosts
MIRAI_PORTS, MIRAI_MIN_TARGETS = (23, 2323), 20
RECON_MIN_PORTS, RECON_MIN_HOSTS = 50, 30
SAMPLE_K = 20
RULES = rv.RULES
DEFS = rv.DEFS + ['attacker_any']          # signature, attacker_victim (main), attacker_any (upper bound)
FLAG_NAMES = ('R1_external', 'R2_service', 'R3_benign_pair')
OLD_KINDS = ('bruteforce', 'web', 'dns', 'arp')
FLOOD_KINDS = ('syn', 'udp', 'ackfrag', 'proto0flood')
NEW_KINDS = FLOOD_KINDS + ('mirai_scan', 'recon')
STRATA = [f'{r}:{s}' for r in RULES for s in ('flagged', 'kept')]
SVC = np.array(sorted(SERVICE_PORTS), np.int32)
EPOCH = pd.Timestamp('1970-01-01')
CLASS_ABBR = {'BruteForce': 'BF', 'DDOS': 'DD', 'DOS': 'DS', 'Mirai': 'MI', 'Recon': 'RC',
              'Spoofing': 'SP', 'Web-Based': 'WB'}
DECISIONS = {'attack': 'attack', 'a': 'attack', 'background': 'background', 'b': 'background',
             'bg': 'background', 'unclear': 'unclear', 'u': 'unclear', '?': 'unclear'}
_r, _pct, _json = rv._r, rv._pct, rv._json
SIGNATURES = {
    'bruteforce': 'rule_validation.py: TCP 22/23 between testbed hosts; attackers = client side (80 % cover, <= 10), '
                  'victims = server side',
    'web': 'rule_validation.py: TCP 80/8080 between testbed hosts; attackers = client side, victims = server side '
           '(SQLi, XSS, Uploading, DoS and DDoS HTTP Flood)',
    'dns': 'rule_validation.py: rogue DNS responders (testbed hosts other than the gateway answering >= 5 UDP/53 flows)',
    'arp': 'rule_validation.py: ARP pseudo-flows 8.6.0.1<->8.0.6.4 plus all flows of the spoofing host (largest '
           'ICMP fan-out to testbed hosts)',
    'syn': 'TCP, SYN Flag Count >= 1 and >= 0.5 x hi, no payload in either direction, ACK Flag Count <= lo '
           '(hi/lo = larger/smaller of forward and backward packets); to a victim (sender = side with more packets)',
    'udp': f'UDP, lo = 0, hi >= {FLOOD_MIN_PKTS} packets, and >= {FLOOD_MIN_RATE:g} packets/s per flow or >= '
           f'{UDP_BURST_FLOWS} such flows to the same receiving host:port starting within one second; to a victim',
    'ackfrag': f'(TCP, ACK >= 1, SYN = 0, payload > 0, lo <= 1 or 2 lo <= hi) or (protocol 0, not the ARP '
               f'pseudo-flow, hi >= {FLOOD_MIN_PKTS}, lo <= hi/10); to a victim',
    'proto0flood': f'protocol 0 (ICMP, GRE, fragments), not the ARP pseudo-flow, >= {HEAVY_PKTS} packets; to a victim',
    'mirai_scan': f'TCP to port 23/2323 from a testbed host (not the gateway) with >= {MIRAI_MIN_TARGETS} distinct '
                  'destination addresses on these ports',
    'recon': f'TCP/UDP flows from a testbed host (not the gateway) with >= {RECON_MIN_PORTS} distinct destination '
             f'ports or >= {RECON_MIN_HOSTS} distinct testbed destination hosts (scanner) to testbed hosts',
}
ASSUMPTIONS = [
    'Flow-level evidence only (flow CSVs); "attack-related" is a partial, heuristic ground truth derived without '
    'R1-R3. Flows not linked to a signature are unconfirmed, not proven background: kept_attack_share and '
    'flagged_attack_share are lower bounds.',
    'Rates are computed on the raw flows of each capture (before the de-duplication and DOS/DDOS caps of '
    'flagged_loader.py). R1-R3 are recomputed exactly as in flagged_loader.py (R3: IP pairs of all Benign flows).',
    'bruteforce, web, dns and arp are the signatures of rule_validation.py (its identify() is called unchanged); '
    'they restrict attackers/victims to testbed pairs, so R1 is not tested independently for them.',
    'Flood signatures (syn, udp, ackfrag, proto0flood) are direction-agnostic: the sender is the side with more '
    'packets (CICFlowMeter orients a flow by its first packet, which can be the victim\'s reply). Victim hosts = '
    f'testbed unicast receivers covering >= 80 % of the predicate packets (<= {VICTIM_CAP}); victim endpoints '
    f'(host:port) are used when <= {VICTIM_CAP} of them cover >= 80 % of the packets to the victim hosts; '
    f'attackers = senders covering >= 80 % of the signature packets (<= {ATTACKER_CAP}); when no such set exists '
    '(e.g. spoofed sources) attacker_victim = signature.',
    'attacker_any adds every flow of an identified attacker (any peer, port or protocol). It is an upper bound: '
    'attacks on other ports or hosts are covered, but so is the attacker device\'s own background traffic.',
    'Flood sources are NOT restricted to the testbed, so R1 is tested independently for the floods: a spoofed or '
    'external flood source counts as attack-related and a removal by R1 as a false removal.',
    f'proto0flood uses a fixed threshold of {HEAVY_PKTS} packets per flow; the sensitivity to 100 and 10,000 is '
    'reported (heavy_threshold_sensitivity).',
    'mirai_scan targets may be Internet addresses (Mirai scans random addresses), so R1 is tested independently '
    'for them; the Mirai capture is scored on the union of proto0flood and mirai_scan.',
    'recon: scanner-initiated flows to testbed hosts are the signature; attacker_victim adds every flow between a '
    'scanner and a probed host (any direction/protocol); scanner flows to non-testbed hosts are reported separately.',
    'R1 audit: the external endpoint of a flow is each endpoint outside 192.168.137.0/24 and 205.174.165.0/24; '
    '"in Benign" means that every external endpoint of the flow occurs in a Benign flow (address, or the same '
    'address:port endpoint in any Benign flow). A spoofed-source candidate is a flow whose external source address '
    'is a routable IPv4 address (IPv6, link-local, loopback, multicast and broadcast sources are reported '
    'separately), occurs in exactly one flow of the capture, has no backward packet and never occurs in Benign.',
    'DNS extra-answer indicator: UDP/53 flows with an external resolver in which the resolver side sends more '
    'packets than the client side (a forged and a genuine answer to one query share one CICFlowMeter flow); '
    'retransmitted or multi-part answers can also produce it, hence the Benign baseline.',
    'Audit sample: raw flows of the attack captures (Benign is excluded because the rules are not applied to it); '
    'bottom-20 of a seeded hash of (file, row) per class and stratum = a simple random sample per stratum; a flow '
    'can be sampled for several strata (column selected_strata).',
]


# ----------------------------------------------------------------------------- small helpers
def _special(name):
    """Broadcast, multicast, unspecified or unparseable address (never a victim)."""
    try:
        a = ipaddress.ip_address(name)
    except ValueError:
        return True
    return bool(a.is_multicast or a.is_unspecified or name.endswith('.255'))


def _routable_v4(name):
    """Routable IPv4 unicast address (spoofed-source check: IPv6, link-local, loopback, multicast, broadcast,
    unspecified and unparseable sources are excluded, e.g. a device's single IPv6 multicast-listener report)."""
    try:
        a = ipaddress.ip_address(name)
    except ValueError:
        return False
    return bool(a.version == 4 and not (a.is_multicast or a.is_unspecified or a.is_link_local or a.is_loopback
                                        or name.endswith('.255')))


class IPTable:
    """Global string <-> int32 code table for IP addresses: one Python string per distinct address,
    int32 codes per flow (the identifier columns of ~11 M flows would need >1 GB as strings)."""

    def __init__(self):
        self.idx, self.names = {}, []
        self._int = np.zeros(0, bool)
        self._spec = np.zeros(0, bool)
        self._rv4 = np.zeros(0, bool)
        self._arr = None

    def encode(self, s):
        codes, uniq = pd.factorize(s.astype(str).to_numpy(), sort=False)
        m = np.empty(len(uniq), np.int32)
        for i, u in enumerate(uniq):
            j = self.idx.get(u)
            if j is None:
                j = self.idx[u] = len(self.names)
                self.names.append(u)
            m[i] = j
        return m[codes]

    def _grow(self):
        k = len(self._int)
        if k < len(self.names):
            new = self.names[k:]
            self._int = np.concatenate([self._int, internal(pd.Series(new, dtype=object)).astype(bool)])
            self._spec = np.concatenate([self._spec, np.array([_special(x) for x in new], bool)])
            self._rv4 = np.concatenate([self._rv4, np.array([_routable_v4(x) for x in new], bool)])

    @property
    def int_mask(self):
        self._grow()
        return self._int

    @property
    def special_mask(self):
        self._grow()
        return self._spec

    @property
    def routable_v4_mask(self):
        self._grow()
        return self._rv4

    @property
    def arr(self):
        if self._arr is None or len(self._arr) != len(self.names):
            self._arr = np.asarray(self.names, dtype=object)
        return self._arr

    def code(self, name):
        return self.idx.get(name, -1)

    def codes(self, names):
        return [self.idx[n] for n in names if n in self.idx]

    def name_list(self, codes):
        return [self.names[int(c)] for c in codes]


def lookup(arr, codes, fill=0):
    out = np.full(len(codes), fill, dtype=arr.dtype)
    ok = codes < len(arr)
    out[ok] = arr[codes[ok]]
    return out


def in_sorted(x, s):
    """Membership of x in the sorted unique array s (lean alternative to np.isin for large x)."""
    if len(s) == 0:
        return np.zeros(len(x), bool)
    i = np.searchsorted(s, x)
    i[i == len(s)] = len(s) - 1
    return s[i] == x


def isin_c(arr, codes):
    if len(codes) == 0:
        return np.zeros(len(arr), bool)
    return np.isin(arr, np.asarray(codes, dtype=arr.dtype))


def between_c(src, dst, a, v):
    return (isin_c(src, a) & isin_c(dst, v)) | (isin_c(src, v) & isin_c(dst, a))


def pair_c(src, dst):
    return (np.minimum(src, dst).astype(np.int64) << 31) | np.maximum(src, dst).astype(np.int64)


def ep_key(codes, ports):
    return codes.astype(np.int64) * 65537 + (ports.astype(np.int64) + 1)


def cover_w(values, weights=None, cap=MAX_HOSTS, share=COVER):
    """Smallest set of codes covering >= share of the (weighted) entries, at most cap; returns
    (codes, achieved coverage). Ties are broken by code (first appearance)."""
    if len(values) == 0:
        return [], None
    w = np.bincount(values, weights=weights).astype(np.float64)
    if w.sum() <= 0:
        return [], None
    order = np.argsort(-w, kind='stable')
    order = order[w[order] > 0]
    cum = np.cumsum(w[order]) / w.sum()
    k = min(int(np.searchsorted(cum, share - 1e-9)) + 1, cap, len(order))
    return [int(x) for x in order[:k]], round(float(cum[k - 1]), 4)


def top_c(ipt, codes, n=10, weights=None, testbed=False, benign=None):
    """Most frequent addresses of a code array, with flows, share, packets, testbed flag, Benign flows."""
    if len(codes) == 0:
        return []
    cnt = np.bincount(codes)
    order = np.argsort(-cnt, kind='stable')[:n]
    order = order[cnt[order] > 0]
    pw = np.bincount(codes, weights=weights) if weights is not None else None
    out = []
    for k in order:
        o = {'value': ipt.names[k], 'flows': int(cnt[k]), 'share': _r(cnt[k], len(codes))}
        if pw is not None:
            o['packets'] = int(pw[k])
        if testbed:
            o['testbed'] = bool(ipt.int_mask[k])
        if benign is not None:
            o['benign_flows'] = int(benign[k]) if k < len(benign) else 0
        out.append(o)
    return out


def top_v(values, n=10, weights=None):
    """Most frequent plain values (ports, protocol/port tags)."""
    if len(values) == 0:
        return []
    s = pd.Series(values)
    vc = s.value_counts().head(n)
    pw = pd.Series(weights).groupby(s.to_numpy()).sum() if weights is not None else None
    out = []
    for k, c in vc.items():
        o = {'value': _json(k) if not isinstance(k, str) else k, 'flows': int(c), 'share': _r(c, len(s))}
        if pw is not None:
            o['packets'] = int(pw[k])
        out.append(o)
    return out


def top_ep(ipt, codes, ports, n=15, weights=None, benign_ep=None):
    """Most frequent address:port endpoints."""
    if len(codes) == 0:
        return []
    key = ep_key(codes, ports)
    s = pd.Series(key)
    vc = s.value_counts().head(n)
    pw = pd.Series(weights).groupby(key).sum() if weights is not None else None
    out = []
    for k, c in vc.items():
        code, port = int(k) // 65537, int(k) % 65537 - 1
        o = {'value': f'{ipt.names[code]}:{port}', 'flows': int(c), 'share': _r(c, len(s))}
        if pw is not None:
            o['packets'] = int(pw[k])
        if benign_ep is not None:
            o['in_benign'] = bool(in_sorted(np.array([k], np.int64), benign_ep)[0])
        out.append(o)
    return out


def _ts(x):
    return None if x is None or not np.isfinite(x) else str(pd.Timestamp(float(x), unit='s'))


def window(ts, m):
    """(first, last) timestamp of the flows of a mask, or None."""
    t = ts[m & np.isfinite(ts)]
    return (float(t.min()), float(t.max())) if len(t) else None


def in_window(ts, w):
    if w is None:
        return np.zeros(len(ts), bool)
    return np.isfinite(ts) & (ts >= w[0]) & (ts <= w[1])


def _relpath(f):
    try:
        return Path(f).resolve().relative_to(DATA.resolve()).as_posix()
    except ValueError:
        return Path(f).name


def _slug(name):
    return re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_')


def row_keys(fid, rows):
    """Deterministic pseudo-random key per (file, row): splitmix64 of (crc32(file) << 32 | row) mixed with
    SEED. The SAMPLE_K smallest keys of a stratum form a simple random sample without replacement, and the
    k smallest keys of a union are the k smallest of the per-capture k smallest (exact merge)."""
    with np.errstate(over='ignore'):
        z = (np.uint64(fid) << np.uint64(32)) | rows.astype(np.uint64)
        z = z ^ np.uint64((SEED * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF)
        z = z + np.uint64(0x9E3779B97F4A7C15)
        z = (z ^ (z >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        z = (z ^ (z >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        z = z ^ (z >> np.uint64(31))
    return (z >> np.uint64(1)).astype(np.int64)


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def write_json(obj, path):
    tmp = Path(str(path) + '.tmp')           # atomic: an interrupted write never leaves a JSON that is skipped
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=1, default=_json)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------- reading (chunked, integer-coded)
def chunk_arrays(ch, ipt):
    def num(c, dt, fill=0):
        return pd.to_numeric(ch[c], errors='coerce').fillna(fill).to_numpy(dt)
    ts = pd.to_datetime(ch['Timestamp'], format=TS_FMT, errors='coerce')
    return {'src': ipt.encode(ch['Src IP']), 'dst': ipt.encode(ch['Dst IP']),
            'sp': num('Src Port', np.int32, -1), 'dp': num('Dst Port', np.int32, -1),
            'proto': num('Protocol', np.int16, -1),
            'fwd': num('Total Fwd Packet', np.float32), 'bwd': num('Total Bwd packets', np.float32),
            'fbytes': num('Total Length of Fwd Packet', np.float32),
            'bbytes': num('Total Length of Bwd Packet', np.float32),
            'syn': num('SYN Flag Count', np.float32), 'ack': num('ACK Flag Count', np.float32),
            'dur': num('Flow Duration', np.float32),
            'ts': ((ts - EPOCH) / pd.Timedelta(seconds=1)).to_numpy(np.float64)}


def read_arrays(files, ipt, cols, max_rows=None, on_chunk=None, verbose=True):
    """Chunked read of only the needed columns into compact numpy arrays (one entry per flow, file order)."""
    parts, n0 = [], 0
    for fi, f in enumerate(files):
        row0 = 0
        for ch in pd.read_csv(f, usecols=cols, chunksize=CHUNK, low_memory=False, nrows=max_rows):
            a = chunk_arrays(ch, ipt)
            a['file'] = np.full(len(ch), fi, np.int16)
            a['row'] = np.arange(row0, row0 + len(ch), dtype=np.int32)
            if on_chunk is not None:
                on_chunk(ch, a, f, n0)
            parts.append(a)
            row0 += len(ch)
            n0 += len(ch)
            del ch
        if verbose:
            print(f'      {Path(f).name}: {row0:,} flows', flush=True)
    if not parts:
        return None
    out = {}
    for k in list(parts[0]):                 # concatenate key by key and free the chunk arrays
        out[k] = np.concatenate([p.pop(k) for p in parts])
    return out


def rule_flags_codes(a, sub, ipt, bset):
    """R1-R3 exactly as flagged_loader.py / rule_validation.rule_flags, on integer-coded identifiers."""
    im = ipt.int_mask
    r1 = ~(im[a['src']] & im[a['dst']])
    svc = np.isin(a['sp'], SVC) | np.isin(a['dp'], SVC)
    if sub == DNS_ATTACK:                    # DNS is the attack itself here
        svc &= ~((a['sp'] == 53) | (a['dp'] == 53))
    r3 = in_sorted(pair_c(a['src'], a['dst']), bset['pairs'])
    return r1, svc, r3


def flags_of(c):
    return {'R1_external': c['r1'], 'R2_service': c['r2'], 'R3_benign_pair': c['r3'],
            'any': c['r1'] | c['r2'] | c['r3']}


# ----------------------------------------------------------------------------- signatures
def identify_old(kind, c, ipt, int_s, int_d, pk):
    """rule_validation.identify() on a string frame (object arrays share the table's string objects)."""
    names = ipt.arr
    df = pd.DataFrame({'Src IP': names[c['src']], 'Dst IP': names[c['dst']], 'Src Port': c['sp'],
                       'Dst Port': c['dp'], 'Protocol': c['proto'], 'bwd': c['bwd'], 'pk': pk,
                       'dur': c['dur'].astype(np.float64)})
    idn = rv.identify(kind, df, int_s, int_d)
    del df
    on = np.isin(c['dp'], rv.PORTS[kind]) if kind in rv.PORTS else (c['dp'] == 53 if kind == 'dns' else None)
    if on is not None:                       # same orientation rule as rv.identify, in code space
        idn['server'], idn['client'] = np.where(on, c['dst'], c['src']), np.where(on, c['src'], c['dst'])
    else:
        idn['server'] = idn['client'] = None
    return idn


def identify_new(kind, c, ipt, int_s, int_d, pk):
    src, dst, sp, dp, proto = c['src'], c['dst'], c['sp'], c['dp'], c['proto']
    fwd, bwd = c['fwd'], c['bwd']
    spec = ipt.special_mask
    gw = ipt.code(GATEWAY)
    pa, pb = ipt.code(ARP_PSEUDO[0]), ipt.code(ARP_PSEUDO[1])
    arp = ((src == pa) & (dst == pb)) | ((src == pb) & (dst == pa))
    dst_uni = int_d & ~spec[dst]
    both = int_s & int_d
    tot_pk = float(pk.sum())
    if kind in FLOOD_KINDS:
        hi, lo = np.maximum(fwd, bwd), np.minimum(fwd, bwd)
        pay = c['fbytes'] + c['bbytes']
        if kind == 'syn':
            pred = (proto == TCP) & (c['syn'] >= 1) & (c['syn'] >= 0.5 * hi) & (pay == 0) & (c['ack'] <= lo)
        elif kind == 'udp':
            dur_s = c['dur'].astype(np.float64) / 1e6
            with np.errstate(divide='ignore', invalid='ignore'):
                rate = np.where(dur_s > 0, hi / np.where(dur_s > 0, dur_s, 1.0), np.inf)
            base = (proto == UDP) & (lo == 0) & (hi >= FLOOD_MIN_PKTS)
            ek0 = ep_key(np.where(bwd > fwd, src, dst), np.where(bwd > fwd, sp, dp))    # receiving endpoint
            fin = base & np.isfinite(c['ts'])
            burst = np.zeros(len(src), bool)
            if fin.any():
                g = pd.DataFrame({'e': ek0[fin], 's': np.floor(c['ts'][fin]).astype(np.int64)}).value_counts()
                hot = np.unique(g[g >= UDP_BURST_FLOWS].index.get_level_values('e').to_numpy().astype(np.int64))
                burst = base & in_sorted(ek0, hot)
            pred = base & ((rate >= FLOOD_MIN_RATE) | burst)
        elif kind == 'ackfrag':
            pred = (((proto == TCP) & (c['syn'] == 0) & (c['ack'] >= 1) & (pay > 0) & ((lo <= 1) | (2 * lo <= hi)))
                    | ((proto == PROTO0) & ~arp & (hi >= FLOOD_MIN_PKTS) & (lo * 10 <= hi)))
        else:
            pred = (proto == PROTO0) & ~arp & (pk >= HEAVY_PKTS)
        uni = ipt.int_mask & ~spec                              # testbed unicast address (per code)
        det = fwd != bwd
        recv0 = np.where(bwd > fwd, src, dst)                   # receiver = side with fewer packets
        cand = pred & det & uni[recv0]
        if not cand.any():                                      # only tie flows: orient by destination
            cand = pred & uni[recv0]
        vic, vcov = cover_w(recv0[cand], pk[cand], VICTIM_CAP)
        in_s, in_d = isin_c(src, vic), isin_c(dst, vic)
        rev = (bwd > fwd) | (~det & in_s & ~in_d)               # receiver is the flow source
        recv, send = np.where(rev, src, dst), np.where(rev, dst, src)
        rport = np.where(rev, sp, dp)
        to_vic = pred & isin_c(recv, vic)
        ek = ep_key(recv, rport)
        level, vep, epcov = 'host', [], None
        if to_vic.any():
            uq, inv = np.unique(ek[to_vic], return_inverse=True)
            ep_idx, epcov = cover_w(inv.astype(np.int64), pk[to_vic], VICTIM_CAP)
            if epcov is not None and epcov >= COVER - 1e-9:
                level, vep = 'host:port', [int(uq[i]) for i in ep_idx]
        sig = to_vic & np.isin(ek, np.asarray(vep, np.int64)) if level == 'host:port' else to_vic
        att, acov = cover_w(send[sig], pk[sig], ATTACKER_CAP)
        ok = bool(att) and acov is not None and acov >= COVER - 1e-9
        av = sig | (between_c(src, dst, att, vic) if ok else np.zeros(len(src), bool))
        vw = np.bincount(recv[sig], weights=pk[sig]) if sig.any() else np.zeros(0)
        with np.errstate(divide='ignore', invalid='ignore'):
            prate = hi[sig] / (c['dur'][sig].astype(np.float64) / 1e6)
        prate = prate[np.isfinite(prate)]
        ext_s = ~ipt.int_mask[send]
        extra = {'predicate_flows': int(pred.sum()), 'predicate_packet_share': _r(pk[pred].sum(), tot_pk),
                 'predicate_flows_testbed_receiver': int(cand.sum()),
                 'predicate_flows_receiver_is_flow_source': int((pred & rev).sum()),
                 'victim_packet_coverage': vcov, 'victim_level': level,
                 'victim_endpoints': [f'{ipt.names[int(k) // 65537]}:{int(k) % 65537 - 1}' for k in vep],
                 'victim_endpoint_packet_coverage': epcov,
                 'victims_packets': [{'host': ipt.names[v], 'signature_packets': int(vw[v]) if v < len(vw) else 0,
                                      'signature_flows': int((sig & (recv == v)).sum())} for v in vic],
                 'attackers_identified': ok, 'attacker_packet_coverage': acov,
                 'signature_distinct_senders': int(np.unique(send[sig]).size),
                 'signature_external_sender_flows': int((sig & ext_s).sum()),
                 'signature_external_sender_share': _r((sig & ext_s).sum(), sig.sum()),
                 'signature_external_sender_packet_share': _r(pk[sig & ext_s].sum(), pk[sig].sum()),
                 'signature_top_senders': top_c(ipt, send[sig], n=10, weights=pk[sig], testbed=True),
                 'signature_victim_ports': top_v(rport[sig], n=8, weights=pk[sig]),
                 'signature_packets_per_flow_median': (round(float(np.median(pk[sig])), 1) if sig.any() else None),
                 'signature_packets_per_second_median': (round(float(np.median(prate)), 1) if len(prate) else None)}
        return {'raw': pred, 'both': both, 'server': recv, 'client': send, 'sig': sig, 'av': av,
                'attackers': ipt.name_list(att) if ok else [], 'attackers_candidates': ipt.name_list(att),
                'victims': ipt.name_list(vic), 'extra': extra}
    if kind == 'mirai_scan':
        cand = (proto == TCP) & np.isin(dp, MIRAI_PORTS) & int_s & (src != gw)
        d = pd.DataFrame({'s': src[cand], 'd': dst[cand]}).drop_duplicates()
        fan = d.groupby('s').size().sort_values(ascending=False, kind='stable')
        scan = [int(s) for s, k in fan.items() if k >= MIRAI_MIN_TARGETS][:ATTACKER_CAP]
        sig = cand & isin_c(src, scan)
        extra = {'candidate_flows': int(cand.sum()),
                 'fanout_top': [{'host': ipt.names[int(s)], 'distinct_targets': int(k)} for s, k in fan.head(5).items()],
                 'scanners': ipt.name_list(scan),
                 'signature_distinct_targets': int(np.unique(dst[sig]).size),
                 'signature_external_destination_flows': int((sig & ~int_d).sum()),
                 'signature_external_destination_share': _r((sig & ~int_d).sum(), sig.sum()),
                 'signature_destination_ports': top_v(dp[sig], n=4)}
        return {'raw': cand, 'both': both, 'server': dst, 'client': src, 'sig': sig, 'av': sig.copy(),
                'attackers': ipt.name_list(scan), 'victims': [], 'extra': extra}
    if kind == 'recon':
        cand = np.isin(proto, (TCP, UDP)) & int_s & (src != gw) & dst_uni
        d = pd.DataFrame({'s': src[cand], 'd': dst[cand], 'p': dp[cand]}).drop_duplicates()
        g = d.groupby('s')
        fan = pd.DataFrame({'targets': g.size(), 'hosts': g['d'].nunique(), 'ports': g['p'].nunique()})
        fan = fan.sort_values('targets', ascending=False, kind='stable')
        hit = fan[(fan['ports'] >= RECON_MIN_PORTS) | (fan['hosts'] >= RECON_MIN_HOSTS)]
        scan = [int(s) for s in hit.index[:MAX_HOSTS]]
        sig = cand & isin_c(src, scan)
        vic = [int(v) for v in np.unique(dst[sig])]
        av = sig | between_c(src, dst, scan, vic)
        s_any = isin_c(src, scan)
        extra = {'candidate_flows': int(cand.sum()),
                 'fanout_top': [{'host': ipt.names[int(s)], 'distinct_targets': int(r.targets),
                                 'distinct_hosts': int(r.hosts), 'distinct_ports': int(r.ports)}
                                for s, r in fan.head(10).iterrows()],
                 'scanners': ipt.name_list(scan), 'probed_hosts': len(vic),
                 'scanner_flows_to_non_testbed': int((s_any & ~int_d).sum()),
                 'scanner_flows_to_non_testbed_top': top_c(ipt, dst[s_any & ~int_d], n=5),
                 'scanner_flows_as_destination': int((isin_c(dst, scan) & int_s & ~s_any).sum()),
                 'signature_destination_ports_top': top_v(dp[sig], n=10)}
        return {'raw': cand, 'both': both, 'server': dst, 'client': src, 'sig': sig, 'av': av,
                'attackers': ipt.name_list(scan), 'victims': ipt.name_list(vic), 'extra': extra}
    raise ValueError(kind)


def identify(kind, c, ipt, int_s, int_d, pk):
    if kind in OLD_KINDS:
        return identify_old(kind, c, ipt, int_s, int_d, pk)
    return identify_new(kind, c, ipt, int_s, int_d, pk)


def kinds_for(cls, sub):
    s = sub.upper()
    if cls == 'BruteForce':
        return ['bruteforce']
    if cls == 'Web-Based':
        return ['web']
    if sub == 'DNS Spoofing':
        return ['dns']
    if sub == 'ARP Spoofing':
        return ['arp']
    if cls == 'Mirai':
        return ['proto0flood', 'mirai_scan']
    if cls == 'Recon':
        return ['recon']
    for key, kind in (('SYN', 'syn'), ('UDP', 'udp'), ('HTTP', 'web'), ('ACK', 'ackfrag'), ('ICMP', 'proto0flood')):
        if key in s:
            return [kind]
    return []


# ----------------------------------------------------------------------------- scoring / reporting
def score2(att, flags, pk):
    """rule_validation.score() plus packet-weighted attack shares of the flagged and kept flows."""
    out = rv.score(att, flags, pk)
    for r, f in flags.items():
        out[r]['packet_flagged_attack_share'] = _r(pk[att & f].sum(), pk[f].sum())
        out[r]['packet_kept_attack_share'] = _r(pk[att & ~f].sum(), pk[~f].sum())
    return out


def examples_c(c, ipt, mask, k=3):
    """IP pairs that account for most flows of a mask, with their main protocol/port."""
    if not mask.any():
        return []
    s, d = c['src'][mask], c['dst'][mask]
    key = pair_c(s, d)
    tag = c['proto'][mask].astype(np.int64) * 100000 + np.minimum(c['sp'][mask], c['dp'][mask])
    out = []
    for p, n in pd.Series(key).value_counts().head(k).items():
        a, b = sorted((ipt.names[int(p) >> 31], ipt.names[int(p) & 0x7FFFFFFF]))
        t = int(pd.Series(tag[key == p]).value_counts().index[0])
        out.append({'pair': f'{a}|{b}', 'flows': int(n),
                    'main_proto_port': f'{rv.PROTO_NAME.get(t // 100000, t // 100000)}/{t % 100000}'})
    return out


def raw_block_c(c, ipt, idn, flags, pk):
    raw, both = idn['raw'], idn['both']
    nr, ni, ne = int(raw.sum()), int((raw & both).sum()), int((raw & ~both).sum())
    blk = {'flows': nr, 'share_of_capture': _r(nr, len(raw)), 'packet_share_of_capture': _r(pk[raw].sum(), pk.sum()),
           'testbed_pairs': ni, 'with_non_testbed_endpoint': ne,
           'flag_share': {r: _r((raw & f).sum(), nr) for r, f in flags.items()},
           'flag_share_testbed_pairs': {r: _r((raw & both & f).sum(), ni) for r, f in flags.items()},
           'flag_share_non_testbed_pairs': {r: _r((raw & ~both & f).sum(), ne) for r, f in flags.items()},
           'top_pairs': examples_c(c, ipt, raw, k=8)}
    if idn['server'] is not None:
        blk['top_destination_hosts'] = top_c(ipt, idn['server'][raw], n=10, testbed=True)
        blk['top_source_hosts'] = top_c(ipt, idn['client'][raw], n=10, testbed=True)
    return blk


def time_block2(ts, sig, av):
    ok = np.isfinite(ts)
    out = {'capture_start': _ts(ts[ok].min()) if ok.any() else None,
           'capture_end': _ts(ts[ok].max()) if ok.any() else None, 'unparsed_timestamps': int((~ok).sum())}
    w = window(ts, sig)
    if w is not None:
        inw = in_window(ts, w)
        out.update({'signature_start': _ts(w[0]), 'signature_end': _ts(w[1]),
                    'signature_window_minutes': round((w[1] - w[0]) / 60, 1),
                    'share_of_flows_in_window': _r(inw.sum(), ok.sum()),
                    'share_of_attack_related_in_window': _r((inw & av).sum(), (av & ok).sum())})
    return out


def attacker_any(c, ipt, av, attackers):
    """attacker_victim plus every flow of an identified attacker (upper bound)."""
    A = ipt.codes(attackers)
    return av | isin_c(c['src'], A) | isin_c(c['dst'], A)


def definitions_block(c, ipt, sig, av, anyd, flags, pk):
    n, dur = len(pk), c['dur']
    out = {}
    for d, m in (('signature', sig), ('attacker_victim', av), ('attacker_any', anyd)):
        na = int(m.sum())
        out[d] = {'attack_related': na, 'attack_share_before_cleaning': _r(na, n),
                  'packet_share_before_cleaning': _r(pk[m].sum(), pk.sum()),
                  'median_duration_s': round(float(np.median(dur[m])) / 1e6, 3) if na else None,
                  'median_duration_s_other_flows': round(float(np.median(dur[~m])) / 1e6, 3) if na < n else None,
                  'rules': score2(m, flags, pk),
                  'false_removal_by_pair': {r: examples_c(c, ipt, m & flags[r]) for r in RULES}}
    return out


def summary_of(defs, n):
    return {d: {'flows': n, 'attack_related': v['attack_related'],
                'attack_share_before_cleaning': v['attack_share_before_cleaning'],
                'packet_share_before_cleaning': v['packet_share_before_cleaning'],
                **{k: {r: s[k] for r, s in v['rules'].items()}
                   for k in ('false_removal_rate', 'packet_false_removal_rate', 'flagged_attack_share',
                             'kept_attack_share', 'packet_flagged_attack_share', 'packet_kept_attack_share')}}
            for d, v in defs.items()}


# ----------------------------------------------------------------------------- part 2: R1 audit
def r1_audit(c, ipt, B, flags, pk, int_s, int_d):
    src, dst, sp, dp, bwd = c['src'], c['dst'], c['sp'], c['dp'], c['bwd']
    r1 = flags['R1_external']
    n, n1, p1 = len(r1), int(r1.sum()), float(pk[r1].sum())
    ext_s, ext_d = ~int_s, ~int_d
    ab = B['addr_flows']
    inb_s, inb_d = lookup(ab, src) > 0, lookup(ab, dst) > 0
    epb_s, epb_d = in_sorted(ep_key(src, sp), B['ep']), in_sorted(ep_key(dst, dp), B['ep'])
    addr_ok = r1 & (~ext_s | inb_s) & (~ext_d | inb_d)
    ep_ok = r1 & (~ext_s | epb_s) & (~ext_d | epb_d)
    ext_code, ext_port = np.where(ext_d, dst, src), np.where(ext_d, dp, sp)
    int_code = np.where(ext_d, src, dst)

    def blk(m):
        return {'flows': int(m.sum()), 'share_of_r1': _r(m.sum(), n1), 'packet_share_of_r1': _r(pk[m].sum(), p1)}

    occ = np.bincount(src, minlength=len(ipt.names)) + np.bincount(dst, minlength=len(ipt.names))
    pseudo = isin_c(src, ipt.codes(ARP_PSEUDO))            # ARP header bytes, not an IP source
    rv4 = ipt.routable_v4_mask[src]                         # spoofing tools forge routable IPv4 sources
    single = ext_s & ~pseudo & (occ[src] == 1)
    spoof = single & rv4 & (bwd == 0) & ~inb_s
    spoof_excl = single & ~rv4 & (bwd == 0) & ~inb_s       # IPv6 / link-local etc.: reported, not counted
    one_ext = r1 & ~(ext_s & ext_d)
    pname = lambda v: rv.PROTO_NAME.get(int(v), str(int(v)))  # noqa: E731
    by_proto = pd.Series(c['proto'][r1]).value_counts()
    sp_tag = pd.Series(c['proto'][spoof].astype(np.int64) * 100000 + dp[spoof]).value_counts().head(5)
    out = {'r1_flows': n1, 'r1_share': _r(n1, n), 'r1_packet_share': _r(p1, pk.sum()),
           'both_endpoints_external': int((r1 & ext_s & ext_d).sum()),
           'external_address_in_benign': blk(addr_ok),
           'external_address_port_in_benign': blk(ep_ok),
           'external_address_not_in_benign': blk(r1 & ~addr_ok),
           'ip_pair_in_benign_R3': blk(r1 & flags['R3_benign_pair']),
           'on_service_port_R2': blk(r1 & flags['R2_service']),
           'by_protocol': {pname(k): int(v) for k, v in by_proto.items()},
           'distinct_external_addresses': int(np.unique(ext_code[r1]).size),
           'top_external_addresses': top_c(ipt, ext_code[r1], n=15, weights=pk[r1], benign=ab),
           'top_external_addresses_not_in_benign': top_c(ipt, ext_code[r1 & ~addr_ok], n=10,
                                                         weights=pk[r1 & ~addr_ok]),
           'top_external_address_ports': top_ep(ipt, ext_code[r1], ext_port[r1], n=15, weights=pk[r1],
                                                benign_ep=B['ep']),
           'top_external_ports': top_v(ext_port[r1], n=15, weights=pk[r1]),
           'top_internal_endpoints': top_c(ipt, int_code[one_ext], n=10, weights=pk[one_ext]),
           'spoofed_source_check': {
               'definition': 'routable IPv4 external source address that occurs in exactly one flow of the capture, '
                             'no backward packet, never in Benign',
               'external_source_flows': int(ext_s.sum()),
               'distinct_external_sources': int(np.unique(src[ext_s]).size),
               'single_flow_external_sources': int(single.sum()),
               'excluded_non_routable_or_ipv6_flows': int(spoof_excl.sum()),
               'flows': int(spoof.sum()), 'share_of_r1': _r(spoof.sum(), n1),
               'share_of_external_source_flows': _r(spoof.sum(), ext_s.sum()),
               'packet_share_of_r1': _r(pk[spoof].sum(), p1),
               'top_protocol_ports': [{'value': f'{pname(k // 100000)}/{k % 100000}', 'flows': int(v)}
                                      for k, v in sp_tag.items()]}}
    masks = {'ext_addr_in_benign': addr_ok, 'ext_addr_port_in_benign': ep_ok, 'spoofed_source_candidate': spoof}
    return out, masks


def arp_focus(c, ipt, idn, flags, pk, int_s, int_d, addr_ok):
    host = idn['extra'].get('spoofing_host')
    r1 = flags['R1_external']
    n1 = int(r1.sum())
    if not host:
        return {'spoofing_host': None, 'note': 'no spoofing host identified (see rule_validation arp signature)'}
    h, V = ipt.code(host), ipt.codes(idn['victims'])
    src, dst, ts = c['src'], c['dst'], c['ts']
    ext_d = ~int_d
    int_code = np.where(ext_d, src, dst)
    red = (c['proto'] == PROTO0) & (src == h) & isin_c(dst, V)       # ICMP redirects / pings of the host
    w = window(ts, red)
    inw = in_window(ts, w)
    vf = r1 & isin_c(int_code, V) & ~(~int_s & ~int_d)
    hf = r1 & ((src == h) | (dst == h))
    ext_code = np.where(ext_d, dst, src)
    return {'spoofing_host': host, 'victims': len(V),
            'poisoning_window': None if w is None else [_ts(w[0]), _ts(w[1])],
            'poisoning_window_minutes': None if w is None else round((w[1] - w[0]) / 60, 1),
            'r1_flows_of_victims': int(vf.sum()), 'r1_flows_of_victims_share_of_r1': _r(vf.sum(), n1),
            'r1_flows_of_victims_packet_share_of_r1': _r(pk[vf].sum(), pk[r1].sum()),
            'r1_flows_of_victims_inside_window': int((vf & inw).sum()),
            'r1_flows_of_victims_inside_window_share_of_r1': _r((vf & inw).sum(), n1),
            'victim_flows_external_address_in_benign_share': _r((vf & addr_ok).sum(), vf.sum()),
            'victim_flows_ip_pair_in_benign_share': _r((vf & flags['R3_benign_pair']).sum(), vf.sum()),
            'victim_flows_top_external_addresses': top_c(ipt, ext_code[vf], n=10, weights=pk[vf]),
            'r1_flows_of_spoofing_host': int(hf.sum()), 'r1_flows_of_spoofing_host_share_of_r1': _r(hf.sum(), n1),
            'r1_share_inside_window': _r((r1 & inw).sum(), n1),
            'note': 'during successful poisoning the victims\' Internet flows are relayed by the spoofing host (MAC '
                    'level, IP addresses unchanged), so R1 removes them although they cross the attacker; the '
                    'victim flows inside the window are an upper bound of such relayed flows (pcap_validation.py '
                    'measures them at MAC level)'}


def dns_indicators(c, int_s, int_d):
    sp, dp, fwd, bwd = c['sp'], c['dp'], c['fwd'], c['bwd']
    on_dst = dp == 53
    udp53 = (c['proto'] == UDP) & (on_dst | (sp == 53))
    rf = udp53 & np.where(on_dst, ~int_d, ~int_s)                  # the port-53 side is an external resolver
    res_pk, cli_pk = np.where(on_dst, bwd, fwd), np.where(on_dst, fwd, bwd)
    return rf, res_pk, cli_pk, on_dst


def dns_focus(c, ipt, idn, flags, pk, int_s, int_d, addr_ok, benign_extra_share, B):
    r1 = flags['R1_external']
    n1 = int(r1.sum())
    rf, res_pk, cli_pk, on_dst = dns_indicators(c, int_s, int_d)
    resolver, client = np.where(on_dst, c['dst'], c['src']), np.where(on_dst, c['src'], c['dst'])
    extra = rf & (res_pk > cli_pk)
    w = window(c['ts'], idn['sig'])
    inw = in_window(c['ts'], w)
    A = ipt.codes(idn['attackers'])
    att_ext = r1 & (isin_c(c['src'], A) | isin_c(c['dst'], A))
    return {'external_resolver_flows': int(rf.sum()), 'share_of_r1': _r((rf & r1).sum(), n1),
            'packet_share_of_r1': _r(pk[rf & r1].sum(), pk[r1].sum()),
            'answered_share': _r((rf & (res_pk > 0)).sum(), rf.sum()),
            'extra_answer_flows': int(extra.sum()), 'extra_answer_share': _r(extra.sum(), rf.sum()),
            'benign_baseline_extra_answer_share': benign_extra_share,
            'extra_answer_share_inside_window': _r((extra & inw).sum(), (rf & inw).sum()),
            'extra_answer_share_outside_window': _r((extra & ~inw).sum(), (rf & ~inw).sum()),
            'rogue_responder_window': None if w is None else [_ts(w[0]), _ts(w[1])],
            'external_resolver_flows_inside_window': int((rf & inw).sum()),
            'resolver_address_in_benign_share': _r((rf & addr_ok).sum(), (rf & r1).sum()),
            'resolvers_top': top_c(ipt, resolver[rf], n=10, benign=B['addr_flows']),
            'clients_top': top_c(ipt, client[rf], n=10),
            'clients_top_extra_answer': top_c(ipt, client[extra], n=10),
            'r1_flows_of_rogue_responders': int(att_ext.sum()),
            'note': 'forged answers that carry the resolver\'s address cannot be separated at flow level; an extra '
                    'answer in a flow is the flow-level trace of a race between forged and genuine answer'}


# ----------------------------------------------------------------------------- part 3: sampler
class Sampler:
    """Bottom-k per stratum (rule x flagged/kept) of the per-row hash key, with all read columns."""

    def __init__(self, k=SAMPLE_K):
        self.k, self.best = k, {}

    def offer(self, ch, a, keys, rel, offset):
        fl = {'R1_external': a['r1'], 'R2_service': a['r2'], 'R3_benign_pair': a['r3']}
        fl['any'] = fl['R1_external'] | fl['R2_service'] | fl['R3_benign_pair']
        for r, f in fl.items():
            for s, m in (('flagged', f), ('kept', ~f)):
                idx = np.flatnonzero(m)
                if not len(idx):
                    continue
                if len(idx) > self.k:
                    idx = idx[np.argpartition(keys[idx], self.k - 1)[:self.k]]
                sub = ch.iloc[idx].copy()
                sub['sample_key'], sub['file'] = keys[idx], rel
                sub['row'], sub['cap_index'] = a['row'][idx], offset + idx
                st = f'{r}:{s}'
                cur = self.best.get(st)
                both = sub if cur is None else pd.concat([cur, sub], ignore_index=True)
                self.best[st] = both.sort_values('sample_key', kind='stable').head(self.k).reset_index(drop=True)

    def candidates(self):
        if not self.best:
            return pd.DataFrame()
        allc = pd.concat([df.assign(stratum=st) for st, df in self.best.items()], ignore_index=True)
        memb = pd.crosstab(allc['cap_index'], allc['stratum']).astype(bool)
        for st in STRATA:
            if st not in memb:
                memb[st] = False
        rows = allc.drop_duplicates('cap_index').drop(columns='stratum').set_index('cap_index')
        return rows.join(memb[STRATA].add_prefix('cand_')).reset_index()


# ----------------------------------------------------------------------------- Benign
def load_benign(ipt, max_rows=None):
    files = [f for _, fs in capture_groups('Benign') for f in fs]
    bc = read_arrays(files, ipt, BASE_COLS, max_rows)
    ipt.int_mask                              # extend the masks to the Benign addresses
    pairs = np.unique(pair_c(bc['src'], bc['dst']))
    addr = np.bincount(bc['src'], minlength=len(ipt.names)) + np.bincount(bc['dst'], minlength=len(ipt.names))
    ep = np.unique(np.concatenate([ep_key(bc['src'], bc['sp']), ep_key(bc['dst'], bc['dp'])]))
    B = {'pairs': pairs, 'addr_flows': addr, 'ep': ep, 'files': [Path(f).name for f in files], 'flows': len(bc['src'])}
    return bc, B


def benign_baseline(bc, ipt, B, kinds):
    int_s, int_d = ipt.int_mask[bc['src']], ipt.int_mask[bc['dst']]
    pk = bc['fwd'].astype(np.float64) + bc['bwd']
    n, tot = len(pk), float(pk.sum())
    base = {'files': B['files'], 'flows': n, 'packets': int(tot), 'distinct_ip_pairs': int(len(B['pairs'])),
            'distinct_addresses': int((B['addr_flows'] > 0).sum()),
            'distinct_address_port_endpoints': int(len(B['ep']))}
    for kind in kinds:
        idn = identify(kind, bc, ipt, int_s, int_d, pk)
        base[kind] = {'signature': SIGNATURES[kind],
                      'signature_raw_flows': int(idn['raw'].sum()), 'signature_raw_share': _r(idn['raw'].sum(), n),
                      'signature_raw_packet_share': _r(pk[idn['raw']].sum(), tot),
                      'signature_raw_testbed_pairs': int((idn['raw'] & idn['both']).sum()),
                      'would_be_attackers': idn['attackers'], 'would_be_victims': list(idn['victims']),
                      'n_would_be_victims': len(idn['victims']),
                      'signature_flows': int(idn['sig'].sum()), 'signature_share': _r(idn['sig'].sum(), n),
                      'signature_packet_share': _r(pk[idn['sig']].sum(), tot),
                      'attacker_victim_flows': int(idn['av'].sum()), 'attacker_victim_share': _r(idn['av'].sum(), n),
                      'attacker_victim_packet_share': _r(pk[idn['av']].sum(), tot), **idn['extra']}
        anyb = attacker_any(bc, ipt, idn['av'], idn['attackers'])
        base[kind].update({'attacker_any_flows': int(anyb.sum()), 'attacker_any_share': _r(anyb.sum(), n)})
        del anyb
        if idn['server'] is not None:
            base[kind]['top_destination_hosts'] = top_c(ipt, idn['server'][idn['raw']], n=5, testbed=True)
        del idn
    rf, res_pk, cli_pk, _ = dns_indicators(bc, int_s, int_d)
    base['dns_extra_answer'] = {'external_resolver_flows': int(rf.sum()),
                                'extra_answer_flows': int((rf & (res_pk > cli_pk)).sum()),
                                'extra_answer_share': _r((rf & (res_pk > cli_pk)).sum(), rf.sum())}
    base['address_flow_counts'] = {ipt.names[k]: int(v) for k, v in enumerate(B['addr_flows']) if v > 0}
    return base


# ----------------------------------------------------------------------------- one capture
def process_capture(cap, ipt, B, baseline, out, args):
    cls, sub, files, kinds, name = cap['class'], cap['sub'], cap['files'], cap['kinds'], cap['name']
    t0 = time.time()
    sampler = Sampler(SAMPLE_K)

    def on_chunk(ch, a, f, offset):
        a['r1'], a['r2'], a['r3'] = rule_flags_codes(a, sub, ipt, B)
        rel = _relpath(f)
        sampler.offer(ch, a, row_keys(zlib.crc32(rel.encode()), a['row']), rel, offset)

    c = read_arrays(files, ipt, READ_COLS, args.max_rows, on_chunk, verbose=len(files) <= 30)
    if c is None or not len(c['src']):
        print(f'    {name}: no flows - skipped', flush=True)
        return None
    n = len(c['src'])
    int_s, int_d = ipt.int_mask[c['src']], ipt.int_mask[c['dst']]
    pk = c['fwd'].astype(np.float64) + c['bwd']
    flags = flags_of(c)
    print(f'    read {n:,} flows ({time.time() - t0:.0f} s); R1 {flags["R1_external"].mean():.1%} '
          f'R2 {flags["R2_service"].mean():.1%} R3 {flags["R3_benign_pair"].mean():.1%} any {flags["any"].mean():.1%}',
          flush=True)

    idns = {k: identify(k, c, ipt, int_s, int_d, pk) for k in kinds}
    sig, av = np.zeros(n, bool), np.zeros(n, bool)
    for idn in idns.values():
        sig |= idn['sig']
        av |= idn['av']
    all_att = sorted({x for idn in idns.values() for x in idn['attackers']})
    anyd = attacker_any(c, ipt, av, all_att)
    entry = {'name': name, 'class': cls, 'capture_group': sub, 'kinds': kinds,
             'max_rows': args.max_rows,          # None = every row; a test run (--max-rows) is never taken as done
             'files': [Path(f).name for f in files], 'flows': n, 'packets': int(pk.sum()),
             'rule_flag_share': {r: _r(f.sum(), n) for r, f in flags.items()},
             'rule_packet_share': {r: _r(pk[f].sum(), pk.sum()) for r, f in flags.items()},
             'stratum_counts': {r: {'flagged': int(f.sum()), 'kept': int(n - f.sum())} for r, f in flags.items()},
             'attackers_all_kinds': all_att,
             'signatures': {}, 'time': time_block2(c['ts'], sig, av),
             'definitions': definitions_block(c, ipt, sig, av, anyd, flags, pk)}
    for k, idn in idns.items():
        bb = baseline.get(k, {})
        entry['signatures'][k] = {
            'signature': SIGNATURES[k], 'attackers': idn['attackers'], 'victims': idn['victims'],
            'attackers_also_derived_in_benign': sorted(set(idn['attackers']) & set(bb.get('would_be_attackers', []))),
            'victims_also_derived_in_benign': sorted(set(idn['victims']) & set(bb.get('would_be_victims', []))),
            **({'attacker_candidates_not_accepted': idn['attackers_candidates']}
               if 'attackers_candidates' in idn and not idn['attackers'] else {}),
            **idn['extra'],
            'signature_raw': raw_block_c(c, ipt, idn, flags, pk),
            'benign_baseline': {x: bb.get(x) for x in ('signature_raw_flows', 'signature_raw_share',
                                                         'signature_raw_packet_share', 'signature_flows',
                                                         'signature_share', 'attacker_victim_flows',
                                                         'attacker_victim_share', 'attacker_any_flows',
                                                         'attacker_any_share', 'would_be_attackers',
                                                         'n_would_be_victims')}}
        if len(kinds) > 1:
            entry['signatures'][k]['definitions'] = summary_of(
                definitions_block(c, ipt, idn['sig'], idn['av'], attacker_any(c, ipt, idn['av'], idn['attackers']),
                                  flags, pk), n)
    if 'proto0flood' in kinds:
        pa, pb = ipt.code(ARP_PSEUDO[0]), ipt.code(ARP_PSEUDO[1])
        p0 = (c['proto'] == PROTO0) & ~(((c['src'] == pa) & (c['dst'] == pb)) | ((c['src'] == pb) & (c['dst'] == pa)))
        V = ipt.codes(idns['proto0flood']['victims'])
        recv = idns['proto0flood']['server']                    # receiver side (direction-agnostic)
        sens = {}
        for th in HEAVY_SENS:
            m = p0 & (pk >= th) & isin_c(recv, V)
            sens[str(th)] = {'flows': int(m.sum()), 'packet_share_of_capture': _r(pk[m].sum(), pk.sum()),
                             'false_removal_rate': {r: _r((m & f).sum(), m.sum()) for r, f in flags.items()},
                             'packet_false_removal_rate': {r: _r(pk[m & f].sum(), pk[m].sum()) for r, f in flags.items()}}
        entry['heavy_threshold_sensitivity'] = sens
        entry['protocol0_share'] = {'flows': _r(p0.sum(), n), 'packets': _r(pk[p0].sum(), pk.sum())}

    audit, masks = r1_audit(c, ipt, B, flags, pk, int_s, int_d)
    audit['r1_flows_attack_related'] = int((flags['R1_external'] & av).sum())
    audit['r1_flows_attacker_any'] = int((flags['R1_external'] & anyd).sum())
    audit['spoofed_source_check']['in_attack_related'] = int((masks['spoofed_source_candidate'] & av).sum())
    audit['share_inside_signature_window'] = _r((flags['R1_external'] & in_window(c['ts'], window(c['ts'], sig))).sum(),
                                                flags['R1_external'].sum())
    if 'arp' in idns:
        audit['arp_focus'] = arp_focus(c, ipt, idns['arp'], flags, pk, int_s, int_d, masks['ext_addr_in_benign'])
    if 'dns' in idns:
        audit['dns_focus'] = dns_focus(c, ipt, idns['dns'], flags, pk, int_s, int_d, masks['ext_addr_in_benign'],
                                       baseline.get('dns_extra_answer', {}).get('extra_answer_share'), B)
    entry['r1_audit'] = audit
    entry['summary'] = summary_of(entry['definitions'], n)

    derived = {x for idn in idns.values() for x in idn['attackers'] + list(idn['victims'])}
    cnt = np.bincount(c['src'], minlength=len(ipt.names)) + np.bincount(c['dst'], minlength=len(ipt.names))
    im = ipt.int_mask
    entry['address_flow_counts'] = {ipt.names[k]: int(v) for k, v in enumerate(cnt)
                                    if v > 0 and (im[k] or ipt.names[k] in derived)}

    cand = sampler.candidates()
    if len(cand):
        ix = cand['cap_index'].to_numpy()
        cand.insert(0, 'class', cls)
        cand.insert(1, 'capture', name)
        for r, f in flags.items():
            cand[r] = f[ix]
        cand['signature'], cand['attack_related'], cand['attacker_any'] = sig[ix], av[ix], anyd[ix]
        cand['kinds'] = '+'.join(kinds)
        for k, m in masks.items():
            cand[k] = m[ix]
        cand.to_csv(out / 'captures' / f'{_slug(name)}_sample.csv', index=False)
    entry['sample_candidates'] = int(len(cand))
    entry['seconds'] = round(time.time() - t0, 1)
    write_json(entry, out / 'captures' / f'{_slug(name)}.json')

    s = entry['summary']['attacker_victim']
    fr, pf = s['false_removal_rate'], s['packet_false_removal_rate']
    sc = audit['spoofed_source_check']
    print(f'    attack-related {s["attack_related"]:,} ({_pct(s["attack_share_before_cleaning"])} of flows, '
          f'{_pct(s["packet_share_before_cleaning"])} of packets)  false removal flows R1 {_pct(fr["R1_external"])} '
          f'R2 {_pct(fr["R2_service"])} R3 {_pct(fr["R3_benign_pair"])} any {_pct(fr["any"])} | packets R1 '
          f'{_pct(pf["R1_external"])} any {_pct(pf["any"])} | attacker_any: '
          f'{entry["summary"]["attacker_any"]["attack_related"]:,} flows, false removal any '
          f'{_pct(entry["summary"]["attacker_any"]["false_removal_rate"]["any"])}', flush=True)
    print(f'    R1 audit: {audit["r1_flows"]:,} R1 flows, external address in Benign '
          f'{_pct(audit["external_address_in_benign"]["share_of_r1"])}, address+port '
          f'{_pct(audit["external_address_port_in_benign"]["share_of_r1"])}, spoofed-source candidates '
          f'{sc["flows"]:,} ({_pct(sc["share_of_r1"])})  attackers={[x for i in idns.values() for x in i["attackers"]][:6]} '
          f'({time.time() - t0:.0f} s)', flush=True)
    del c, flags, idns, pk, int_s, int_d, sig, av, anyd, masks
    gc.collect()
    return entry


# ----------------------------------------------------------------------------- discovery / merge
def discover():
    caps = []
    for cls in CLASSES:
        if cls == 'Benign':
            continue
        for sub, files in capture_groups(cls):
            ok = [f for f in files if set(READ_COLS) <= set(pd.read_csv(f, nrows=0).columns)]
            if not ok:
                continue
            name = f'{cls} / {sub}' if sub != cls else cls
            caps.append({'class': cls, 'sub': sub, 'files': ok, 'kinds': kinds_for(cls, sub), 'name': name,
                         'bytes': sum(os.path.getsize(f) for f in ok)})
    return sorted(caps, key=lambda x: (x['bytes'], x['name']))


AUDIT_FILES = ('audit_sample.csv', 'audit_strata_counts.json', 'audit_template.md', 'audit_template_blind.md')


def _has_decisions(path):
    if not path.exists() or path.suffix == '.json':
        return False
    try:
        return any(v[0].strip() for v in read_decisions(path).values())
    except Exception:                                       # unreadable: treat as filled (never overwrite it)
        return True


def audit_paths(out):
    """Target paths of the audit files. A filled audit (decisions in the sample CSV or a template) is never
    overwritten: the whole regenerated set then goes to <name>.regenerated<ext> (sample, counts and templates
    stay consistent with each other) and a warning is printed."""
    locked = [n for n in AUDIT_FILES if _has_decisions(out / n)]
    if locked:
        print(f'[warn] {locked} already hold audit decisions - the audit files are NOT overwritten; the regenerated '
              f'set is written as *.regenerated.* (same sample IDs if the merged captures are unchanged)', flush=True)
    return {n: (out / n if not locked else out / f'{Path(n).stem}.regenerated{Path(n).suffix}') for n in AUDIT_FILES}


def build_sample(out, entries):
    # only the per-capture candidates of the merged captures (a stale or test-run *_sample.csv is ignored)
    files = [out / 'captures' / f'{_slug(e["name"])}_sample.csv' for e in entries if e.get('sample_candidates')]
    parts = [pd.read_csv(p) for p in files if p.exists()]
    if not parts:
        return None
    df = pd.concat(parts, ignore_index=True)
    df['uid'] = df['file'].astype(str) + '#' + df['row'].astype(str)
    order = {c: i for i, c in enumerate(CLASSES)}
    sel = []
    for cls in sorted(df['class'].unique(), key=lambda x: order.get(x, 99)):
        g = df[df['class'] == cls]
        chosen = {}
        for st in STRATA:
            col = f'cand_{st}'
            if col not in g:
                continue
            h = g[g[col].astype(bool)].sort_values('sample_key', kind='stable').drop_duplicates('uid').head(SAMPLE_K)
            for u in h['uid']:
                chosen.setdefault(u, []).append(st)
        gg = g[g['uid'].isin(list(chosen))].drop_duplicates('uid').sort_values('sample_key', kind='stable').copy()
        gg['selected_strata'] = gg['uid'].map(lambda u: ';'.join(chosen[u]))
        gg.insert(0, 'sample_id', [f'{CLASS_ABBR.get(cls, cls[:2].upper())}-{i:03d}' for i in range(1, len(gg) + 1)])
        sel.append(gg)
    s = pd.concat(sel, ignore_index=True)
    for col in ('audit_decision', 'audit_evidence', 'audit_notes'):
        s[col] = ''
    heur = ['signature', 'attack_related', 'attacker_any', 'kinds', 'ext_addr_in_benign', 'ext_addr_port_in_benign',
            'spoofed_source_candidate']
    first = ['sample_id', 'class', 'capture', 'selected_strata', 'audit_decision', 'audit_evidence', 'audit_notes']
    rest = ([c for c in ID_COLS if c in s] + list(RULES) + [c for c in heur if c in s]
            + [c for c in KEY_FEATURES if c in s and c not in ID_COLS] + ['file', 'row', 'sample_key'])
    s = s[first + rest]
    counts = {}
    for e in entries:
        cc = counts.setdefault(e['class'], {r: {'flagged': 0, 'kept': 0} for r in RULES})
        for r in RULES:
            for k in ('flagged', 'kept'):
                cc[r][k] += e['stratum_counts'][r][k]
    P = audit_paths(out)
    s.to_csv(P['audit_sample.csv'], index=False)
    write_json(counts, P['audit_strata_counts.json'])
    write_template(s, P['audit_template.md'], counts)
    write_template(s, P['audit_template_blind.md'], counts, blind=True)
    return s


def _bool(v):
    """CSV round-trip safe truth value (True/False, 'True'/'False', 1/0, NaN)."""
    if isinstance(v, str):
        return v.strip().lower() in ('true', '1', 'yes')
    try:
        return bool(v) and not (isinstance(v, float) and math.isnan(v))
    except (TypeError, ValueError):
        return False


def _int(v, default=-1):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _flow_str(row):
    p = rv.PROTO_NAME.get(_int(row['Protocol']), str(row['Protocol']))
    return f"{p} {row['Src IP']}:{row['Src Port']} → {row['Dst IP']}:{row['Dst Port']}"


def write_template(s, path, counts, blind=False):
    """Markdown audit table. blind=True hides the rule flags, strata and heuristic labels (the auditor decides
    from the flow evidence alone, without anchoring on whether a rule flagged the flow); both versions carry
    the same IDs and are read by --score-audit through their header row."""
    L = ['# Manual audit of the background rules R1-R3' + (' (blind version)' if blind else ''), '',
         'Generated by `experiments/rule_validation2.py` (seed 42). One row per sampled flow of the flow CSVs of '
         'CIC IoT-DIAD 2024. Per attack class and per rule (R1 external endpoint, R2 service port, R3 IP pair seen '
         'in Benign, any = R1|R2|R3) the sample holds 20 flows flagged by the rule and 20 flows kept by it (all '
         'flows if a stratum is smaller); a flow can serve several strata. All identifier columns and key features '
         'are in `audit_sample.csv` (same *ID*).', '',
         '**Decision** (one word): `attack` = the flow is part of the attack of its folder label (sent by or to an '
         'attacking host as part of the attack, a scan probe, a flood packet train, a forged answer, or victim '
         'traffic relayed by a man-in-the-middle attacker); `background` = ordinary device, gateway or Internet '
         'traffic unrelated to the attack; `unclear` = cannot be decided from the evidence.', '',
         '**Evidence** (short): what the decision rests on, e.g. "SSH from attacker .65 to victim .67 in attack '
         'window", "NTP to pool server, also in Benign", "pcap: frames via attacker MAC", "payload UNION SELECT". '
         'Useful checks: attacker/victim addresses and attack window in `captures/<capture>.json`, the packet '
         'release (pcap, `pcap_validation/<capture>/audit_sample_mac.csv`) where available.', '',
         'Fill in ONE of `audit_template.md` / `audit_template_blind.md` (the blind one hides the rule flags and '
         'heuristic labels and is recommended, so that the decision does not anchor on the rule being validated). '
         'Do not change the ID column or the header row. Score after filling in:',
         '`& $py experiments\\rule_validation2.py --score-audit '
         f'results_2026_03_03\\q1_revision\\rule_validation2\\{path.name}`', '']
    if not blind:
        L += ['Heur. = heuristic label of rule_validation2 (S = signature flow, A = attack-related: attacker-victim '
              'flow, U = flow of an identified attacker with another peer (upper-bound definition only), - = none of '
              'these).', '']
    for cls, g in s.groupby('class', sort=False):
        cc = counts.get(cls, {})
        L += [f'## {cls} ({len(g)} flows)', '']
        if not blind:
            L += ['Stratum sizes (flows): ' + ', '.join(f'{r} flagged {cc[r]["flagged"]:,} / kept {cc[r]["kept"]:,}'
                                                      for r in RULES if r in cc), '']
            L += ['| ID | Capture | Timestamp | Flow | Pkts f/b | Dur s | R1 | R2 | R3 | Heur. | Strata | Decision | '
                  'Evidence |', '|---|---|---|---|---|---|---|---|---|---|---|---|---|']
        else:
            L += ['| ID | Capture | Timestamp | Flow | Pkts f/b | Bytes f/b | Dur s | Decision | Evidence |',
                  '|---|---|---|---|---|---|---|---|---|']
        for _, row in g.iterrows():
            dur = _int(row['Flow Duration'], 0) / 1e6
            common = (f"| {row['sample_id']} | {row['capture'].split(' / ')[-1]} | {row['Timestamp']} | "
                      f"{_flow_str(row)} | {_int(row['Total Fwd Packet'])}/{_int(row['Total Bwd packets'])} | ")
            if blind:
                L.append(common + f"{_int(row.get('Total Length of Fwd Packet'), 0)}/"
                                  f"{_int(row.get('Total Length of Bwd Packet'), 0)} | {dur:.2f} |  |  |")
                continue
            heur = ('S' if _bool(row['signature']) else 'A' if _bool(row['attack_related'])
                    else 'U' if _bool(row.get('attacker_any', False)) else '-')
            strata = row['selected_strata'].replace('_external', '').replace('_service', '').replace(
                '_benign_pair', '').replace(';', ', ')
            L.append(common + f"{dur:.2f} | "
                     f"{'x' if _bool(row['R1_external']) else ''} | {'x' if _bool(row['R2_service']) else ''} | "
                     f"{'x' if _bool(row['R3_benign_pair']) else ''} | {heur} | {strata} |  |  |")
        L.append('')
    path.write_text('\n'.join(L), encoding='utf-8')


def load_entry(out, name):
    p = out / 'captures' / f'{_slug(name)}.json'
    if not p.exists():
        return None
    try:
        with open(p, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def merge(out, caps, partial, max_rows=None):
    """Merge the per-capture JSONs made with the same --max-rows (None = every row): a test run with
    --max-rows is never mixed into, or taken for, the full results."""
    entries, missing, other = [], [], []
    for cap in caps:
        e = load_entry(out, cap['name'])
        if e is None:
            missing.append(cap['name'])
        elif e.get('max_rows') != max_rows:
            other.append(f'{cap["name"]} (max_rows={e.get("max_rows")})')
            missing.append(cap['name'])
        else:
            entries.append(e)
    if other:
        print(f'[merge] ignored {len(other)} capture JSON(s) made with another --max-rows: {other}', flush=True)
    if missing and not partial:
        print(f'[merge] waiting for {len(missing)} captures: {missing}', flush=True)
        return
    if not entries:
        print('[merge] nothing to merge', flush=True)
        return
    bpath = out / 'benign_baseline.json'
    baseline = json.load(open(bpath, encoding='utf-8')) if bpath.exists() else {}
    if baseline and baseline.get('max_rows_per_file') != max_rows:
        print(f'[warn] benign_baseline.json was made with --max-rows {baseline.get("max_rows_per_file")}, the merge '
              f'uses {max_rows}: rerun a capture without --max-rows (or with the same value) to refresh it', flush=True)
    res = {'purpose': 'Signature-based validation of background rules R1-R3 on all attack captures, R1 audit and '
                      'manual-audit sample (flow CSVs only).',
           'assumptions': ASSUMPTIONS, 'signatures': SIGNATURES,
           'parameters': {'cover': COVER, 'max_hosts': MAX_HOSTS, 'flood_min_packets': FLOOD_MIN_PKTS,
                          'udp_min_rate_pps': FLOOD_MIN_RATE, 'udp_burst_flows_per_second': UDP_BURST_FLOWS,
                          'heavy_packets': HEAVY_PKTS, 'heavy_sensitivity': list(HEAVY_SENS),
                          'victim_cap_floods': VICTIM_CAP, 'attacker_cap_floods': ATTACKER_CAP,
                          'mirai_ports': list(MIRAI_PORTS), 'mirai_min_targets': MIRAI_MIN_TARGETS,
                          'recon_min_ports': RECON_MIN_PORTS, 'recon_min_hosts': RECON_MIN_HOSTS,
                          'sample_k': SAMPLE_K, 'seed': SEED, 'gateway': GATEWAY, 'main_definition': 'attacker_victim'},
           'max_rows_per_file': max_rows, 'test_run': max_rows is not None,
           'missing_captures': missing, 'ignored_captures_other_max_rows': other,
           'benign_baseline': {k: v for k, v in baseline.items() if k != 'address_flow_counts'},
           'summary': {}, 'r1_audit': {}, 'signatures_per_capture': {}}
    rows, arows = [], []
    for e in entries:
        name = e['name']
        res['summary'][name] = e['summary']
        a = e['r1_audit']
        res['r1_audit'][name] = {k: a[k] for k in ('r1_flows', 'r1_share', 'r1_packet_share',
                                                   'external_address_in_benign', 'external_address_port_in_benign',
                                                   'external_address_not_in_benign', 'ip_pair_in_benign_R3',
                                                   'on_service_port_R2', 'r1_flows_attack_related',
                                                   'r1_flows_attacker_any',
                                                   'top_external_addresses', 'spoofed_source_check')}
        for k in ('arp_focus', 'dns_focus'):
            if k in a:
                res['r1_audit'][name][k] = a[k]
        res['signatures_per_capture'][name] = {k: {'attackers': v['attackers'], 'victims': v['victims'][:20],
                                                   'attackers_also_derived_in_benign': v['attackers_also_derived_in_benign']}
                                               for k, v in e['signatures'].items()}
        sets = [('+'.join(e['kinds']), e['summary'])] + [(k, v['definitions']) for k, v in e['signatures'].items()
                                                         if 'definitions' in v]
        for kind, sm in sets:
            for d, s in sm.items():
                for r in RULES:
                    rows.append({'capture': name, 'class': e['class'], 'kinds': kind, 'definition': d,
                                 'flows': s['flows'], 'attack_related': s['attack_related'],
                                 'attack_share': s['attack_share_before_cleaning'],
                                 'attack_packet_share': s['packet_share_before_cleaning'], 'rule': r,
                                 'false_removal_rate': s['false_removal_rate'][r],
                                 'packet_false_removal_rate': s['packet_false_removal_rate'][r],
                                 'flagged_attack_share': s['flagged_attack_share'][r],
                                 'kept_attack_share': s['kept_attack_share'][r],
                                 'packet_kept_attack_share': s['packet_kept_attack_share'][r]})
        sc = a['spoofed_source_check']
        arows.append({'capture': name, 'class': e['class'], 'flows': e['flows'], 'r1_flows': a['r1_flows'],
                      'r1_share': a['r1_share'], 'r1_packet_share': a['r1_packet_share'],
                      'ext_address_in_benign_share': a['external_address_in_benign']['share_of_r1'],
                      'ext_address_port_in_benign_share': a['external_address_port_in_benign']['share_of_r1'],
                      'ip_pair_in_benign_share': a['ip_pair_in_benign_R3']['share_of_r1'],
                      'service_port_share': a['on_service_port_R2']['share_of_r1'],
                      'r1_attack_related': a['r1_flows_attack_related'],
                      'r1_attacker_any': a.get('r1_flows_attacker_any'),
                      'spoofed_source_flows': sc['flows'], 'spoofed_source_share_of_r1': sc['share_of_r1'],
                      'distinct_external_sources': sc['distinct_external_sources']})
    derived = sorted({x for e in entries for s in e['signatures'].values() for x in s['attackers'] + s['victims'][:20]})
    bcnt = baseline.get('address_flow_counts', {})
    res['address_presence'] = {x: {'Benign': int(bcnt.get(x, 0)),
                                   **{e['name']: int(e['address_flow_counts'].get(x, 0)) for e in entries}}
                               for x in derived}
    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out / 'summary_false_removal.csv', index=False)
    pd.DataFrame(arows).to_csv(out / 'summary_r1_audit.csv', index=False)
    samp = build_sample(out, entries)
    res['audit_sample'] = None if samp is None else {
        'flows': int(len(samp)), 'per_class': {k: int(v) for k, v in samp['class'].value_counts().items()}}
    write_json(res, out / 'rule_validation2.json')

    print('\n=== attacker_victim definition: false-removal rate (flows | packets) and R1 audit ===')
    print(f'  {"capture":36s} {"attack":>9s} {"share":>7s} | {"R1":>6s} {"R2":>6s} {"R3":>6s} {"any":>6s} | '
          f'{"pkR1":>6s} {"pkAny":>6s} | {"R1extInBen":>10s} {"spoof":>6s}')
    for e in entries:
        s = e['summary']['attacker_victim']
        fr, pf = s['false_removal_rate'], s['packet_false_removal_rate']
        a = e['r1_audit']
        print(f'  {e["name"][:36]:36s} {s["attack_related"]:>9,} {_pct(s["attack_share_before_cleaning"])} | '
              f'{_pct(fr["R1_external"])} {_pct(fr["R2_service"])} {_pct(fr["R3_benign_pair"])} {_pct(fr["any"])} | '
              f'{_pct(pf["R1_external"])} {_pct(pf["any"])} | '
              f'{_pct(a["external_address_in_benign"]["share_of_r1"]):>10s} {_pct(a["spoofed_source_check"]["share_of_r1"])}')
    if missing:
        print(f'  (partial merge: missing {missing})')
    if max_rows is not None:
        print(f'  (TEST RUN: at most {max_rows:,} rows per CSV file - not a result)')
    print(f'[merge] {out / "rule_validation2.json"}; audit sample: '
          f'{0 if samp is None else len(samp)} flows -> {out} (audit_template.md / audit_template_blind.md)', flush=True)


# ----------------------------------------------------------------------------- audit scoring
def read_decisions(path):
    """{sample ID: (decision, evidence, timestamp)} from a filled audit_template(_blind).md (columns located by
    the header row of each table) or from audit_sample.csv (audit_decision / audit_evidence columns)."""
    if path.suffix.lower() == '.md':
        dec, hdr = {}, None
        for line in path.read_text(encoding='utf-8').splitlines():
            if not line.lstrip().startswith('|'):
                continue
            s = line.strip()
            cells = [x.strip() for x in (s[1:-1] if s.endswith('|') and len(s) > 1 else s[1:]).split('|')]
            if cells and cells[0] == 'ID':
                hdr = {h: i for i, h in enumerate(cells)}
                continue
            if hdr is None or not re.fullmatch(r'[A-Z]{2}-\d{3,}', cells[0]):
                continue
            get = lambda h: cells[hdr[h]] if h in hdr and hdr[h] < len(cells) else ''  # noqa: E731
            dec[cells[0]] = (get('Decision'), get('Evidence'), get('Timestamp'))
        return dec
    df = pd.read_csv(path, keep_default_na=False)
    return {r['sample_id']: (str(r.get('audit_decision', '')), str(r.get('audit_evidence', '')),
                             str(r.get('Timestamp', ''))) for _, r in df.iterrows()}


def score_audit(path, out):
    # a filled *.regenerated.* template belongs to the regenerated sample / counts
    sfx = '.regenerated' if '.regenerated' in path.name else ''
    sample = pd.read_csv(out / f'audit_sample{sfx}.csv', keep_default_na=False)
    counts = json.load(open(out / f'audit_strata_counts{sfx}.json', encoding='utf-8'))
    raw = read_decisions(path)
    ts = dict(zip(sample['sample_id'], sample['Timestamp'].astype(str)))
    unknown = sorted(i for i in raw if i not in ts)
    mismatch = sorted(i for i, v in raw.items() if i in ts and v[2] and v[2] != ts[i])
    if unknown or mismatch:
        raise SystemExit(f'[audit] {path.name} does not belong to audit_sample{sfx}.csv: {len(unknown)} unknown IDs '
                         f'{unknown[:5]}, {len(mismatch)} IDs with another timestamp {mismatch[:5]}')
    sample['decision'] = sample['sample_id'].map(lambda i: DECISIONS.get(raw.get(i, ('', ''))[0].strip().lower(), ''))
    bad = sorted({raw[i][0] for i in raw if raw[i][0].strip() and raw[i][0].strip().lower() not in DECISIONS})
    res = {'source': str(path), 'decided': int((sample['decision'] != '').sum()), 'sampled': int(len(sample)),
           'unrecognised_decisions': bad, 'per_class': {}, 'pooled': {}}
    rows = []
    pool = {r: {'F': 0, 'K': 0, 'rem': 0.0, 'kept': 0.0} for r in RULES}
    for cls, g in sample.groupby('class', sort=False):
        res['per_class'][cls] = {}
        for r in RULES:
            st = g['selected_strata'].str.split(';')
            fl = g[st.map(lambda x: f'{r}:flagged' in x)]
            kp = g[st.map(lambda x: f'{r}:kept' in x)]
            fb, fa = int((fl['decision'] == 'background').sum()), int((fl['decision'] == 'attack').sum())
            kb, ka = int((kp['decision'] == 'background').sum()), int((kp['decision'] == 'attack').sum())
            F, K = counts[cls][r]['flagged'], counts[cls][r]['kept']
            prec = fb / (fb + fa) if fb + fa else None
            kas = ka / (ka + kb) if ka + kb else None
            est = None
            if prec is not None and kas is not None and F * (1 - prec) + K * kas > 0:
                est = F * (1 - prec) / (F * (1 - prec) + K * kas)
                pool[r]['rem'] += F * (1 - prec)
                pool[r]['kept'] += K * kas
            d = {'flagged_flows': F, 'kept_flows': K,
                 'flagged_sampled': int(len(fl)), 'flagged_background': fb, 'flagged_attack': fa,
                 'flagged_unclear': int(len(fl) - fb - fa),
                 'precision_background': None if prec is None else round(prec, 4), 'precision_ci95': wilson(fb, fb + fa),
                 'kept_sampled': int(len(kp)), 'kept_attack': ka, 'kept_background': kb,
                 'kept_unclear': int(len(kp) - ka - kb),
                 'kept_attack_share': None if kas is None else round(kas, 4), 'kept_attack_share_ci95': wilson(ka, ka + kb),
                 'estimated_false_removal_rate': None if est is None else round(est, 4)}
            res['per_class'][cls][r] = d
            rows.append({'class': cls, 'rule': r, **{k: v for k, v in d.items() if not k.endswith('ci95')},
                         'precision_lo': (d['precision_ci95'] or [None, None])[0],
                         'precision_hi': (d['precision_ci95'] or [None, None])[1],
                         'kept_attack_lo': (d['kept_attack_share_ci95'] or [None, None])[0],
                         'kept_attack_hi': (d['kept_attack_share_ci95'] or [None, None])[1]})
    for r, p in pool.items():
        tot = p['rem'] + p['kept']
        res['pooled'][r] = {'estimated_attack_flows_removed': round(p['rem'], 1),
                            'estimated_attack_flows_kept': round(p['kept'], 1),
                            'estimated_false_removal_rate': round(p['rem'] / tot, 4) if tot else None}
    res['note'] = ('precision_background = share of sampled flagged flows judged background (unclear excluded); '
                   'kept_attack_share = share of sampled kept flows judged attack; estimated_false_removal_rate = '
                   'F(1-precision) / (F(1-precision) + K kept_attack_share) with the stratum sizes F, K of the class.')
    write_json(res, out / 'audit_scores.json')
    pd.DataFrame(rows).to_csv(out / 'audit_scores.csv', index=False)
    print(f'[audit] {res["decided"]}/{res["sampled"]} sampled flows decided; unrecognised: {bad}')
    for cls, d in res['per_class'].items():
        parts = []
        for r, v in d.items():
            pr = 'n/a' if v['precision_background'] is None else f"{v['precision_background']:.2f}"
            ka = 'n/a' if v['kept_attack_share'] is None else f"{v['kept_attack_share']:.2f}"
            parts.append(f'{r.split("_")[0]}: prec {pr} kept-attack {ka}')
        print(f'  {cls:11s} ' + '  '.join(parts))
    for r, p in res['pooled'].items():
        print(f'  pooled {r:15s} estimated false-removal rate {p["estimated_false_removal_rate"]}')
    print(f'[DONE] {out / "audit_scores.json"}')


# ----------------------------------------------------------------------------- self-test (synthetic arrays only)
def self_test():
    rng = np.random.default_rng(0)
    ipt = IPTable()
    # --- rule flags in code space == rule_validation.rule_flags on a synthetic frame
    ips = ['192.168.137.1', '192.168.137.65', '192.168.137.67', '8.8.8.8', '205.174.165.10', '52.1.2.3',
           '224.0.0.251', '192.168.137.255', 'fe80::1']
    m = 3000
    df = pd.DataFrame({'Src IP': rng.choice(ips, m), 'Dst IP': rng.choice(ips, m),
                       'Src Port': rng.choice([53, 123, 5353, 40000, 22, 80], m),
                       'Dst Port': rng.choice([53, 443, 1900, 22, 8080, 50000], m)})
    bdf = pd.DataFrame({'Src IP': rng.choice(ips, 200), 'Dst IP': rng.choice(ips, 200)})
    ipt.encode(bdf['Src IP']); ipt.encode(bdf['Dst IP'])
    bpairs = set(rv.pair_key(bdf['Src IP'], bdf['Dst IP']))
    bs, bd = ipt.encode(bdf['Src IP']), ipt.encode(bdf['Dst IP'])
    B = {'pairs': np.unique(pair_c(bs, bd))}
    a = {'src': ipt.encode(df['Src IP']), 'dst': ipt.encode(df['Dst IP']),
         'sp': df['Src Port'].to_numpy(np.int32), 'dp': df['Dst Port'].to_numpy(np.int32)}
    for sub in ('XSS', DNS_ATTACK):
        ref, _, _ = rv.rule_flags(df, sub, bpairs)
        r1, r2, r3 = rule_flags_codes(a, sub, ipt, B)
        assert (ref['R1_external'] == r1).all() and (ref['R2_service'] == r2).all(), sub
        assert (ref['R3_benign_pair'] == r3).all(), sub
    print('  [ok] R1/R2/R3 in code space == rule_validation.rule_flags (incl. DNS exception, IPv6, multicast)')

    # --- deterministic sampling key; bottom-k merge == bottom-k of the union
    k1 = row_keys(zlib.crc32(b'X/a.csv'), np.arange(5000, dtype=np.int32))
    assert (k1 == row_keys(zlib.crc32(b'X/a.csv'), np.arange(5000, dtype=np.int32))).all() and len(set(k1)) == 5000
    k2 = row_keys(zlib.crc32(b'X/b.csv'), np.arange(3000, dtype=np.int32))
    union = np.sort(np.concatenate([k1, k2]))[:SAMPLE_K]
    merged = np.sort(np.concatenate([np.sort(k1)[:SAMPLE_K], np.sort(k2)[:SAMPLE_K]]))[:SAMPLE_K]
    assert (union == merged).all() and (k1 >= 0).all()
    print('  [ok] hash keys deterministic, non-negative, unique; per-capture bottom-k merges exactly')

    # --- flood / scan signatures on a synthetic capture
    T = ipt
    att, vic, bot2, dev, gw = '192.168.137.182', '192.168.137.93', '192.168.137.30', '192.168.137.88', GATEWAY
    rows = []

    def add(s, d, sp, dp, pr, f, b, syn=0, ack=0, fb=0, n=1, dur=1e6):
        rows.extend([(s, d, sp, dp, pr, f, b, syn, ack, fb, dur)] * n)
    vic3 = '192.168.137.144'
    add(att, vic, 30000, 8008, TCP, 20, 0, syn=20, n=50)             # SYN flood
    add(att, vic, 30001, 8008, TCP, 3, 1, syn=3, ack=1, n=10)        # SYN flood, SYN-ACK back
    add(vic3, att, 49153, 50125, TCP, 1, 10, syn=10, ack=1, n=30)    # flipped: victim's SYN-ACK seen first
    add(vic3, att, 49153, 2699, TCP, 1, 1, syn=2, ack=1, n=5)        # tie flow (1/1): oriented to the victim
    add(dev, '52.1.2.3', 40000, 443, TCP, 10, 8, syn=1, ack=17, fb=900, n=30)   # normal TLS
    add(att, vic, 5555, 554, UDP, 500, 0, n=40)                      # UDP flood (500 packets/s)
    add(dev, vic, 6000, 7000, UDP, 16, 0, n=5, dur=116e6)            # slow one-way UDP: not a flood
    add(dev, gw, 5353, 53, UDP, 1, 1, n=20)                          # DNS
    add(att, gw, 5354, 53, UDP, 1, 1, n=4)                           # the attacker's own DNS (attacker_any only)
    add('8.6.0.1', '8.0.6.4', 0, 0, PROTO0, 5000, 0, n=1)            # ARP pseudo-flow (never a flood)
    add(bot2, vic, 0, 0, PROTO0, 50000, 20, n=5)                     # ICMP flood
    add(att, vic, 0, 0, PROTO0, 40000, 0, n=5)
    add(dev, vic, 0, 0, PROTO0, 3, 3, n=5)                           # small pings
    for i in range(25):                                              # Mirai telnet scan (Internet targets)
        add(bot2, f'45.{i}.1.1', 41000 + i, 23, TCP, 2, 1, syn=2, n=1)
    add(dev, '45.0.1.1', 42000, 23, TCP, 2, 1, syn=2, n=3)           # a few telnet flows: not a scanner
    vic2 = '192.168.137.94'
    for p in range(60):                                              # vertical scan of a second host
        add('192.168.137.178', vic2, 50000, 1000 + p, TCP, 1, 1, syn=1, ack=1, n=1)
    cols = ['s', 'd', 'sp', 'dp', 'pr', 'f', 'b', 'syn', 'ack', 'fb', 'dur']
    t = pd.DataFrame(rows, columns=cols)
    c = {'src': T.encode(t['s']), 'dst': T.encode(t['d']), 'sp': t['sp'].to_numpy(np.int32),
         'dp': t['dp'].to_numpy(np.int32), 'proto': t['pr'].to_numpy(np.int16),
         'fwd': t['f'].to_numpy(np.float32), 'bwd': t['b'].to_numpy(np.float32),
         'fbytes': t['fb'].to_numpy(np.float32), 'bbytes': np.zeros(len(t), np.float32),
         'syn': t['syn'].to_numpy(np.float32), 'ack': t['ack'].to_numpy(np.float32),
         'dur': t['dur'].to_numpy(np.float32), 'ts': np.arange(len(t), dtype=np.float64)}
    int_s, int_d = T.int_mask[c['src']], T.int_mask[c['dst']]
    pk = c['fwd'].astype(np.float64) + c['bwd']
    syn = identify('syn', c, T, int_s, int_d, pk)
    assert syn['victims'] == [vic, vic3] and syn['attackers'] == [att], syn['extra']
    assert int(syn['sig'].sum()) == 60 + 30 + 5, int(syn['sig'].sum())            # flipped and tie flows included
    assert syn['extra']['victim_level'] == 'host:port', syn['extra']
    assert sorted(syn['extra']['victim_endpoints']) == sorted([f'{vic}:8008', f'{vic3}:49153'])
    assert syn['extra']['predicate_flows_receiver_is_flow_source'] == 35
    udp = identify('udp', c, T, int_s, int_d, pk)
    assert udp['victims'] == [vic] and int(udp['sig'].sum()) == 40 and udp['attackers'] == [att], udp['extra']
    # burst pattern of the DoS UDP captures: 120 slow one-way flows (distinct source ports) to one endpoint that
    # start in the same second; 99 such flows are not enough
    tb = pd.DataFrame([(bot2, vic3, 30000 + i, 554, UDP, 20, 0, 0, 0, 0, 116e6) for i in range(120)]
                      + [(dev, vic2, 31000 + i, 555, UDP, 20, 0, 0, 0, 0, 116e6) for i in range(99)], columns=cols)
    cb = {'src': T.encode(tb['s']), 'dst': T.encode(tb['d']), 'sp': tb['sp'].to_numpy(np.int32),
          'dp': tb['dp'].to_numpy(np.int32), 'proto': tb['pr'].to_numpy(np.int16), 'fwd': tb['f'].to_numpy(np.float32),
          'bwd': tb['b'].to_numpy(np.float32), 'fbytes': np.zeros(len(tb), np.float32),
          'bbytes': np.zeros(len(tb), np.float32), 'syn': np.zeros(len(tb), np.float32),
          'ack': np.zeros(len(tb), np.float32), 'dur': tb['dur'].to_numpy(np.float32),
          'ts': np.full(len(tb), 1_660_000_000.0)}
    ub = identify('udp', cb, T, T.int_mask[cb['src']], T.int_mask[cb['dst']], cb['fwd'].astype(np.float64))
    assert ub['extra']['predicate_flows'] == 120 and ub['victims'] == [vic3] and ub['attackers'] == [bot2], ub['extra']
    p0 = identify('proto0flood', c, T, int_s, int_d, pk)
    assert p0['victims'] == [vic] and int(p0['sig'].sum()) == 10 and set(p0['attackers']) == {att, bot2}
    assert not (p0['sig'] & (t['s'] == '8.6.0.1').to_numpy()).any()
    assert int(p0['av'].sum()) == 10 + 50 + 10 + 40, int(p0['av'].sum())   # every flow between attackers and victim
    anyd = attacker_any(c, T, udp['av'], udp['attackers'])
    exp = udp['av'] | (t['s'] == att).to_numpy() | (t['d'] == att).to_numpy()
    assert (anyd == exp).all() and int(anyd.sum()) == 40 + 60 + 35 + 4 + 5, int(anyd.sum())
    ms = identify('mirai_scan', c, T, int_s, int_d, pk)
    assert ms['attackers'] == [bot2] and int(ms['sig'].sum()) == 25 and ms['extra']['signature_external_destination_share'] == 1.0
    rc = identify('recon', c, T, int_s, int_d, pk)
    assert rc['attackers'] == ['192.168.137.178'] and int(rc['sig'].sum()) == 60 and rc['victims'] == [vic2]
    ack = identify('ackfrag', c, T, int_s, int_d, pk)
    assert vic in ack['victims'] and not (ack['sig'] & (t['s'] == '8.6.0.1').to_numpy()).any()
    print('  [ok] syn (incl. flipped / tie flows, host:port victims) / udp (rate, endpoint burst) / proto0flood / mirai_scan / '
          'recon / ackfrag signatures and attacker_any on synthetic flows')

    # --- R1 audit: Benign endpoints, spoofed sources
    c['r1'], c['r2'], c['r3'] = rule_flags_codes(c, 'X', T, {'pairs': np.unique(pair_c(bs, bd))})
    flags = flags_of(c)
    Bf = {'addr_flows': np.bincount(T.encode(pd.Series(['52.1.2.3', dev])), minlength=len(T.names)),
          'ep': np.unique(ep_key(np.array([T.code('52.1.2.3')], np.int32), np.array([443], np.int32)))}
    audit, masks = r1_audit(c, T, Bf, flags, pk, int_s, int_d)
    n_tls = 30
    assert audit['external_address_in_benign']['flows'] == n_tls, audit['external_address_in_benign']
    assert audit['external_address_port_in_benign']['flows'] == n_tls
    assert audit['spoofed_source_check']['flows'] == 0          # the Internet hosts are destinations here
    c2 = {k: v.copy() for k, v in c.items()}
    c2['src'][:3] = T.encode(pd.Series(['99.1.1.1', '99.1.1.2', '99.1.1.3']))
    int_s2 = T.int_mask[c2['src']]
    c2['r1'] = ~(int_s2 & T.int_mask[c2['dst']])
    a2, _ = r1_audit(c2, T, Bf, flags_of(c2), pk, int_s2, T.int_mask[c2['dst']])
    assert a2['spoofed_source_check']['flows'] == 3, a2['spoofed_source_check']
    c3 = {k: v.copy() for k, v in c2.items()}           # single-flow IPv6 / link-local sources: not spoofing
    c3['src'][3:5] = T.encode(pd.Series(['fe80::abcd', '169.254.7.7']))
    c3['bwd'][3:5] = 0
    int_s3 = T.int_mask[c3['src']]
    c3['r1'] = ~(int_s3 & T.int_mask[c3['dst']])
    a3, _ = r1_audit(c3, T, Bf, flags_of(c3), pk, int_s3, T.int_mask[c3['dst']])
    assert a3['spoofed_source_check']['flows'] == 3, a3['spoofed_source_check']
    assert a3['spoofed_source_check']['excluded_non_routable_or_ipv6_flows'] == 2, a3['spoofed_source_check']
    print('  [ok] R1 audit: external endpoint in Benign (address, address+port) and spoofed-source check '
          '(routable IPv4 only)')

    # --- audit files: blind / full template round trip, header-driven parsing, scoring, overwrite protection
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        od = Path(td)
        rows = []
        for i in range(8):                  # class X: R1 flagged 0-3, kept 4-7
            fl = i < 4
            rows.append({'sample_id': f'XX-{i + 1:03d}', 'class': 'X', 'capture': 'X / Y',
                         'selected_strata': 'R1_external:flagged' if fl else 'R1_external:kept',
                         'audit_decision': '', 'audit_evidence': '', 'audit_notes': '', 'Flow ID': 'f',
                         'Src IP': '192.168.137.5', 'Src Port': 1000 + i, 'Dst IP': '8.8.8.8' if fl else '192.168.137.6',
                         'Dst Port': 443, 'Protocol': 6, 'Timestamp': f'01/01/2023 10:00:0{i} AM',
                         'R1_external': fl, 'R2_service': False, 'R3_benign_pair': False, 'any': fl,
                         'signature': False, 'attack_related': not fl, 'attacker_any': False,
                         'Flow Duration': 1e6, 'Total Fwd Packet': 2, 'Total Bwd packets': 1,
                         'Total Length of Fwd Packet': 10, 'Total Length of Bwd Packet': 0})
        sm = pd.DataFrame(rows)
        cnt = {'X': {r: {'flagged': 100, 'kept': 300} for r in RULES}}
        Pp = audit_paths(od)
        sm.to_csv(Pp['audit_sample.csv'], index=False)
        write_json(cnt, Pp['audit_strata_counts.json'])
        write_template(sm, Pp['audit_template.md'], cnt)
        write_template(sm, Pp['audit_template_blind.md'], cnt, blind=True)
        dec = ['background', 'background', 'b', 'attack', 'attack', 'background', 'bg', 'unclear']
        for name in ('audit_template_blind.md', 'audit_template.md'):
            lines = (od / name).read_text(encoding='utf-8').split('\n')
            for j, ln in enumerate(lines):
                m = re.match(r'\| (XX-\d{3}) \|', ln)
                if m:
                    k = int(m.group(1)[3:]) - 1
                    lines[j] = ln[:-len('|  |  |')] + f'| {dec[k]} | ev {k} |'
            (od / name).write_text('\n'.join(lines), encoding='utf-8')
            assert [read_decisions(od / name)[f'XX-{k + 1:03d}'][0] for k in range(8)] == dec, name
            score_audit(od / name, od)
            sc = json.load(open(od / 'audit_scores.json', encoding='utf-8'))['per_class']['X']['R1_external']
            assert sc['flagged_background'] == 3 and sc['flagged_attack'] == 1 and sc['precision_background'] == 0.75
            assert sc['kept_attack'] == 1 and sc['kept_background'] == 2 and sc['kept_unclear'] == 1, sc
            assert sc['estimated_false_removal_rate'] == round(25 / (25 + 100), 4), sc
        Pq = audit_paths(od)                 # filled -> the regenerated set never overwrites the audit
        assert all('.regenerated' in p.name for p in Pq.values()), Pq
        bad = od / 'audit_template.md'
        bad.write_text(bad.read_text(encoding='utf-8').replace('01/01/2023 10:00:00 AM', '02/01/2023 10:00:00 AM'),
                       encoding='utf-8')
        try:
            score_audit(bad, od)
            raise AssertionError('a template of another sample must be rejected')
        except SystemExit:
            pass
    print('  [ok] audit templates (full and blind) parsed by header, scored (precision, kept-attack share, '
          'false-removal estimate); filled audit files are not overwritten; foreign template rejected')

    # --- cover_w and wilson
    assert cover_w(np.array([1, 1, 1, 2, 3], np.int32)) == ([1, 2], 0.8)
    assert cover_w(np.array([1, 2], np.int32), np.array([9.0, 1.0]))[0] == [1]
    assert cover_w(np.array([], np.int32)) == ([], None)
    assert wilson(0, 20)[0] == 0.0 and wilson(20, 20)[1] == 1.0
    print('[self-test] all checks passed')


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[3])
    ap.add_argument('--only', nargs='*', default=None, help='process only captures whose name contains one of these')
    ap.add_argument('--force', action='store_true', help='recompute captures whose JSON exists')
    ap.add_argument('--max-captures', type=int, default=None, help='stop after N processed captures')
    ap.add_argument('--merge', action='store_true', help='only (re)build the merged outputs (missing captures allowed)')
    ap.add_argument('--score-audit', default=None, help='filled audit_template.md or audit_sample.csv')
    ap.add_argument('--out', default=str(OUT_DEFAULT), help='output folder')
    ap.add_argument('--max-rows', type=int, default=None, help='TEST ONLY: read at most N rows per CSV file')
    ap.add_argument('--self-test', action='store_true', help='synthetic checks, no data read')
    a = ap.parse_args()
    out = Path(a.out)
    if a.self_test:
        return self_test()
    if a.score_audit:
        return score_audit(Path(a.score_audit), out)
    caps = discover()
    if a.merge:
        return merge(out, caps, partial=True, max_rows=a.max_rows)
    (out / 'captures').mkdir(parents=True, exist_ok=True)
    sel = [x for x in caps if not a.only or any(o.lower() in x['name'].lower() for o in a.only)]
    done = {x['name']: load_entry(out, x['name']) for x in sel}
    stale = [n for n, e in done.items() if e is not None and e.get('max_rows') != a.max_rows]
    if stale:          # a JSON of a --max-rows test run (or a full run, when testing) is recomputed, never reused
        print(f'[plan] {len(stale)} capture JSON(s) were made with another --max-rows and are recomputed: {stale}',
              flush=True)
    todo = [x for x in sel if a.force or done[x['name']] is None or x['name'] in stale]
    print(f'[plan] {len(caps)} attack captures, {len(sel) - len(todo)} done, {len(todo)} to do'
          + (f' (max {a.max_captures} now)' if a.max_captures else '')
          + (f'  [TEST RUN: --max-rows {a.max_rows}]' if a.max_rows else ''), flush=True)
    if a.max_captures is not None:
        todo = todo[:a.max_captures]
    if todo:
        t0 = time.time()
        ipt = IPTable()
        print('[1] Benign captures: R3 pair set, endpoint sets, signature baselines', flush=True)
        bc, B = load_benign(ipt, a.max_rows)
        kinds = sorted({k for x in caps for k in x['kinds']}, key=lambda k: (OLD_KINDS + NEW_KINDS).index(k))
        baseline = benign_baseline(bc, ipt, B, kinds)
        baseline['max_rows_per_file'] = a.max_rows          # None = every row
        write_json(baseline, out / 'benign_baseline.json')
        del bc
        gc.collect()
        print(f'    {B["flows"]:,} Benign flows, {len(B["pairs"]):,} IP pairs ({time.time() - t0:.0f} s)', flush=True)
        for k in kinds:
            b = baseline[k]
            print(f'    baseline {k:11s} signature {b["signature_flows"]:>7,} flows ({_pct(b["signature_share"])})'
                  f'  would-be attackers {b["would_be_attackers"][:4]}', flush=True)
        for i, cap in enumerate(todo, 1):
            print(f'[{i}/{len(todo)}] {cap["name"]}  kinds={cap["kinds"]}  {len(cap["files"])} file(s), '
                  f'{cap["bytes"] / 1e6:,.0f} MB', flush=True)
            process_capture(cap, ipt, B, baseline, out, a)
    merge(out, caps, partial=False, max_rows=a.max_rows)


if __name__ == '__main__':
    main()
