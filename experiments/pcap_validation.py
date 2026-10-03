# -*- coding: utf-8 -*-
"""
pcap_validation.py
==================
Packet-level (MAC-address) validation of the background rules R1-R3 (reviewer points meth-02 and nove-03).
The flow CSVs of CIC IoT-DIAD 2024 carry no attacker labels; the packet release (pcap files) carries the
Ethernet MAC address of every frame, so the attacking DEVICE can be identified independently of IP
addresses, and every CICFlowMeter flow of the capture can be labelled as attacker-involved or not. R1, R2,
R3 and any = R1|R2|R3 (exactly as flagged_loader.py / rule_validation2.py) are scored against that label.
Flow-level companion: experiments/rule_validation2.py (signatures, R1 audit, manual-audit sample).

Input: a folder with the pcap/pcapng files of ONE capture (BruteForce, a Web-Based sub-attack, DNS Spoofing,
ARP Spoofing, ...) and the flow CSVs of that capture: --capture picks them from data/CIC IoT-DIAD 2024
(restricted to <pcap name>_Flow.csv when every pcap has one, e.g. BruteForce.pcap ->
BruteForce/BruteForce.pcap_Flow.csv); --csv gives them explicitly; without both, <pcap name>_Flow.csv is
searched under the data folder.

Steps
 1 Packets. Every frame is decoded (Ethernet II incl. 802.1Q, Linux cooked SLL/SLL2, raw IP; IPv4, IPv6,
   TCP, UDP, ARP) into a compact table: time (us), flow key, source/destination MAC, source/destination IP,
   signature code. The flow key follows CICFlowMeter: unordered 5-tuple; TCP (6) and UDP (17) with ports,
   every other IP protocol (ICMP, GRE, IGMP) and non-first fragments as protocol 0 without ports; non-IP
   Ethernet frames as the pseudo-flow of frame bytes 12-19 read as IPv4 addresses (ARP -> 8.6.0.1 <->
   8.0.6.4, the pseudo-addresses found in the flow CSVs).
 2 Time offset. CICFlowMeter prints the flow start in local time to the second; the offset to pcap time
   (UTC) is the most frequent difference, rounded to 15 min, between the CSV start of a 5-tuple that has
   exactly one CSV flow and the first packet of that 5-tuple (--tz-offset-hours overrides). Agreement =
   share of these 5-tuples whose CSV start is the floor of (first packet + offset).
 3 Packet -> flow. A packet belongs to a CSV flow with its key whose window [start, start + 1 s + Flow
   Duration + 2 ms] contains it; if several flows of the key qualify (120 s timeout, FIN split), packets
   go in time order to the earliest flow whose packet count (Total Fwd Packet + Total Bwd packets) is not
   yet reached. Exact duplicate CSV rows share their packets. Reported: matched flows, flows with exactly
   their packet count, unmatched packets by frame type.
 4 Attacker MAC (documented rule; --attacker-mac / --attacker-ip override it). Attackers = the smallest
   set of source MACs (<= 5) that originates >= 80 % of the attack-signature frames (>= 3 frames needed):
     bruteforce  TCP frames sent to port 22 or 23 (client side of SSH/Telnet sessions; the port-22 flows of
                 the BruteForce flow CSV carry no SYN flag, so SYNs are not required)
     web         TCP payload towards port 80/8080 (or starting with an HTTP method) matching the pattern of
                 the sub-attack (sqli: UNION SELECT, OR 1=1, information_schema, sleep(, %27 ...; xss:
                 <script, javascript:, onerror=, alert( ...; upload: multipart/form-data, form-data
                 filename=); fallback if fewer than 3 such frames: TCP frames sent to port 80/8080
     dns         DNS responses (UDP source port 53, QR = 1) that carry the gateway's or an Internet
                 resolver's IP but were sent from a MAC other than the gateway MAC (MAC-level
                 impersonation: forged, or relayed by a man in the middle), or that come from a testbed
                 host other than the gateway (rogue responder)
     arp         ARP frames that bind an IP address also claimed by another MAC, sent by a MAC that binds
                 >= 2 distinct IP addresses (poisoning replies / gratuitous ARP)
   Gateway MAC = most frequent source MAC of frames with an Internet source IP (--gateway-mac overrides);
   it is never an attacker for bruteforce/web/dns. It is checked against the sender of the ARP requests
   for 192.168.137.1 (roles.gateway_arp_request_sender_agrees; a warning is printed if they differ).
   Owner of an IP = the sender MAC of its ARP requests, else the most frequent source MAC of its IP
   packets; an attacker MAC owns only addresses that no other MAC sends (ARP requests or IP packets), so
   a forged or relayed address (gateway, victims) never becomes an attacker IP. Attacker IPs = testbed IPs owned by an
   attacker MAC. Victims = destination IPs of >= 80 % of the signature frames (<= 10; dns <= 50); arp:
   the poisoned targets and the impersonated addresses.
 5 Flow labels (flows with >= 1 matched packet; the others are reported, not scored)
     attacker_involved  >= 1 packet with an attacker MAC as Ethernet source or destination     <- main
     attacker_victim    attacker_involved and an endpoint is a victim IP
     attacker_endpoint  Src IP or Dst IP is an attacker IP
     signature_flow     contains an attack-signature frame
     relayed            attacker_involved without an attacker-IP endpoint (MITM relay, ARP pseudo-flow)
 6 Scores for R1, R2, R3, any per truth definition: precision_background (flagged and not attacker /
   flagged), recall_background (flagged and not attacker / not attacker), false_removal_rate (attacker
   flows flagged / attacker flows), kept_attack_share (attacker flows among the kept flows), flow counts
   and packet-weighted (CSV packets), Wilson 95 % CIs. R3 uses the IP pairs of ALL Benign flow CSVs and
   DNS Spoofing keeps the DNS exception of R2. Also: the flow-level heuristic of rule_validation2.py
   (signature / attacker_victim) scored against the MAC label, the R1-flagged attacker flows (relayed vs
   attacker endpoint, external addresses), and the MAC labels of this capture's flows in
   rule_validation2/audit_sample.csv (pcap evidence for the manual audit).
Outputs: results_2026_03_03/q1_revision/pcap_validation/<capture>/
  pcap_validation.json   mapping quality, time offset, MAC roles, label counts, scores, assumptions
  flow_labels.csv.gz     one row per CSV flow: file, row, identifiers, packet counts, labels, rule flags
  flow_labels.npz        the same as compact arrays
  audit_sample_mac.csv   the audit-sample flows of this capture with their MAC labels (if the sample exists)
  parsed/<pcap>.npz/.json  per-file packet tables (cache: an interrupted run resumes without re-parsing)
Resumable: skipped when pcap_validation.json exists with the same settings (run_key: kind, overrides, max rows /
packets, file names); a run with other settings (e.g. a --max-packets test, or a run that stopped with
no_attacker_identified and is repeated with --attacker-ip) is recomputed. --force recomputes, --no-cache
re-parses the pcaps.
No model is trained (--max-fits does not apply).
Requirements: pip install dpkt   (pcap/pcapng reader; scapy and dpkt were not installed in the MyProject env
  when this was written - without dpkt a built-in reader for classic pcap (us/ns) and pcapng is used).
  Frames are decoded with struct in both cases (no per-packet dissection objects). Pure Python: roughly
  0.2-0.4 M frames/s (see the benchmark line of --self-test) and ~30 bytes of RAM per packet, meant for
  the small captures (BruteForce, Web-Based, Spoofing); a flood capture of 10^8 packets needs ~3 GB.
Run (PowerShell, from the project root; the pcap folders are where the packet release was unpacked):
  $py = "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe"
  & $py experiments\\pcap_validation.py --self-test 2>&1 | Tee-Object -FilePath pcap_validation.log
  & $py experiments\\pcap_validation.py --pcap-dir "D:\\CIC-IoT-DIAD-2024-pcap\\BruteForce" --capture BruteForce 2>&1 | Tee-Object -FilePath pcap_validation.log -Append
  & $py experiments\\pcap_validation.py --pcap-dir "D:\\CIC-IoT-DIAD-2024-pcap\\SqlInjection" --capture Sqlinjection 2>&1 | Tee-Object -FilePath pcap_validation.log -Append
  & $py experiments\\pcap_validation.py --pcap-dir "D:\\CIC-IoT-DIAD-2024-pcap\\DNS_Spoofing" --capture "DNS Spoofing" 2>&1 | Tee-Object -FilePath pcap_validation.log -Append
  & $py experiments\\pcap_validation.py --pcap-dir "D:\\CIC-IoT-DIAD-2024-pcap\\ARP_Spoofing" --capture "ARP Spoofing" 2>&1 | Tee-Object -FilePath pcap_validation.log -Append
  # other captures: give the attacker yourself, e.g. --capture "DOS SYN" --attacker-ip 192.168.137.182
"""
import argparse, gc, hashlib, ipaddress, json, os, re, struct, sys, tempfile, time
from array import array
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import DATA, TS_FMT  # noqa: E402
from relabel_background import internal  # noqa: E402
import rule_validation as rv  # noqa: E402
import rule_validation2 as rv2  # noqa: E402

try:
    import dpkt  # noqa: F401
    HAVE_DPKT = True
except ImportError:
    HAVE_DPKT = False

sys.stdout.reconfigure(encoding='utf-8')
OUT_DEFAULT = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'pcap_validation'
AUDIT_SAMPLE = rv2.OUT_DEFAULT / 'audit_sample.csv'
VERSION = 1
TCP, UDP, PROTO0 = 6, 17, 0
GATEWAY = rv.GATEWAY
ET_IP4, ET_IP6, ET_ARP = 0x0800, 0x86DD, 0x0806
VLAN_ET = (0x8100, 0x88A8, 0x9100)
PCAPNG_SHB = b'\x0a\x0d\x0d\x0a'
PCAP_MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', False), b'\xa1\xb2\xc3\xd4': ('>', False),
              b'\x4d\x3c\xb2\xa1': ('<', True), b'\xa1\xb2\x3c\x4d': ('>', True)}
CAT_NAMES = ('ipv4', 'ipv6', 'arp', 'other_non_ip', 'undecoded')
SIG_NAMES = {0: 'none', 1: 'tcp_to_22_23', 2: 'tcp_to_80_8080', 3: 'http_attack_payload', 4: 'dns_response',
             5: 'arp', 6: 'dns_query'}
HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'OPTIONS ', b'PATCH ')
BF_PORTS, WEB_PORTS = (22, 23), (80, 8080)
_S = rb'(\s|\+|%20|/\*\*/)'
WEB_PATTERNS = {
    'sqli': rb'(?i)(union' + _S + rb'+(all' + _S + rb'+)?select|select' + _S + rb'[^&\r\n]{0,200}?' + _S + rb'from'
            + rb'|information_schema|sleep(\(|%28)|benchmark(\(|%28)|%27|\'' + _S + rb'*(or|and)' + _S
            + rb'|(or|and)' + _S + rb'+\d+(=|%3d)\d+|;' + _S + rb'*drop' + _S + rb')',
    'xss': rb'(?i)(<script|%3cscript|javascript(:|%3a)|onerror(\s|%20)*(=|%3d)|onload(\s|%20)*(=|%3d)|onmouseover'
           rb'|alert(\(|%28)|prompt(\(|%28)|document\.cookie|<svg|%3csvg|<img[^>]{0,100}src|%3cimg|<iframe|%3ciframe)',
    'upload': rb'(?i)(multipart/form-data|content-disposition:\s*form-data[^\r\n]{0,200}filename=)',
}
KINDS = ('bruteforce', 'web', 'dns', 'arp', 'manual')
TOL_US = 2000                   # window tolerance (Flow Duration is stored as float32 microseconds)
TZ_STEP = 900                   # time-zone offsets are multiples of 15 min
COVER = rv.COVER                # 80 % of the signature frames
ATT_MAC_CAP, VIC_CAP, VIC_CAP_DNS = 5, 10, 50
MIN_SIG = 3                     # fewer signature frames -> attacker not identified
RULES = rv.RULES
TRUTHS = ('attacker_involved', 'attacker_victim', 'attacker_endpoint', 'signature_flow')
_r, _pct, wilson, write_json = rv._r, rv._pct, rv2.wilson, rv2.write_json
ASSUMPTIONS = [
    'Ground truth is MAC-level attacker involvement: a flow is attack-related when at least one of its packets '
    'has an attacker MAC as Ethernet source or destination. It includes the attacker device\'s own background '
    'traffic (e.g. its DNS or NTP) and victim traffic relayed by a man-in-the-middle attacker; attacker_victim '
    'and attacker_endpoint are narrower definitions.',
    'The attacker MAC is derived from attack-signature frames (rule in the docstring and in "attacker_rule"); '
    'the pcap release carries MAC addresses but no attack labels, so the rule is heuristic, but it does not use '
    'R1-R3 or IP-address ranges.',
    'Packets are mapped to CICFlowMeter flows by unordered 5-tuple (protocol 0 without ports for non-TCP/UDP, '
    'pseudo-addresses from frame bytes 12-19 for non-IP frames) and time window; the time-zone offset is '
    'estimated from the data. Flows without a matched packet are not scored.',
    'Rules are recomputed exactly as in flagged_loader.py on the raw flows of the capture (before de-duplication '
    'and caps): R1 external endpoint, R2 service ports (DNS exception for DNS Spoofing), R3 IP pair in Benign '
    '(all Benign flow CSVs).',
    'precision_background treats the rule as a detector of background (non-attacker) flows; false_removal_rate '
    '= share of attacker flows the rule removes; kept_attack_share = attacker share of the flows kept.',
]


# ----------------------------------------------------------------------------- small helpers
def mac_str(b):
    return ':'.join(f'{x:02x}' for x in b)


def norm_mac(s):
    h = re.sub(r'[^0-9a-fA-F]', '', s).lower()
    if len(h) != 12:
        raise SystemExit(f'not a MAC address: {s}')
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2))


def canon_ip(name):
    """(packed bytes, canonical text) of an address string; (None, text) if unparseable."""
    s = str(name).strip().split('%')[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None, s
    return a.packed, str(a)


def cover_codes(values, cap, weights=None):
    v = values[values >= 0]
    if weights is not None:
        weights = weights[values >= 0]
    return rv2.cover_w(v.astype(np.int64), weights, cap=cap)


def top_codes(names, values, n=10):
    v = values[values >= 0]
    if not len(v):
        return []
    cnt = np.bincount(v)
    order = np.argsort(-cnt, kind='stable')[:n]
    return [{'value': names[k], 'frames': int(cnt[k]), 'share': _r(cnt[k], len(v))} for k in order if cnt[k] > 0]


# ----------------------------------------------------------------------------- pcap / pcapng readers
def _pcapng_idb(body, e):
    """Link type, time units per second and offset (s) of an Interface Description Block body."""
    lt = struct.unpack_from(e + 'H', body, 0)[0]
    ups, off, p = 1_000_000, 0, 8
    while p + 4 <= len(body) - 4:
        code, ln = struct.unpack_from(e + 'HH', body, p)
        if code == 0:
            break
        val = body[p + 4:p + 4 + ln]
        if code == 9 and ln >= 1:                                   # if_tsresol
            v = val[0]
            ups = 10 ** (v & 0x7F) if not v & 0x80 else 2 ** (v & 0x7F)
        elif code == 14 and ln == 8:                                # if_tsoffset (seconds)
            off = struct.unpack(e + 'q', val)[0]
        p += 4 + ln + (-ln % 4)
    return lt, ups, off


def _iter_builtin(fh, head, stats):
    if head == PCAPNG_SHB:
        fh.seek(0)
        e, ifaces = '<', []
        while True:
            h = fh.read(8)
            if len(h) < 8:
                break
            if h[:4] == PCAPNG_SHB:                                 # Section Header Block: byte order
                bom = fh.read(4)
                e = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
                blen = struct.unpack(e + 'I', h[4:8])[0]
                fh.read(blen - 12)
                ifaces = []
                continue
            btype, blen = struct.unpack(e + 'II', h)
            body = fh.read(blen - 8)
            if len(body) < blen - 8:
                stats['truncated'] = True
                break
            if btype == 1:
                ifaces.append(_pcapng_idb(body, e))
            elif btype in (6, 2):                                   # Enhanced / obsolete Packet Block
                if btype == 6:
                    ifid, tsh, tsl, caplen = struct.unpack_from(e + 'IIII', body, 0)
                else:
                    ifid, _, tsh, tsl, caplen = struct.unpack_from(e + 'HHIII', body, 0)
                lt, ups, toff = ifaces[ifid]
                yield ((tsh << 32) | tsl) * 1_000_000 // ups + toff * 1_000_000, lt, body[20:20 + caplen]
            elif btype == 3:
                stats['frames_without_timestamp'] = stats.get('frames_without_timestamp', 0) + 1
        return
    e, nano = PCAP_MAGIC[head]
    hdr = head + fh.read(20)
    lt = struct.unpack(e + 'I', hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(e + 'IIII')
    while True:
        h = fh.read(16)
        if len(h) < 16:
            break
        sec, frac, incl, _ = rec.unpack(h)
        buf = fh.read(incl)
        if len(buf) < incl:
            stats['truncated'] = True
            break
        yield sec * 1_000_000 + (frac // 1000 if nano else frac), lt, buf


def _iter_dpkt(fh, head, stats):
    import dpkt as _d
    fh.seek(0)
    rd = _d.pcapng.Reader(fh) if head == PCAPNG_SHB else _d.pcap.Reader(fh)
    lt = rd.datalink()
    it = iter(rd)
    while True:
        try:
            ts, buf = next(it)
        except StopIteration:
            break
        except (ValueError, struct.error, _d.dpkt.NeedData, _d.dpkt.UnpackError):
            stats['truncated'] = True
            break
        yield int(round(float(ts) * 1e6)), lt, bytes(buf)


def iter_frames(path, backend='auto', stats=None, max_packets=None):
    """(time in microseconds since the epoch, link type, frame bytes) for every frame of a pcap/pcapng file."""
    stats = {} if stats is None else stats
    use_dpkt = backend == 'dpkt' or (backend == 'auto' and HAVE_DPKT)
    stats['backend'] = 'dpkt' if use_dpkt else 'builtin'
    with open(path, 'rb', buffering=1 << 20) as fh:
        head = fh.read(4)
        if head != PCAPNG_SHB and head not in PCAP_MAGIC:
            raise ValueError(f'{path}: not a pcap/pcapng file (magic {head.hex()})')
        it = _iter_dpkt(fh, head, stats) if use_dpkt else _iter_builtin(fh, head, stats)
        for i, x in enumerate(it):
            if max_packets is not None and i >= max_packets:
                stats['max_packets_reached'] = True
                break
            yield x


# ----------------------------------------------------------------------------- frame decoding
def _l2_other(buf, lt):
    """(src MAC, dst MAC, ethertype, L3 offset) for Linux cooked capture and raw IP; None otherwise."""
    L = len(buf)
    if lt == 113 and L >= 16:                                       # SLL: pkttype hatype halen addr[8] proto
        hl = min((buf[4] << 8) | buf[5], 8)
        return buf[6:6 + hl], None, (buf[14] << 8) | buf[15], 16
    if lt == 276 and L >= 20:                                       # SLL2: proto res ifindex hatype pkttype halen addr[8]
        return buf[12:12 + min(buf[11], 8)], None, (buf[0] << 8) | buf[1], 20
    if lt in (101, 12, 14, 228, 229) and L:                         # raw IP
        v = buf[0] >> 4
        return None, None, ET_IP4 if v == 4 else ET_IP6 if v == 6 else -1, 0
    return None


def _ip6(buf, off, L):
    nh = buf[off + 6]
    plen = (buf[off + 4] << 8) | buf[off + 5]
    end = min(L, off + 40 + plen) if plen else L
    p, frag = off + 40, 0
    for _ in range(8):                                              # extension headers
        if nh in (0, 43, 60) and p + 2 <= L:
            nh, p = buf[p], p + (buf[p + 1] + 1) * 8
        elif nh == 51 and p + 2 <= L:
            nh, p = buf[p], p + (buf[p + 1] + 2) * 4
        elif nh == 44 and p + 8 <= L:
            frag = ((buf[p + 2] << 8) | buf[p + 3]) >> 3
            nh, p = buf[p], p + 8
        else:
            break
    return buf[off + 8:off + 24], buf[off + 24:off + 40], nh, frag, p, end


def parse_file(path, keys, kind, web_re, backend='auto', max_packets=None):
    """Decode every frame of one file into typed arrays (see step 1 of the docstring)."""
    T, K, SM, DM, SI, DI = array('q'), array('i'), array('i'), array('i'), array('i'), array('i')
    SG, CT = array('b'), array('b')
    assert K.itemsize == 4 and T.itemsize == 8
    macs, ips, arp, dns = {}, {}, [], []
    stats, cats, unm = {}, Counter(), Counter()
    kget = keys.get
    want_bf, want_web, want_dns, want_arp = kind == 'bruteforce', kind == 'web', kind == 'dns', kind == 'arp'
    t_start, n = time.time(), 0
    for ts, lt, buf in iter_frames(path, backend, stats, max_packets):
        L = len(buf)
        smac = dmac = src = dst = None
        et, off, sp, dp, pc, sig, cat = -1, 0, 0, 0, 0, 0, 4
        if lt == 1:
            if L >= 14:
                dmac, smac = buf[0:6], buf[6:12]
                et, off = (buf[12] << 8) | buf[13], 14
                while et in VLAN_ET and L >= off + 4:
                    et, off = (buf[off + 2] << 8) | buf[off + 3], off + 4
        else:
            r = _l2_other(buf, lt)
            if r is not None:
                smac, dmac, et, off = r
        pr = frag = l4 = end = -1
        if et == ET_IP4 and L >= off + 20:
            cat = 0
            ihl = (buf[off] & 15) * 4
            pr = buf[off + 9]
            frag = ((buf[off + 6] & 0x1F) << 8) | buf[off + 7]
            tot = (buf[off + 2] << 8) | buf[off + 3]
            end = off + tot if ihl <= tot and off + tot <= L else L
            src, dst, l4 = buf[off + 12:off + 16], buf[off + 16:off + 20], off + ihl
        elif et == ET_IP6 and L >= off + 40:
            cat = 1
            src, dst, pr, frag, l4, end = _ip6(buf, off, L)
        elif et >= 0 and et != ET_IP4 and et != ET_IP6:
            cat = 2 if et == ET_ARP else 3
            if lt == 1 and L >= 20:                                 # CICFlowMeter pseudo-flow of a non-IP frame
                src, dst = buf[12:16], buf[16:20]
            if et == ET_ARP and L >= off + 28 and buf[off + 4] == 6 and buf[off + 5] == 4:
                arp.append((n, (buf[off + 6] << 8) | buf[off + 7],
                            macs.setdefault(buf[off + 8:off + 14], len(macs)),
                            ips.setdefault(buf[off + 14:off + 18], len(ips)),
                            macs.setdefault(buf[off + 18:off + 24], len(macs)),
                            ips.setdefault(buf[off + 24:off + 28], len(ips))))
                if want_arp:
                    sig = 5
        if cat <= 1:
            if pr == 6 and frag == 0 and end >= l4 + 20:
                pc = 6
                sp, dp = (buf[l4] << 8) | buf[l4 + 1], (buf[l4 + 2] << 8) | buf[l4 + 3]
                if want_bf:
                    if dp in BF_PORTS and sp not in BF_PORTS:
                        sig = 1
                elif want_web:
                    ps = l4 + (buf[l4 + 12] >> 4) * 4
                    if (ps < end and (dp in WEB_PORTS or buf[ps:ps + 8].startswith(HTTP_METHODS))
                            and web_re is not None and web_re.search(buf, ps, min(end, ps + 8192))):
                        sig = 3
                    elif dp in WEB_PORTS and sp not in WEB_PORTS:
                        sig = 2
            elif pr == 17 and frag == 0 and end >= l4 + 8:
                pc = 17
                sp, dp = (buf[l4] << 8) | buf[l4 + 1], (buf[l4 + 2] << 8) | buf[l4 + 3]
                if want_dns and (sp == 53 or dp == 53) and end >= l4 + 20:
                    q = l4 + 8
                    did, qr = (buf[q] << 8) | buf[q + 1], buf[q + 2] >> 7
                    if sp == 53 and qr:
                        sig = 4
                        dns.append((n, did, 1, dp))
                    elif dp == 53 and not qr:
                        sig = 6
                        dns.append((n, did, 0, sp))
        k = -1
        if src is not None:
            k = kget((pc, src, sp, dst, dp) if (src, sp) <= (dst, dp) else (pc, dst, dp, src, sp), -1)
            if k < 0:
                unm[f'{CAT_NAMES[cat]}/{pc}'] += 1
        T.append(ts)
        K.append(k)
        SM.append(-1 if smac is None else macs.setdefault(smac, len(macs)))
        DM.append(-1 if dmac is None else macs.setdefault(dmac, len(macs)))
        SI.append(ips.setdefault(src, len(ips)) if cat <= 1 else -1)
        DI.append(ips.setdefault(dst, len(ips)) if cat <= 1 else -1)
        SG.append(sig)
        CT.append(cat)
        cats[cat] += 1
        n += 1
        if n % 2_000_000 == 0:
            print(f'      {path.name}: {n:,} frames ({n / (time.time() - t_start):,.0f}/s)', flush=True)
    arrays = {'t': np.frombuffer(T, np.int64).copy(), 'key': np.frombuffer(K, np.int32).copy(),
              'smac': np.frombuffer(SM, np.int32).copy(), 'dmac': np.frombuffer(DM, np.int32).copy(),
              'sip': np.frombuffer(SI, np.int32).copy(), 'dip': np.frombuffer(DI, np.int32).copy(),
              'sig': np.frombuffer(SG, np.int8).copy(), 'cat': np.frombuffer(CT, np.int8).copy(),
              'arp': np.array(arp, np.int64).reshape(-1, 6), 'dns': np.array(dns, np.int64).reshape(-1, 4)}
    meta = {'file': path.name, 'frames': n, 'seconds': round(time.time() - t_start, 1),
            'frames_per_second': round(n / max(time.time() - t_start, 1e-3)),
            'macs': [mac_str(m) for m, _ in sorted(macs.items(), key=lambda x: x[1])],
            'ips': [canon_ip_bytes(b) for b, _ in sorted(ips.items(), key=lambda x: x[1])],
            'by_category': {CAT_NAMES[c]: int(v) for c, v in sorted(cats.items())},
            'unmatched_by_type': dict(unm.most_common()), 'reader': stats}
    return arrays, meta


def canon_ip_bytes(b):
    try:
        return str(ipaddress.ip_address(bytes(b)))
    except ValueError:
        return bytes(b).hex()


# ----------------------------------------------------------------------------- CSV flows
def flow_keys(c, ipt):
    """Key code per CSV flow (-1 if an address is unparseable) and the key dict {tuple: code}."""
    packed = [canon_ip(x)[0] for x in ipt.names]
    keys, out = {}, []
    src, dst = c['src'].tolist(), c['dst'].tolist()
    sp, dp, pr = c['sp'].tolist(), c['dp'].tolist(), c['proto'].tolist()
    for i in range(len(src)):
        a, b = packed[src[i]], packed[dst[i]]
        if a is None or b is None:
            out.append(-1)
            continue
        p = pr[i]
        if p == 6 or p == 17:
            x, y = sp[i], dp[i]
        else:
            p, x, y = 0, 0, 0
        k = (p, a, x, b, y) if (a, x) <= (b, y) else (p, b, y, a, x)
        out.append(keys.setdefault(k, len(keys)))
    return np.asarray(out, np.int64), keys


def estimate_offset(P, fkey, fts, n_keys, override_h=None):
    """Local-time offset (s) of the CSV timestamps relative to the pcap (UTC) time."""
    ok = P['key'] >= 0
    first = np.full(n_keys, np.iinfo(np.int64).max, np.int64)
    if ok.any():
        g = pd.Series(P['t'][ok]).groupby(P['key'][ok]).min()
        first[g.index.to_numpy()] = g.to_numpy()
    valid = (fkey >= 0) & np.isfinite(fts)
    cnt = np.bincount(fkey[valid], minlength=n_keys)
    fk = np.where(valid, fkey, 0)
    one = valid & (cnt[fk] == 1) & (first[fk] < np.iinfo(np.int64).max)
    delta = fts[one] - first[fk[one]] / 1e6
    info = {'keys_used': int(one.sum())}
    if override_h is not None:
        off = float(override_h) * 3600.0
        info['source'] = 'override (--tz-offset-hours)'
    elif len(delta):
        q = np.round((delta + 0.5) / TZ_STEP) * TZ_STEP
        vals, cnts = np.unique(q, return_counts=True)
        off = float(vals[np.argmax(cnts)])
        info.update({'source': 'estimated', 'mode_share': _r(cnts.max(), cnts.sum()),
                     'runner_up_offsets_h': [round(float(v) / 3600, 2) for v in vals[np.argsort(-cnts)][1:4]]})
    else:
        return None, dict(info, source='no 5-tuple shared by pcap and CSV')
    d = delta - off
    info.update({'seconds': off, 'hours': round(off / 3600, 2),
                 'agreement': _r(((d > -1.0 - 1e-6) & (d <= 1e-6)).sum(), len(d)),
                 'agreement_within_2s': _r((np.abs(d + 0.5) <= 2.5).sum(), len(d))})
    return off, info


def assign(pkey, pt, ikey, ist, ien, icap, itb, n_keys):
    """Instance index per packet (-1: none), see step 3 of the docstring. Instances of one key are taken in
    order of start second, then of itb (first CSV row: CICFlowMeter writes a flow when it ends, and flows of
    one 5-tuple are sequential, so row order breaks ties between flows that start in the same second)."""
    order = np.lexsort((itb, ist, ikey))
    ks, st, en, cap = ikey[order], ist[order], ien[order], icap[order]
    ar = np.arange(n_keys)
    lo, hi = np.searchsorted(ks, ar, 'left'), np.searchsorted(ks, ar, 'right')
    nin = hi - lo
    res = np.full(len(pkey), -1, np.int64)
    valid = pkey >= 0
    ni = np.where(valid, nin[np.where(valid, pkey, 0)], 0)
    s = np.flatnonzero(ni == 1)                                     # one CSV flow for the key: window test
    j = lo[pkey[s]]
    ok = (pt[s] >= st[j]) & (pt[s] <= en[j])
    res[s[ok]] = order[j[ok]]
    m = np.flatnonzero(ni > 1)                                      # several: time order + packet counts
    if len(m):
        m = m[np.lexsort((pt[m], pkey[m]))]
        stl, enl, capl, ordl = st.tolist(), en.tolist(), cap.tolist(), order.tolist()
        lol, hil = lo.tolist(), hi.tolist()
        used = [0] * len(ks)
        km, tm = pkey[m].tolist(), pt[m].tolist()
        out = [-1] * len(m)
        cur = j0 = h = -1
        for i in range(len(m)):
            k, t = km[i], tm[i]
            if k != cur:
                cur, j0, h = k, lol[k], hil[k]
            while j0 < h and enl[j0] < t:
                j0 += 1
            best = fb = -1
            jj = j0
            while jj < h and stl[jj] <= t:
                if enl[jj] >= t:
                    if used[jj] < capl[jj]:
                        best = jj
                        break
                    fb = jj
                jj += 1
            if best < 0:
                best = fb
            if best >= 0:
                used[best] += 1
                out[i] = ordl[best]
        res[m] = out
    return res


# ----------------------------------------------------------------------------- packets of all files
def input_signature(csvs, kind, web_attack, max_rows, max_packets):
    h = hashlib.sha1(json.dumps([VERSION, kind, web_attack, max_rows, max_packets,
                                 [(Path(f).name, os.path.getsize(f)) for f in csvs]]).encode()).hexdigest()
    return h[:16]


def load_packets(pcaps, keys, kind, web_attack, cache_dir, sig_hash, backend, max_packets, use_cache):
    web_re = re.compile(WEB_PATTERNS[web_attack]) if kind == 'web' and web_attack in WEB_PATTERNS else None
    parts = []
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
    for i, p in enumerate(pcaps, 1):
        st = p.stat()
        fsig = f'{sig_hash}:{st.st_size}:{int(st.st_mtime)}'
        arrays = meta = None
        if cache_dir is not None:
            npz, mp = cache_dir / f'{p.name}.npz', cache_dir / f'{p.name}.json'
            if use_cache and npz.exists() and mp.exists():
                m = json.load(open(mp, encoding='utf-8'))
                if m.get('signature') == fsig:
                    with np.load(npz) as z:
                        arrays = {k: z[k] for k in z.files}
                    meta = m
                    print(f'    [{i}/{len(pcaps)}] {p.name}: {meta["frames"]:,} frames (cached)', flush=True)
        if arrays is None:
            print(f'    [{i}/{len(pcaps)}] {p.name} ({st.st_size / 1e6:,.1f} MB) ...', flush=True)
            arrays, meta = parse_file(p, keys, kind, web_re, backend, max_packets)
            meta['signature'] = fsig
            print(f'        {meta["frames"]:,} frames in {meta["seconds"]} s ({meta["frames_per_second"]:,}/s, '
                  f'{meta["reader"]["backend"]} reader) {meta["by_category"]}', flush=True)
            if cache_dir is not None:
                tmp = cache_dir / f'{p.name}.tmp.npz'
                np.savez_compressed(tmp, **arrays)
                os.replace(tmp, cache_dir / f'{p.name}.npz')
                write_json(meta, cache_dir / f'{p.name}.json')
        parts.append((arrays, meta))
    gm, gi = {}, {}
    cols = {k: [] for k in ('t', 'key', 'smac', 'dmac', 'sip', 'dip', 'sig', 'cat', 'arp', 'dns')}
    n0 = 0

    def remap(a, lut):
        out = np.full(len(a), -1, np.int32)
        ok = a >= 0
        if ok.any():
            out[ok] = lut[a[ok]]
        return out
    for arrays, meta in parts:
        lm = np.array([gm.setdefault(x, len(gm)) for x in meta['macs']] or [0], np.int32)
        li = np.array([gi.setdefault(x, len(gi)) for x in meta['ips']] or [0], np.int32)
        for k in ('t', 'key', 'sig', 'cat'):
            cols[k].append(arrays[k])
        for k, lut in (('smac', lm), ('dmac', lm), ('sip', li), ('dip', li)):
            cols[k].append(remap(arrays[k], lut))
        a = arrays['arp'].copy()
        if len(a):
            a[:, 0] += n0
            a[:, 2], a[:, 4] = lm[a[:, 2]], lm[a[:, 4]]
            a[:, 3], a[:, 5] = li[a[:, 3]], li[a[:, 5]]
        d = arrays['dns'].copy()
        if len(d):
            d[:, 0] += n0
        cols['arp'].append(a)
        cols['dns'].append(d)
        n0 += len(arrays['t'])
    P = {k: np.concatenate(v) if v else np.zeros(0) for k, v in cols.items()}
    info = {'files': [m for _, m in parts], 'frames': int(n0)}
    for m in info['files']:
        m.pop('macs', None)
        m.pop('ips', None)
    return P, list(gm), list(gi), info


# ----------------------------------------------------------------------------- MAC roles
def ip_owners(P, n_ip, zero_ip, exclude=()):
    """Owner MAC per IP code: sender MAC of the IP's ARP requests, else the most frequent source MAC of its
    IP packets. MACs in exclude (the attackers) are ignored in both steps unless they are the only MAC seen
    with the address: an ARP spoofer may send requests with a forged sender IP (e.g. the gateway's), and a
    man in the middle relays the victims' IP packets."""
    owner = np.full(n_ip, -1, np.int64)
    ex = [int(x) for x in exclude]
    a = P['arp']
    req_df = ip_df = None
    if len(a):
        req = (a[:, 1] == 1) & (a[:, 3] != zero_ip) & (a[:, 2] >= 0) & (a[:, 3] >= 0)
        if req.any():
            req_df = pd.DataFrame({'ip': a[req, 3], 'mac': a[req, 2]}).value_counts().reset_index(name='n')
    ipm = (P['cat'] <= 1) & (P['sip'] >= 0) & (P['smac'] >= 0)
    if ipm.any():
        ip_df = pd.DataFrame({'ip': P['sip'][ipm], 'mac': P['smac'][ipm]}).value_counts().reset_index(name='n')

    def fill(df, excluded):
        if df is None or not len(df):
            return
        d = df[df['mac'].isin(ex) == excluded]
        g = d.sort_values(['ip', 'n', 'mac'], ascending=[True, False, True], kind='stable').drop_duplicates('ip')
        ipc, mc = g['ip'].to_numpy(np.int64), g['mac'].to_numpy(np.int64)
        free = owner[ipc] < 0
        owner[ipc[free]] = mc[free]
    fill(req_df, False)                       # 1 ARP requests of non-excluded MACs
    fill(ip_df, False)                        # 2 IP packets of non-excluded MACs
    if ex:                                    # 3 an excluded MAC owns only addresses no other MAC is seen with
        fill(req_df, True)
        fill(ip_df, True)
    return owner


def derive_roles(P, mac_names, ip_names, kind, args):
    n_ip = len(ip_names)
    ip_int = internal(pd.Series(ip_names, dtype=object)).astype(bool) if n_ip else np.zeros(0, bool)
    ip_spec = np.array([rv2._special(x) for x in ip_names], bool)
    iip = {x: i for i, x in enumerate(ip_names)}
    imac = {x: i for i, x in enumerate(mac_names)}
    zero_ip, gw_ip = iip.get('0.0.0.0', -2), iip.get(GATEWAY, -2)
    smac, dmac, sip, dip, sig, cat = P['smac'], P['dmac'], P['sip'], P['dip'], P['sig'], P['cat']
    isip = (cat <= 1) & (sip >= 0) & (smac >= 0)
    sipc = np.where(sip >= 0, sip, 0)
    R = {'kind': kind}

    # gateway MAC
    ext = isip & ~ip_int[sipc] & ~ip_spec[sipc]
    top_ext = top_codes(mac_names, smac[ext], n=3)
    top_gwip = top_codes(mac_names, smac[isip & (sip == gw_ip)], n=3)
    a = P['arp']
    top_gwarp = (top_codes(mac_names, a[(a[:, 1] == 1) & (a[:, 3] == gw_ip), 2], n=3)
                 if len(a) and gw_ip >= 0 else [])
    if args.gateway_mac:
        gw = imac.get(norm_mac(args.gateway_mac), -1)
        R['gateway_source'] = 'override (--gateway-mac)'
    else:
        gw = imac[top_ext[0]['value']] if top_ext else (imac[top_gwip[0]['value']] if top_gwip else -1)
        R['gateway_source'] = ('most frequent source MAC of frames with an Internet source IP' if top_ext else
                               f'most frequent source MAC of frames from {GATEWAY}' if top_gwip else 'not found')
    # independent check: the sender of the ARP requests for the gateway IP (a MITM attacker relays Internet
    # frames and forges gateway-IP frames, so the two can disagree - then --gateway-mac should be given)
    agree = None if not top_gwarp or gw < 0 else top_gwarp[0]['value'] == mac_names[gw]
    R.update({'gateway_mac': mac_names[gw] if gw >= 0 else None,
              'gateway_evidence_internet_sources': top_ext, f'gateway_evidence_{GATEWAY}': top_gwip,
              f'gateway_evidence_arp_requests_for_{GATEWAY}': top_gwarp,
              'gateway_arp_request_sender_agrees': agree})
    if agree is False:
        print(f'    [warn] gateway MAC {mac_names[gw]} (Internet-source frames) differs from the sender of the ARP '
              f'requests for {GATEWAY} ({top_gwarp[0]["value"]}); check roles.gateway_* and give --gateway-mac',
              flush=True)

    # attack-signature frames
    s = np.zeros(len(smac), bool)
    details = {}
    note = None
    if kind == 'bruteforce':
        s = (sig == 1) & (smac != gw)
        details['frames_to_22_23'] = int((sig == 1).sum())
        details['frames_to_22_23_from_gateway_mac'] = int(((sig == 1) & (smac == gw)).sum())
        rule = 'source MACs of >= 80 % of the TCP frames sent to port 22/23 (gateway MAC excluded)'
    elif kind == 'web':
        s = (sig == 3) & (smac != gw)
        details.update({'web_attack': args.web_attack, 'payload_frames': int((sig == 3).sum()),
                        'payload_frames_from_gateway_mac': int(((sig == 3) & (smac == gw)).sum()),
                        'frames_to_80_8080': int((sig == 2).sum())})
        rule = (f'source MACs of >= 80 % of the HTTP frames matching the {args.web_attack} pattern (gateway MAC '
                'excluded)')
        if s.sum() < MIN_SIG:
            s = (sig == 2) & (smac != gw)
            note = f'fewer than {MIN_SIG} payload matches: fallback to TCP frames sent to port 80/8080'
            rule = 'source MACs of >= 80 % of the TCP frames sent to port 80/8080 (gateway MAC excluded)'
    elif kind == 'dns':
        resp = sig == 4
        gw_or_ext = (sip == gw_ip) | ~ip_int[sipc]
        imp = resp & gw_or_ext & (smac != gw)
        rogue = resp & ~gw_or_ext & (sip >= 0)
        s = imp | rogue
        d = P['dns']
        dup = 0
        if len(d):
            r = d[d[:, 2] == 1]
            if len(r):
                g = pd.DataFrame({'client': dip[r[:, 0]], 'port': r[:, 3], 'id': r[:, 1]}).value_counts()
                dup = int((g >= 2).sum())
        details.update({'dns_responses': int(resp.sum()), 'mac_impersonated_responses': int(imp.sum()),
                        'rogue_responder_responses': int(rogue.sum()),
                        'queries_with_two_or_more_responses': dup,
                        'impersonated_resolvers': top_codes(ip_names, sip[imp], n=5),
                        'rogue_responders': top_codes(ip_names, sip[rogue], n=5)})
        rule = ('source MACs of >= 80 % of the DNS responses that carry the gateway\'s or an Internet resolver\'s IP '
                'but come from a MAC other than the gateway MAC, or come from a testbed host other than the gateway')
    elif kind == 'arp':
        a = P['arp']
        if len(a):
            v = np.isin(a[:, 1], (1, 2)) & (a[:, 3] != zero_ip) & (a[:, 2] >= 0) & (a[:, 3] >= 0)
            b = pd.DataFrame({'ip': a[v, 3], 'mac': a[v, 2]}).drop_duplicates()
            n_mac = b.groupby('ip').size()
            n_ips = b.groupby('mac').size()
            conflict = n_mac[n_mac >= 2].index.to_numpy()
            susp = [int(m) for m in n_ips[n_ips >= 2].index
                    if b[(b['mac'] == m) & b['ip'].isin(conflict)].shape[0] > 0]
            rows = v & np.isin(a[:, 2], susp) & np.isin(a[:, 3], conflict)
            s[a[rows, 0]] = True
            details.update({'arp_frames': int(len(a)), 'conflicting_ips': [ip_names[i] for i in conflict[:20]],
                            'macs_binding_2plus_ips_with_conflict': [
                                {'mac': mac_names[m], 'ips': [ip_names[i] for i in b[b['mac'] == m]['ip'][:10]]}
                                for m in susp[:10]]})
        rule = ('source MACs of >= 80 % of the ARP frames that bind an IP also claimed by another MAC, sent by a MAC '
                'binding >= 2 IPs')
    else:
        rule = 'given by the user'

    # attackers
    if args.attacker_mac or args.attacker_ip:
        A = [imac[m] for m in (norm_mac(x) for x in args.attacker_mac or []) if m in imac]
        if args.attacker_ip:
            own0 = ip_owners(P, n_ip, zero_ip)
            A += [int(own0[iip[x]]) for x in (canon_ip(y)[1] for y in args.attacker_ip) if x in iip and own0[iip[x]] >= 0]
        A = sorted(set(A))
        cov, source = None, 'override (--attacker-mac / --attacker-ip)'
        if kind == 'manual' or not s.any():
            s = np.isin(smac, A)
    else:
        n_sig = int((s & (smac >= 0)).sum())
        A, cov = cover_codes(smac[s], ATT_MAC_CAP) if n_sig >= MIN_SIG else ([], None)
        source = 'derived'
    owner = ip_owners(P, n_ip, zero_ip, exclude=A)
    att_ips = [i for i in range(n_ip) if owner[i] in A and ip_int[i] and not ip_spec[i]] if A else []
    Aset = np.asarray(A, np.int64)
    if kind == 'arp' and len(P['arp']) and A:
        a = P['arp']
        mine = np.zeros(len(a), bool)
        mine[:] = s[a[:, 0]] & np.isin(a[:, 2], Aset)
        V = sorted(set(a[mine, 5].tolist()) | set(a[mine, 3].tolist()))
        V = [v for v in V if v >= 0 and v != zero_ip]
        vcov = None
    else:
        cand = np.where(s & (dip >= 0), dip, -1)            # manual kind: s = every frame of the attacker MACs
        cand = np.where((cand >= 0) & ip_int[np.where(cand >= 0, cand, 0)] & ~ip_spec[np.where(cand >= 0, cand, 0)]
                        & ~np.isin(cand, att_ips), cand, -1)
        V, vcov = cover_codes(cand, VIC_CAP_DNS if kind == 'dns' else VIC_CAP)
    R.update({'attacker_rule': rule, 'attacker_source': source, 'note': note,
              'signature_frames': int(s.sum()), 'signature_frames_by_source_mac': top_codes(mac_names, smac[s], n=10),
              'attacker_macs': [mac_names[m] for m in A], 'attacker_frame_coverage': cov,
              'attacker_ips': [ip_names[i] for i in att_ips],
              'victim_ips': [ip_names[i] for i in V], 'victim_coverage': vcov, **details,
              'mac_table': mac_table(P, mac_names, ip_names, owner, A, gw)})
    return R, s, np.isin(smac, Aset) | np.isin(dmac, Aset)


def mac_table(P, mac_names, ip_names, owner, A, gw, n=25):
    """Most active MACs with frames sent/received and the IPs they own."""
    sm, dm = P['smac'], P['dmac']
    cs = np.bincount(sm[sm >= 0], minlength=len(mac_names))
    cd = np.bincount(dm[dm >= 0], minlength=len(mac_names))
    own = {}
    for i, m in enumerate(owner.tolist()):
        if m >= 0:
            own.setdefault(m, []).append(ip_names[i])
    order = np.argsort(-(cs + cd), kind='stable')[:n]
    return [{'mac': mac_names[m], 'frames_sent': int(cs[m]), 'frames_received': int(cd[m]),
             'role': 'attacker' if m in A else 'gateway' if m == gw else '',
             'owned_ips': sorted(own.get(m, []))[:8], 'n_owned_ips': len(own.get(m, []))} for m in order]


# ----------------------------------------------------------------------------- scoring
def score_rules(truth, flags, pk, scored):
    t = truth & scored
    nt, nb = int(t.sum()), int((scored & ~truth).sum())

    def pw(m):
        return float(pk[m].sum())
    out = {}
    for r, f in flags.items():
        fs, ks = f & scored, ~f & scored
        tpb, fp = int((fs & ~truth).sum()), int((fs & truth).sum())
        fnb, tn = int((ks & ~truth).sum()), int((ks & truth).sum())
        out[r] = {'flagged': tpb + fp, 'kept': fnb + tn, 'flagged_background': tpb, 'flagged_attacker': fp,
                  'kept_background': fnb, 'kept_attacker': tn,
                  'precision_background': _r(tpb, tpb + fp), 'precision_background_ci95': wilson(tpb, tpb + fp),
                  'recall_background': _r(tpb, nb), 'recall_background_ci95': wilson(tpb, nb),
                  'false_removal_rate': _r(fp, nt), 'false_removal_rate_ci95': wilson(fp, nt),
                  'kept_attack_share': _r(tn, fnb + tn), 'kept_attack_share_ci95': wilson(tn, fnb + tn),
                  'packet_precision_background': _r(pw(fs & ~truth), pw(fs)),
                  'packet_recall_background': _r(pw(fs & ~truth), pw(scored & ~truth)),
                  'packet_false_removal_rate': _r(pw(fs & truth), pw(t)),
                  'packet_kept_attack_share': _r(pw(ks & truth), pw(ks))}
    return out


def heuristic_vs_mac(kind, c, ipt, truth, scored):
    """rule_validation2's flow-level signature (rule_validation.identify) scored against the MAC label."""
    if kind not in rv2.OLD_KINDS:
        return None
    int_s, int_d = ipt.int_mask[c['src']], ipt.int_mask[c['dst']]
    pk = c['fwd'].astype(np.float64) + c['bwd']
    idn = rv2.identify(kind, c, ipt, int_s, int_d, pk)
    out = {'heuristic_attackers': idn['attackers'], 'heuristic_victims': list(idn['victims'])[:20]}
    for name, m in (('signature', idn['sig']), ('attacker_victim', idn['av'])):
        tp = int((m & truth & scored).sum())
        out[name] = {'flows': int((m & scored).sum()), 'true_positive': tp,
                     'precision': _r(tp, (m & scored).sum()), 'precision_ci95': wilson(tp, int((m & scored).sum())),
                     'recall': _r(tp, (truth & scored).sum()), 'recall_ci95': wilson(tp, int((truth & scored).sum()))}
    return out


def r1_breakdown(c, ipt, canon, flags, lab, B, scored):
    r1 = flags['R1_external'] & lab['attacker_involved'] & scored
    int_d = ipt.int_mask[c['dst']]
    ext = np.where(~int_d, c['dst'], c['src'])
    out = {'r1_flagged_attacker_flows': int(r1.sum()),
           'relayed': int((r1 & lab['relayed']).sum()),
           'attacker_endpoint': int((r1 & lab['attacker_endpoint']).sum()),
           'attacker_victim': int((r1 & lab['attacker_victim']).sum()),
           'top_external_addresses': [{'value': canon[int(k)], 'flows': int(v)}
                                      for k, v in pd.Series(ext[r1]).value_counts().head(10).items()]}
    if B.get('addr_flows') is not None and r1.any():
        inb = rv2.lookup(B['addr_flows'], ext[r1]) > 0
        out['external_address_in_benign_share'] = _r(inb.sum(), r1.sum())
    return out


def audit_link(rel_files, labels, out_dir, path=AUDIT_SAMPLE):
    if path is None or not Path(path).exists():
        return None
    s = pd.read_csv(path, keep_default_na=False)
    s = s[s['file'].isin(rel_files)].copy()
    if not len(s):
        return {'sampled_flows_of_capture': 0}
    s['row'] = s['row'].astype(np.int64)
    lab = labels[['file', 'row', 'matched_packets', 'attacker_involved', 'attacker_victim', 'attacker_endpoint',
                  'relayed', 'signature_flow']].add_prefix('mac_').rename(columns={'mac_file': 'file', 'mac_row': 'row'})
    m = s.merge(lab, on=['file', 'row'], how='left')
    m.to_csv(out_dir / 'audit_sample_mac.csv', index=False)
    ok = m['mac_matched_packets'].fillna(0) > 0
    res = {'sampled_flows_of_capture': int(len(m)), 'matched': int(ok.sum()), 'per_stratum': {}}
    for st in rv2.STRATA:
        sel = ok & m['selected_strata'].str.split(';').map(lambda x: st in x)
        if sel.any():
            res['per_stratum'][st] = {'flows': int(sel.sum()),
                                      'attacker_involved': int(m.loc[sel, 'mac_attacker_involved'].astype(bool).sum())}
    return res


# ----------------------------------------------------------------------------- one capture
def run_key(args, kind, pcaps, csvs):
    """Settings that define a run: a finished JSON is reused only when they are unchanged (a --max-rows /
    --max-packets test run, or a run stopped for want of an attacker, never blocks the real run)."""
    return {'kind': kind, 'web_attack': args.web_attack if kind == 'web' else None, 'max_rows': args.max_rows,
            'max_packets': args.max_packets, 'attacker_mac': sorted(args.attacker_mac or []),
            'attacker_ip': sorted(args.attacker_ip or []), 'gateway_mac': args.gateway_mac,
            'tz_offset_hours': args.tz_offset_hours, 'version': VERSION,
            'pcap_files': sorted(Path(p).name for p in pcaps), 'csv_files': sorted(Path(f).name for f in csvs)}


def finished(jpath, key):
    """The JSON of a finished run with the same settings, else None."""
    if not jpath.exists():
        return None
    try:
        with open(jpath, encoding='utf-8') as fh:
            res = json.load(fh)
    except (OSError, ValueError):
        return None
    if res.get('run_key') != json.loads(json.dumps(key)):
        print(f'[plan] {jpath} was made with other settings ({res.get("run_key")}) - recomputed', flush=True)
        return None
    return res


def run_capture(name, cls, sub, pcaps, csvs, kind, ipt, B, out_dir, args, audit_path=AUDIT_SAMPLE):
    jpath = out_dir / 'pcap_validation.json'
    key = run_key(args, kind, pcaps, csvs)
    if not args.force:
        done = finished(jpath, key)
        if done is not None:
            print(f'[skip] {jpath} exists (use --force to recompute)', flush=True)
            return done
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    print(f'[2] flow CSVs of {name}: {[Path(f).name for f in csvs]}', flush=True)
    c = rv2.read_arrays([str(f) for f in csvs], ipt, rv2.BASE_COLS, args.max_rows)
    n = len(c['src'])
    canon = [canon_ip(x)[1] for x in ipt.names]
    fkey, keys = flow_keys(c, ipt)
    print(f'    {n:,} flows, {len(keys):,} distinct 5-tuples, {int((fkey < 0).sum())} with an unparseable address',
          flush=True)

    print(f'[3] packets of {len(pcaps)} pcap file(s), kind={kind}'
          + (f' ({args.web_attack})' if kind == 'web' else ''), flush=True)
    sig_hash = input_signature(csvs, kind, args.web_attack, args.max_rows, args.max_packets)
    P, mac_names, ip_names, pinfo = load_packets(pcaps, keys, kind, args.web_attack, out_dir / 'parsed', sig_hash,
                                                 args.backend, args.max_packets, not args.no_cache)
    npk = len(P['t'])
    print(f'    {npk:,} frames, {int((P["key"] >= 0).sum()):,} with a 5-tuple of the CSVs, {len(mac_names)} MACs, '
          f'{len(ip_names)} IPs ({time.time() - t0:.0f} s)', flush=True)

    # time offset, instances, assignment
    off, tz = estimate_offset(P, fkey, c['ts'], len(keys), args.tz_offset_hours)
    res = {'capture': name, 'class': cls, 'capture_group': sub, 'kind': kind, 'run_key': key,
           'test_run': args.max_rows is not None or args.max_packets is not None,
           'web_attack': args.web_attack if kind == 'web' else None,
           'pcap_files': [p.name for p in pcaps], 'csv_files': [Path(f).name for f in csvs],
           'reader_backend': 'dpkt' if (args.backend == 'dpkt' or (args.backend == 'auto' and HAVE_DPKT)) else 'builtin',
           'assumptions': ASSUMPTIONS,
           'parameters': {'tolerance_us': TOL_US, 'tz_step_s': TZ_STEP, 'cover': COVER, 'attacker_mac_cap': ATT_MAC_CAP,
                          'victim_cap': VIC_CAP, 'victim_cap_dns': VIC_CAP_DNS, 'min_signature_frames': MIN_SIG,
                          'max_rows': args.max_rows, 'max_packets': args.max_packets, 'version': VERSION},
           'time_offset': tz, 'packets': pinfo}
    if off is None:
        res['status'] = 'no_packets_matched'
        write_json(res, jpath)
        print(f'[stop] no 5-tuple shared by the pcaps and the CSVs - wrong capture? ({jpath})', flush=True)
        return res
    print(f'    time offset {tz["hours"]:+.2f} h ({tz["source"]}; agreement {_pct(tz.get("agreement"))} over '
          f'{tz["keys_used"]:,} 5-tuples)', flush=True)
    valid = (fkey >= 0) & np.isfinite(c['ts'])
    start = np.where(valid, np.round((np.nan_to_num(c['ts']) - off) * 1e6), 0).astype(np.int64)
    dur = np.round(c['dur'].astype(np.float64)).astype(np.int64)
    cap = np.round(c['fwd'].astype(np.float64) + c['bwd']).astype(np.int64)
    tab = np.stack([fkey, start, dur, cap], axis=1)[valid]
    inst, inv = np.unique(tab, axis=0, return_inverse=True)
    inv = inv.reshape(-1)
    row_inst = np.full(n, -1, np.int64)
    row_inst[valid] = inv
    ni = len(inst)
    first_row = np.full(ni, np.iinfo(np.int64).max, np.int64)
    np.minimum.at(first_row, inv, np.flatnonzero(valid))
    pidx = assign(P['key'].astype(np.int64), P['t'], inst[:, 0], inst[:, 1], inst[:, 1] + 1_000_000 + inst[:, 2] + TOL_US,
                  inst[:, 3], first_row, len(keys))
    hit = pidx >= 0
    mcount = np.bincount(pidx[hit], minlength=ni)

    # roles and labels
    R, sigmask, attpk = derive_roles(P, mac_names, ip_names, kind, args)
    per_inst = {'attacker_involved': np.bincount(pidx[hit], weights=attpk[hit], minlength=ni) > 0,
                'signature_flow': np.bincount(pidx[hit], weights=sigmask[hit], minlength=ni) > 0}
    ri = np.where(row_inst >= 0, row_inst, 0)
    matched_pk = np.where(row_inst >= 0, mcount[ri], 0)
    scored = matched_pk > 0
    lab = {k: np.where(row_inst >= 0, v[ri], False) & scored for k, v in per_inst.items()}
    cn = np.asarray(canon, dtype=object)
    att_set, vic_set = set(R['attacker_ips']), set(R['victim_ips'])
    is_att = np.array([x in att_set for x in canon], bool)
    is_vic = np.array([x in vic_set for x in canon], bool)
    lab['attacker_endpoint'] = (is_att[c['src']] | is_att[c['dst']]) & scored
    lab['attacker_victim'] = lab['attacker_involved'] & (is_vic[c['src']] | is_vic[c['dst']])
    lab['relayed'] = lab['attacker_involved'] & ~lab['attacker_endpoint']

    csv_pk = c['fwd'].astype(np.float64) + c['bwd']
    exact = scored & (matched_pk == np.round(csv_pk))
    near = scored & (np.abs(matched_pk - csv_pk) <= np.maximum(1, 0.1 * csv_pk))
    res['mapping'] = {
        'csv_flows': n, 'csv_flows_with_valid_key_and_time': int(valid.sum()),
        'csv_distinct_flow_instances': ni, 'csv_exact_duplicate_rows': int(valid.sum() - ni),
        'csv_flows_matched': int(scored.sum()), 'csv_flows_matched_share': _r(scored.sum(), n),
        'csv_flows_exact_packet_count_share_of_matched': _r(exact.sum(), scored.sum()),
        'csv_flows_packet_count_within_10pct_share_of_matched': _r(near.sum(), scored.sum()),
        'csv_packets_of_matched_flows': int(csv_pk[scored].sum()),
        'csv_packets_all_flows': int(csv_pk.sum()),
        'frames': npk, 'frames_with_csv_5tuple': int((P['key'] >= 0).sum()), 'frames_matched': int(hit.sum()),
        'frames_matched_share': _r(hit.sum(), npk),
        'frames_by_category': {CAT_NAMES[k]: int(v) for k, v in zip(*np.unique(P['cat'], return_counts=True))},
        'frames_matched_by_category': {CAT_NAMES[k]: int(v) for k, v in zip(*np.unique(P['cat'][hit], return_counts=True))},
        'unmatched_csv_flows_by_protocol': {str(k): int(v) for k, v in
                                            pd.Series(c['proto'][~scored]).value_counts().head(5).items()}}
    res['roles'] = R
    if not R['attacker_macs']:
        res['status'] = 'no_attacker_identified'
        write_json(res, jpath)
        print(f'[stop] no attacker MAC identified ({R["signature_frames"]} signature frames); give --attacker-mac or '
              f'--attacker-ip ({jpath})', flush=True)
        return res

    # rules and scores
    c['r1'], c['r2'], c['r3'] = rv2.rule_flags_codes(c, sub, ipt, B)
    flags = rv2.flags_of(c)
    res['labels'] = {k: int(v.sum()) for k, v in lab.items()}
    res['labels'].update({'scored_flows': int(scored.sum()),
                          'attacker_involved_share': _r(lab['attacker_involved'].sum(), scored.sum()),
                          'attacker_involved_packet_share': _r(csv_pk[lab['attacker_involved']].sum(),
                                                               csv_pk[scored].sum())})
    res['rule_flag_share_scored'] = {r: _r((f & scored).sum(), scored.sum()) for r, f in flags.items()}
    res['scores'] = {t: score_rules(lab[t], flags, csv_pk, scored) for t in TRUTHS}
    res['r1_attacker_flows'] = r1_breakdown(c, ipt, canon, flags, lab, B, scored)
    try:
        res['flow_heuristic_vs_mac'] = heuristic_vs_mac(kind, c, ipt, lab['attacker_involved'], scored)
    except Exception as e:                                          # diagnostic only
        res['flow_heuristic_vs_mac'] = {'error': repr(e)}

    rel = [rv2._relpath(f) for f in csvs]
    labels = pd.DataFrame({'file': np.asarray(rel, dtype=object)[c['file']], 'row': c['row'],
                           'Src IP': cn[c['src']], 'Src Port': c['sp'], 'Dst IP': cn[c['dst']], 'Dst Port': c['dp'],
                           'Protocol': c['proto'],
                           'Timestamp': pd.to_datetime(c['ts'], unit='s').strftime(TS_FMT),
                           'csv_packets': csv_pk.astype(np.int64), 'matched_packets': matched_pk.astype(np.int64),
                           **{k: lab[k] for k in ('attacker_involved', 'attacker_victim', 'attacker_endpoint',
                                                  'relayed', 'signature_flow')},
                           **{r: flags[r] for r in RULES}})
    labels.to_csv(out_dir / 'flow_labels.csv.gz', index=False, compression='gzip')
    np.savez_compressed(out_dir / 'flow_labels.npz', csv_file=c['file'], row=c['row'], csv_packets=csv_pk.astype(np.int64),
                        matched_packets=matched_pk.astype(np.int64), **{k: v for k, v in lab.items()},
                        **{r: flags[r] for r in RULES})
    res['audit_sample'] = audit_link(rel, labels, out_dir, audit_path)
    res['status'] = 'ok'
    res['seconds'] = round(time.time() - t0, 1)
    write_json(res, jpath)

    m = res['mapping']
    print(f'    mapping: {m["csv_flows_matched"]:,}/{n:,} CSV flows matched ({_pct(m["csv_flows_matched_share"])}), exact '
          f'packet count {_pct(m["csv_flows_exact_packet_count_share_of_matched"])}, frames matched '
          f'{_pct(m["frames_matched_share"])}', flush=True)
    print(f'    attacker MAC(s) {R["attacker_macs"]} (coverage {R["attacker_frame_coverage"]}, {R["signature_frames"]:,} '
          f'signature frames), attacker IPs {R["attacker_ips"][:4]}, victims {R["victim_ips"][:4]}', flush=True)
    print(f'    attacker-involved flows {res["labels"]["attacker_involved"]:,} of {int(scored.sum()):,} '
          f'({_pct(res["labels"]["attacker_involved_share"])}), relayed {res["labels"]["relayed"]:,}', flush=True)
    for r, v in res['scores']['attacker_involved'].items():
        ci = v['precision_background_ci95'] or [None, None]
        print(f'    {r:15s} precision {_pct(v["precision_background"])} [{_pct(ci[0])},{_pct(ci[1])}]  recall '
              f'{_pct(v["recall_background"])}  false removal {_pct(v["false_removal_rate"])} '
              f'({v["flagged_attacker"]:,}/{res["labels"]["attacker_involved"]:,})  kept attack share '
              f'{_pct(v["kept_attack_share"])}  | packets: false removal {_pct(v["packet_false_removal_rate"])}',
              flush=True)
    print(f'[DONE] {jpath} ({time.time() - t0:.0f} s)', flush=True)
    del P, c
    gc.collect()
    return res


# ----------------------------------------------------------------------------- capture resolution
def _csvs_by_name(pcaps, pool):
    by = {Path(f).name.lower(): Path(f) for f in pool}
    out = []
    for p in pcaps:
        cand = [f'{p.name}_Flow.csv', f'{p.stem}.pcap_Flow.csv', f'{p.stem}_Flow.csv']
        hit = next((by[x.lower()] for x in cand if x.lower() in by), None)
        if hit is None:
            return None
        out.append(hit)
    return sorted(set(out), key=lambda x: str(x))


def resolve(args, pcaps):
    if args.csv:
        files = [Path(x) for x in args.csv]
    elif args.capture:
        caps = rv2.discover()
        q = args.capture.lower()
        sel = [x for x in caps if q in x['name'].lower()]
        exact = [x for x in sel if q in (x['name'].lower(), x['sub'].lower())]
        sel = exact if len(exact) == 1 else sel
        if len(sel) != 1:
            raise SystemExit(f'--capture {args.capture!r} matches {[x["name"] for x in sel]}; captures: '
                             f'{[x["name"] for x in caps]}')
        files = [Path(f) for f in sel[0]['files']]
        files = _csvs_by_name(pcaps, files) or files
    else:
        files = _csvs_by_name(pcaps, DATA.rglob('*_Flow.csv'))
        if not files:
            raise SystemExit('no flow CSV named <pcap name>_Flow.csv found; give --capture or --csv')
    try:
        parts = files[0].resolve().relative_to(DATA.resolve()).parts
        cls, sub = parts[0], (parts[1] if len(parts) > 2 else parts[0])
    except ValueError:
        cls = sub = args.capture or 'custom'
    name = f'{cls} / {sub}' if sub != cls else cls
    kind = args.kind
    if kind is None:
        k = rv2.kinds_for(cls, sub)
        kind = k[0] if k and k[0] in KINDS else 'manual'
    if kind == 'manual' and not (args.attacker_mac or args.attacker_ip):
        raise SystemExit(f'{name}: no MAC signature rule for this capture - give --attacker-mac or --attacker-ip')
    if kind == 'web' and args.web_attack is None:
        s = sub.lower()
        args.web_attack = 'sqli' if 'sql' in s else 'xss' if 'xss' in s else 'upload' if 'upload' in s else 'none'
    return name, cls, sub, files, kind


# ----------------------------------------------------------------------------- self-test (synthetic packets only)
def _mac(x):
    return bytes.fromhex(x.replace(':', ''))


def _ipb(x):
    return ipaddress.ip_address(x).packed


class _Synth:
    """Synthetic frames and the CICFlowMeter rows they would produce (local time = UTC + tz)."""

    def __init__(self, tz_h):
        self.frames, self.rows, self.tz = [], [], tz_h * 3600

    def pkt(self, t, smac, dmac, sip, dip, proto, sp=0, dp=0, flags=0, payload=b''):
        if proto == TCP:
            l4 = struct.pack('!HHIIBBHHH', sp, dp, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload
        elif proto == UDP:
            l4 = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
        else:
            l4 = payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, _ipb(sip), _ipb(dip)) + l4
        fr = _mac(dmac) + _mac(smac) + b'\x08\x00' + ip
        self.frames.append((t, fr + b'\x00' * max(0, 60 - len(fr))))
        return (t, sip, dip, sp, dp, proto, len(payload), flags)

    def arp(self, t, smac, dmac, op, sha, spa, tha, tpa):
        body = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, _mac(sha), _ipb(spa), _mac(tha), _ipb(tpa))
        self.frames.append((t, _mac(dmac) + _mac(smac) + b'\x08\x06' + body + b'\x00' * 18))
        return (t, '8.6.0.1', '8.0.6.4', 0, 0, 0, 0, 0)

    def ip6(self, t, smac, dmac):
        l4 = struct.pack('!HHHH', 5353, 5353, 8, 0)
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(l4), 17, 255, _ipb('fe80::1'), _ipb('ff02::fb')) + l4
        self.frames.append((t, _mac(dmac) + _mac(smac) + b'\x86\xdd' + ip))

    def flow(self, pk):
        t0, s, d, sp, dp, pr = pk[0][:6]
        fwd = [p for p in pk if (p[1], p[3]) == (s, sp)]
        bwd = [p for p in pk if (p[1], p[3]) != (s, sp)]
        ts = pd.Timestamp(t0 / 1e6 + self.tz, unit='s').strftime(TS_FMT)
        self.rows.append({'Flow ID': f'{s}-{d}-{sp}-{dp}-{pr}', 'Src IP': s, 'Src Port': sp, 'Dst IP': d,
                          'Dst Port': dp, 'Protocol': pr, 'Timestamp': ts,
                          'Flow Duration': pk[-1][0] - t0, 'Total Fwd Packet': len(fwd),
                          'Total Bwd packets': len(bwd), 'Total Length of Fwd Packet': sum(p[6] for p in fwd),
                          'Total Length of Bwd Packet': sum(p[6] for p in bwd),
                          'SYN Flag Count': sum(1 for p in pk if p[7] & 2),
                          'ACK Flag Count': sum(1 for p in pk if p[7] & 16), 'Label': 'NeedManualLabel'})


def _write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, b in frames:
            f.write(struct.pack('<IIII', t // 10 ** 6, t % 10 ** 6, len(b), len(b)) + b)


def _write_pcapng(path, frames):
    def block(btype, body):
        body += b'\x00' * (-len(body) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(block(1, struct.pack('<HHI', 1, 0, 65535) + struct.pack('<HHB3x', 9, 1, 9) + struct.pack('<HH', 0, 0)))
        for t, b in frames:
            ns = t * 1000
            f.write(block(6, struct.pack('<IIIII', 0, ns >> 32, ns & 0xFFFFFFFF, len(b), len(b)) + b))


def _scenario():
    S = _Synth(tz_h=-4.0)
    G, A, V, D, W = '02:00:00:00:00:01', '02:00:00:00:00:65', '02:00:00:00:00:67', '02:00:00:00:00:88', '02:00:00:00:00:86'
    BC, Z = 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'
    g, a, v, d, w, I, I2 = ('192.168.137.1', '192.168.137.65', '192.168.137.67', '192.168.137.88', '192.168.137.86',
                            '52.1.2.3', '52.9.9.9')
    T0 = 1_666_000_000_000_000
    q = struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0) + b'\x07example\x03com\x00\x00\x01\x00\x01'
    ans = struct.pack('!HHHHHH', 7, 0x8180, 1, 1, 0, 0) + b'\x07example\x03com\x00\x00\x01\x00\x01'
    tags = {}
    arp = [S.arp(T0, D, BC, 1, D, d, Z, g), S.arp(T0 + 1000, G, D, 2, G, g, D, d),
           S.arp(T0 + 2000, V, BC, 1, V, v, Z, g), S.arp(T0 + 3000, A, BC, 1, A, a, Z, v)]
    for i in range(5):
        arp.append(S.arp(T0 + 10_000 + i * 2_000_000, A, V, 2, A, g, V, v))      # "g is-at A" to the victim
        arp.append(S.arp(T0 + 10_500 + i * 2_000_000, A, G, 2, A, v, G, g))      # "v is-at A" to the gateway
    S.flow(arp)
    tags['arp'] = 0
    for i in range(10):                                                          # SSH brute force A -> V
        t = T0 + 20_000_000 + i * 1_000_000 + 123
        S.flow([S.pkt(t, A, V, a, v, TCP, 40000 + i, 22, 0x02), S.pkt(t + 500, V, A, v, a, TCP, 22, 40000 + i, 0x12),
                S.pkt(t + 900, A, V, a, v, TCP, 40000 + i, 22, 0x18, b'SSH-2.0-x\r\n'),
                S.pkt(t + 1500, V, A, v, a, TCP, 22, 40000 + i, 0x04)])
    tags['bf'] = list(range(1, 11))
    t = T0 + 40_000_000                                                          # F11 device <-> Internet (TLS)
    S.flow([S.pkt(t + 10 * i, D if i % 2 == 0 else G, G if i % 2 == 0 else D, d if i % 2 == 0 else I,
                  I if i % 2 == 0 else d, TCP, 50000 if i % 2 == 0 else 443, 443 if i % 2 == 0 else 50000, 0x18, b'x' * 20)
            for i in range(6)])
    tags['tls1'] = 11
    t = T0 + 41_000_000                                                          # F12 device DNS (+ duplicate row)
    S.flow([S.pkt(t, D, G, d, g, UDP, 53001, 53, 0, q), S.pkt(t + 800, G, D, g, d, UDP, 53, 53001, 0, ans)])
    S.rows.append(dict(S.rows[-1]))
    tags['dns_dev'] = [12, 13]
    t = T0 + 42_000_000                                                          # F13 attacker's own DNS
    S.flow([S.pkt(t, A, G, a, g, UDP, 53002, 53, 0, q), S.pkt(t + 800, G, A, g, a, UDP, 53, 53002, 0, ans)])
    tags['dns_att'] = 14
    t = T0 + 43_000_000                                                          # F14 SQL injection A -> W:80
    get = b'GET /item.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1\r\nHost: w\r\n\r\n'
    S.flow([S.pkt(t, A, W, a, w, TCP, 41000, 80, 0x02), S.pkt(t + 300, W, A, w, a, TCP, 80, 41000, 0x12)]
           + [S.pkt(t + 600 + 400 * i, A, W, a, w, TCP, 41000, 80, 0x18, get) for i in range(3)]
           + [S.pkt(t + 2000, W, A, w, a, TCP, 80, 41000, 0x18, b'HTTP/1.1 200 OK\r\n\r\n')])
    tags['web'] = 15
    t = T0 + 44_000_000                                                          # F16 victim <-> Internet relayed by A
    S.flow([S.pkt(t, V, A, v, I, TCP, 50500, 443, 0x18, b'y' * 10), S.pkt(t + 100, A, G, v, I, TCP, 50500, 443, 0x18, b'y' * 10),
            S.pkt(t + 900, G, A, I, v, TCP, 443, 50500, 0x18, b'z' * 10), S.pkt(t + 1000, A, V, I, v, TCP, 443, 50500, 0x18, b'z' * 10)])
    tags['relayed'] = 16
    for i in range(3):                                                           # F17 forged DNS answers (IP g, MAC A)
        t = T0 + 45_000_000 + i * 100_000
        S.flow([S.pkt(t, V, A, v, g, UDP, 53101 + i, 53, 0, q), S.pkt(t + 700, A, V, g, v, UDP, 53, 53101 + i, 0, ans)])
    tags['forged'] = [17, 18, 19]
    t = T0 + 240_000_000                                                         # F18 second instance of F11's 5-tuple
    S.flow([S.pkt(t, D, G, d, I, TCP, 50000, 443, 0x18, b'x'), S.pkt(t + 50, G, D, I, d, TCP, 443, 50000, 0x18, b'x'),
            S.pkt(t + 90, D, G, d, I, TCP, 50000, 443, 0x18, b'x')])
    tags['tls2'] = 20
    t = T0 + 300_000_100                                                         # F19 FIN split within one second
    S.flow([S.pkt(t, D, G, d, I2, TCP, 50600, 80, 0x02), S.pkt(t + 1000, G, D, I2, d, TCP, 80, 50600, 0x12),
            S.pkt(t + 2000, D, G, d, I2, TCP, 50600, 80, 0x11)])
    S.flow([S.pkt(t + 300_000, G, D, I2, d, TCP, 80, 50600, 0x10), S.pkt(t + 400_000, D, G, d, I2, TCP, 50600, 80, 0x10)])
    tags['fin'] = [21, 22]
    S.ip6(T0 + 301_000_000, D, '33:33:00:00:00:fb')                              # no CSV row: unmatched frame
    S.rows.append({**S.rows[tags['tls1']], 'Dst IP': '1.1.1.1', 'Flow ID': 'x',  # CSV row without packets
                   'Timestamp': pd.Timestamp(T0 / 1e6 + 500 - 4 * 3600, unit='s').strftime(TS_FMT)})
    tags['nopk'] = 23
    S.frames.sort(key=lambda x: x[0])
    return S, tags, {'G': G, 'A': A, 'V': V, 'D': D}, {'g': g, 'a': a, 'v': v, 'd': d, 'I': I}


def self_test():
    ns = argparse.Namespace(gateway_mac=None, attacker_mac=None, attacker_ip=None, web_attack='sqli', force=False,
                            max_rows=None, max_packets=None, backend='builtin', no_cache=False, tz_offset_hours=None)
    S, tags, M, IP = _scenario()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        half = len(S.frames) // 2
        _write_pcap(td / 'cap.pcap', S.frames[:half])
        _write_pcapng(td / 'cap1.pcapng', S.frames[half:])
        got = [(t, b) for f in ('cap.pcap', 'cap1.pcapng') for t, lt, b in iter_frames(td / f, 'builtin')]
        assert got == S.frames, 'builtin reader'
        if HAVE_DPKT:
            got2 = [(t, b) for f in ('cap.pcap', 'cap1.pcapng') for t, lt, b in iter_frames(td / f, 'dpkt')]
            assert got2 == S.frames, 'dpkt reader'
        print(f'  [ok] classic pcap (us) and pcapng (ns resolution) readers return every frame and timestamp'
              f'{" (builtin and dpkt)" if HAVE_DPKT else " (builtin; dpkt not installed)"}')
        csv = td / 'cap.pcap_Flow.csv'
        pd.DataFrame(S.rows).to_csv(csv, index=False)
        ipt = rv2.IPTable()
        bp = [(IP['d'], IP['I']), (IP['d'], IP['g']), (IP['a'], IP['g'])]
        bs, bd = ipt.encode(pd.Series([x for x, _ in bp])), ipt.encode(pd.Series([y for _, y in bp]))
        B = {'pairs': np.unique(rv2.pair_c(bs, bd)), 'addr_flows': None}
        pcaps = [td / 'cap.pcap', td / 'cap1.pcapng']
        out = td / 'out'

        # derivation of the attacker MAC for every kind (parse with the kind's signature codes)
        c = rv2.read_arrays([str(csv)], ipt, rv2.BASE_COLS, verbose=False)
        fkey, keys = flow_keys(c, ipt)
        for kind in ('bruteforce', 'web', 'dns', 'arp'):
            P, macs, ips, _ = load_packets(pcaps, keys, kind, 'sqli', None, 'x', 'builtin', None, False)
            R, s, attpk = derive_roles(P, macs, ips, kind, ns)
            assert R['attacker_macs'] == [M['A']], (kind, R['attacker_macs'], R['signature_frames_by_source_mac'])
            assert R['gateway_mac'] == M['G'] and R['attacker_ips'] == [IP['a']], (kind, R['gateway_mac'], R['attacker_ips'])
            exp_v = {'bruteforce': [IP['v']], 'web': ['192.168.137.86'], 'dns': [IP['v']],
                     'arp': sorted([IP['g'], IP['v']])}[kind]
            assert sorted(R['victim_ips']) == exp_v, (kind, R['victim_ips'])
            assert int(s.sum()) == {'bruteforce': 20, 'web': 3, 'dns': 3, 'arp': 10}[kind], (kind, int(s.sum()))
        print('  [ok] attacker MAC, gateway MAC, attacker IP and victims derived for bruteforce / web (sqli) / dns / arp')
        # owners: attacker MAC 1 forges ARP requests for the gateway IP 0 (the gateway MAC 0 sends none) and relays
        # the victim's (MAC 2, IP 2) packets; its own IP 1 is the only address it owns
        Po = {'arp': np.array([[0, 1, 1, 0, 9, 3], [1, 1, 1, 1, 9, 3], [2, 1, 2, 2, 9, 0]], np.int64),
              'cat': np.zeros(6, np.int8), 'sip': np.array([0, 0, 2, 2, 2, 1], np.int32),
              'smac': np.array([0, 0, 2, 1, 1, 1], np.int32)}
        assert ip_owners(Po, 4, -2, exclude=[1]).tolist() == [0, 1, 2, -1]
        assert ip_owners(Po, 4, -2).tolist() == [1, 1, 2, -1]            # without exclusion the forgery would win
        print('  [ok] IP owners: a forged ARP request or relayed packets never make the attacker own the address')

        # full run (bruteforce kind): mapping, labels, scores, outputs, resume
        res = run_capture('Synthetic', 'BruteForce', 'BruteForce', pcaps, [csv], 'bruteforce', ipt, B, out, ns,
                          audit_path=None)
        mp = res['mapping']
        assert res['time_offset']['hours'] == -4.0 and res['time_offset']['agreement'] == 1.0, res['time_offset']
        assert mp['csv_flows'] == 24 and mp['csv_flows_matched'] == 23, mp
        assert mp['csv_flows_exact_packet_count_share_of_matched'] == 1.0, mp
        assert mp['csv_exact_duplicate_rows'] == 1 and mp['frames'] - mp['frames_matched'] == 1, mp
        lab = pd.read_csv(out / 'flow_labels.csv.gz')
        inv = set(np.flatnonzero(lab['attacker_involved']).tolist())
        exp = {tags['arp'], *tags['bf'], tags['dns_att'], tags['web'], tags['relayed'], *tags['forged']}
        assert inv == exp, (sorted(inv), sorted(exp))
        assert set(np.flatnonzero(lab['relayed']).tolist()) == {tags['arp'], tags['relayed'], *tags['forged']}
        assert set(np.flatnonzero(lab['attacker_victim']).tolist()) == {*tags['bf'], tags['relayed'], *tags['forged']}
        assert set(np.flatnonzero(lab['attacker_endpoint']).tolist()) == {*tags['bf'], tags['dns_att'], tags['web']}
        assert lab.loc[tags['nopk'], 'matched_packets'] == 0 and (lab['matched_packets'][lab['matched_packets'] > 0]
                                                                   == lab['csv_packets'][lab['matched_packets'] > 0]).all()
        sc = res['scores']['attacker_involved']
        assert (sc['R1_external']['flagged_attacker'], sc['R1_external']['flagged_background']) == (2, 4), sc['R1_external']
        assert sc['R1_external']['precision_background'] == round(4 / 6, 4) and sc['R1_external']['false_removal_rate'] == round(2 / 17, 4)
        assert sc['R2_service']['flagged_attacker'] == 4 and sc['R3_benign_pair']['flagged_attacker'] == 1, sc
        assert res['labels']['attacker_involved'] == 17 and res['labels']['scored_flows'] == 23
        hv = res['flow_heuristic_vs_mac']
        assert hv['heuristic_attackers'] == [IP['a']] and hv['signature']['precision'] == 1.0, hv
        assert (out / 'flow_labels.npz').exists() and (out / 'parsed' / 'cap.pcap.npz').exists()
        print('  [ok] time offset (-4 h), packet->flow mapping (timeout split, FIN split in one second, duplicate '
              'CSV row, unmatched frame and flow), labels (involved / relayed / attacker_victim / endpoint)')
        print('  [ok] R1/R2/R3 precision, recall and false removals against the MAC label; heuristic vs MAC; outputs')
        res2 = run_capture('Synthetic', 'BruteForce', 'BruteForce', pcaps, [csv], 'bruteforce', ipt, B, out, ns,
                           audit_path=None)
        assert res2['scores'] == json.loads(json.dumps(res['scores'], default=rv._json))
        ns.force = True
        (out / 'parsed' / 'cap1.pcapng.npz').unlink()
        res3 = run_capture('Synthetic', 'BruteForce', 'BruteForce', pcaps, [csv], 'bruteforce', ipt, B, out, ns,
                           audit_path=None)
        assert json.loads(json.dumps(res3['scores'], default=rv._json)) == res2['scores']
        ns.force, ns.max_packets = False, 10 ** 9              # other settings: the finished JSON is not reused
        res4 = run_capture('Synthetic', 'BruteForce', 'BruteForce', pcaps, [csv], 'bruteforce', ipt, B, out, ns,
                           audit_path=None)
        assert res4['run_key']['max_packets'] == 10 ** 9 and res4['test_run'] and 'seconds' in res4
        ns.max_packets = None
        print('  [ok] resume: finished JSON skipped; a missing cache file is re-parsed, cached files reused; a JSON '
              'made with other settings is recomputed')

        # parser throughput on synthetic frames
        big = [(S.frames[i % len(S.frames)][0] + i, S.frames[i % len(S.frames)][1]) for i in range(200_000)]
        _write_pcap(td / 'big.pcap', big)
        t = time.time()
        arr, meta = parse_file(td / 'big.pcap', keys, 'web', re.compile(WEB_PATTERNS['sqli']), 'builtin')
        print(f'  [info] parser throughput: {len(big) / (time.time() - t):,.0f} frames/s (builtin reader, web kind)')
    print('[self-test] all checks passed')


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description='Packet-level (MAC) validation of the background rules R1-R3.')
    ap.add_argument('--pcap-dir', help='folder with the pcap/pcapng files of one capture')
    ap.add_argument('--pattern', default='*.pcap*', help='file pattern inside --pcap-dir (default *.pcap*)')
    ap.add_argument('--capture', help='capture name (substring), e.g. BruteForce, Sqlinjection, "DNS Spoofing"')
    ap.add_argument('--csv', nargs='+', help='flow CSVs of the capture (default: from --capture / pcap names)')
    ap.add_argument('--kind', choices=KINDS, help='signature rule (default: from the capture name)')
    ap.add_argument('--web-attack', choices=sorted(WEB_PATTERNS) + ['none'], help='payload pattern for kind web')
    ap.add_argument('--attacker-mac', nargs='+', help='override: attacker MAC address(es)')
    ap.add_argument('--attacker-ip', nargs='+', help='override: attacker IP(s); MAC = owner of the address')
    ap.add_argument('--gateway-mac', help='override: gateway MAC address')
    ap.add_argument('--tz-offset-hours', type=float, help='override: CSV local time minus UTC, in hours')
    ap.add_argument('--out', default=str(OUT_DEFAULT), help='output root')
    ap.add_argument('--force', action='store_true', help='recompute although the JSON exists')
    ap.add_argument('--no-cache', action='store_true', help='re-parse the pcaps although a cache exists')
    ap.add_argument('--backend', choices=('auto', 'dpkt', 'builtin'), default='auto', help='pcap reader')
    ap.add_argument('--max-packets', type=int, help='TEST ONLY: read at most N frames per pcap file')
    ap.add_argument('--max-rows', type=int, help='TEST ONLY: read at most N rows per CSV file')
    ap.add_argument('--self-test', action='store_true', help='synthetic packets only, no data read')
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.pcap_dir:
        ap.error('--pcap-dir is required')
    if a.backend == 'dpkt' and not HAVE_DPKT:
        raise SystemExit('dpkt is not installed: pip install dpkt  (or use --backend builtin)')
    pdir = Path(a.pcap_dir)
    pcaps = sorted(p for p in pdir.glob(a.pattern) if p.is_file() and not p.name.endswith('_Flow.csv'))
    if not pcaps:
        raise SystemExit(f'no files matching {a.pattern} in {pdir}')
    name, cls, sub, csvs, kind = resolve(a, pcaps)
    out = Path(a.out) / rv2._slug(name)
    print(f'[plan] {name}: {len(pcaps)} pcap file(s) ({sum(p.stat().st_size for p in pcaps) / 1e6:,.0f} MB), '
          f'{len(csvs)} flow CSV(s), kind={kind}, reader={"dpkt" if (a.backend != "builtin" and HAVE_DPKT) else "builtin"}'
          f' -> {out}', flush=True)
    if not a.force and finished(out / 'pcap_validation.json', run_key(a, kind, pcaps, csvs)) is not None:
        print(f'[skip] {out / "pcap_validation.json"} exists (use --force to recompute)', flush=True)
        return
    t0 = time.time()
    ipt = rv2.IPTable()
    print('[1] Benign flow CSVs: IP-pair set for R3', flush=True)
    bc, B = rv2.load_benign(ipt, a.max_rows)
    del bc
    gc.collect()
    print(f'    {B["flows"]:,} Benign flows, {len(B["pairs"]):,} IP pairs ({time.time() - t0:.0f} s)', flush=True)
    run_capture(name, cls, sub, pcaps, csvs, kind, ipt, B, out, a)


if __name__ == '__main__':
    main()
