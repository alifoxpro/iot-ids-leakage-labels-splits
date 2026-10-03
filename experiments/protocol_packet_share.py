# -*- coding: utf-8 -*-
"""
protocol_packet_share.py
========================
Where is the flood traffic of the ICMP and GRE (Mirai) captures?

CICFlowMeter assigns a protocol number only to TCP (6) and UDP (17); every other IP packet
(ICMP, GRE, IGMP, fragments without a transport header) ends up in flows with protocol 0 and
ports 0. Counting FLOWS, the ICMP captures therefore look like Benign traffic; counting PACKETS
shows whether the flood is hidden in a few long protocol-0 flows.

For every capture group (all rows of all CSV files, no sampling) this script reports, per
protocol value, the share of flows and the share of packets (Total Fwd Packet + Total Bwd
packets), plus the size of the largest protocol-0 flow.
Only five columns are read, in chunks, so memory stays small.
Output: results_2026_03_03/split_pilot/protocol_packet_share.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\protocol_packet_share.py
"""
import json, sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pilot_temporal_split import CLASSES, OUT  # noqa: E402
from relabel_background import capture_groups  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8')
COLS = ['Protocol', 'Total Fwd Packet', 'Total Bwd packets', 'Src Port', 'Dst Port']


def main():
    res = {}
    for cls in CLASSES:
        for sub, files in capture_groups(cls):
            name = f'{cls} / {sub}' if sub != cls else cls
            flows, pkts, max0, ports0 = {}, {}, 0, 0
            for f in files:
                for ch in pd.read_csv(f, usecols=COLS, chunksize=500_000, low_memory=False):
                    ch = ch.dropna(subset=['Protocol'])
                    proto = ch['Protocol'].astype(int)
                    n = ch['Total Fwd Packet'].fillna(0) + ch['Total Bwd packets'].fillna(0)
                    for p, cnt in proto.value_counts().items():
                        flows[int(p)] = flows.get(int(p), 0) + int(cnt)
                    for p, s in n.groupby(proto).sum().items():
                        pkts[int(p)] = pkts.get(int(p), 0) + int(s)
                    z = proto == 0
                    if z.any():
                        max0 = max(max0, int(n[z].max()))
                        ports0 += int(((ch.loc[z, 'Src Port'] != 0) | (ch.loc[z, 'Dst Port'] != 0)).sum())
            F, P = sum(flows.values()), sum(pkts.values())
            res[name] = {'flows': F, 'packets': P,
                         'flow_share': {str(k): round(v / F, 4) for k, v in sorted(flows.items())},
                         'packet_share': {str(k): round(v / P, 4) for k, v in sorted(pkts.items())},
                         'largest_proto0_flow_packets': max0,
                         'proto0_flows_with_nonzero_port': ports0}
            fs, ps = res[name]['flow_share'], res[name]['packet_share']
            print(f'{name:38s} flows={F:>9,} packets={P:>12,}  proto0: {100 * fs.get("0", 0):5.1f}% of flows, '
                  f'{100 * ps.get("0", 0):5.1f}% of packets (largest flow {max0:,} packets)', flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(res, open(OUT / 'protocol_packet_share.json', 'w'), indent=1)
    print('[DONE]', OUT / 'protocol_packet_share.json')


if __name__ == '__main__':
    main()
