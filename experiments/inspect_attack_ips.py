# -*- coding: utf-8 -*-
"""
inspect_attack_ips.py
=====================
Can attack flows be told apart from background traffic inside each attack capture?
CIC IoT-DIAD 2024 labels every flow by the folder of its pcap, so background traffic
recorded during an attack is labelled as the attack. For every capture group this
script reports, from the identifier columns only (Src/Dst IP, ports, Protocol):

  * concentration: share of flows carried by the top-1 / top-5 unordered IP pairs,
    and by the top-3 destination IPs
  * background overlap: share of flows whose unordered IP pair also occurs in the
    Benign captures (a strong hint that the flow is ordinary background traffic)
  * the dominant pairs with their protocol and destination port

Large captures (DOS, DDOS ACK Fragmentation) are read in chunks; only identifier
columns are loaded, so memory stays small.
Output: results_2026_03_03/split_pilot/attack_ip_inspection.json
Run (PowerShell):
  & "C:\\Users\\lenovo\\.conda\\envs\\MyProject\\python.exe" experiments\\inspect_attack_ips.py
"""
import glob, json, sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data' / 'CIC IoT-DIAD 2024'
OUT = ROOT / 'results_2026_03_03' / 'split_pilot'
COLS = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol']
PROTO = {0: 'proto0', 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE'}


def groups():
    for cls_dir in sorted(p for p in DATA.iterdir() if p.is_dir()):
        subs = [p for p in cls_dir.iterdir() if p.is_dir()]
        for g in (subs or [cls_dir]):
            files = [f for f in sorted(glob.glob(str(g / '*.csv')))
                     if 'Src IP' in pd.read_csv(f, nrows=0).columns]      # skip empty stubs
            if files:
                yield cls_dir.name, g.name, files


def scan(files):
    pairs, dst, proto_port, n = Counter(), Counter(), {}, 0
    for f in files:
        for ch in pd.read_csv(f, usecols=COLS, chunksize=1_000_000, low_memory=False):
            n += len(ch)
            a, b = ch['Src IP'].astype(str), ch['Dst IP'].astype(str)
            key = (a.where(a < b, b) + ' <-> ' + b.where(a < b, a))   # unordered pair
            vc = key.value_counts()
            pairs.update(vc.to_dict())
            dst.update(ch['Dst IP'].astype(str).value_counts().to_dict())
            top = set(vc.index[:20])
            sel = ch[key.isin(top)].assign(pair=key[key.isin(top)])
            for pk, gg in sel.groupby('pair'):
                c = proto_port.setdefault(pk, Counter())
                c.update(zip(gg['Protocol'].map(lambda v: PROTO.get(int(v), str(v))),
                             gg['Dst Port'].astype(int)))
    return n, pairs, dst, proto_port


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    benign_files = sorted(glob.glob(str(DATA / 'Benign' / '*.csv')))
    print('[1] collecting Benign IP pairs')
    _, benign_pairs, _, _ = scan(benign_files)
    benign_set = set(benign_pairs)
    print(f'    {len(benign_set):,} distinct IP pairs in the Benign captures\n')

    res = {}
    hdr = f'{"class / capture group":40s} {"flows":>10s} {"top1 pair":>9s} {"top5 pairs":>10s} {"top3 dst":>9s} {"pair seen in Benign":>20s}'
    print(hdr); print('-' * len(hdr))
    for cls, grp, files in groups():
        n, pairs, dst, pp = scan(files)
        top = pairs.most_common(5)
        top1 = top[0][1] / n
        top5 = sum(c for _, c in top) / n
        dst3 = sum(c for _, c in dst.most_common(3)) / n
        bg = sum(c for k, c in pairs.items() if k in benign_set) / n if cls != 'Benign' else float('nan')
        name = f'{cls} / {grp}' if grp != cls else cls
        print(f'{name:40s} {n:>10,} {top1:>9.1%} {top5:>10.1%} {dst3:>9.1%} {bg:>20.1%}')
        res[name] = {
            'flows': n, 'top1_pair_share': round(top1, 4), 'top5_pairs_share': round(top5, 4),
            'top3_dst_share': round(dst3, 4), 'benign_pair_overlap': None if cls == 'Benign' else round(bg, 4),
            'top_pairs': [{'pair': k, 'flows': c, 'share': round(c / n, 4),
                           'main_proto_port': [f'{p}/{port}' for (p, port), _ in pp.get(k, Counter()).most_common(2)]}
                          for k, c in top],
        }

    print('\n=== dominant IP pairs per attack (share, protocol/dst-port) ===')
    for name, r in res.items():
        if name == 'Benign':
            continue
        print(f'\n{name}')
        for t in r['top_pairs'][:3]:
            print(f'   {t["share"]:6.1%}  {t["pair"]:40s} {", ".join(t["main_proto_port"])}')

    json.dump(res, open(OUT / 'attack_ip_inspection.json', 'w'), indent=2)
    print('\n[DONE]', OUT / 'attack_ip_inspection.json')


if __name__ == '__main__':
    main()
