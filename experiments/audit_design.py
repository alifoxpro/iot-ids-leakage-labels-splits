# -*- coding: utf-8 -*-
r"""
audit_design.py
===============
Round-2 review (Reviewer 1, point 2): the exact sampling, de-duplication and weighting of the 472-flow audit,
its stratum counts and inclusion probabilities, and the estimands of the reported audit numbers. Reads only
existing files of rule_validation2.py and the language-model audit; nothing is sampled or labelled again.

Sampling (rule_validation2.py, part 3): every flow of the 15 attack captures (all raw flows, not only the
experimental sample) gets a pseudo-random key from a hash of (file, row) with seed 42. For each attack class
and each of the eight strata  {R1, R2, R3, any rule} x {flagged, kept}  the 20 flows with the smallest keys
are taken (bottom-20 = simple random sampling without replacement of 20 of the N_s flows of the stratum; all
flows when N_s < 20). The keys are shared by the strata, so one flow can be selected for several strata; it
appears once in the sample (de-duplication on file and row) and is used in every stratum it was selected for
(column selected_strata). 7 classes x 8 strata x 20 = 1,120 stratum slots give the 472 distinct flows.
Inclusion probabilities
  within a stratum            pi_s = n_s / N_s (exact: bottom-k of i.i.d. uniform keys is an SRS)
  of a flow in the 472        between max_s pi_s and min(1, sum_s pi_s) over the strata that contain it
                              (the selections share the keys, so they are positively dependent)
Estimands (all per class; unclear decisions excluded unless stated; flows judged by the language-model audit,
not verified by a human):
  background share of the flagged flows   B_s / (B_s + A_s) in the stratum 'rule: flagged'  (Wilson 95%)
  attack share of the kept flows          A_s / (A_s + B_s) in the stratum 'rule: kept'     (Wilson 95%)
  share of the class's attack flows removed by the rule (false-removal rate)
                                          F (1 - p_f) / (F (1 - p_f) + K p_k), F, K = N of the flagged and kept
                                          strata (the stratum weights), p_f, p_k the two shares above; Jeffreys
                                          interval by numerical integration (llm_audit/audit_summary.json)
  Fig. 2e and Table 2 use the 'any rule' strata: 20 flagged by any rule + 20 kept by all rules per class
  = 280 distinct flows (a flow cannot be in both). No weights are needed inside a stratum (each is an SRS);
  between the flagged and kept strata the weights are F and K. Sensitivity: unclear counted as attack
  (worst case for the rules) and as background, written next to every estimate.

Output: results_2026_03_03/q1_revision/rule_validation2/design/
          strata.csv      class x rule x status: N, n, pi, decisions (attack, background, unclear),
                          flows also selected for other strata
          flows.csv       the 472 flows: class, capture, strata, pi per stratum, bounds of the overall pi,
                          final decision
          estimands.csv   per class and rule: the three estimands with intervals, unclear excluded / as attack /
                          as background
          design.json     the description above and the totals (1,120 slots, 472 flows, 280 in the any-rule strata)
Run: & $py experiments\audit_design.py
"""
import json, math, sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
RV2 = HERE.parent / 'results_2026_03_03' / 'q1_revision' / 'rule_validation2'
OUT = RV2 / 'design'
RULES = ['R1_external', 'R2_service', 'R3_benign_pair', 'any']
STATUS = ['flagged', 'kept']
K_PER = 20


def wilson(k, n, z=1.959964):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def frr(F, K, pf_bg, pk_att):
    """share of attack flows removed: F (1 - p_f) / (F (1 - p_f) + K p_k)."""
    if pf_bg is None or pk_att is None:
        return None
    den = F * (1 - pf_bg) + K * pk_att
    return None if den == 0 else round(F * (1 - pf_bg) / den, 4)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sample = pd.read_csv(RV2 / 'audit_sample.csv', keep_default_na=False)
    counts = json.load(open(RV2 / 'audit_strata_counts.json', encoding='utf-8'))
    dec = pd.read_csv(RV2 / 'llm_audit' / 'final_decisions.csv', keep_default_na=False)
    summ = json.load(open(RV2 / 'llm_audit' / 'audit_summary.json', encoding='utf-8'))
    sample = sample.merge(dec[['sample_id', 'decision']], on='sample_id', how='left')
    assert sample['decision'].isin(['attack', 'background', 'unclear']).all(), 'missing final decisions'
    st = sample['selected_strata'].str.split(';')

    strata, est = [], []
    for cls in counts:
        g = sample[sample['class'] == cls]
        gs = st[g.index]
        for r in RULES:
            row_est = {'class': cls, 'rule': r}
            for s in STATUS:
                key = f'{r}:{s}'
                m = gs.map(lambda x: key in x)
                h = g[m]
                N, n = counts[cls][r][s], int(len(h))
                vc = h['decision'].value_counts()
                strata.append({'class': cls, 'rule': r, 'status': s, 'N': N, 'n': n,
                               'pi': round(n / N, 8) if N else None,
                               'attack': int(vc.get('attack', 0)), 'background': int(vc.get('background', 0)),
                               'unclear': int(vc.get('unclear', 0)),
                               'also_selected_for_other_strata': int((gs[m].map(len) > 1).sum())})
                a, b, u = (int(vc.get(k, 0)) for k in ('attack', 'background', 'unclear'))
                if s == 'flagged':
                    row_est.update({'F': N, 'flagged_n': n, 'bg_share': None if a + b == 0 else round(b / (a + b), 4),
                                    'bg_share_ci95': wilson(b, a + b), 'bg_share_unclear_as_attack': None if n == 0 else round(b / n, 4),
                                    'bg_share_unclear_as_background': None if n == 0 else round((b + u) / n, 4)})
                else:
                    row_est.update({'K': N, 'kept_n': n, 'att_share': None if a + b == 0 else round(a / (a + b), 4),
                                    'att_share_ci95': wilson(a, a + b), 'att_share_unclear_as_attack': None if n == 0 else round((a + u) / n, 4),
                                    'att_share_unclear_as_background': None if n == 0 else round(a / n, 4)})
            row_est['removed_share'] = frr(row_est['F'], row_est['K'], row_est['bg_share'], row_est['att_share'])
            row_est['removed_share_worst'] = frr(row_est['F'], row_est['K'], row_est['bg_share_unclear_as_attack'],
                                                 row_est['att_share_unclear_as_background'])
            pc = summ['per_class'].get(cls, {}).get(r, {})
            row_est['removed_share_ci95_jeffreys'] = pc.get('false_removal_ci95_jeffreys')
            est.append(row_est)
    strata = pd.DataFrame(strata)
    pi = {(r['class'], f'{r["rule"]}:{r["status"]}'): r['pi'] for _, r in strata.iterrows()}

    flows = []
    for i, r in sample.iterrows():
        ps = {k: pi[(r['class'], k)] for k in st[i]}
        flows.append({'sample_id': r['sample_id'], 'class': r['class'], 'capture': r['capture'], 'file': r['file'],
                      'row': r['row'], 'strata': ';'.join(st[i]), 'n_strata': len(st[i]),
                      'pi_by_stratum': json.dumps({k: round(v, 8) for k, v in ps.items()}),
                      'pi_lower': round(max(ps.values()), 8), 'pi_upper': round(min(1.0, sum(ps.values())), 8),
                      'in_any_rule_strata': any(k.startswith('any:') for k in st[i]), 'decision': r['decision']})
    flows = pd.DataFrame(flows)
    strata.to_csv(OUT / 'strata.csv', index=False)
    flows.to_csv(OUT / 'flows.csv', index=False)
    e = pd.DataFrame(est)
    for c in [c for c in e.columns if c.endswith('ci95') or c.endswith('jeffreys')]:
        e[c] = e[c].map(lambda v: None if v is None or (isinstance(v, float) and np.isnan(v)) else
                        f'{v[0]}-{v[1]}' if isinstance(v, (list, tuple)) and v[0] is not None else None)
    e.to_csv(OUT / 'estimands.csv', index=False)
    tot = {'classes': len(counts), 'strata_per_class': len(RULES) * len(STATUS), 'per_stratum': K_PER,
           'stratum_slots': int(strata['n'].sum()), 'distinct_flows': int(len(sample)),
           'any_rule_strata_flows': int(flows['in_any_rule_strata'].sum()),
           'flows_in_several_strata': int((flows['n_strata'] > 1).sum()),
           'decisions': sample['decision'].value_counts().to_dict()}
    with open(OUT / 'design.json', 'w', encoding='utf-8') as f:
        json.dump({'description': __doc__.split('Output:')[0].strip(), 'totals': tot,
                   'sources': ['audit_sample.csv', 'audit_strata_counts.json', 'llm_audit/final_decisions.csv',
                               'llm_audit/audit_summary.json']}, f, indent=1)
    print(json.dumps(tot))
    print(strata[strata['rule'] == 'any'].to_string(index=False))


if __name__ == '__main__':
    main()
