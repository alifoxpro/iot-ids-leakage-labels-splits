# Evidence brief: DDOS

Distributed denial of service: several attacking devices flood one or more victims at the same time. Four captures: ACK Fragmentation, HTTP Flood, ICMP Flood and ICMP Fragmentation.

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## DDOS ACK Fragmentation

- Flow files: DDoS-ACK_Fragmentation*.pcap_Flow.csv (13 files). Flows in the capture: 2,450,086 (all traffic recorded during the session). Packets: 19,246,485.
- Capture period (first and last flow start): 25/10/2022 09:26:00 AM to 26/10/2022 05:21:00 PM.
- Attack window (first and last pattern flow to an identified victim): 25/10/2022 09:26:00 AM to 26/10/2022 05:20:14 PM (1,914.2 minutes); 99.95% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: ackfrag

TCP flows with the ACK flag, without SYN, with payload and at most one packet (or at most half as many packets) in the reverse direction; or protocol-0 flows (IP fragments without a transport header) with at least 10 packets and at most a tenth as many in the reverse direction. ARP pseudo-flows are excluded.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 2,354,939 of 2,450,086 flows of the capture (96.1%), carrying 93.3% of its packets.
- Victims (20; together they receive 74.6% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.46 | 120,113 | 955,882 |
| 192.168.137.33 | 99,906 | 900,058 |
| 192.168.137.71 | 107,442 | 803,122 |
| 192.168.137.171 | 79,038 | 724,308 |
| 192.168.137.194 | 88,815 | 669,629 |
| 192.168.137.235 | 89,622 | 693,598 |
| 192.168.137.206 | 77,377 | 674,616 |
| 192.168.137.247 | 94,786 | 730,140 |
| 192.168.137.187 | 97,806 | 666,566 |
| 192.168.137.10 | 70,407 | 578,419 |
| 192.168.137.195 | 77,403 | 632,351 |
| 192.168.137.132 | 47,689 | 537,701 |
| 192.168.137.109 | 55,759 | 517,956 |
| 192.168.137.131 | 114,167 | 593,723 |
| 192.168.137.241 | 41,793 | 496,064 |
| 192.168.137.91 | 83,680 | 587,719 |
| 192.168.137.157 | 63,203 | 520,261 |
| 192.168.137.228 | 45,423 | 466,527 |
| 192.168.137.85 | 48,832 | 467,146 |
| 192.168.137.24 | 37,264 | 424,955 |

- The cap of 20 victims binds: the listed victims receive only 74.6% of the pattern packets addressed to testbed hosts, so further hosts also receive flood traffic.

- No small set of victim ports covers most of the pattern packets (the flood uses many destination ports), so the pattern counts at the level of the victim host.

- Attackers (accepted; they send 88.6% of the pattern packets to the victims): 192.168.137.17, 192.168.137.65, 192.168.137.42, 192.168.137.12, 192.168.137.196, 192.168.137.20.
- Distinct senders of pattern flows to the victims: 196; flows from senders outside the testbed: 1,052 (0.070% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.17 | 423,932 | 2,885,590 | yes | yes |
| 192.168.137.65 | 362,937 | 2,598,571 | yes | yes |
| 192.168.137.42 | 186,455 | 1,663,386 | yes | yes |
| 192.168.137.12 | 160,743 | 1,599,337 | yes | yes |
| 192.168.137.20 | 132,814 | 1,218,999 | yes | yes |
| 192.168.137.196 | 131,293 | 1,239,163 | yes | yes |
| 192.168.137.186 | 94,836 | 961,459 | yes | no |
| 192.168.137.121 | 46,248 | 467,081 | yes | no |
| 192.168.137.246 | 160 | 595 | yes | no |
| 192.168.137.89 | 43 | 975 | yes | no |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 6668 | 745,464 | 1,548,180 |
| 554 | 289,019 | 600,985 |
| 443 | 94,677 | 196,508 |
| 8008 | 89,426 | 182,400 |
| 1443 | 83,468 | 177,096 |
| 55442 | 77,277 | 163,185 |
| 10002 | 63,164 | 133,536 |
| 8009 | 48,454 | 99,084 |

- Typical pattern flow to a victim: median 2 packets per flow, median below 0.1 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.123 <-> 192.168.137.65 | 85,911 | TCP/53 |
| 192.168.137.17 <-> 192.168.137.194 | 78,493 | TCP/6668 |
| 192.168.137.131 <-> 192.168.137.17 | 76,313 | TCP/554 |
| 192.168.137.17 <-> 192.168.137.71 | 68,006 | TCP/6668 |
| 192.168.137.20 <-> 192.168.137.204 | 63,429 | TCP/80 |
| 192.168.137.17 <-> 192.168.137.46 | 62,206 | TCP/6668 |
| 192.168.137.204 <-> 192.168.137.42 | 59,856 | TCP/80 |
| 192.168.137.12 <-> 192.168.137.204 | 56,981 | TCP/80 |

Limits: The pattern is not specific: ordinary TCP traffic with little return traffic (one-way data, keep-alives, a flow cut by a timeout) can match it. At most 20 victims and 50 attackers are listed.

## DDOS HTTP FLOOD

- Flow files: DDoS-HTTP_Flood-.pcap_Flow.csv. Flows in the capture: 505,720 (all traffic recorded during the session). Packets: 2,723,549.
- Capture period (first and last flow start): 14/09/2022 10:47:00 AM to 07/11/2022 03:46:00 PM.
- Attack window (first and last TCP 80/8080 flow between an identified attacker and victim): 14/09/2022 10:47:03 AM to 07/11/2022 03:45:59 PM (78,058.9 minutes); 99.99% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: web

TCP flows with port 80 or 8080 on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 489,502 of 505,720 (96.8%); 487,599 of them run between two testbed hosts and 1,903 have an endpoint outside the testbed.
- Attackers (client side; they account for 81.4% of the port-pattern flows between testbed hosts): 192.168.137.178, 192.168.137.89, 192.168.137.82, 192.168.137.225, 192.168.137.186, 192.168.137.64, 192.168.137.238, 192.168.137.17, 192.168.137.212, 192.168.137.23.
- Victims (server side; they account for 83.7% of the attackers' port-pattern flows): 192.168.137.132, 192.168.137.139, 192.168.137.150, 192.168.137.44, 192.168.137.133.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.132 <-> 192.168.137.89 | 38,154 | TCP/8080 |
| 192.168.137.132 <-> 192.168.137.225 | 31,703 | TCP/8080 |
| 192.168.137.132 <-> 192.168.137.64 | 30,095 | TCP/8080 |
| 192.168.137.132 <-> 192.168.137.178 | 29,395 | TCP/8080 |
| 192.168.137.132 <-> 192.168.137.238 | 26,247 | TCP/8080 |
| 192.168.137.139 <-> 192.168.137.178 | 24,773 | TCP/80 |
| 192.168.137.150 <-> 192.168.137.186 | 13,841 | TCP/80 |
| 192.168.137.132 <-> 192.168.137.90 | 13,530 | TCP/8080 |

- Most frequent hosts on the server side of all pattern flows: 192.168.137.132 (177,226), 192.168.137.139 (76,103), 192.168.137.150 (56,692), 192.168.137.44 (49,516), 192.168.137.133 (44,251), 192.168.137.114 (38,801).

Limits: Attackers and victims were sought among testbed addresses only. HTTP between testbed hosts can also be ordinary traffic (device web interfaces, local streaming or control services). Payloads are not in the flow records.

## DDOS ICMP FLOOD

- Flow files: DDoS-ICMP_Flood*.pcap_Flow.csv (27 files). Flows in the capture: 202,251 (all traffic recorded during the session). Packets: 719,635,485.
- Capture period (first and last flow start): 06/09/2022 12:57:00 PM to 28/11/2022 04:01:59 PM.
- Attack window (first and last pattern flow to an identified victim): 06/09/2022 12:57:06 PM to 28/11/2022 04:01:56 PM (119,704.8 minutes); 99.95% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: proto0flood

Protocol-0 flows (ICMP, GRE, IP fragments) with at least 1,000 packets; ARP pseudo-flows are excluded.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 2,141 of 202,251 flows of the capture (1.1%), carrying 99.6% of its packets.
- Victims (20; together they receive 50.3% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.44 | 138 | 46,166,581 |
| 192.168.137.136 | 78 | 29,992,181 |
| 192.168.137.154 | 42 | 20,259,719 |
| 192.168.137.85 | 42 | 17,796,187 |
| 192.168.137.124 | 42 | 17,455,939 |
| 192.168.137.222 | 42 | 16,975,320 |
| 192.168.137.157 | 42 | 16,139,088 |
| 192.168.137.211 | 39 | 16,116,973 |
| 192.168.137.93 | 42 | 15,956,181 |
| 192.168.137.254 | 41 | 15,785,515 |
| 192.168.137.245 | 37 | 15,381,995 |
| 192.168.137.52 | 39 | 15,156,230 |
| 192.168.137.102 | 38 | 15,127,160 |
| 192.168.137.59 | 43 | 14,974,697 |
| 192.168.137.207 | 43 | 14,904,483 |
| 192.168.137.134 | 49 | 14,693,823 |
| 192.168.137.187 | 0 | 0 |
| 192.168.137.95 | 0 | 0 |
| 192.168.137.128 | 0 | 0 |
| 192.168.137.84 | 0 | 0 |

- A victim with 0 pattern flows in this table has no endpoint among the victim endpoints listed below (the fewest endpoints that receive at least 80% of the victims' pattern packets); it still receives pattern traffic, which the table does not count.

- The cap of 20 victims binds: the listed victims receive only 50.3% of the pattern packets addressed to testbed hosts, so further hosts also receive flood traffic.

- The pattern is restricted to these victim endpoints (host:port; port 0 = no port), which receive 83.9% of the victims' pattern packets: 192.168.137.44:0, 192.168.137.136:0, 192.168.137.154:0, 192.168.137.85:0, 192.168.137.124:0, 192.168.137.222:0, 192.168.137.157:0, 192.168.137.211:0, 192.168.137.93:0, 192.168.137.254:0, 192.168.137.245:0, 192.168.137.52:0, 192.168.137.102:0, 192.168.137.59:0, 192.168.137.207:0, 192.168.137.134:0.

- Attackers (accepted; they send 84.5% of the pattern packets to the victims): 192.168.137.114, 192.168.137.117, 192.168.137.170, 192.168.137.30, 192.168.137.190, 192.168.137.125, 192.168.137.43, 192.168.137.198, 192.168.137.214, 192.168.137.23, 192.168.137.81.
- Distinct senders of pattern flows to the victims: 21; flows from senders outside the testbed: 0 (0.0% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.43 | 74 | 19,595,189 | yes | yes |
| 192.168.137.30 | 74 | 25,531,182 | yes | yes |
| 192.168.137.114 | 73 | 37,063,937 | yes | yes |
| 192.168.137.170 | 72 | 26,566,442 | yes | yes |
| 192.168.137.190 | 71 | 25,239,129 | yes | yes |
| 192.168.137.125 | 71 | 23,232,951 | yes | yes |
| 192.168.137.117 | 70 | 33,794,170 | yes | yes |
| 192.168.137.81 | 38 | 14,245,332 | yes | yes |
| 192.168.137.216 | 37 | 10,761,340 | yes | no |
| 192.168.137.108 | 37 | 14,047,186 | yes | no |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 0 | 797 | 302,882,072 |

- Typical pattern flow to a victim: median 350,623 packets per flow, median 3,301 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.198 <-> 192.168.137.44 | 14 | proto0/0 |
| 192.168.137.214 <-> 192.168.137.44 | 14 | proto0/0 |
| 192.168.137.44 <-> 192.168.137.81 | 14 | proto0/0 |
| 192.168.137.216 <-> 192.168.137.44 | 14 | proto0/0 |
| 192.168.137.108 <-> 192.168.137.44 | 14 | proto0/0 |
| 192.168.137.44 <-> 192.168.137.64 | 13 | proto0/0 |
| 192.168.137.23 <-> 192.168.137.44 | 12 | proto0/0 |
| 192.168.137.114 <-> 192.168.137.182 | 7 | proto0/0 |

Limits: Only flows with at least 1,000 packets define the pattern; the flood streams of CICFlowMeter can also leave short protocol-0 flows (streams split by timeouts, replies). At most 20 victims are listed.

## DDOS ICMP Fragmentation

- Flow files: DDoS-ICMP_Fragmentation*.pcap_Flow.csv (20 files). Flows in the capture: 320,757 (all traffic recorded during the session). Packets: 44,873,040.
- Capture period (first and last flow start): 04/10/2022 01:55:00 PM to 29/11/2022 04:40:59 PM.
- Attack window (first and last pattern flow to an identified victim): 04/10/2022 02:32:15 PM to 13/10/2022 03:17:18 PM (13,005.0 minutes); 93.7% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: proto0flood

Protocol-0 flows (ICMP, GRE, IP fragments) with at least 1,000 packets; ARP pseudo-flows are excluded.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 2,133 of 320,757 flows of the capture (0.7%), carrying 92.6% of its packets.
- Victims (20; together they receive 53.7% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.79 | 72 | 1,688,189 |
| 192.168.137.192 | 23 | 1,402,934 |
| 192.168.137.61 | 42 | 1,365,684 |
| 192.168.137.83 | 40 | 1,356,476 |
| 192.168.137.224 | 40 | 1,322,163 |
| 192.168.137.7 | 42 | 1,250,177 |
| 192.168.137.67 | 34 | 1,244,993 |
| 192.168.137.95 | 39 | 1,173,776 |
| 192.168.137.134 | 79 | 1,162,207 |
| 192.168.137.235 | 38 | 1,102,703 |
| 192.168.137.228 | 41 | 1,051,104 |
| 192.168.137.139 | 40 | 1,051,056 |
| 192.168.137.187 | 41 | 1,014,204 |
| 192.168.137.181 | 41 | 955,193 |
| 192.168.137.209 | 33 | 916,260 |
| 192.168.137.132 | 0 | 0 |
| 192.168.137.245 | 0 | 0 |
| 192.168.137.35 | 0 | 0 |
| 192.168.137.151 | 0 | 0 |
| 192.168.137.22 | 0 | 0 |

- A victim with 0 pattern flows in this table has no endpoint among the victim endpoints listed below (the fewest endpoints that receive at least 80% of the victims' pattern packets); it still receives pattern traffic, which the table does not count.

- The cap of 20 victims binds: the listed victims receive only 53.7% of the pattern packets addressed to testbed hosts, so further hosts also receive flood traffic.

- The pattern is restricted to these victim endpoints (host:port; port 0 = no port), which receive 80.8% of the victims' pattern packets: 192.168.137.79:0, 192.168.137.192:0, 192.168.137.61:0, 192.168.137.83:0, 192.168.137.224:0, 192.168.137.7:0, 192.168.137.67:0, 192.168.137.95:0, 192.168.137.134:0, 192.168.137.235:0, 192.168.137.228:0, 192.168.137.139:0, 192.168.137.187:0, 192.168.137.181:0, 192.168.137.209:0.

- Attackers (accepted; they send 83.0% of the pattern packets to the victims): 192.168.137.248, 192.168.137.221, 192.168.137.246, 192.168.137.203, 192.168.137.165, 192.168.137.240, 192.168.137.128, 192.168.137.44, 192.168.137.245.
- Distinct senders of pattern flows to the victims: 21; flows from senders outside the testbed: 0 (0.0% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.248 | 70 | 2,373,674 | yes | yes |
| 192.168.137.221 | 67 | 2,359,620 | yes | yes |
| 192.168.137.246 | 66 | 2,056,210 | yes | yes |
| 192.168.137.128 | 62 | 1,462,907 | yes | yes |
| 192.168.137.203 | 62 | 1,926,859 | yes | yes |
| 192.168.137.240 | 62 | 1,620,958 | yes | yes |
| 192.168.137.165 | 61 | 1,772,875 | yes | yes |
| 192.168.137.142 | 24 | 478,862 | yes | no |
| 192.168.137.44 | 23 | 777,170 | yes | yes |
| 192.168.137.245 | 22 | 637,341 | yes | yes |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 0 | 645 | 18,057,119 |

- Typical pattern flow to a victim: median 24,063 packets per flow, median 244.8 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.203 <-> 192.168.137.95 | 7 | proto0/0 |
| 192.168.137.248 <-> 192.168.137.95 | 7 | proto0/0 |
| 192.168.137.134 <-> 192.168.137.27 | 7 | proto0/0 |
| 192.168.137.127 <-> 192.168.137.134 | 7 | proto0/0 |
| 192.168.137.134 <-> 192.168.137.178 | 7 | proto0/0 |
| 192.168.137.248 <-> 192.168.137.7 | 7 | proto0/0 |
| 192.168.137.246 <-> 192.168.137.7 | 7 | proto0/0 |
| 192.168.137.246 <-> 192.168.137.35 | 7 | proto0/0 |

Limits: Only flows with at least 1,000 packets define the pattern; the flood streams of CICFlowMeter can also leave short protocol-0 flows (streams split by timeouts, replies). At most 20 victims are listed.
