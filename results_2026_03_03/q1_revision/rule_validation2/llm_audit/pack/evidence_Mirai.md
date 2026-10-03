# Evidence brief: Mirai

Attack traffic of the Mirai botnet. The flow files are named greeth_flood, the Mirai GRE flood that encapsulates Ethernet frames in GRE packets (protocol 0 in the flow records).

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## Mirai

- Flow files: Mirai-greeth_flood*.pcap_Flow.csv (29 files). Flows in the capture: 174,588 (all traffic recorded during the session). Packets: 98,807,831.
- Capture period (first and last flow start): 12/01/2023 11:19:00 AM to 18/01/2023 11:52:01 AM.
- Attack window (first and last pattern flow to an identified victim): 12/01/2023 11:19:44 AM to 18/01/2023 10:48:15 AM (8,608.5 minutes); 90.6% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: proto0flood

Protocol-0 flows (ICMP, GRE, IP fragments) with at least 1,000 packets; ARP pseudo-flows are excluded.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 1,950 of 174,588 flows of the capture (1.1%), carrying 98.1% of its packets.
- Victims (20; together they receive 53.1% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.47 | 46 | 3,153,654 |
| 192.168.137.97 | 42 | 3,077,780 |
| 192.168.137.224 | 38 | 2,999,948 |
| 192.168.137.184 | 43 | 2,937,574 |
| 192.168.137.205 | 44 | 2,921,824 |
| 192.168.137.242 | 42 | 2,822,732 |
| 192.168.137.108 | 42 | 2,698,501 |
| 192.168.137.112 | 42 | 2,632,866 |
| 192.168.137.65 | 38 | 2,591,294 |
| 192.168.137.29 | 42 | 2,533,242 |
| 192.168.137.191 | 41 | 2,481,712 |
| 192.168.137.185 | 41 | 2,440,056 |
| 192.168.137.254 | 36 | 2,438,431 |
| 192.168.137.77 | 41 | 2,429,930 |
| 192.168.137.120 | 33 | 2,359,351 |
| 192.168.137.66 | 35 | 2,318,563 |
| 192.168.137.236 | 0 | 0 |
| 192.168.137.89 | 0 | 0 |
| 192.168.137.186 | 0 | 0 |
| 192.168.137.172 | 0 | 0 |

- A victim with 0 pattern flows in this table has no endpoint among the victim endpoints listed below (the fewest endpoints that receive at least 80% of the victims' pattern packets); it still receives pattern traffic, which the table does not count.

- The cap of 20 victims binds: the listed victims receive only 53.1% of the pattern packets addressed to testbed hosts, so further hosts also receive flood traffic.

- The pattern is restricted to these victim endpoints (host:port; port 0 = no port), which receive 83.2% of the victims' pattern packets: 192.168.137.47:0, 192.168.137.97:0, 192.168.137.224:0, 192.168.137.184:0, 192.168.137.205:0, 192.168.137.242:0, 192.168.137.108:0, 192.168.137.112:0, 192.168.137.65:0, 192.168.137.29:0, 192.168.137.191:0, 192.168.137.185:0, 192.168.137.254:0, 192.168.137.77:0, 192.168.137.120:0, 192.168.137.66:0.

- Attackers (accepted; they send 89.7% of the pattern packets to the victims): 192.168.137.238, 192.168.137.207, 192.168.137.128, 192.168.137.147, 192.168.137.150, 192.168.137.162.
- Distinct senders of pattern flows to the victims: 7; flows from senders outside the testbed: 0 (0.0% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.238 | 95 | 12,747,243 | yes | yes |
| 192.168.137.150 | 95 | 4,785,001 | yes | yes |
| 192.168.137.207 | 94 | 5,910,171 | yes | yes |
| 192.168.137.128 | 93 | 5,621,529 | yes | yes |
| 192.168.137.162 | 90 | 4,497,480 | yes | yes |
| 192.168.137.147 | 90 | 4,881,788 | yes | yes |
| 192.168.137.106 | 89 | 4,394,246 | yes | no |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 0 | 646 | 42,837,458 |

- Typical pattern flow to a victim: median 53,990 packets per flow, median 540.3 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.236 <-> 192.168.137.238 | 7 | proto0/0 |
| 192.168.137.205 <-> 192.168.137.238 | 7 | proto0/0 |
| 192.168.137.150 <-> 192.168.137.87 | 7 | proto0/0 |
| 192.168.137.106 <-> 192.168.137.87 | 7 | proto0/0 |
| 192.168.137.238 <-> 192.168.137.87 | 7 | proto0/0 |
| 192.168.137.238 <-> 192.168.137.47 | 7 | proto0/0 |
| 192.168.137.106 <-> 192.168.137.47 | 7 | proto0/0 |
| 192.168.137.147 <-> 192.168.137.47 | 7 | proto0/0 |

Limits: Only flows with at least 1,000 packets define the pattern; the flood streams of CICFlowMeter can also leave short protocol-0 flows (streams split by timeouts, replies). At most 20 victims are listed.

### Traffic pattern: mirai_scan

TCP flows to port 23 or 2323 (Telnet) from a testbed host other than the gateway that contacts at least 20 distinct addresses on these ports (Mirai scanning; targets may be Internet addresses).

- No testbed host other than the gateway opens a TCP flow to port 23 or 2323 in this capture, so Telnet scanning is not visible in its flow records; only the flood pattern above can be traced.
