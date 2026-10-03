# Evidence brief: DOS

Denial of service from one or a few attacking devices. Three captures: HTTP Flood, SYN Flood and UDP Flood.

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## DOS HTTP FLOOD

- Flow files: DoS-HTTP_Flood*.pcap_Flow.csv (2 files). Flows in the capture: 1,642,744 (all traffic recorded during the session). Packets: 7,108,757.
- Capture period (first and last flow start): 08/08/2022 01:25:00 PM to 09/08/2022 01:22:00 PM.
- Attack window (first and last TCP 80/8080 flow between an identified attacker and victim): 08/08/2022 01:25:03 PM to 09/08/2022 11:37:00 AM (1,332.0 minutes); 67.2% of all flows of the capture start inside it.

### Traffic pattern: web

TCP flows with port 80 or 8080 on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 1,101,647 of 1,642,744 (67.1%); 1,093,974 of them run between two testbed hosts and 7,673 have an endpoint outside the testbed.
- Attackers (client side; they account for 99.6% of the port-pattern flows between testbed hosts): 192.168.137.66.
- Victims (server side; they account for 83.6% of the attackers' port-pattern flows): 192.168.137.211, 192.168.137.235, 192.168.137.174, 192.168.137.131.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.211 <-> 192.168.137.66 | 676,791 | TCP/8080 |
| 192.168.137.235 <-> 192.168.137.66 | 87,224 | TCP/80 |
| 192.168.137.174 <-> 192.168.137.66 | 78,372 | TCP/80 |
| 192.168.137.131 <-> 192.168.137.66 | 68,231 | TCP/80 |
| 192.168.137.66 <-> 192.168.137.71 | 58,052 | TCP/80 |
| 192.168.137.141 <-> 192.168.137.66 | 56,516 | TCP/80 |
| 192.168.137.64 <-> 192.168.137.66 | 39,680 | TCP/80 |
| 192.168.137.186 <-> 192.168.137.66 | 24,380 | TCP/80 |

- Most frequent hosts on the server side of all pattern flows: 192.168.137.211 (676,791), 192.168.137.235 (87,224), 192.168.137.174 (78,372), 192.168.137.131 (68,231), 192.168.137.71 (58,052), 192.168.137.141 (56,516).

Limits: Attackers and victims were sought among testbed addresses only. HTTP between testbed hosts can also be ordinary traffic (device web interfaces, local streaming or control services). Payloads are not in the flow records.

## DOS SYN FLOOD

- Flow files: DoS-SYN_Flood*.pcap_Flow.csv (5 files). Flows in the capture: 7,999,807 (all traffic recorded during the session). Packets: 125,430,335.
- Capture period (first and last flow start): 02/08/2022 12:06:04 PM to 05/08/2022 04:07:00 PM.
- Attack window (first and last pattern flow to an identified victim): 02/08/2022 12:22:01 PM to 05/08/2022 02:38:42 PM (4,456.7 minutes); 94.5% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: syn

TCP flows dominated by SYN packets without a completed handshake: SYN Flag Count at least 1 and at least half of the larger of the forward and backward packet counts, no payload in either direction, and ACK Flag Count not above the smaller packet count.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 7,801,686 of 7,999,807 flows of the capture (97.5%), carrying 98.7% of its packets.
- Victims (12; together they receive 80.5% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.93 | 396,830 | 10,340,922 |
| 192.168.137.23 | 399,093 | 9,804,989 |
| 192.168.137.218 | 431,044 | 9,587,005 |
| 192.168.137.216 | 393,310 | 9,474,646 |
| 192.168.137.224 | 393,752 | 9,452,061 |
| 192.168.137.236 | 393,299 | 8,741,773 |
| 192.168.137.254 | 637,030 | 8,350,648 |
| 192.168.137.95 | 418,826 | 7,639,716 |
| 192.168.137.144 | 1,116,284 | 7,534,320 |
| 192.168.137.165 | 0 | 0 |
| 192.168.137.14 | 0 | 0 |
| 192.168.137.210 | 0 | 0 |

- A victim with 0 pattern flows in this table has no endpoint among the victim endpoints listed below (the fewest endpoints that receive at least 80% of the victims' pattern packets); it still receives pattern traffic, which the table does not count.

- The pattern is restricted to these victim endpoints (host:port; port 0 = no port), which receive 81.2% of the victims' pattern packets: 192.168.137.93:8008, 192.168.137.23:6668, 192.168.137.218:554, 192.168.137.216:6668, 192.168.137.224:6668, 192.168.137.236:6668, 192.168.137.254:8009, 192.168.137.95:6668, 192.168.137.144:49153.

- Attackers (accepted; they send 100.0% of the pattern packets to the victims): 192.168.137.182, 192.168.137.240, 192.168.137.66.
- Distinct senders of pattern flows to the victims: 4; flows from senders outside the testbed: 0 (0.0% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.240 | 1,908,687 | 26,813,955 | yes | yes |
| 192.168.137.66 | 1,424,074 | 26,544,448 | yes | yes |
| 192.168.137.182 | 1,246,700 | 27,567,643 | yes | yes |
| 192.168.137.80 | 7 | 34 | yes | no |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 6668 | 1,998,280 | 45,113,185 |
| 49153 | 1,116,284 | 7,534,320 |
| 8009 | 637,030 | 8,350,648 |
| 554 | 431,044 | 9,587,005 |
| 8008 | 396,830 | 10,340,922 |

- Typical pattern flow to a victim: median 22 packets per flow, median 0.2 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.144 <-> 192.168.137.240 | 1,116,329 | TCP/49153 |
| 192.168.137.254 <-> 192.168.137.66 | 637,030 | TCP/8009 |
| 192.168.137.165 <-> 192.168.137.66 | 442,384 | TCP/443 |
| 192.168.137.182 <-> 192.168.137.218 | 431,057 | TCP/554 |
| 192.168.137.14 <-> 192.168.137.66 | 422,153 | TCP/443 |
| 192.168.137.182 <-> 192.168.137.95 | 418,959 | TCP/6668 |
| 192.168.137.23 <-> 192.168.137.240 | 399,093 | TCP/6668 |
| 192.168.137.182 <-> 192.168.137.93 | 396,841 | TCP/8008 |

Limits: At most 20 victims and 50 attackers are listed; other receivers of flood traffic can exist.

## DOS UDP FLOOD

- Flow files: DoS-UDP_Flood*.pcap_Flow.csv (15 files). Flows in the capture: 5,210,536 (all traffic recorded during the session). Packets: 303,269,228.
- Capture period (first and last flow start): 09/08/2022 03:37:00 PM to 16/08/2022 01:05:00 PM.
- Attack window (first and last pattern flow to an identified victim): 09/08/2022 03:37:13 PM to 15/08/2022 11:18:00 AM (8,380.8 minutes); 99.71% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: udp

One-directional UDP flows (no packet in one direction) with at least 10 packets that either reach 100 packets per second or belong to a burst of at least 100 such flows to the same receiving host:port starting within one second.

For every pattern flow the side that sends more packets is taken as the sender (CICFlowMeter orients a flow by its first packet, which can be the victim's reply). Victims are the fewest testbed receivers that receive at least 80% of the pattern packets (at most 20); when at most 20 host:port endpoints of these victims receive at least 80% of their pattern packets, the pattern is restricted to these endpoints. Attackers are the fewest senders that send at least 80% of the pattern packets to the victims (at most 50).

- Flows matching the pattern: 3,895,606 of 5,210,536 flows of the capture (74.8%), carrying 96.3% of its packets.
- Victims (20; together they receive 63.7% of the pattern packets addressed to testbed hosts):

| Victim | Pattern flows | Pattern packets |
|---|---|---|
| 192.168.137.2 | 18,459 | 18,386,607 |
| 192.168.137.184 | 13,702 | 13,684,969 |
| 192.168.137.250 | 13,347 | 13,326,617 |
| 192.168.137.13 | 11,118 | 11,107,635 |
| 192.168.137.172 | 9,407 | 9,399,593 |
| 192.168.137.14 | 9,011 | 9,006,409 |
| 192.168.137.170 | 8,980 | 8,977,430 |
| 192.168.137.89 | 8,754 | 8,747,076 |
| 192.168.137.191 | 3,519 | 8,679,152 |
| 192.168.137.144 | 8,581 | 8,577,752 |
| 192.168.137.205 | 8,477 | 8,472,475 |
| 192.168.137.100 | 8,472 | 8,469,104 |
| 192.168.137.19 | 7,711 | 7,703,538 |
| 192.168.137.204 | 7,723 | 7,684,276 |
| 192.168.137.235 | 393,216 | 7,604,735 |
| 192.168.137.104 | 7,441 | 7,431,918 |
| 192.168.137.48 | 7,396 | 7,387,246 |
| 192.168.137.212 | 7,200 | 7,191,510 |
| 192.168.137.111 | 7,181 | 7,172,737 |
| 192.168.137.203 | 7,065 | 7,051,517 |

- The cap of 20 victims binds: the listed victims receive only 63.7% of the pattern packets addressed to testbed hosts, so further hosts also receive flood traffic.

- No small set of victim ports covers most of the pattern packets (the flood uses many destination ports), so the pattern counts at the level of the victim host.

- Attackers (accepted; they send 95.9% of the pattern packets to the victims): 192.168.137.195.
- Distinct senders of pattern flows to the victims: 2; flows from senders outside the testbed: 0 (0.0% of these flows).
- Largest senders of pattern flows to the victims:

| Sender | Flows | Packets | Testbed address | Listed as attacker |
|---|---|---|---|---|
| 192.168.137.66 | 393,216 | 7,604,735 | yes | no |
| 192.168.137.195 | 173,544 | 178,457,561 | yes | yes |

- Victim ports of the pattern flows (port 0 = protocol 0, no port):

| Port | Flows | Packets |
|---|---|---|
| 554 | 393,217 | 7,605,735 |
| 21571 | 12 | 11,999 |
| 55502 | 12 | 13,481 |
| 44546 | 11 | 11,000 |
| 11779 | 11 | 11,000 |
| 44104 | 11 | 11,000 |
| 45085 | 11 | 11,000 |
| 65528 | 11 | 11,000 |

- Typical pattern flow to a victim: median 20 packets per flow, median 0.2 packets per second.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.235 <-> 192.168.137.66 | 393,216 | UDP/554 |
| 192.168.137.160 <-> 192.168.137.66 | 393,216 | UDP/55442 |
| 192.168.137.194 <-> 192.168.137.195 | 393,216 | UDP/80 |
| 192.168.137.18 <-> 192.168.137.195 | 393,215 | UDP/0 |
| 192.168.137.195 <-> 192.168.137.68 | 393,210 | UDP/0 |
| 192.168.137.195 <-> 192.168.137.247 | 374,836 | UDP/0 |
| 192.168.137.195 <-> 192.168.137.199 | 334,753 | UDP/0 |
| 192.168.137.163 <-> 192.168.137.195 | 327,680 | UDP/554 |

Limits: At most 20 victims and 50 attackers are listed; other receivers of flood traffic can exist. A sender with many flows but few packets per flow can fall outside the packet-based attacker list (see the sender table).
