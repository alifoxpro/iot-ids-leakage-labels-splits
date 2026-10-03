# Evidence brief: Web-Based

Attacks on web applications of victim devices over HTTP. Three captures: SQL injection (Sqlinjection), cross-site scripting (XSS) and a malicious file upload (Uploading Attack).

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## Sqlinjection

- Flow files: SqlInjection.pcap_Flow.csv. Flows in the capture: 6,603 (all traffic recorded during the session). Packets: 50,992.
- Capture period (first and last flow start): 03/10/2022 02:17:00 PM to 03/10/2022 03:09:00 PM.
- Attack window (first and last TCP 80/8080 flow between an identified attacker and victim): 03/10/2022 02:17:12 PM to 03/10/2022 03:07:28 PM (50.3 minutes); 87.8% of all flows of the capture start inside it.

### Traffic pattern: web

TCP flows with port 80 or 8080 on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 1,545 of 6,603 (23.4%); 486 of them run between two testbed hosts and 1,059 have an endpoint outside the testbed.
- Attackers (client side; they account for 100.0% of the port-pattern flows between testbed hosts): 192.168.137.178.
- Victims (server side; they account for 99.6% of the attackers' port-pattern flows): 192.168.137.86, 192.168.137.217, 192.168.137.4.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 157.249.81.141 <-> 192.168.137.41 | 895 | TCP/80 |
| 192.168.137.178 <-> 192.168.137.86 | 215 | TCP/80 |
| 192.168.137.178 <-> 192.168.137.217 | 140 | TCP/80 |
| 192.168.137.178 <-> 192.168.137.4 | 129 | TCP/80 |
| 120.76.210.199 <-> 192.168.137.163 | 59 | TCP/80 |
| 192.168.137.177 <-> 35.175.71.102 | 11 | TCP/80 |
| 192.168.137.177 <-> 44.199.80.228 | 11 | TCP/80 |
| 192.168.137.177 <-> 54.167.177.211 | 10 | TCP/80 |

- Most frequent hosts on the server side of all pattern flows: 157.249.81.141 (895, outside the testbed), 192.168.137.86 (215), 192.168.137.217 (140), 192.168.137.4 (129), 120.76.210.199 (59, outside the testbed), 35.175.71.102 (11, outside the testbed).

Limits: Attackers and victims were sought among testbed addresses only. HTTP between testbed hosts can also be ordinary traffic (device web interfaces, local streaming or control services). Payloads are not in the flow records.

## Uploading Attack

- Flow files: Uploading_Attack.pcap_Flow.csv. Flows in the capture: 1,348 (all traffic recorded during the session). Packets: 12,301.
- Capture period (first and last flow start): 14/02/2023 12:52:00 PM to 14/02/2023 01:05:00 PM.
- Attack window (first and last TCP 80/8080 flow between an identified attacker and victim): 14/02/2023 12:52:01 PM to 14/02/2023 01:04:58 PM (12.9 minutes); 98.6% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: web

TCP flows with port 80 or 8080 on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 108 of 1,348 (8.0%); 62 of them run between two testbed hosts and 46 have an endpoint outside the testbed.
- Attackers (client side; they account for 95.2% of the port-pattern flows between testbed hosts): 192.168.137.147.
- Victims (server side; they account for 100.0% of the attackers' port-pattern flows): 192.168.137.11, 192.168.137.13, 192.168.137.236.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 120.76.210.199 <-> 192.168.137.163 | 29 | TCP/80 |
| 192.168.137.11 <-> 192.168.137.147 | 24 | TCP/80 |
| 192.168.137.13 <-> 192.168.137.147 | 20 | TCP/80 |
| 192.168.137.147 <-> 192.168.137.236 | 15 | TCP/80 |
| 142.251.33.163 <-> 192.168.137.121 | 3 | TCP/80 |
| 192.168.137.237 <-> 52.87.19.91 | 3 | TCP/80 |
| 192.168.137.228 <-> 52.3.178.24 | 3 | TCP/80 |
| 192.168.137.1 <-> 192.168.137.190 | 3 | TCP/80 |

- Most frequent hosts on the server side of all pattern flows: 120.76.210.199 (29, outside the testbed), 192.168.137.11 (24), 192.168.137.13 (20), 192.168.137.236 (15), 192.168.137.190 (3), 52.3.178.24 (3, outside the testbed).

Limits: Attackers and victims were sought among testbed addresses only. HTTP between testbed hosts can also be ordinary traffic (device web interfaces, local streaming or control services). Payloads are not in the flow records.

## XSS

- Flow files: XSS.pcap_Flow.csv. Flows in the capture: 3,377 (all traffic recorded during the session). Packets: 37,750.
- Capture period (first and last flow start): 14/02/2023 11:46:00 AM to 14/02/2023 12:25:59 PM.
- Attack window (first and last TCP 80/8080 flow between an identified attacker and victim): 14/02/2023 11:46:03 AM to 14/02/2023 12:25:49 PM (39.8 minutes); 98.1% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: web

TCP flows with port 80 or 8080 on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 228 of 3,377 (6.8%); 106 of them run between two testbed hosts and 122 have an endpoint outside the testbed.
- Attackers (client side; they account for 90.6% of the port-pattern flows between testbed hosts): 192.168.137.147.
- Victims (server side; they account for 100.0% of the attackers' port-pattern flows): 192.168.137.236, 192.168.137.13, 192.168.137.11.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 120.76.210.199 <-> 192.168.137.163 | 73 | TCP/80 |
| 192.168.137.147 <-> 192.168.137.236 | 34 | TCP/80 |
| 192.168.137.13 <-> 192.168.137.147 | 32 | TCP/80 |
| 192.168.137.11 <-> 192.168.137.147 | 30 | TCP/80 |
| 192.168.137.1 <-> 192.168.137.190 | 10 | TCP/80 |
| 142.251.33.163 <-> 192.168.137.121 | 9 | TCP/80 |
| 192.168.137.246 <-> 34.104.35.123 | 6 | TCP/80 |
| 13.225.189.62 <-> 192.168.137.12 | 5 | TCP/80 |

- Most frequent hosts on the server side of all pattern flows: 120.76.210.199 (73, outside the testbed), 192.168.137.236 (34), 192.168.137.13 (32), 192.168.137.11 (30), 192.168.137.190 (10), 142.251.33.163 (9, outside the testbed).

Limits: Attackers and victims were sought among testbed addresses only. HTTP between testbed hosts can also be ordinary traffic (device web interfaces, local streaming or control services). Payloads are not in the flow records.
