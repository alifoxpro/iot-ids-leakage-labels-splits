# Evidence brief: BruteForce

Repeated login attempts against the SSH or Telnet service of a victim device from an attacking device.

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## BruteForce

- Flow files: BruteForce.pcap_Flow.csv. Flows in the capture: 3,619 (all traffic recorded during the session). Packets: 15,632.
- Capture period (first and last flow start): 14/10/2022 01:18:01 PM to 17/10/2022 12:02:00 PM.
- Attack window (first and last TCP 22/23 flow between an identified attacker and victim): 17/10/2022 10:21:50 AM to 17/10/2022 10:44:38 AM (22.8 minutes); 60.4% of all flows of the capture start inside it.

### Traffic pattern: bruteforce

TCP flows with port 22 (SSH) or 23 (Telnet) on either side. Among such flows between two testbed hosts, the attackers are the fewest client-side addresses (the side without the service port) that account for at least 80% of these flows (at most 10), and the victims are the fewest server-side addresses that account for at least 80% of the attackers' flows.

- Flows matching the port pattern: 79 of 3,619 (2.2%); 79 of them run between two testbed hosts and 0 have an endpoint outside the testbed.
- Attackers (client side; they account for 100.0% of the port-pattern flows between testbed hosts): 192.168.137.65.
- Victims (server side; they account for 100.0% of the attackers' port-pattern flows): 192.168.137.67.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.65 <-> 192.168.137.67 | 79 | TCP/22 |

- Most frequent hosts on the server side of all pattern flows: 192.168.137.67 (79).

Limits: Attackers and victims were sought among testbed addresses only. An SSH or Telnet session between other hosts, or other traffic between the attacker and the victim, is not covered by the pattern and must be judged on its own evidence.
