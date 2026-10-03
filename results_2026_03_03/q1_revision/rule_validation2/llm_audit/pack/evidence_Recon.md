# Evidence brief: Recon

Reconnaissance: a vulnerability scan of the testbed hosts (flow file VulnerabilityScan).

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## Recon

- Flow files: VulnerabilityScan.pcap_Flow.csv. Flows in the capture: 442,158 (all traffic recorded during the session). Packets: 3,626,033.
- Capture period (first and last flow start): 03/10/2022 11:02:00 AM to 04/10/2022 09:31:03 AM.
- Attack window (first and last flow from an identified scanning host to a testbed host): 03/10/2022 11:02:02 AM to 04/10/2022 09:30:41 AM (1,348.7 minutes); 99.97% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: recon

A scanning host is a testbed host other than the gateway that opens TCP or UDP flows to at least 50 distinct destination ports or to at least 30 distinct testbed hosts (at most 10 such hosts, those with the most distinct host:port targets). Its flows to testbed hosts are the pattern flows; the hosts it contacts are the probed hosts.

- TCP/UDP flows from testbed hosts (not the gateway) to testbed hosts: 130,243 of 442,158 flows of the capture.
- Scanning hosts (attackers), with the number of distinct targets they contact:

| Scanning host | Distinct host:port targets | Distinct hosts | Distinct ports |
|---|---|---|---|
| 192.168.137.178 | 55,416 | 59 | 1,479 |
| 192.168.137.154 | 1,400 | 3 | 1,386 |
| 192.168.137.212 | 1,000 | 4 | 992 |
| 192.168.137.187 | 336 | 4 | 336 |
| 205.174.165.69 | 299 | 1 | 299 |
| 192.168.137.167 | 212 | 10 | 208 |
| 192.168.137.116 | 95 | 3 | 95 |
| 192.168.137.206 | 77 | 4 | 77 |
| 192.168.137.236 | 56 | 31 | 2 |
| 192.168.137.52 | 52 | 2 | 52 |

- Probed testbed hosts (66): 192.168.137.41, 192.168.137.86, 192.168.137.175, 192.168.137.187, 192.168.137.133, 192.168.137.148, 192.168.137.167, 192.168.137.82, 192.168.137.224, 192.168.137.249, 192.168.137.181, 192.168.137.154, 192.168.137.58, 192.168.137.45, 192.168.137.132, 192.168.137.66, 192.168.137.1, 192.168.137.128, 192.168.137.71, 192.168.137.173, 192.168.137.57, 192.168.137.40, 205.174.165.69, 192.168.137.74, 192.168.137.4, 192.168.137.178, 192.168.137.234, 192.168.137.252, 192.168.137.208, 192.168.137.100, 192.168.137.242, 192.168.137.212, 192.168.137.241, 192.168.137.108, 192.168.137.75, 192.168.137.52, 192.168.137.189, 192.168.137.196, 192.168.137.59, 192.168.137.177, 192.168.137.206, 192.168.137.15, 192.168.137.109, 192.168.137.107, 192.168.137.223, 192.168.137.50, 192.168.137.180, 192.168.137.137, 192.168.137.174, 192.168.137.164, 192.168.137.248, 192.168.137.93, 192.168.137.20, 192.168.137.67, 192.168.137.101, 192.168.137.116, 192.168.137.106, 192.168.137.226, 192.168.137.244, 192.168.137.237, 192.168.137.169, 192.168.137.205, 192.168.137.238, 192.168.137.55, 192.168.137.217, 192.168.137.236.
- Most frequent destination ports of the scanning hosts' flows to testbed hosts:

| Port | Flows |
|---|---|
| 53 | 3,066 |
| 7 | 1,910 |
| 443 | 1,464 |
| 80 | 1,372 |
| 40872 | 999 |
| 55443 | 830 |
| 6668 | 608 |
| 55444 | 486 |
| 30000 | 423 |
| 8009 | 295 |

- Flows of the scanning hosts to addresses outside the testbed: 15,173; most frequent: 52.91.195.103 (1,953), 239.255.255.250 (1,056), 224.0.0.251 (982), 13.225.196.108 (882), 34.158.253.218 (648).

- Most frequent address pairs among all TCP/UDP flows between testbed hosts whose source is not the gateway (scanning or not), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.1 <-> 192.168.137.41 | 32,835 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.177 | 5,951 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.133 | 5,212 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.206 | 2,766 | TCP/7 |
| 192.168.137.154 <-> 192.168.137.178 | 2,145 | UDP/1900 |
| 192.168.137.178 <-> 192.168.137.86 | 2,089 | TCP/443 |
| 192.168.137.178 <-> 192.168.137.4 | 2,083 | TCP/43727 |
| 192.168.137.178 <-> 192.168.137.217 | 2,072 | TCP/43208 |

Limits: The scanner selection is heuristic: a device that contacts many hosts on one or two ports (discovery or streaming services) can meet the threshold without scanning, and the probed-host list includes every testbed host that a selected host contacted. Scanning hosts also produce ordinary traffic (DNS, NTP, cloud services).
