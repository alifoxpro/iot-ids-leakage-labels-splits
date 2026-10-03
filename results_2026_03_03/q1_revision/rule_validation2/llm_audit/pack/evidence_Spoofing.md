# Evidence brief: Spoofing

Man-in-the-middle attacks. Two captures: ARP Spoofing (forged ARP replies make victims send their traffic through the attacker) and DNS Spoofing (forged DNS answers).

How these facts were obtained: no labels are published for individual flows, so the attack traffic was traced in the complete flow records of each capture with the traffic patterns described below. The attackers, victims and windows listed here are therefore inferred, not ground truth: hosts can be missing from the lists, and a listed host also sends ordinary traffic. Use these facts as leads and decide every flow from its own fields (see README_annotators.md). Timestamps use the format of the flow tables (day/month/year, local capture time).

## ARP Spoofing

- Flow files: MITM-ArpSpoofing*.pcap_Flow.csv (2 files). Flows in the capture: 82,382 (all traffic recorded during the session). Packets: 3,038,721.
- Capture period (first and last flow start): 17/10/2022 05:20:00 PM to 18/10/2022 05:56:00 PM.
- Attack window (first and last ARP pseudo-flow): 17/10/2022 05:20:01 PM to 18/10/2022 05:55:00 PM (1,475.0 minutes); 99.65% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.
- ICMP window of the spoofing host (first and last ICMP flow to a presumed victim): 17/10/2022 05:20:03 PM to 18/10/2022 05:55:37 PM (1,475.6 minutes).

### Traffic pattern: arp

CICFlowMeter turns every ARP frame into a protocol-0 flow between the pseudo-addresses 8.6.0.1 and 8.0.6.4, so normal and forged ARP frames of one flow-timeout window share one pseudo-flow and the sender cannot be read from it. The spoofing host is taken as the testbed host (not the gateway) that sends protocol-0 (ICMP) flows to the largest number of distinct testbed hosts, if that number is at least 3 and at least twice that of the next host: a man-in-the-middle host that forwards the victims' packets emits ICMP redirects. Its ICMP targets are listed as the presumed victims.

- ARP pseudo-flows (8.6.0.1 <-> 8.0.6.4): 146 flows, 43,134 ARP frames, 295.4 frames per flow, 2.961 frames per second over their total duration.
- Hosts with the largest protocol-0 fan-out to other testbed hosts:

| Host | Distinct testbed hosts reached |
|---|---|
| 192.168.137.89 | 18 |
| 192.168.137.36 | 3 |
| 205.174.165.65 | 1 |

- Spoofing host (attacker): 192.168.137.89; it appears in 292 flows of the capture.
- Presumed victims (18; the testbed hosts to which it sends ICMP): 192.168.137.106, 192.168.137.11, 192.168.137.115, 192.168.137.130, 192.168.137.139, 192.168.137.162, 192.168.137.163, 192.168.137.174, 192.168.137.197, 192.168.137.205, 192.168.137.210, 192.168.137.241, 192.168.137.247, 192.168.137.253, 192.168.137.28, 192.168.137.70, 192.168.137.94, 192.168.137.98.

Limits: This identification is weak: other hosts can also send ICMP to many devices, and the ARP pseudo-flows mix ordinary and forged ARP frames. While the poisoning is active, the spoofing host relays the victims' packets at link level; the IP addresses are unchanged, so a relayed flow (for example victim to Internet service) looks exactly like an ordinary flow in the flow records.

## DNS Spoofing

- Flow files: DNS_Spoofing.pcap_Flow.csv. Flows in the capture: 74,856 (all traffic recorded during the session). Packets: 1,754,206.
- Capture period (first and last flow start): 15/11/2022 12:16:00 PM to 16/11/2022 04:25:00 PM.
- Attack window (first and last UDP 53 flow between an identified responder and its counterpart): 15/11/2022 12:16:46 PM to 16/11/2022 04:24:52 PM (1,688.1 minutes); 99.70% of all flows of the capture start inside it. The window spans almost the whole capture, so the time of a flow does not separate attack from ordinary traffic here.

### Traffic pattern: dns

UDP flows with port 53 on either side. A responder is a testbed host other than the gateway 192.168.137.1 that is on the port-53 side of at least 5 UDP flows in which it sends packets, i.e. it answers DNS queries (the devices normally resolve through the gateway or Internet resolvers). The responders are the fewest such hosts covering at least 80% of these answering flows; their counterparts are the fewest testbed hosts covering at least 80% of the responders' UDP 53 flows with testbed hosts.

- UDP 53 flows in the capture: 15,363 of 74,856 (20.5%); 12,858 between two testbed hosts, 2,505 with an endpoint outside the testbed (Internet resolvers).
- Testbed hosts other than the gateway that answer UDP 53 flows (56 answering flows in total):

| Host | Answering flows |
|---|---|
| 192.168.137.42 | 29 |
| 192.168.137.62 | 25 |
| 192.168.137.97 | 1 |
| 192.168.137.184 | 1 |

- Identified responders (at least 5 answering flows): 192.168.137.42, 192.168.137.62.
- Their counterparts (presumed victims): 192.168.137.1 (the gateway).
- UDP 53 flows between the responders and these counterparts: 1,605, of which the responders answer at most 56.

- Most frequent address pairs among all flows that match the pattern (attack and non-attack), with their main protocol/port:

| Pair | Flows | Main protocol/port |
|---|---|---|
| 192.168.137.1 <-> 192.168.137.199 | 3,246 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.121 | 2,860 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.42 | 1,458 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.163 | 999 | UDP/53 |
| 192.168.137.49 <-> 8.8.8.8 | 651 | UDP/53 |
| 192.168.137.1 <-> 192.168.137.18 | 501 | UDP/53 |
| 192.168.137.49 <-> 8.8.4.4 | 431 | UDP/53 |
| 192.168.137.124 <-> 8.8.8.8 | 417 | UDP/53 |

- Most frequent hosts on the port-53 side (resolver) of all pattern flows: 192.168.137.1 (12,802), 8.8.8.8 (1,695, outside the testbed), 8.8.4.4 (501, outside the testbed), 8.208.8.243 (269, outside the testbed), 192.168.137.42 (29), 192.168.137.62 (25).

Limits: This identification is weak. A DNS answer from a testbed host can also arise in ordinary traffic (for example when a flow is oriented by a late packet), and the listed responders answer only a few flows while most of their UDP 53 flows with the gateway can be their own look-ups. Forged answers that carry the address of the real resolver (the gateway or an Internet resolver) cannot be told from genuine ones at flow level, except when a forged and a genuine answer to the same query fall into one flow (more answer packets from the resolver side than query packets); retransmitted or multi-part answers can produce the same trace.
