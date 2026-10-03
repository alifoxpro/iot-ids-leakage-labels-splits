# Blind flow annotation: instructions for annotators

*Release copy of the instructions given to the annotators (identical to the original except for the note under item 3 of Section 1).*

This folder holds a blind annotation task: 472 flows sampled at random, per attack class, from the flow records (CICFlowMeter) of the attack captures of CIC IoT-DIAD 2024. For every flow, decide whether it belongs to the attack of its capture. The labels of this dataset are the capture folders, and the ordinary traffic of the other devices continued during every attack, so a capture labelled with an attack also contains traffic that has nothing to do with it.

## 1. Procedure

1. The annotation is model-assisted: two annotators (A and B) work independently, each on every batch, using only the files named in Section 2; an adjudicator then resolves every flow on which A and B disagree, again using only these files and the two decisions with their evidence. Agreement between A and B is recorded before adjudication.
2. A third annotator (C) works on `spotcheck.md` (40 flows, every 12th flow of the sample ordered by class and ID), independently of A, B and the adjudicator.
3. The author checks a further blind set of 50 flows independently; that file is not part of this folder and must not be opened by A, B, C or the adjudicator.

   *Note added for the release (2026-10-01): not carried out; no human checked any label.*

4. Copy each file you annotate into your own folder under `results_2026_03_03/q1_revision/rule_validation2/llm_audit/` (`annotator_A/`, `annotator_B/`, `annotator_C/`) and fill in the copy; never edit the files in this folder. Keep the file names. The adjudicator writes `llm_audit/final_decisions.csv` with the columns `sample_id`, `decision`, `evidence` and `basis` (`agreement` if A and B agree, otherwise `adjudicated`), one row per flow.

## 2. Blindness

- Open only this README, the evidence brief of the class you annotate (`evidence_<class>.md`) and your batch files (C: `spotcheck.md`).
- Do not open any other file of the repository: in particular no other file of `results_2026_03_03/` (sample tables, capture summaries, earlier templates, scores), no script, no manuscript text and no other annotator's folder. Do not run code on the dataset or on result files.
- The tables deliberately show only the identifiers and the traffic features of each flow. Do not try to reconstruct how or why a flow was sampled; the sample over-represents some kinds of flows, so the mix of a batch says nothing about any single flow.
- Decide every flow on its own evidence. Do not change a decision after seeing another annotator's work (only the adjudicator sees A and B).

## 3. Decisions

Write one word in the Decision column:

- `attack`: the flow is part of the attack of its capture: sent by or to an attacking host as part of the attack, a scan probe, a flood packet train, a forged answer, or victim traffic relayed by a man-in-the-middle attacker.
- `background`: ordinary device, gateway or Internet traffic unrelated to the attack.
- `unclear`: cannot be decided from the evidence.

Decision guide:

1. Read the evidence brief of the class, find the section of the flow's capture (column Capture) and note which endpoints of the flow are listed there (attacker, victim, scanning host, responder, spoofing host), which are the gateway, and which are outside the testbed.
2. `attack` if the flow matches the attack pattern of its capture in protocol, ports and packet pattern and links to the attack (a listed attacker or victim, or timing inside the attack window), or if its pattern is so specific that ordinary traffic would not produce it (for example a SYN-only TCP flow to a flooded victim port, a protocol-0 flow with tens of thousands of packets to a flooded host, a probe of an unusual port from a scanning host). A flow that evidently contains attack packets mixed with ordinary ones counts as `attack`.
3. `background` if the flow is a recognisable ordinary exchange (a DNS look-up, NTP, DHCP, mDNS, SSDP, IGMP, a cloud or streaming connection of a device) that is not part of the attack. This also holds for the ordinary traffic of an attacking or victim device, for example an attacker's own DNS look-up to the gateway, unless the brief says that the attack uses exactly this traffic (as for DNS Spoofing).
4. `unclear` if the evidence supports neither decision: for example a flow between a listed host and another host that neither matches the attack pattern nor looks like an ordinary service, or a flow whose attack role is invisible at flow level (such as possible relaying of a victim's traffic by an ARP-spoofing host). Do not guess; `unclear` is a valid result.
5. No single attribute decides a flow. An address outside the testbed is not by itself proof of ordinary traffic (flood sources can be spoofed, Mirai scans Internet addresses, relayed or forged traffic keeps the addresses of the real endpoints), a service port is not by itself proof of ordinary traffic (floods and forged answers can use service ports), and a listed attacker address is not by itself proof of attack.

Evidence column: a short phrase (at most about 25 words) naming the facts the decision rests on: roles of the endpoints, protocol and port, packet pattern, time relative to the attack window. Examples: "SYN-only, 22 pkts, no payload, attacker .240 to victim .144:49153, in window"; "DNS query of device .96 to gateway, ordinary look-up"; "SSH session attacker .65 to victim .67 in window"; "victim .130 to Internet HTTPS; relaying not visible at flow level". Use `a`, `b` or `u` only if you must abbreviate; no other words in the Decision column. Do not change the ID, Timestamp or header cells.

## 4. Testbed facts

- Addresses: the IoT testbed network is 192.168.137.0/24; 205.174.165.0/24 is the network of the CIC laboratory and is part of the test environment. All other addresses are outside the testbed: Internet services and resolvers, other private networks (for example 192.168.1.1), multicast groups and broadcast. Device addresses can change between capture days, so the same address can denote different devices in different captures; always use the brief section of the flow's own capture.
- Gateway: 192.168.137.1 is the default gateway of the testbed. The devices resolve names through it (UDP or TCP port 53) or through Internet resolvers such as 8.8.8.8 and 8.8.4.4, and reach the Internet through it.
- Ordinary services seen in the captures: DNS (53) to the gateway or to Internet resolvers; NTP (UDP 123) to Internet time servers; DHCP (UDP 67/68; a device without an address sends from 0.0.0.0 to 255.255.255.255); mDNS (UDP 5353, 224.0.0.251); SSDP (UDP 1900, 239.255.255.250); IGMP membership reports (protocol 0, to 224.0.0.22); NetBIOS (UDP 137/138); local broadcasts to 255.255.255.255 or 192.168.137.255 (for example smart-device discovery on UDP 6666/6667); HTTPS (443), MQTT (1883/8883) and other cloud connections of the devices; camera streams (RTSP 554) and peer-to-peer camera traffic.
- The dataset documentation states that all attacks are executed by malicious IoT devices targeting other IoT devices. Attack traffic can nevertheless carry addresses outside the testbed (see point 5 of the decision guide).
- Each attack was recorded in its own capture session; the ordinary traffic of the other devices continued during the attacks, so every capture mixes attack and ordinary traffic.

## 5. Flow-record facts (CICFlowMeter)

- A flow is the bidirectional exchange between two endpoints (address, port, protocol) from its first packet until a FIN/RST or a timeout; a long exchange is split into several flows. No flow in the sample lasts longer than 120 s.
- Direction: Src is the endpoint that sent the first packet that CICFlowMeter saw for the flow. This can be the responder or the victim (for example a DNS answer or a SYN-ACK seen first). Pkts f/b and Bytes f/b are the forward (from Src) and backward packets and bytes.
- Bytes are payload bytes (headers excluded): 0/0 means that no packet carried data (for example bare SYN, ACK or RST packets).
- Proto: TCP (6), UDP (17) or proto0, which CICFlowMeter uses for every other protocol (ICMP, IGMP, GRE, IP fragments without a transport header) and also for non-IP frames; proto0 flows have port 0. The sample holds 180 TCP, 260 UDP and 32 proto0 flows.
- ARP: CICFlowMeter reads the ARP header as an IPv4 header, so every ARP frame appears in a proto0 flow between the pseudo-addresses 8.6.0.1 and 8.0.6.4; all ARP frames (ordinary and forged) of one timeout window share such a flow. Other proto0 flows with an invalid host address (for example 0.6.0.1) are probably also non-IP frames; they are not documented.
- Floods: CICFlowMeter compresses a flood stream into a few long flows with very many packets (thousands to millions), so most flows of a flood capture can be ordinary traffic even when most packets are attack packets.
- Flags S/A/F/R/P: number of packets carrying SYN, ACK, FIN, RST and PSH (both directions); shown as "-" for UDP and proto0.
- Dur s: flow duration in seconds. Bytes/s and Pkts/s: payload bytes and packets per second over the flow ("inf" when the duration is 0). Avg pkt B: the average packet size as reported by CICFlowMeter; it does not always equal (bytes f + bytes b) / (packets f + packets b), which is easy to compute from the table.
- Timestamp: start of the flow, local capture time, day/month/year, one-second resolution.
- The Flow ID column of the flow files is not shown: it repeats the five-tuple of the Flow column.

## 6. Common ports

| Port | Service |
|---|---|
| TCP 22 / 23, 2323 | SSH / Telnet |
| 53 | DNS |
| UDP 67 / 68 | DHCP server / client |
| TCP 80, 8080 | HTTP |
| UDP 123 | NTP |
| UDP 137 / 138 | NetBIOS name / datagram |
| TCP 443 | HTTPS (UDP 443: QUIC) |
| TCP 554 | RTSP (camera streams) |
| TCP 1883 / 8883 | MQTT / MQTT over TLS |
| UDP 1900 | SSDP (UPnP discovery) |
| UDP 3478 | STUN |
| UDP 5353 | mDNS |
| UDP 6666 / 6667, TCP 6668 | smart-device (Tuya) discovery / control |
| TCP 8008 / 8009 | Google Cast device services |
| TCP 8443 | alternative HTTPS |

## 7. Attack classes and evidence briefs

- **BruteForce** (71 flows; `evidence_BruteForce.md`; batches `batch_01_BruteForce.md` (24), `batch_02_BruteForce.md` (24), `batch_03_BruteForce.md` (23)). Repeated login attempts against SSH (TCP 22) or Telnet (TCP 23) of a victim device from an attacking device: a series of short TCP sessions from one client to the same server port, each with a handshake, a few small payload packets and a FIN or RST.
- **DDOS** (59 flows; `evidence_DDOS.md`; batches `batch_04_DDOS.md` (30), `batch_05_DDOS.md` (29)). Several attacking devices at once. ACK Fragmentation: TCP packets with the ACK flag and payload but no handshake, or IP fragments, with little or no return traffic. HTTP Flood: very many HTTP connections to TCP 80/8080 of victim web services. ICMP Flood: ICMP packets at a high rate (proto0 flows with thousands to millions of packets). ICMP Fragmentation: large fragmented ICMP packets (proto0 flows with many packets).
- **DOS** (73 flows; `evidence_DOS.md`; batches `batch_06_DOS.md` (25), `batch_07_DOS.md` (24), `batch_08_DOS.md` (24)). One or a few attacking devices. SYN Flood: TCP flows of SYN packets without payload and without a completed handshake. UDP Flood: one-directional UDP packet trains to victim ports, often many flows that start in the same second. HTTP Flood: very many HTTP connections to TCP 80/8080 of a victim.
- **Mirai** (82 flows; `evidence_Mirai.md`; batches `batch_09_Mirai.md` (28), `batch_10_Mirai.md` (27), `batch_11_Mirai.md` (27)). Mirai botnet traffic; this capture holds a GRE flood (proto0 flows with very many packets from bots to victims). Telnet scanning (TCP 23/2323), typical of Mirai propagation, does not appear in its flow records.
- **Recon** (59 flows; `evidence_Recon.md`; batches `batch_12_Recon.md` (30), `batch_13_Recon.md` (29)). Vulnerability scan: scanning hosts probe many ports and/or many hosts: short flows (one or two packets each way, SYN answered by RST, UDP probes without answer), many distinct destination ports, and application-level probes of open services.
- **Spoofing** (65 flows; `evidence_Spoofing.md`; batches `batch_14_Spoofing.md` (22), `batch_15_Spoofing.md` (22), `batch_16_Spoofing.md` (21)). ARP Spoofing: an attacking device sends forged ARP replies to place itself between victims and the gateway; visible at flow level only as ARP pseudo-flows (which also carry ordinary ARP), ICMP redirects or pings from the spoofing host to its victims, and the traffic of the spoofing host itself (relaying keeps the IP addresses). DNS Spoofing: forged DNS answers; visible as UDP 53 answers from a testbed host other than the gateway, or as a flow with more answer than query packets.
- **Web-Based** (63 flows; `evidence_Web-Based.md`; batches `batch_17_Web-Based.md` (21), `batch_18_Web-Based.md` (21), `batch_19_Web-Based.md` (21)). SQL injection, cross-site scripting and malicious upload: HTTP sessions (TCP 80/8080) from an attacking device to a web application on a victim device, often many in succession during the attack window; the payload itself is not in the flow records.

The briefs give, per capture: the capture period, the attack window, the attackers and victims that were identified from the traffic and the pattern used to identify them, and the protocol and port pattern of the attack. They contain no decision about any individual flow.

## 8. Table columns

ID, Capture (sub-capture of the class), Timestamp, Proto, Flow (src address:port -> dst address:port), Pkts f/b, Bytes f/b, Dur s, Flags S/A/F/R/P, Bytes/s, Pkts/s, Avg pkt B, Decision (to fill in), Evidence (to fill in).
