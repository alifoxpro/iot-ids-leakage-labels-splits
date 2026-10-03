# Author review: blind check of 50 audit flows

50 flows of the 472-flow audit sample, stratified by attack class and by whether the flow is flagged by the background rules (seed 42; 7 flows per class, 8 in one class; the selected IDs are listed under `author_review` in `llm_audit/pack/pack_manifest.json`). The status of each flow is hidden and should not be guessed. The same flows are annotated independently in the model-assisted audit; a scoring script, kept with the manuscript sources, was to compare the two afterwards. This check was not carried out and the template is empty (see `llm_audit/README.md`).

## Instructions (English)

1. Read `llm_audit/pack/README_annotators.md` (decision definitions, decision guide, testbed facts) and, for each class, its evidence brief `llm_audit/pack/evidence_<class>.md`. Do not open `audit_sample.csv`, `audit_template.md`, the capture summaries, the annotators' folders under `llm_audit/` or any score file before you have finished.
2. For every row write one word in Decision: `attack` (the flow is part of the attack of its capture), `background` (ordinary device, gateway or Internet traffic unrelated to the attack) or `unclear` (cannot be decided from the evidence). Allowed abbreviations: `a`, `b`, `u`. Nothing else.
3. In Evidence write in English, briefly (up to about 25 words), what the decision rests on, for example "DNS query of device .96 to gateway, ordinary look-up".
4. Do not change the ID, Timestamp or header cells.

## التعليمات (بالعربية)

1. اقرأ أولاً الملف `llm_audit/pack/README_annotators.md` (تعريف القرارات، دليل اتخاذ القرار، حقائق الـ testbed)، ثم ملف الأدلة الخاص بكل صنف `llm_audit/pack/evidence_<class>.md`. لا تفتح `audit_sample.csv` ولا `audit_template.md` ولا ملفات الـ captures ولا مجلدات المُعلِّمين تحت `llm_audit/` ولا أي ملف نتائج قبل أن تنتهي.
2. في عمود Decision اكتب كلمة واحدة فقط: `attack` (الـ flow جزء من الهجوم الذي سُجِّل في هذا الـ capture)، أو `background` (حركة عادية لجهاز أو للـ gateway أو للإنترنت لا علاقة لها بالهجوم)، أو `unclear` (لا يمكن الحكم من الأدلة المتاحة؛ لا تخمّن). الاختصارات المسموحة: `a` و`b` و`u`، ولا شيء غيرها.
3. في عمود Evidence اكتب بالإنجليزية وباختصار (نحو 25 كلمة على الأكثر) الدليل الذي بنيت عليه قرارك، مثل: "DNS query of device .96 to gateway, ordinary look-up".
4. لا تغيّر خلايا ID وTimestamp وصف العناوين.

## BruteForce (7 flows)

Evidence brief: `llm_audit/pack/evidence_BruteForce.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| BF-005 | BruteForce | 17/10/2022 10:45:30 AM | UDP | 192.168.137.1:53 -> 192.168.137.173:33765 | 1/1 | 52/36 | 0.003691 | - | 23,842 | 541.86 | 70.0 |  |  |
| BF-038 | BruteForce | 17/10/2022 10:24:24 AM | UDP | 192.168.137.1:53 -> 192.168.137.173:57160 | 1/1 | 52/36 | 0.013384 | - | 6,575 | 149.43 | 70.0 |  |  |
| BF-054 | BruteForce | 17/10/2022 10:26:11 AM | TCP | 192.168.137.206:47331 -> 192.168.137.1:7 | 2/0 | 0/0 | 0.961143 | 2/0/0/0/0 | 0 | 2.08 | 0.0 |  |  |
| BF-055 | BruteForce | 17/10/2022 10:49:00 AM | UDP | 192.168.137.1:53 -> 192.168.137.173:58441 | 1/1 | 51/35 | 0.010598 | - | 8,115 | 188.71 | 68.5 |  |  |
| BF-065 | BruteForce | 17/10/2022 10:41:47 AM | TCP | 192.168.137.206:47385 -> 192.168.137.1:7 | 2/0 | 0/0 | 1.01899 | 2/0/0/0/0 | 0 | 1.96 | 0.0 |  |  |
| BF-066 | BruteForce | 17/10/2022 10:26:20 AM | TCP | 192.168.137.65:54468 -> 192.168.137.67:22 | 1/1 | 0/0 | 0.046263 | 0/2/0/0/0 | 0 | 43.23 | 0.0 |  |  |
| BF-068 | BruteForce | 17/10/2022 10:23:02 AM | TCP | 192.168.137.89:51821 -> 192.168.137.233:80 | 4/0 | 0/0 | 7.00969 | 4/0/0/0/0 | 0 | 0.571 | 0.0 |  |  |

## DDOS (7 flows)

Evidence brief: `llm_audit/pack/evidence_DDOS.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DD-012 | DDOS ACK Fragmentation | 25/10/2022 10:49:35 AM | TCP | 192.168.137.17:8799 -> 192.168.137.10:6668 | 2/0 | 2920/0 | 71.5845 | 0/2/0/0/0 | 40.79 | 0.0279 | 2190.0 |  |  |
| DD-015 | DDOS ACK Fragmentation | 26/10/2022 01:38:24 PM | TCP | 192.168.137.204:80 -> 192.168.137.42:49480 | 1/1 | 0/1460 | 0.032212 | 0/1/0/1/0 | 45,325 | 62.09 | 730.0 |  |  |
| DD-016 | DDOS ACK Fragmentation | 25/10/2022 03:31:26 PM | TCP | 192.168.137.17:44547 -> 192.168.137.228:6668 | 2/0 | 2920/0 | 71.1176 | 0/2/0/0/0 | 41.06 | 0.0281 | 2190.0 |  |  |
| DD-030 | DDOS ICMP FLOOD | 08/09/2022 10:10:57 AM | UDP | 192.168.137.1:67 -> 192.168.137.51:68 | 2/0 | 612/0 | 0.030383 | - | 20,143 | 65.83 | 459.0 |  |  |
| DD-034 | DDOS ACK Fragmentation | 26/10/2022 02:04:55 PM | UDP | 192.168.137.207:58040 -> 8.8.8.8:53 | 1/1 | 35/51 | 0.110097 | - | 781.13 | 18.17 | 60.5 |  |  |
| DD-038 | DDOS ICMP FLOOD | 12/09/2022 11:18:30 AM | UDP | 192.168.137.1:53 -> 192.168.137.138:41248 | 1/1 | 48/32 | 0.050237 | - | 1,592 | 39.81 | 64.0 |  |  |
| DD-057 | DDOS ICMP Fragmentation | 05/10/2022 05:19:53 PM | TCP | 192.168.137.41:54119 -> 157.249.81.141:80 | 2/1 | 0/0 | 0.125074 | 0/3/1/0/0 | 0 | 23.99 | 0.0 |  |  |

## DOS (7 flows)

Evidence brief: `llm_audit/pack/evidence_DOS.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DS-003 | DOS UDP FLOOD | 10/08/2022 02:41:25 PM | UDP | 192.168.137.195:54062 -> 192.168.137.196:1080 | 18/1 | 2160/10 | 117.135 | - | 18.53 | 0.162 | 120.5 |  |  |
| DS-009 | DOS HTTP FLOOD | 08/08/2022 03:48:01 PM | TCP | 192.168.137.235:80 -> 192.168.137.66:56130 | 2/0 | 0/0 | 0.452051 | 0/0/0/2/0 | 0 | 4.42 | 0.0 |  |  |
| DS-015 | DOS UDP FLOOD | 10/08/2022 05:09:40 PM | UDP | 192.168.137.195:17025 -> 192.168.137.247:0 | 20/0 | 2400/0 | 117.331 | - | 20.45 | 0.17 | 126.0 |  |  |
| DS-020 | DOS UDP FLOOD | 10/08/2022 01:30:49 PM | UDP | 192.168.137.195:57887 -> 192.168.137.211:8080 | 18/0 | 2520/0 | 117.159 | - | 21.51 | 0.154 | 147.8 |  |  |
| DS-068 | DOS UDP FLOOD | 09/08/2022 03:47:46 PM | UDP | 192.168.137.1:53 -> 192.168.137.160:14071 | 1/1 | 53/37 | 0.149259 | - | 602.98 | 13.4 | 71.5 |  |  |
| DS-069 | DOS UDP FLOOD | 12/08/2022 03:47:35 PM | UDP | 192.168.137.1:53 -> 192.168.137.209:49878 | 4/4 | 316/124 | 3.80056 | - | 115.77 | 2.1 | 64.9 |  |  |
| DS-070 | DOS UDP FLOOD | 16/08/2022 12:53:16 PM | UDP | 192.168.137.1:53 -> 192.168.137.224:35992 | 1/1 | 44/28 | 0.141453 | - | 509 | 14.14 | 58.0 |  |  |

## Mirai (7 flows)

Evidence brief: `llm_audit/pack/evidence_Mirai.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MI-033 | Mirai | 12/01/2023 02:57:11 PM | UDP | 8.8.8.8:53 -> 192.168.137.254:5385 | 1/1 | 308/44 | 0.054788 | - | 6,425 | 36.5 | 330.0 |  |  |
| MI-047 | Mirai | 13/01/2023 11:12:57 AM | UDP | 192.168.137.1:53 -> 192.168.137.68:63793 | 1/1 | 139/57 | 0.039764 | - | 4,929 | 50.3 | 167.5 |  |  |
| MI-048 | Mirai | 12/01/2023 01:02:01 PM | UDP | 192.168.137.120:47584 -> 192.168.137.1:53 | 2/2 | 64/96 | 13.598 | - | 11.77 | 0.294 | 48.0 |  |  |
| MI-052 | Mirai | 16/01/2023 09:01:06 AM | TCP | 192.168.137.162:43812 -> 192.168.137.248:8009 | 17/13 | 990/990 | 51.1814 | 0/29/1/1/18 | 38.69 | 0.586 | 69.7 |  |  |
| MI-062 | Mirai | 13/01/2023 12:42:30 PM | proto0 | 192.168.137.171:0 -> 192.168.137.120:0 | 18/7 | 0/0 | 20.5434 | - | 0 | 1.22 | 0.0 |  |  |
| MI-066 | Mirai | 17/01/2023 12:10:14 PM | proto0 | 192.168.137.128:0 -> 192.168.137.47:0 | 56942/18 | 0/0 | 77.2047 | - | 0 | 737.78 | 0.0 |  |  |
| MI-077 | Mirai | 16/01/2023 09:08:32 AM | proto0 | 192.168.137.171:0 -> 192.168.137.142:0 | 9/0 | 0/0 | 10.0331 | - | 0 | 0.897 | 0.0 |  |  |

## Recon (7 flows)

Evidence brief: `llm_audit/pack/evidence_Recon.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| RC-007 | Recon | 03/10/2022 05:34:11 PM | TCP | 192.168.137.178:64340 -> 192.168.137.206:9500 | 1/1 | 0/0 | 0.034754 | 1/1/0/1/0 | 0 | 57.55 | 0.0 |  |  |
| RC-013 | Recon | 04/10/2022 03:13:11 AM | UDP | 192.168.137.1:53 -> 192.168.137.41:59295 | 2/0 | 128/0 | 0.008606 | - | 14,873 | 232.4 | 84.0 |  |  |
| RC-020 | Recon | 03/10/2022 06:46:37 PM | TCP | 3.226.196.104:443 -> 192.168.137.212:47418 | 1/1 | 31/0 | 0 | 0/2/0/1/1 | inf | inf | 31.0 |  |  |
| RC-026 | Recon | 03/10/2022 05:34:20 PM | TCP | 192.168.137.178:64340 -> 192.168.137.55:777 | 1/1 | 0/0 | 0.038518 | 1/1/0/1/0 | 0 | 51.92 | 0.0 |  |  |
| RC-029 | Recon | 03/10/2022 10:36:14 PM | UDP | 192.168.137.1:53 -> 192.168.137.41:51805 | 2/0 | 72/0 | 0.009199 | - | 7,827 | 217.41 | 50.0 |  |  |
| RC-045 | Recon | 04/10/2022 04:04:34 AM | TCP | 192.168.137.41:37918 -> 157.249.81.141:80 | 2/1 | 0/0 | 0.007687 | 0/3/1/0/0 | 0 | 390.27 | 0.0 |  |  |
| RC-057 | Recon | 03/10/2022 05:35:43 PM | TCP | 192.168.137.178:64340 -> 192.168.137.74:389 | 1/1 | 0/0 | 0.128878 | 1/1/0/1/0 | 0 | 15.52 | 0.0 |  |  |

## Spoofing (8 flows)

Evidence brief: `llm_audit/pack/evidence_Spoofing.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SP-014 | DNS Spoofing | 15/11/2022 04:49:29 PM | TCP | 192.168.137.102:40446 -> 192.168.137.55:55443 | 12/8 | 2896/1152 | 90.1013 | 0/20/0/0/12 | 44.93 | 0.222 | 238.6 |  |  |
| SP-015 | DNS Spoofing | 15/11/2022 02:13:17 PM | UDP | 192.168.137.163:59364 -> 47.254.83.84:8877 | 3/1 | 116/16 | 20.6388 | - | 6.4 | 0.194 | 54.0 |  |  |
| SP-039 | DNS Spoofing | 15/11/2022 05:12:41 PM | UDP | 192.168.137.121:44216 -> 192.168.137.1:53 | 1/1 | 41/299 | 0.240074 | - | 1,416 | 8.33 | 190.5 |  |  |
| SP-041 | ARP Spoofing | 18/10/2022 02:33:17 PM | UDP | 192.168.137.1:53 -> 192.168.137.197:58778 | 1/1 | 315/41 | 0.007855 | - | 45,321 | 254.61 | 335.5 |  |  |
| SP-050 | DNS Spoofing | 15/11/2022 12:32:58 PM | TCP | 192.168.137.18:35204 -> 192.168.137.35:443 | 1/1 | 0/0 | 0.098849 | 1/1/0/1/0 | 0 | 20.23 | 0.0 |  |  |
| SP-051 | ARP Spoofing | 18/10/2022 05:27:55 PM | UDP | 192.168.137.197:54236 -> 192.168.137.1:53 | 1/1 | 41/299 | 0.056838 | - | 5,982 | 35.19 | 190.5 |  |  |
| SP-053 | DNS Spoofing | 16/11/2022 02:24:21 PM | TCP | 192.168.137.121:51057 -> 192.168.137.35:443 | 1/1 | 0/0 | 0.15302 | 1/1/0/1/0 | 0 | 13.07 | 0.0 |  |  |
| SP-064 | ARP Spoofing | 18/10/2022 03:53:59 PM | UDP | 192.168.137.1:53 -> 192.168.137.23:47911 | 1/1 | 53/37 | 0.015281 | - | 5,890 | 130.88 | 71.5 |  |  |

## Web-Based (7 flows)

Evidence brief: `llm_audit/pack/evidence_Web-Based.md`.

| ID | Capture | Timestamp | Proto | Flow (src -> dst) | Pkts f/b | Bytes f/b | Dur s | Flags S/A/F/R/P | Bytes/s | Pkts/s | Avg pkt B | Decision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| WB-010 | Uploading Attack | 14/02/2023 01:03:27 PM | UDP | 192.168.137.179:35083 -> 8.8.8.8:53 | 1/1 | 33/234 | 0.033917 | - | 7,872 | 58.97 | 150.0 |  |  |
| WB-012 | Sqlinjection | 03/10/2022 02:28:09 PM | TCP | 192.168.137.178:42176 -> 192.168.137.86:80 | 3/1 | 0/0 | 0.010087 | 0/4/1/0/0 | 0 | 396.55 | 0.0 |  |  |
| WB-017 | Uploading Attack | 14/02/2023 12:58:01 PM | UDP | 192.168.137.10:49154 -> 255.255.255.255:6667 | 24/0 | 4512/0 | 115.001 | - | 39.23 | 0.209 | 195.8 |  |  |
| WB-018 | Sqlinjection | 03/10/2022 02:30:44 PM | TCP | 192.168.137.41:49371 -> 157.249.81.141:80 | 5/4 | 196/375 | 0.278442 | 2/8/2/0/2 | 2,051 | 32.32 | 63.4 |  |  |
| WB-023 | Sqlinjection | 03/10/2022 02:28:29 PM | TCP | 192.168.137.86:80 -> 192.168.137.178:42226 | 5/6 | 1629/425 | 0.072515 | 2/10/2/0/2 | 28,325 | 151.69 | 186.7 |  |  |
| WB-025 | Sqlinjection | 03/10/2022 02:20:16 PM | UDP | 192.168.137.133:54601 -> 192.168.137.1:53 | 1/1 | 36/52 | 0.004061 | - | 21,670 | 492.49 | 62.0 |  |  |
| WB-059 | Sqlinjection | 03/10/2022 02:27:04 PM | TCP | 192.168.137.177:59853 -> 192.168.137.167:55443 | 9/7 | 1594/1698 | 61.3223 | 2/15/1/0/7 | 53.68 | 0.261 | 205.8 |  |  |
