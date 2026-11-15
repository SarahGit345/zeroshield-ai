# Stage 4 (MITRE ATT&CK retrieval): what was wrong, what changed, what was measured

## The problem

The query sent to the TF-IDF index was feature names and numbers ("syn_count value -1.0099, perturbation contribution 2.326; ..."). ATT&CK descriptions are plain language ("high volume of packets", "SYN flood", "scanning"), so the two share almost no words. Measured on the 180 labelled samples of the tuned model's XAI evidence, the old query returned a relevant technique for **0 of 180** (0 of 100 flagged) samples, and **159 of 180** alerts got the same top result, T1547.014 Active Setup (a persistence technique that cannot be seen in network flow data).

## What changed (`backend/services/mitre_service.py`)

- **Behaviour query.** A hand-written map (`BEHAVIOR_ONTOLOGY`) turns each feature that is clearly outside the benign range (scaled value at or beyond +/-1) and pushes the score up into the behaviour it signals, for example a very high `PacketDensity` into "very high packet density in a very short time high volume flood denial of service". It is written from networking knowledge, not fitted to labels, and the query never contains a dataset label.
- **Network-observable tactics only.** Flow statistics cannot support persistence, privilege-escalation, defense-evasion or execution techniques, so only techniques with a network-observable tactic can be returned.
- **Similarity floor of 0.15** and **abstention.** If no feature is clearly outside the benign range, or nothing clears the floor, the result says so instead of returning irrelevant techniques.
- A protocol that is absent adds nothing (absence of HTTPS is not attack behaviour).
- Every result carries the evidence features behind the query and a reliability note.

## How it was measured (`python backend/evaluate_retrieval.py`)

Data: `model_training/outputs/Deep_SVDD_XAI_per_sample.csv` (180 samples of nine labelled attack families, top-10 XAI features each). The label is used only to score an answer. A technique counts as relevant if it is in the expected family (Mirai floods: T1498, T1499, T1584; web attacks: T1190, T1059, T1505, T1185, T1189). That is generous but still label-based.

The samples were split by position within each family. The similarity floor was chosen on the tuning half; the other half is the reported result. The ontology was revised once after looking at the results (dropping absence phrases for protocols), so the held-out half was inspected twice. The change left the tuning-half relevant count unchanged (18).

## Result (held-out half, detector-flagged samples, n = 53)

| | Before | After |
|---|---:|---:|
| Relevant technique in the top 5 | 0 of 100 (both halves) | **19 of 53 (36%)** |
| Answers given | all | 37 (the rest abstain) |
| Precision when it answers | 0% | 51% |

| Family (flagged, held-out half) | Flagged | Answered | Relevant |
|---|---:|---:|---:|
| Mirai-greeth_flood | 10 | 10 | 9 |
| Mirai-greip_flood | 10 | 10 | 9 |
| Mirai-udpplain | 10 | 4 | 1 |
| **All Mirai floods** | **30** | **24** | **19** |
| Web attacks (SQL injection, XSS, command injection, backdoor, uploading, browser hijacking) | 23 | 13 | **0** |

## How to read this honestly

- Flow statistics can point to **network-level techniques** such as floods (19 of 30). They **cannot identify application-layer attacks**: for web attacks the evidence does not contain the information, and all 13 answers given were wrong. Treat candidates for such flows as low confidence. The dashboard and the LLM context carry this reliability note.
- The five candidates score close together. Roughly half of the flagged alerts get Credential Stuffing (T1110.004) as the first candidate, even for floods whose relevant technique is lower in the list. Do not read the order as a ranking.
- Some "wrong" answers are faithful to the evidence: an XSS flow whose statistics look like a flood is given flood techniques and scored wrong, because the label says XSS.
- Better retrieval for web attacks needs better evidence (application-layer features), not better wording.

## Post hoc: plausibility-based abstention (plan amendment 5, 2026-11-14)

Third look at the held-out half; nothing tuned (the rules have no threshold). `retrieve_behavior(..., abstain_implausible=True)` drops candidates that `plausibility-rules-v1` judges unsupported by the observed behaviours. Full tables: `backend/experiments/plausibility/summary.md`.

| detector-flagged | answered | relevant | wrong answers | precision when answering |
|---|---|---|---|---|
| test half, off (current) | 37 of 53 | 19 | 18 | 51.4% |
| test half, abstention on | 13 of 53 | 3 | 10 | 23.1% |
| tuning half, off | 29 of 47 | 18 | 11 | 62.1% |
| tuning half, abstention on | 10 of 47 | 5 | 5 | 50.0% |

Abstention made retrieval worse on both halves: relevant answers for Mirai floods fell from 19 of 30 to 3 of 30 on the test half. Mirai flows are explained by absent ACK and SYN packets (for example `ack_flag_number` -2.36, `syn_count` -1.04), which the v1 flood rule does not list, so the correct flood techniques were removed. On the 100 LLM-run alerts the rules removed 106 of 198 candidates and cut alerts with a relevant candidate from 18 to 8. Abstention stays off; the existing 0.15 similarity floor remains the only abstention rule.

## Post hoc: plausibility rules v2, tuned on S58, tested once on S10 (plan amendment 6, 2026-11-14)

v1 (above) failed because floods in this data appear as missing TCP behaviour. v2 adds two behaviours written from networking knowledge: one-way, non-TCP floods (ACK, SYN or inbound packets far below the benign range) for T1498/T1499, and brute force inside one sustained session (long gaps between packets, pushed application data) for T1110. Three variants were compared on the S58 tuning stream only (`backend/experiments/plausibility_v2/tune_s58.txt`); the best (balanced accuracy 0.682 vs v1 0.493) was frozen in commit `ee5af0e` before the S10 test stream was evaluated once. Unit: flagged alert x retrieved candidate (139 relevant, 7,433 irrelevant; every candidate on a benign alert is irrelevant). Full tables: `backend/experiments/plausibility_v2/test_s10.md`.

| S10, run once | relevant candidates kept [95% CI] | irrelevant candidates removed [95% CI] | balanced accuracy |
|---|---|---|---|
| no rules (current) | 100.0% | 0.0% | 0.500 |
| v1 | 40.3% [32.5%, 48.6%] | 51.9% [50.7%, 53.0%] | 0.461 |
| **v2** | **90.6% [84.7%, 94.5%]** | **38.4% [37.3%, 39.5%]** | **0.645** |

**Verdict under the pre-stated rule: improvement over v1** (difference +0.185, 95% paired-bootstrap interval [+0.123, +0.245]) and over no rules (interval [+0.101, +0.183]). Per family: Mirai relevant kept 38 of 38 and irrelevant removed 111 of 111 (balanced 1.000; v1 0.697); DDoS 34 of 34 kept (0.815; v1 0.668); Brute Force 37 of 50 kept (v1 0 of 50) but only 6 of 55 irrelevant removed; DoS unchanged (0.850). Attacks keeping a relevant candidate: 76 of 81 (v1: 30 of 81).

Limits. Recon, Spoofing and Web-Based never receive a relevant candidate from retrieval, so rules can only remove their wrong ones; the gain is in floods and brute force. Benign flows often look flood-like, so 62.8% of benign candidates are still kept. This is a candidate-level test; the effect on the verifier with real LLM reports (amendment 5 used v1) has not been measured and needs fresh reports. Both features stay off by default.

## Post hoc, amendment 7: behaviour-to-technique mapping (S10b evaluated once)

Starting from each alert's stored `xai_evidence`, all methods recomputed candidates with the TF-IDF retriever; the mapping merged behavior-supported ATT&CK parent techniques from the prebuilt index, applied the v2 plausibility filter, ranked supported candidates first, and kept at most five. Labels were not provided to retrieval and were used only afterward to score relevance; the new option remains off by default.

This is a **revised-data-basis replication**, not a result on the older source snapshot recorded in the original stream metadata. The current validation and zero-day CSV hashes are recorded in amendments 10-11 of the evaluation plan; S58/S10/S30 were rebuilt with that snapshot, and S10b was built after freeze commit `8659cbf` with no overlapping source rows. The tuning used S58 and S10 only. The selected `v1-core-scan` variant had the highest mean primary score (0.2640; tie resolved by declared variant order); `v2-icmp-short-scan` also scored 0.2640 and `v3-broad-scan` scored 0.2537. Per-stream mapping scores were 0.2778 / 0.2503 for v1, 0.2778 / 0.2503 for v2, and 0.2658 / 0.2415 for v3 on S58 / S10, respectively. The mapping was frozen and pushed before S10b was built.

### One-time S10b test

S10b (seed 4) contained 3,010 flagged alerts: 301 attacks, 2,709 benign, and 43 Web-Based alerts. Candidate-level relevance used label-level expected techniques where available and family-level relevant sets otherwise. Coverage is alert-level coverage: at least one relevant candidate. The primary score is the mean of macro coverage across the six in-scope attack families and benign clean rate. Wilson intervals are 95%; precision is relevant / all candidates for in-scope attack alerts; mean candidates per alert includes all 3,010 alerts.

| Method | DDoS coverage | DoS coverage | Recon coverage | Brute Force coverage | Spoofing coverage | Mirai coverage | Benign clean rate | Primary balanced score | Precision | Mean candidates / alert |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| TF-IDF only | 27/43 62.8% [47.9%, 75.6%] | 10/43 23.3% [13.2%, 37.7%] | 0/43 0.0% [0.0%, 8.2%] | 15/43 34.9% [22.4%, 49.8%] | 0/43 0.0% [0.0%, 8.2%] | 27/43 62.8% [47.9%, 75.6%] | 417/2709 15.4% [14.1%, 16.8%] | 0.2301 | 23.4% | 2.51 |
| TF-IDF + v2 filter | 27/43 62.8% [47.9%, 75.6%] | 10/43 23.3% [13.2%, 37.7%] | 0/43 0.0% [0.0%, 8.2%] | 8/43 18.6% [9.7%, 32.6%] | 0/43 0.0% [0.0%, 8.2%] | 27/43 62.8% [47.9%, 75.6%] | 739/2709 27.3% [25.6%, 29.0%] | 0.2759 | 39.4% | 1.51 |
| TF-IDF + mapping + v2 filter | 27/43 62.8% [47.9%, 75.6%] | 11/43 25.6% [14.9%, 40.2%] | 17/43 39.5% [26.4%, 54.4%] | 14/43 32.6% [20.5%, 47.5%] | 1/43 2.3% [0.4%, 12.1%] | 28/43 65.1% [50.2%, 77.6%] | 415/2709 15.3% [14.0%, 16.7%] | 0.2665 | 42.5% | 3.03 |

**Verdict: no improvement over TF-IDF + v2 filter.** The mapping's primary score was lower (0.2665 vs 0.2759); the paired difference was -0.0094, with a 95% paired-bootstrap interval of [-0.0264, +0.0086] (2,000 stratified resamples, seed 20261115). The interval includes zero, so the success rule is not met.

Recon coverage was **17/43 (39.5%; 95% Wilson [26.4%, 54.4%])**. Spoofing coverage was **1/43 (2.3%; [0.4%, 12.1%])**. Web-Based was out of scope because flow features do not reveal HTTP content (43 alerts, no coverage claim).

The mapping raised in-scope attack candidate precision from 39.4% to 42.5% and mean candidates from 1.51 to 3.03, but benign clean rate fell from 27.3% to 15.3%; this trade-off lowered the primary score. Results are based on one held-out stream with 43 alerts per attack family. The source snapshot differs from the original stream metadata, one non-finite input row was skipped, and the unflagged DoS quota was exhausted across the disjoint streams; neither unflagged rows nor their quota affect routed-alert metrics. No independent human judgment of candidate relevance was collected. The mapping remains opt-in and was not enabled in `main.py`.

## Post hoc, amendment 12: guarded behaviour mapping (original snapshot, S10b evaluated once)

Plan: `docs/stage10-evaluation-plan.md`, amendment 12 (committed `555aa89` before any code). Code `0778c6b`; variant frozen in `caaa512` (pushed) before S10b was built. Data: the original snapshot (43,149,298 + 2,658,953 rows); S58 and S10 hashes matched the committed table before tuning. Design informed by the amendment 7 S10b breakdown (disclosed in the plan), so that stream is not reused.

**Why amendment 7 did not improve.** Its map also added flood (T1498, T1499) and login (T1110) techniques, which landed on flood-looking benign alerts. The guarded map adds only scan (T1046, T1595) and spoofing (T1557) techniques; flood and login techniques come from TF-IDF alone.

**Tuning (S58, S10 only).** Mean primary score: g1-scan-only 0.3029, g2-scan-only-strong 0.3023, g3-scan-only-two 0.2689 (adds nothing: two scan behaviours rarely co-occur in the top features). Selected g1. Output: `backend/experiments/mapping_a12/tune.txt`.

**One-time test on S10b** (seed 4, 3,010 flagged: 301 attacks, 2,709 benign; SHA-256 `93fe6dab564504cdf4e49adb8345bbe660432d83b6081f57c3a1043d1ef0aa18`). Coverage with 95% Wilson intervals; full table in `backend/experiments/mapping_a12/test_s10b.md`.

| Method | Recon | Spoofing | Brute Force | Benign clean | Primary score | Precision | Mean candidates |
|---|---|---|---|---|---|---|---|
| TF-IDF only | 0/43 | 0/43 | 13/43 | 15.1% | 0.2245 | 22.4% | 2.53 |
| TF-IDF + v2 filter | 0/43 | 0/43 | 8/43 | 27.1% | 0.2752 | 38.9% | 1.51 |
| Amendment 7 map + v2 | 15/43 | 0/43 | 16/43 | 16.1% | 0.2725 | 43.1% | 3.02 |
| **Guarded map (g1) + v2** | **17/43 (39.5% [26.4%, 54.4%])** | 0/43 | 8/43 | 26.8% | **0.3065** | 40.5% | 1.91 |

DDoS (29/43), DoS (7/43) and Mirai (28/43) are unchanged by the guarded map.

**Verdict: success under the pre-stated rule.** Guarded minus TF-IDF + v2 = **+0.0313, 95% paired bootstrap [+0.0191, +0.0433]**. The amendment 7 map replicated on this snapshot gives -0.0027 [-0.0198, +0.0167], matching the teammate's no-improvement result on the other snapshot.

**What this does and does not show.** The guard recovers Recon (0% to 39.5%) without adding noise to benign alerts (clean rate 27.1% to 26.8%). Spoofing is still never covered (0/43), Brute Force stays at the v2 level (18.6%), and Web-Based (43 alerts) is out of scope. Relevance is family-level and generous, as before. One stream, one snapshot, run once; the mapping stays off by default and `backend/main.py` is unchanged. Environment: scikit-learn 1.6.1 for tuning and test (index pickled with 1.7.2; warning only).

## Post hoc, amendment 15: score-gated ATT&CK context (S10c evaluated once)

Plan: amendment 15 (committed `218986b` before any code). Code `3ae8f77`; gate frozen in `d897ba2` (pushed) before S10c was built. Tuning on S58 and S10 only: mean primary score gate-1.5x 0.4308, gate-2x 0.5044, gate-3x 0.5693; gate-3x selected by the pre-stated rule (`backend/experiments/mapping_a15/tune.txt`).

**One-time test on S10c** (seed 5, original snapshot, excluding S58, S10, S30 and S10b; 3,010 flagged: 301 attacks, 2,709 benign; 45,808,251 rows read, 9,401 excluded rows skipped, 0 mismatches; SHA-256 `97d0411bcd10f4f724ec8d8c91943d927ad8f212196eac2276b9cc5cb86531c5`). Full table: `backend/experiments/mapping_a15/test_s10c.md`.

| Method | Recon | Brute Force | Spoofing | Benign clean | Primary score | Precision | Mean candidates |
|---|---|---|---|---|---|---|---|
| TF-IDF only | 0/43 | 15/43 | 0/43 | 15.6% | 0.2215 | 21.9% | 2.53 |
| TF-IDF + v2 filter | 0/43 | 9/43 | 0/43 | 28.2% | 0.2730 | 40.9% | 1.52 |
| Guarded mapping (g1) | 17/43 | 9/43 | 0/43 | 28.1% | 0.3050 | 43.0% | 1.89 |
| **Guarded + gate-3x** | 16/43 | **0/43** | 0/43 | **79.0%** | **0.5405** | 49.8% | 0.60 |

**Verdict: success under the pre-stated rule.** Gated minus guarded = **+0.2355, 95% paired bootstrap [+0.2208, +0.2489]**. DDoS (21/43), DoS (9/43) and Mirai (29/43) coverage are unchanged by the gate.

**The cost, stated plainly.** The gain comes from withholding context on low-score alerts, which are mostly false alarms: 79% of benign alerts now carry no misleading technique (28% before). Low-score attacks lose context too: share of attack alerts with candidates that the gate empties: Brute Force 57%, Spoofing 67%, Web-Based 43%, Recon 12%, floods 0%. Brute Force loses all of its relevant context (9/43 to 0/43). The primary score weights benign alerts as half the score, so it rewards silence on false alarms; a user who values context on quiet attacks more would not choose this gate. Off by default; the live monitor can show it as an option.

**Second look at amendment 12 (descriptive, not a planned test).** On S10c the guarded mapping again beats TF-IDF + v2 (0.3050 vs 0.2730) and Recon again reaches 17/43, consistent with the S10b result.
