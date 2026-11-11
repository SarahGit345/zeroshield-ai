# Stage 10 step 3: verification on a real LLM

**Question.** When a real LLM writes the incident report instead of the template, how often does the rule-based verifier (`backend/services/verification_service.py`, 11 checks) pass, flag or reject it, which checks fail, and does the verification gate keep detector false positives away from the automated response policy?

**Short answer.** On 100 flagged alerts, qwen3:8b produced valid JSON every time, and the verifier passed 98 reports and flagged 2, both correctly. The gate let **all 30 benign false positives through (0% reduction)**. This measurement gives **no evidence that the gate reduces false positives**. The verifier is good at catching unsupported claims added to a report (13 of 14 damage kinds caught in every report), but it checks faithfulness to the evidence, not truth. Many VERIFIED reports faithfully repeat an ATT&CK technique that does not fit the flow: 47 of 100 by a post-hoc count.

## Method

- **Plan.** `docs/stage10-evaluation-plan.md`, amendment 2 (committed in `dce2f2b`) and its addendum of 2026-11-11 (committed in `27ef54c` at 00:12 IST, before the main run started). Amendment 2 records that its addendum was written after a 1-alert pilot, which was a lapse.
- **Model (frozen).** `qwen3:8b` via Ollama 0.40.15, digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` (Q4_K_M, 8.2B), CPU only. Temperature 0, seed 20261108, thinking off, output constrained to the report JSON schema, one parse-and-repair retry. 600 s budget per alert (retry included), 768-token output cap.
- **Prompt, retrieval, verifier.** As committed in `dce2f2b`: the prompt asks for three to six short evidence strings quoting the exact score, threshold and top features; MITRE descriptions are cut to 300 characters; the verifier includes the contextual rank rule. Nothing changed between the smoke test and the main run.
- **Data.** Flagged alerts of stream S30 (`replay_stream_share30_seed3.jsonl`, SHA-256 `1fb74980…5e13`, 30% attacks). No dataset label is in the prompt. Main set: 30 benign (detector false positives) + 10 per attack family (DDoS, DoS, Recon, Brute Force, Spoofing, Mirai, Web-Based) = 100. Drawn with seed 20261108, disjoint from the pilot and smoke alerts (checked at start-up), processed in round-robin family order.
- **Earlier runs, not in the results.** Pilot 0 (1 alert, before the post-pilot fixes; REJECTED for listing feature ranks, 461 s). Smoke test (the 10 pilot alerts, after the fixes; 10 VERIFIED, mean 178 s).
- **Main-run history.** The first start (00:13 IST) failed on every alert with HTTP 500 because Ollama could not allocate memory (C: full, so the page file could not grow); no model output was produced. After space was freed, the same command was restarted at 00:22 IST, retrying those alerts from scratch, and ran all 100 to completion (4 h 53 min). The stop rule (more than 2 of the first 10 failing or timing out, or mean above 270 s) was checked on the restart's first 10: 0 failures, mean 179 s.
- **Gate.** As in the live API: only VERIFIED alerts reach the automated response policy; UNCERTAIN and REJECTED go to human review.
- **Outputs.** `backend/experiments/llm_verification/main_qwen3_8b/`: one raw file per alert (prompt, raw model output, parsed report, every check), `summary.md/.json`, `damage_test.md/.json`, `posthoc_technique_names.json`, `human_check_packet.html` (blind; the key is kept outside the repository).

## Results

### Verdicts, failures, timing

| verdict | count | share (95% Wilson) |
|---|---|---|
| VERIFIED | 98 | 98% [93.0%, 99.4%] |
| UNCERTAIN | 2 | 2% [0.6%, 7.0%] |
| REJECTED | 0 | 0% [0%, 3.7%] |
| LLM_FAILED | 0 | 0% |
| TIMEOUT | 0 | 0% |

Per family, all 30 Benign, 10 DoS, 10 Mirai, 10 Recon, 10 Spoofing and 10 Web-Based reports were VERIFIED; DDoS and Brute Force had 9 VERIFIED and 1 UNCERTAIN each. The only failed check was `feature_directions_consistent` (2 reports).

| parsing and limits | count |
|---|---|
| valid JSON on the first attempt | 100 |
| invalid on the first attempt / fixed by retry / still invalid | 0 / 0 / 0 |
| repaired without retry | 0 |
| replies that hit the 768-token cap | 0 |
| timeouts | 0 |

Time per alert: mean 176 s, max 281 s; mean 315 output tokens per attempt (laptop CPU, 16 GB RAM). Template reasoning on the same 100 alerts: 100 VERIFIED.

### The two UNCERTAIN reports

Both reports made the same mistake: they say a feature had a **negative contribution** when its contribution is positive. All ten of each flow's top contributions are positive; the named features have negative *prepared values*, which the model confused with contributions.

| alert | family (label) | report says | evidence | classification |
|---|---|---|---|---|
| `495dd3cc` | DDoS (ICMP flood) | "Protocol Type and SYNRatio show negative contributions" | Protocol Type +0.922, SYNRatio +0.799 (values −2.87, −0.88) | **Verifier correct, LLM wrong** |
| `8bb3a4a2` | Brute Force (dictionary) | "HTTPS and Weight show negative contributions" | HTTPS +7.278, Weight +6.522 (values −1.56, −1.00) | **Verifier correct, LLM wrong** |

So the verifier raised 2 flags and neither was a false alarm. Both alerts were real attacks, so the cost of these two catches is that two attacks go to human review instead of the automated policy.

### Damage test on the LLM reports

After the run, without new LLM calls (`backend/damage_llm_reports.py`), each of the 98 VERIFIED reports was damaged once per kind. The damage sentence was added to the model's own text (or the limitations were emptied), and the report was verified again. Catch = no longer VERIFIED. These are the same damage kinds as the unit tests (`DamagedReportsAreCaught`), adapted to each alert's evidence.

| damage | expected check | caught | rate [95% CI] |
|---|---|---|---|
| status contradicts detector ("not anomalous") | threshold_and_status | 98/98 | 100% [96.2%, 100%] |
| below-threshold claim | threshold_and_status | 98/98 | 100% [96.2%, 100%] |
| technique not retrieved | technique_ids_retrieved | 98/98 | 100% [96.2%, 100%] |
| fabricated number (0.987654) | numeric_claims_grounded | 98/98 | 100% [96.2%, 100%] |
| **fake rounding of threshold ("about 0.1")** | numeric_claims_grounded | **59/98** | **60.2% [50.3%, 69.3%]** |
| wrong feature direction | feature_directions_consistent | 98/98 | 100% [96.2%, 100%] |
| feature outside XAI evidence | feature_claims_supported | 98/98 | 100% [96.2%, 100%] |
| certainty overclaim ("confirms") | certainty_claims_hedged | 98/98 | 100% [96.2%, 100%] |
| completed-action claim | no_completed_action_claims | 98/98 | 100% [96.2%, 100%] |
| invented IP / MAC / date / URL | no_invented_specifics | 98/98 each | 100% [96.2%, 100%] each |
| limitations removed | uncertainty_present | 98/98 | 100% [96.2%, 100%] |

Overall 1,333 of 1,372 damaged reports were caught; every catch came from the expected check. **The verifier missed all 39 misses on one kind, a wrong threshold.** The numeric check accepts a number if it is a rounding of *any* number in the evidence and does not check which quantity the sentence is about. In 38 of the 39 missed reports, some feature value or contribution rounds to 0.1, so "the threshold was about 0.1" passes (the last one was not traced). This is a real gap: a misquoted score or threshold can pass if it happens to match another number. The damage test is post hoc, and the damage sentences are clear-cut, so it measures sensitivity to blunt errors, not to subtle ones.

### False positives with and without the gate

| | benign false positives reaching the automated policy | attacks reaching the automated policy |
|---|---|---|
| without the gate | 30 of 30 | 70 of 70 |
| with the gate | **30 of 30** (benign VERIFIED rate 100%, 95% Wilson [88.6%, 100%]) | 68 of 70 (97.1% [90.2%, 99.2%]) |

The gate removed **no** false positives; it diverted 2 attacks to human review. With 30 benign alerts, the data are consistent with a benign pass rate as low as about 89%, so a small effect cannot be ruled out. Nothing here shows a reduction. That is the expected outcome for a faithfulness check: an honest report about a benign flow that the detector flagged is a faithful report, and it passes.

### "Faithful but wrong": techniques the reports cite

**Pre-registered count (addendum item 3): technique IDs only.** Attacks: 1 relevant, 0 irrelevant, 69 cite no ID. Benign: 1 cites an ID (unsupported), 29 cite none. Faithful but wrong: **1**. This count badly understates citations, because the reports almost always give the technique *name* ("OS Exhaustion Flood", "Direct Network Flood") rather than its ID.

**Post-hoc count (decided after seeing the results; `backend/posthoc_llm_analysis.py`): technique name or ID.** It uses the same relevant sets, matched against the names and IDs of the candidates the model was given.

| family | relevant | irrelevant | no candidates retrieved | faithful but wrong (VERIFIED and irrelevant / benign citing one) |
|---|---|---|---|---|
| Benign (30) | n/a | 21 cite a technique (unsupported) | 9 | 21 |
| DDoS (10) | 5 | 1 | 4 | 1 |
| DoS (10) | 2 | 1 | 7 | 1 |
| Mirai (10) | 5 | 1 | 4 | 1 |
| Brute Force (10) | 5 | 4 | 1 | 3 |
| Recon (10) | 0 | 8 | 2 | 8 |
| Spoofing (10) | 0 | 7 | 3 | 7 |
| Web-Based (10) | 0 | 5 | 5 | 5 |
| **total** | **17** | **27 + 21 benign** | **35** | **47** |

**Split by verdict (post-hoc classes):**

| class | VERIFIED | UNCERTAIN | total |
|---|---|---|---|
| benign, cites a technique (unsupported) | 21 | 0 | 21 |
| attack, cites only irrelevant techniques | 26 | 1 | 27 |
| attack, cites a relevant technique | 16 | 1 | 17 |
| no candidates retrieved (benign 9, attacks 26) | 35 | 0 | 35 |
| **faithful but wrong = VERIFIED and (benign citing, or irrelevant)** | **21 + 26 = 47** | | |

Reconciliation: a figure of 48 given in conversation before this write-up was a rough sum of benign-citing (21) and irrelevant (27) reports, marked "up to". One of the 27 irrelevant reports (Brute Force, `8bb3a4a2`) was UNCERTAIN, not VERIFIED, so it is not "faithful but wrong" by the definition. The correct count is **47**. The other UNCERTAIN report (DDoS) cites a relevant flood technique.

Every alert that was given candidates cited at least one; in the reports read, the citation was hedged ("suggest", "not confirmed"). The verifier's certainty check found no unhedged claim in any report. Whether the cited technique fits depends on retrieval, not the LLM. Retrieval maps most flagged flows to flood techniques (T1498/T1499), so floods get relevant techniques, while Recon, Spoofing, Web-Based and benign flows get irrelevant ones. The verifier accepts these by design, because the technique was retrieved. In 47 of 100 VERIFIED reports, the report points the analyst at an ATT&CK technique that does not fit the flow. The 17 "relevant" are mostly the generous flood match for flood families, plus T1110 for some Brute Force alerts.

**Relevant sets and when they were fixed.**
- **Label level:** `evaluate_retrieval.EXPECTED` (committed with the retrieval evaluation, long before this run). Mirai labels T1498, T1499, T1584. Backdoor_Malware T1505, T1190. BrowserHijacking T1185, T1189, T1190. CommandInjection T1190, T1059. SqlInjection T1190. Uploading_Attack T1190, T1505. XSS T1190, T1189.
- **Family level**, for labels without an entry (`RELEVANT_BY_FAMILY` in `measure_llm_verification.py`, committed in `27ef54c` before the main run started): DDoS and DoS T1498, T1499. Recon T1046, T1595, T1018, T1590. Brute Force T1110. Spoofing T1557.
- Any sub-technique counts. The sets were fixed before the main-run results. The authors had seen the 10 smoke-test reports, which cited only flood technique names. The name-based matching rule is the only post-hoc element.

### Human check (pending)

`main_qwen3_8b/human_check_packet.html` (built by `backend/build_human_check_packet.py`) is one self-contained page with 32 rows: the 30 reports drawn with seed 20261108 before the run, plus the 2 UNCERTAIN ones.
- **Order and IDs:** rows are shuffled with seed 20261108 and labelled R01–R32.
- **What each row shows:** only the evidence the model was given (score, threshold, top-5 features with values and contributions, ATT&CK candidates with IDs and names) and the report text.
- **Blank fields:** supported by evidence (Yes / Partly / No), technique plausible (Yes / No / None cited), notes.
- **What it leaves out:** the verdict, failed checks, family, dataset label, alert ID and file paths.
- **The key** (row ID to alert ID, verdict, family) is kept outside the repository and is not committed.
- **Leak scan:** the only matches for family or verdict words are in the model's own report text. "DoS" appears 10 times (for example, "candidates suggest potential DoS attacks") and "benign" 9 times (for example, "a benign anomaly"). There are no alert IDs, verdicts or labels.
- **Known limit on blindness:** the raw outputs with verdicts are committed in the same folder, and an earlier, non-blind sheet with alert IDs is in the git history (`8b599cc`). A checker could find a report's verdict by searching for its text, so checkers are asked to use only the packet.

The result is to be reported here next to the verifier verdicts. It has not been done yet.

## Limitations

- **One model, one configuration.** qwen3:8b at temperature 0 with one seed. Other models, prompts or temperatures may produce more unsupported claims and so more verifier flags.
- **The prompt is designed to make reports easy to verify.** It tells the model to quote the exact score and threshold, list the top features with contributions, hedge, and not claim actions. A 98% VERIFIED rate partly reflects that design. It does not show that the reports are correct.
- **Faithful is not true.** The verifier checks agreement with the evidence. Wrong techniques come from retrieval, which cannot identify application-layer, reconnaissance or spoofing behaviour from flow statistics (`docs/mitre-retrieval-evaluation.md`). The LLM faithfully repeats them, and the verifier passes them.
- **A known verifier gap.** The numeric check does not bind a number to the quantity it describes (wrong-threshold damage caught in 60%).
- **Small n.** 30 benign and 10 per attack family; per-family numbers have wide intervals. One stream (S30), one sampling seed.
- **Post-hoc parts are labelled as such.** The damage test on the LLM reports and the name-based technique count were defined after the run. The pre-registered count is reported as the primary one.
- **The human check is pending,** so faithfulness has so far been judged only by the verifier and by reading the 2 UNCERTAIN cases.
- **CPU only.** About 3 minutes per alert, so this setup is not usable for live triage.

## Reproduce

From `backend/` with Ollama running: `python -u measure_llm_verification.py --phase main` (about 5 h; resumes), then `python damage_llm_reports.py` and `python posthoc_llm_analysis.py` (seconds; no LLM calls). See `README_STAGE10.md`.
