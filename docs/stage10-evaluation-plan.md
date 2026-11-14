# Stage 10 evaluation plan (fixed before the confirmatory run)

Written and committed on 2026-11-08, before any of the code or experiments it describes. Everything below is fixed in advance. If a bug forces a change, the change, the reason and both sets of results are reported; no definition is changed silently.

Everything here is a simulated prototype. Rewards are designed values, not measured costs. No real network or host action is executed.

## 0. What has already been seen (exploratory, not evidence)

Before this plan, the following results were looked at once each:

- `backend/experiments/replay_study_seed1_stream/`: the seed-1 replay stream (1,150 rows, 720 flagged: 420 attacks, 300 benign false positives), seeds 1-5, 5 folds, 7 reward tables, comparing the bandit, the fixed rule, always-review, random, and hindsight constant actions.
- `backend/e2e_check.py` on the same stream: seeds 1-3 and an attack-share sweep (0.1, 0.3, 0.5, 0.8).

Those results showed that the fixed rule is a strawman on template-reasoning streams (every alert is VERIFIED at confidence 1.0, so it auto-remediates every alert) and that the comparison needs stronger baselines. That is why this plan exists. **The seed-1 stream is therefore exploratory only.** No claim in the final report rests on it.

## 1. Data

- **Confirmatory stream:** built by `backend/build_replay_stream.py --seed 2` from `validation_set.csv` and `zero_day_test_scaled_v2.csv`, using the same quotas as the seed-1 stream (per family: 60 flagged and 40 unflagged attacks; benign: 300 flagged and 150 unflagged) and the same detector checkpoint and threshold (0.06141921002417763).
- **No overlap with the exploratory stream:** any (source file, row) already in the seed-1 stream is excluded before sampling. The builder gets an `--exclude-stream` option for this (with a test). The number of excluded rows is reported.
- Reasoning is the labelled template (no LLM), as in the seed-1 stream. A stream with real LLM reasoning (Stage 10 step 3) would need its own addendum to this plan, written before it is run.
- Only detector-flagged rows are routed to the policies (`route()`); unflagged rows are counted, never scored.

## 2. Policies

Every learned or tuned policy is fitted on the **training folds only** and evaluated on the held-out fold. Every routed alert is evaluated exactly once per seed. All policies see the same folds (`make_folds(routed, 5, seed)`), the same 7 pre-action context features (`intercept, normalized_score, detected, verification_confidence, xai_feature_fraction, leading_xai_magnitude, mitre_context_present`) and never a label, outcome or reward at decision time. Labels are read only to compute rewards (and, for the supervised policy, to fit it on training folds).

The **AUTO safety mask** is the bandit's: AUTO_REMEDIATE is allowed only if `detected` and `verification_confidence >= 0.85`. Ties between actions are broken by the fixed order AUTO_REMEDIATE, CONFIRM_TO_ACT, HUMAN_REVIEW, MONITOR_ONLY.

| # | Policy | Definition |
|---|---|---|
| P0 | **Contextual bandit** | Existing LinUCB (`bandit_service.py`), alpha 0.25, trained with exploration and feedback on the training folds, evaluated greedily. Unchanged. |
| B1 | **Always HUMAN_REVIEW** | Existing baseline. |
| B2 | **Seeded random** | Existing baseline: `random.Random(seed)`, one draw per held-out alert. |
| B3 | **Best constant action, chosen on training folds** | On each fold, the single action with the highest mean reward on that fold's training alerts (subject to the safety mask, applied per alert at evaluation). Expected to be CONFIRM_TO_ACT on this stream mix, but chosen from data, not assumed. |
| B4 | **Supervised expected-reward policy** | Logistic regression predicting P(attack) from the 6 non-constant context features (the intercept is the model's own). Features standardised with a scaler fitted on the training folds. scikit-learn `LogisticRegression(C=1.0, penalty="l2", solver="lbfgs", max_iter=1000)`, no other tuning. Chooses the action with the highest expected reward `p * R_attack[a] + (1 - p) * R_benign[a]` under the reward table in use, with the safety mask. |
| B5 | **Tuned score-tier rule** | Alerts are split into up to three tiers by `normalized_score` (score / threshold) with cut points c1 <= c2 taken from the training folds' normalized-score quantiles at 0.05, 0.10, ..., 0.95 (c1 = c2 gives two tiers). Each tier gets the action with the highest mean reward on the training alerts in that tier (safety mask applied). The (c1, c2) pair with the highest training mean reward is chosen; ties go to the first pair in grid order (c1 ascending, then c2 ascending). |
| B6 | **Verification-gate rule (strawman on this stream)** | The old fixed rule: VERIFIED + detected + confidence >= 0.9 gives AUTO_REMEDIATE, otherwise HUMAN_REVIEW or MONITOR_ONLY. Kept for continuity. With template reasoning it auto-remediates every routed alert, so beating it is not evidence of anything. |

**Oracle references (use labels; never baselines, never deployable):**

- **O1 Best single action chosen with labels** on the whole evaluated set.
- **O2 Per-alert best action**: AUTO_REMEDIATE for every attack, MONITOR_ONLY for every benign flow (3.333 per alert on the seed-1 stream under v2).

They are reported in a separate table, labelled "oracle (labels used)", and no policy is called better or worse than them in the sense of section 4.

## 3. Primary comparison

- **Reward table:** `designed-simulation-v2` only.
- **Comparisons:** P0 (bandit) against each of B1-B6, i.e. six paired comparisons.
- **Primary metric:** mean reward per routed alert.
- **Seeds and folds:** seeds 1, 2, 3, 4, 5; 5 folds each.

**Sensitivity checks (not evidence for the primary question):** the same comparisons under `designed-simulation-v1` and the five named perturbations already in the code (`sens-v2-false-remediation-6`, `sens-v2-false-remediation-24`, `sens-v2-missed-attack-12`, `sens-v2-analyst-time-x2`, `sens-v2-automation-gain-3`), and under attack shares of 0.1, 0.3, 0.5 and 0.8 among flagged alerts (resampled from the confirmatory stream's flagged alerts as in `e2e_check.py`, per seed). These are reported with the same intervals, but they only say whether the primary result is robust; they cannot rescue or overturn it.

**Secondary metrics (descriptive):** per-family mean reward and action shares; benign remediation rate (wrongful blocks); attack monitor-only rate (missed attacks); approval-queue size; mean and std of per-seed means.

## 4. Evidence rule

- For each comparison, compute for every routed alert i its reward under the bandit and under the baseline, each averaged over the 5 seeds, and take the difference d_i.
- **Paired bootstrap:** resample alerts with replacement, stratified by family (the stream was sampled per family), 10,000 resamples, bootstrap RNG seed 20261108; take the 2.5th and 97.5th percentiles of the mean of d.
- **"Bandit better than X"** only if the whole 95% interval is above 0. **"Bandit worse than X"** only if it is wholly below 0. Otherwise **"no difference shown"** (a tie), which is reported as plainly as a win or a loss.
- Six primary comparisons are made, so one interval could exclude zero by chance. The verdict uses the 95% rule above. For information, the report also says whether each verdict holds at a Bonferroni-adjusted 99.17% interval, but this does not change the verdict.
- No significance language beyond this rule.

## 5. Things that will not change after results are seen

- Reward tables (values and names), the safety mask, and every policy definition, hyperparameter and grid above.
- The stream seed (2), quotas, exclusion rule, seeds 1-5, 5 folds, and the bootstrap settings.
- The choice of v2 as the primary table and B1-B6 as the baselines.

If a bug is found after results are seen, it is fixed with a test, everything is rerun, and the report states the bug, the fix and both results.

## 6. Order of work

1. Commit this plan (no experiment run before the commit).
2. Implement `--exclude-stream` in the builder and B3-B5 in the replay, each with tests; run the full suite and `e2e_check.py`.
3. Build the seed-2 stream once. Report its counts per family, flagged and unflagged, and the number of excluded rows.
4. Run the primary comparison and the sensitivity checks once. Record how many times the confirmatory results were looked at (target: once).
5. Write the results into `docs/` with the method, data, seeds and limitations.

## Amendment 1 (2026-11-08, before any new stream is built or any new baseline is run on real data)

Requested change of data. Nothing below was chosen after seeing a result: no confirmatory stream exists yet, and B3-B5 have only been run on synthetic test data.

**Data (replaces section 1's single seed-2 stream).** Two confirmatory streams, each with at least 300 flagged attacks split evenly over the 7 attack families (43 per family, 301 attacks, so each family is 14.3% of attacks):

| stream | command (from `backend/`) | flagged attacks | flagged benign | attack share |
|---|---|---|---|---|
| S10 | `python build_replay_stream.py --seed 2 --attack-share 0.1 --min-attacks 300 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --out experiments/replay_streams/replay_stream_share10_seed2.jsonl` | 301 | 2,709 | 0.100 |
| S30 | `python build_replay_stream.py --seed 3 --attack-share 0.3 --min-attacks 300 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --exclude-stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --out experiments/replay_streams/replay_stream_share30_seed3.jsonl` | 301 | 702 | 0.300 |

Unflagged quotas stay at 40 per attack family and 150 benign (never routed). S10 and S30 share no row with the seed-1 stream or with each other. The flagged benign population is 10,989 rows, so S10 uses about a quarter of all flagged benign flows.

**Seed-1 stream (S58, attack share 0.583).** Re-run with all seven policies and reported alongside, but labelled **exploratory**: its earlier results were seen before this plan.

**Primary comparison.** Bandit vs B1-B6 under `designed-simulation-v2`, on S10 and on S30 separately (12 comparisons). Verdicts use the section 4 rule per comparison. The Bonferroni interval (information only) adjusts for the 6 comparisons within a stream.

**Attack-share sensitivity (replaces the resampled 0.1/0.3/0.5/0.8 sweep in section 3).** Covered by the real streams S10 and S30, with S58 as exploratory. `e2e_check.py` still prints its resampled sweep, as a check only.

**Implementation details fixed now (they were not stated above):**
- B3-B5 learn from full-information labels on the training folds (every action's reward is known for a labelled alert); the bandit only sees the reward of the action it chose. This favours the baselines and is deliberate.
- B4: if a training fold contains a single class, P(attack) is that fold's attack rate.
- B5: a held-out alert whose tier had no training alerts uses the training-wide action ranking.
- Bootstrap: one set of resample indices per stream and reward table, shared by all six comparisons.
- The run writes `evaluation_decisions.csv` per run instead of the full action ledger (1.7 GB on S58); decisions and rewards are identical.

## Amendment 2 (2026-11-08): Stage 10 step 3, verification on a real LLM

Written after a 1-alert pilot and before any main-set alert is generated. Section 1 said a stream with real LLM reasoning would need an addendum before it is run; this addendum was not written before the 1-alert pilot, which is a lapse. The method itself was committed in code (`85b6a0e`) before the pilot ran.

**What was run before this amendment.** Pilot 0: one alert (`7b4cbfff-746d-54af-ab94-f43232d90c78`, benign, S30) sent to `qwen3:8b` with the prompt as committed in `85b6a0e`. Output kept in `backend/experiments/llm_verification/pilot0_before_fixes_qwen3_8b/`. It was REJECTED by `numeric_claims_grounded` because the report listed feature ranks, and it took 461 s (1,962 prompt and 1,008 output tokens). A rerun of the pilot with a first version of the rank fix was stopped during its first alert; it saved no output.

**Changes made after pilot 0 (both before any main-set alert):**
1. *Verifier, rank numbers.* A number counts as a rank only in a rank context ("rank N", "ranked N", "rank: N", "#N", "Nth") and only if it equals the rank of the nearest top feature named in the same sentence or JSON object; such a mention is then not an unsupported number. A rank mention with the wrong rank, or with no ranked feature nearby, is unsupported. Numbers outside a rank context are checked as before, so an invented small integer such as "3 failed logins" is still flagged. (A first version that accepted any rank value anywhere was committed in `0979014` and replaced by this rule before any further model output was used.) Tests: `RankClaims` in `test_verification_service.py`; the damage suite (`DamagedReportsAreCaught`, 17 tests) was rerun and passes.
2. *Prompt and cost.* The `evidence` field now asks for "three to six short strings" (the exact score and threshold and the three highest-ranked features, in words, so the prompt does not invite a bare "3"), and "Do not copy the whole input". MITRE descriptions sent to the LLM are cut to 300 characters (IDs, names, tactics, sources and similarities unchanged).
3. *Limits.* Per-alert time budget 600 s covering the first attempt and the retry; output cap 768 tokens per attempt (`num_predict`). A budget overrun is recorded as TIMEOUT (not VERIFIED, not a parse failure).

**Measurement (fixed now).**
- Model `qwen3:8b` (Ollama digest `500a1f067a9f…`, Q4_K_M, 8.2B), thinking off, temperature 0, seed 20261108, JSON schema format, parse-and-repair with one retry, CPU only.
- Data: flagged alerts of S30 (`replay_stream_share30_seed3.jsonl`, SHA-256 `1fb74980…5e13`); no dataset label in the prompt.
- Smoke test: the 10 pilot alerts (3 benign + 1 per attack family, including the pilot-0 alert), run once with the settings above. Its numbers are shown to the user before the main run starts. If it reveals a defect, any fix is recorded here before the main run.
- Main set: 30 benign + 10 per attack family (100), seeded (20261108), disjoint from the pilot alerts and explicitly excluding the pilot-0 alert (`SEEN_BEFORE_MAIN` in `measure_llm_verification.py`).
- Reported: verified / uncertain / rejected / LLM-failed / timeout shares overall and per family; counts of each failed check; invalid JSON on the first attempt, fixed by the retry, still invalid; repairs; replies that hit the output cap; timeouts; mean and max time per alert. False positives reaching the automated policy without the gate (all flagged benign alerts) and with the live API's gate (only VERIFIED), with the attacks the gate diverts to human review, and Wilson 95% intervals. Verification checks faithfulness to the evidence, not truth, so a small false-positive reduction is the expected honest outcome.
- Every raw model output, the exact prompt and every check are saved per alert.

## Amendment 3 (2026-11-08): HTTP content check for Web-Based attacks

Written and committed before any CIC-IoT-2023 web-attack capture has been parsed (none is on the build machine). The only capture inspected so far is the benign `BenignTraffic3.pcap`, and only by counting byte markers (about 1,650 `GET` and 19 `POST` request lines, about 3,700 TLS handshakes); the rules have not been run on it.

**Purpose.** A signature-based layer next to the flow detector: the anomaly detector for what is unusual in flow statistics, frozen rules for known web-attack patterns in plaintext HTTP. It is not zero-day detection and is reported separately from the zero-day results.

**Frozen rules.** `backend/services/content_rules.py`, `content-rules-v1`, 20 rules, SHA-256 `4275b674d4600a3b71f38857c37c69070a8ef35e1342a0787d5e7a0753529635`, written from general web-security knowledge (OWASP-style patterns) for SQL injection, cross-site scripting, command injection, path traversal and web shells / executable uploads. Matching is case-insensitive on the request line, query and body after two rounds of URL decoding. ATT&CK: SQL injection, command injection, path traversal -> T1190; web shells -> T1505.003; XSS -> no technique (client-side). Output per hit: rule, category, technique, matching snippet. Tiers, not probabilities: flow flagged and content hit = strong evidence; content hit only = alert on content; flow only = as today. No rule is changed after results are seen; a change needs a new version and an amendment.

**Data and go/no-go.** Requests are extracted from captures with `backend/pcap_http_extract.py` (dpkt; client-to-server TCP reassembly; TLS counted, not read). Go/no-go: if a web-attack capture yields no plaintext HTTP requests, the check cannot be evaluated on that attack and this is reported.

**Evaluation (`backend/evaluate_content_check.py`), run once.** Per capture: requests, requests with at least one hit (Wilson 95% interval), hits per category and rule, example snippets. Labels are per capture file, so the hit rate on an attack capture is a lower bound on recall over attack requests (captures can include benign background requests). Benign false positives on `BenignTraffic3.pcap` (and any other benign capture used), with a Wilson interval. Side by side: the flow detector's flag rate per family over the full dataset. No fused number is reported: CSV rows cannot be linked to individual requests; a fused evaluation needs flow features computed from the same captures (future work).

**Not in this amendment.** Feeding content hits into the live app, the reasoning prompt or the verifier. If that is added later, content-rule techniques must enter as a separately labelled source (not as retrieval) and the verifier's technique check must say which source a technique came from, with tests.

### Addendum to amendment 2 (2026-11-11), before any main-set alert is generated

Amendment 2 already fixed the main-run method (committed in `dce2f2b`); it stays as written: S30 flagged alerts, 30 benign + 10 per attack family (100), model digest `500a1f067a9f…`, Ollama 0.40.15, temperature 0, seed 20261108, thinking off, 600 s per alert, 768-token cap, and the prompt, schema, retrieval and verifier as committed. Nothing in them changes here. Additions, all descriptive or procedural:

1. **Exclusions.** The main set excludes pilot 0 and the 10 smoke-test alerts (which are the pilot sample); the script asserts this at start-up.
2. **Order.** Main-set alerts are processed in round-robin family order (Benign, DDoS, DoS, Recon, Brute Force, Spoofing, Mirai, Web-Based, repeated), so a partial run stays balanced. Membership is unchanged. Output is append-only (one raw file per alert, never overwritten) and resumable.
3. **"Faithful but wrong" count.** Technique IDs cited anywhere in each report are classed: for attacks, *relevant* (any cited technique in the relevant set for its label or family), *irrelevant* (cites only others) or *none*; for benign alerts, any cited technique counts as unsupported. Relevant sets: label level from `evaluate_retrieval.EXPECTED` where it exists (Mirai and Web-Based labels), otherwise family level: DDoS/DoS T1498, T1499; Recon T1046, T1595, T1018, T1590; Brute Force T1110; Spoofing T1557. "Faithful but wrong" = VERIFIED and (irrelevant, or benign citing a technique).
4. **Human check.** 30 completed reports drawn with seed 20261108 (`human_check_sample` in `summary.json`) are read by a team member against the evidence and marked faithful / not faithful; the result is reported next to the verifier verdicts.
5. **Stop rule.** If more than 2 of the first 10 alerts fail (LLM_FAILED, ERROR) or time out, or their mean time is above 270 s, the run is stopped and reported before continuing.
6. The verifier damage test (`DamagedReportsAreCaught`) was rerun on 2026-11-11 before the run: passes.

## Amendment 4 (2026-11-14): trade-off table and break-even analysis (post hoc, descriptive)

Decided after the policy results in `docs/stage10-results.md` were seen, to answer "the reward table is designed, not measured". It adds analysis only: no policy is rerun or retrained, no reward table is added or changed, and nothing new is tuned.

1. **Input.** The saved per-alert decisions of the reward-v2 replay studies (`evaluation_decisions.csv`, 5 seeds each) on S10 (`replay_study_share10_seed2`), S30 (`replay_study_share30_seed3`) and S58, exploratory (`replay_study_seed1_all_policies`). Each decision's label is recovered from its (action, reward) pair under that seed's `reward_table.json`; the script stops if a pair is ambiguous.
2. **Trade-off table.** Per stream and policy, mean ± std over seeds of: attacks left at MONITOR_ONLY, attacks sent to HUMAN_REVIEW, attacks actioned (CONFIRM_TO_ACT or AUTO_REMEDIATE), benign alerts AUTO_REMEDIATED, benign alerts sent to CONFIRM_TO_ACT, and analyst workload (share of all alerts sent to HUMAN_REVIEW or CONFIRM_TO_ACT). No reward is involved.
3. **Break-even.** With every policy's v2 decisions held fixed, mean reward is linear in each reward entry. One entry at a time, the others at v2: (a) the benign AUTO_REMEDIATE value (wrongful block), (b) the attack MONITOR_ONLY value (missed attack), (c) a shift added to both HUMAN_REVIEW values (analyst cost). For each, the value at which the bandit's mean reward equals each baseline's is solved exactly and reported with the side on which the bandit wins.
4. **Stated limit.** Break-even values hold the decisions fixed; a policy retrained under a different table would choose differently. The reruns under six other tables (`docs/stage10-results.md`, Sensitivity) remain the evidence for that case. Results are reported as post hoc and descriptive, once.

## Amendment 5 (2026-11-14): technique plausibility rules for retrieval abstention and the verifier (post hoc)

Decided after the LLM main run showed 47 VERIFIED reports citing a wrong technique, and after the retrieval results (19 of 53) were seen. Designed after seeing aggregate results, so everything here is reported as post hoc. No LLM is rerun; no reward table or detector setting changes.

1. **Rules (`plausibility-rules-v1`, `backend/services/technique_plausibility.py`).** Each ATT&CK technique family (root ID) lists the flow behaviours that could support it, written from the ATT&CK description and the existing behaviour ontology (for example T1498/T1499 need a flood behaviour such as high packet rate or density, many SYN packets, UDP or ICMP; T1110 needs SSH, Telnet, HTTP or HTTPS traffic or very short connections; T1190/T1059/T1505/T1185/T1189 need HTTP or HTTPS traffic). A behaviour counts only under the ontology's own rule: positive contribution and value at least +1 (high) or at most -1 (low), protocols only when present. A technique with no entry is "not judged" and is never removed. The rules are frozen by this commit, before any evaluation run.
2. **Retrieval abstention.** `retrieve_behavior(..., abstain_implausible=True)` drops candidates the rules judge implausible; if none remain it abstains. The live API default is unchanged (off) until the results are reviewed.
3. **Verifier check.** `verify_record(..., plausibility=True)` adds a major check `cited_techniques_plausible`: a retrieved technique cited in the report by ID or name must not be judged implausible. Default off; the 11-check verifier is unchanged.
4. **Evaluation, run once (`backend/evaluate_plausibility.py`).** (a) The 200-sample retrieval evidence, both halves, with and without abstention: answered, relevant, precision when answering. The held-out half was already looked at twice (see `docs/mitre-retrieval-evaluation.md`); this is the third look, and nothing is tuned on it (the rules have no threshold). (b) The 100 saved main-run reports: candidates removed, alerts with a relevant candidate before and after, benign alerts left with a candidate; verifier verdicts with and without the check, the faithful-but-wrong count (name-or-ID, as in `posthoc_technique_names.json`) before and after, benign false positives reaching the policy, and attacks newly marked UNCERTAIN. (c) The damage test still passes with the check on.
