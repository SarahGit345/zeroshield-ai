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

## Amendment 6 (2026-11-14): plausibility rules v2, tuned on S58, tested once on S10

Follows amendment 5, whose rules (v1) removed correct flood techniques because floods in this data appear as missing TCP behaviour (no ACK, few SYN packets), not only as high rates. Written before any v2 rule exists and before any S58 or S10 behaviour data is inspected for this purpose.

1. **Unit.** A (flagged alert, retrieved candidate technique) pair, using each alert's stored `xai_evidence` and `retrieved_techniques`. For attacks a candidate is *relevant* if its root ID is in `relevant_set` (label level from `evaluate_retrieval.EXPECTED`, else family level, as in amendments 2 and 5); every candidate on a benign alert is *irrelevant*. Unflagged alerts are excluded (they never reach the pipeline).
2. **Tuning set: S58** (`replay_stream_seed1.jsonl`, flagged alerts). v2 rules are written from networking knowledge and the behaviour ontology, then checked and revised on S58 only. Every revision is counted and listed in the results.
3. **Test set: S10** (`replay_stream_share10_seed2.jsonl`, flagged alerts), which shares no row with S58 and was never used for any rule. v2 is frozen in a commit before S10 is evaluated, and S10 is evaluated once. S30 (which contains the 100 LLM-run alerts used in amendment 5) is not used for v2.
4. **Metrics, per family and overall, with 95% Wilson intervals, for no rules, v1 and v2:** relevant candidates kept; irrelevant candidates removed; **primary: balanced accuracy of the keep/drop judgment** = mean of those two rates (no rules = 0.5). Alert level: attacks still holding a relevant candidate; benign alerts left with no candidate.
5. **Success rule, fixed now.** v2 is reported as an improvement over v1 only if, on S10, its balanced accuracy is higher and the 95% paired-bootstrap interval of the difference (v2 minus v1; 2,000 resamples of alerts, seed 20261114) excludes 0. Otherwise it is reported as no improvement. The same test is reported for v2 against no rules. Web-Based families are expected to stay weak (flow features cannot show HTTP content) and are reported separately.
6. Both features stay off by default whatever the result; enabling either in the live API is a separate decision.

## Amendment 7 (2026-11-15): behaviour-to-technique mapping, tuned on S58 and S10, tested once on a fresh stream S10b

Follows amendment 6. Retrieval never suggests a relevant technique for Recon (T1046, T1595, T1018, T1590) or Spoofing (T1557), because TF-IDF never ranks them in the top five. Web-Based attacks are out of scope for this amendment (flow features cannot show HTTP content); they are still reported, marked out of scope. Written before any mapping code exists and before S10b is built.

1. **Method.** A direct mapping from observed behaviours to techniques, reusing the behaviour rule of `technique_plausibility.observed_behaviours` (positive contribution, value at least +1 or at most -1, protocols only when present): scan patterns to T1046/T1595, ARP/DNS/DHCP activity to T1557, one-way or volumetric floods to T1498/T1499, login sessions to T1110. Mapped techniques are merged with the TF-IDF candidates, the `plausibility-rules-v2` filter is applied, candidates supported by an observed behaviour rank first, and at most five are kept. Exposed as `retrieve_behavior(..., behaviour_mapping=True)`, default off. Rules are written from ATT&CK descriptions and networking knowledge, with no threshold.
2. **Candidates are recomputed** from each alert's `xai_evidence` by the retrieval code (not read from the stream's stored `retrieved_techniques`), for every method compared, so all methods see the same input.
3. **Tuning sets: S58 and S10** (both already used; flagged alerts). At most three mapping variants are compared; every variant is listed with its tuning numbers.
4. **Test set: S10b**, a new stream built with `--seed 4 --attack-share 0.1 --min-attacks 300 --chunk-rows 200000` and `--exclude-stream` for S58, S10 and S30, so it shares no row with any earlier stream. Its SHA-256 is recorded in `docs/stage10-streams.md`. The chosen mapping is frozen in a commit before S10b is evaluated, and S10b is evaluated once.
5. **Methods compared on S10b:** TF-IDF only (current); TF-IDF + v2 filter; TF-IDF + mapping + v2 filter (new).
6. **Metrics, per family, with 95% Wilson intervals.** Coverage = attack alerts with at least one relevant candidate (relevance as in amendment 6: `relevant_set`, label level else family level). Benign clean rate = benign alerts with no candidate. **Primary: balanced score = mean of coverage (attack families except Web-Based) and benign clean rate.** Secondary: precision of attack candidates (relevant / all), mean candidates per alert.
7. **Success rule.** The new method is reported as an improvement over TF-IDF + v2 filter only if its primary score on S10b is higher and the 95% paired-bootstrap interval of the difference (2,000 resamples of alerts, seed 20261115) excludes 0. Otherwise it is reported as no improvement. Recon and Spoofing coverage are reported separately whatever the outcome.
8. Default stays off; enabling it in the live API is a separate decision.

## Amendment 9 (2026-11-15): policy-context ablation, exploration setting, XAI deletion test, occlusion vs SHAP (descriptive)

Written before any code for it exists. All four parts are descriptive ablations: nothing is selected or becomes a default. They run on the already-used streams S58, S10 and S30 (never S10b, reserved for amendment 7). No LLM is called.

**Known before running.** In every replay stream the `verification_confidence` context feature is 1.0 for all flagged alerts (the streams were built with template reasoning, which always verifies; checked on S30: 1,003 of 1,003). So the policy experiments so far never used verification as a signal. Part A will show this directly; the results docs will say so.

**A. Policy-context ablation.** The LinUCB bandit is retrained and evaluated with one context group removed at a time, by holding it constant (a constant column is absorbed by the intercept, which is equivalent to removing it): (1) full context; (2) without score (`normalized_score` constant); (3) without XAI (`xai_feature_fraction` and `leading_xai_magnitude` constant); (4) without ATT&CK (`mitre_context_present` constant); (5) without verification (`verification_confidence` constant); (6) score only (all of 3 to 5 constant). Same folds, seeds 1 to 5, 5 folds, reward v2, the existing `BanditService` unchanged. Metric: mean reward per flagged alert (mean and std over seeds), attacks missed, benign wrongly auto-remediated, analyst workload; paired-bootstrap 95% interval of each condition minus full (2,000 resamples of alerts, seed 20261115). **Harness check: condition (1) must reproduce the published bandit means in `docs/stage10-results.md` (S10 0.591, S30 -0.260, S58 0.755); if it does not, Part A is not reported.**

**B. Exploration setting.** The same harness with LinUCB alpha 0 (no exploration), 0.25 (current) and 1.0, full context. Descriptive; alpha stays 0.25.

**C. XAI deletion test (faithfulness).** For every flagged alert in the three streams, the top-k features named by the stored occlusion explanation (k = 1, 3, 5) are reset to 0 together and the detector re-scores the flow; compared with resetting k features drawn at random (20 seeded draws per alert, seed 20261115) and the k lowest-ranked of the 43. Metrics: mean share of the anomaly score removed, and share of alerts that fall below the threshold, per family. The explanation is called faithful at k if its score removal exceeds the random baseline with a non-overlapping 95% bootstrap interval.

**D. Occlusion vs SHAP.** On a seeded stratified sample of up to 300 flagged alerts from S30, SHAP values from `shap.GradientExplainer` on the detector's score (background: 200 unflagged benign alerts from S58, seed 20261115) are compared with the occlusion explanation: top-1 agreement and overlap of the top-5 features. Descriptive; occlusion stays the method.

## Amendment 10 (2026-11-15): local validation snapshot for amendment 7 rerun

This note is committed before any new mapping code or amendment 7 tuning. The teammate confirms the repository-root `validation_set.csv` is the correct current validation input, and the user directs that it be used. This file is the 31,159,073-row validation set named in `CLAUDE.md`; its SHA-256 is `E661CC9C6861A7692BD77918D79315D7B1CD814F46E55BAAD54288167C890AC8` (22,992,531,456 bytes). The companion `zero_day_test_scaled_v2.csv` is 2,658,953 rows, SHA-256 `1FE72BC723CD46106A57DE29012C3EE23FC7A504D931230269BCE2E2791A87BA` (2,051,913,808 bytes).

The committed stage-10 stream metadata records a different, larger validation snapshot (43,149,298 rows; 31,840,234,859 bytes). The earlier local rebuild from the current files read 33,818,026 total rows and skipped one non-finite row, so its populations and stream hashes did not match that metadata. We therefore proceed using the two hash-pinned current files above and preserve amendment 7's mapping, quotas, tuning/test separation, metrics, bootstrap, and success rule. S58, S10 and S30 must be rebuilt from this snapshot before tuning; the old stream population counts and hashes are not claimed for this rerun. S10b remains untouched until the mapping is frozen in a commit. The amendment 7 result will be reported as a revised-data-basis replication, not as a result on the older snapshot recorded in `stage10-streams.md`; both source hashes, stream counts and hashes, and this deviation must be included in the report. No change is made to amendment 7's success threshold or default-off requirement.

## Amendment 11 (2026-11-15): preserve non-overlap when an unflagged stratum is exhausted

The revised-data S10 build exposed only 69 unflagged DoS rows in the source population. S58 already used 40; after excluding S58, only 29 remained for S10. The builder therefore sampled 29 rather than the planned 40 unflagged DoS rows. Preserve the disjoint-row rule and use the available count for S30 as well (which may be zero after excluding S58 and S10); do not sample with replacement. All flagged quotas were met. Unflagged rows are never routed or evaluated, so this shortfall does not change the amendment 7 mapping metrics. Record these actual counts in the stream metadata and report. This clarification is committed before the S30 build, any code changes, or tuning.

## Amendment 12 (2026-11-15): mapping v2 with a benign guard, on the original data snapshot

Post hoc. Written and committed before any new code, any stream build from the original snapshot, or any tuning.

**Why.** Amendment 7 (S10b, revised data basis) showed the direct mapping recovers Recon (0/43 to 17/43) but lowers the benign clean rate (27.3% to 15.3%), so the primary score did not improve (-0.0094 [-0.0264, +0.0086]). The design below was informed by that S10b breakdown; S10b (revised basis) is therefore never used again, and the new version is tested on a stream no one has seen.

**Data.** The original snapshot recorded in `docs/stage10-streams.md`: `validation_set.csv` with 43,149,298 rows (31,840,234,859 bytes) and `zero_day_test_scaled_v2.csv` with 2,658,953 rows (2,051,913,808 bytes). The original S58 (seed 1) and S10 (share 0.10, seed 2) stream files already exist on the build machine. Before tuning, their SHA-256 must match the first table in `docs/stage10-streams.md` (allowing for its documented line-ending caveat); if either does not match, rebuild it with the documented command (45,808,251 rows read, 0 skipped) or stop and report. Do not tune on a mismatching stream.

**Variants (fixed now; no others will be tried).** All keep the TF-IDF retriever, the v2 plausibility filter and the cap of 5.
- `g1-scan-only`: the direct map adds only T1046, T1595 (scan core behaviours, as `v1-core-scan`) and T1557 (as amendment 7). Flood (T1498, T1499) and login (T1110) techniques come only from TF-IDF, never from the map.
- `g2-scan-only-strong`: as g1, but a scan or spoofing behaviour counts for the map only if its scaled value is at least 2 (instead of 1); positive contribution still required.
- `g3-scan-only-two`: as g1, but a mapped technique is added only if at least two of its behaviours are observed.

**Tuning.** On rebuilt S58 and S10 only. Metric and selection rule as amendment 7: highest mean primary balanced score across S58 and S10; ties follow the order above. Commit the frozen variant (code plus tuning output) before building the test stream.

**One-time test.** After the freeze commit, build S10b (share 0.10, seed 4, excluding S58, S10 and S30) from the original snapshot, and evaluate it once. Report four methods: TF-IDF only; TF-IDF + v2 filter; mapping v1 as frozen in `8659cbf` (a replication of amendment 7 on the original snapshot, no change); and the frozen guarded mapping.

**Metrics.** As amendment 7: coverage per in-scope family (DDoS, DoS, Recon, Brute Force, Spoofing, Mirai) with 95% Wilson intervals, benign clean rate, primary balanced score, precision, mean candidates per alert. Web-Based is reported separately, out of scope.

**Success rule.** The guarded mapping succeeds if its primary score minus TF-IDF + v2 filter is above 0 with the 95% stratified paired-bootstrap interval (2,000 resamples, seed 20261115, as amendment 7) entirely above 0. Reported whatever the outcome.

**Unchanged.** The mapping stays off by default; `backend/main.py` is not changed; labels are used only after retrieval to score relevance; the committed metadata of the original streams is not overwritten (new metadata files take new names).

## Amendment 13 (2026-11-15): detector operating points per family (descriptive)

Post hoc, descriptive; written and committed before any code or run. Motivation: the S10b build population (amendment 12) showed per-family flag rates at the deployed threshold far below the headline recall (Recon 56.6%, Spoofing 25.7%, Brute Force 20.8%, Web-Based 33.9%), because DDoS dominates the row count.

**Method.** One pass scores every row of `train_benign_only.csv`; thresholds are its benign-score percentiles 90, 93, 95, 97 and 99, plus the deployed threshold 0.0614 (`threshold_percentile` 95 in the checkpoint). A second pass scores every row of the original snapshot (`validation_set.csv`, 43,149,298 rows; `zero_day_test_scaled_v2.csv`, 2,658,953 rows) and counts, per source and family, rows at or above each threshold. Same detector, no retraining.

**Reported.** Per threshold: false-positive rate on validation benign rows, recall per family (validation families and zero-day families separately) with 95% Wilson intervals, row-weighted overall recall, and flagged benign rows per 1,000 benign rows.

**What is not done.** No threshold is selected and the deployed threshold is not changed: every stream, policy result and amendment uses 0.0614, and changing it would need its own plan and new streams. Families with low recall at every listed threshold are reported as a limit of flow-level features.

## Amendment 14 (2026-11-15): benign-reference occlusion (descriptive)

Post hoc, descriptive; written and committed before any code or run. Motivation: amendment 9 parts C and D showed the occlusion explanation is reliable mainly for its top feature, because the reference value 0 (the scaled mean) is not a realistic benign flow, and SHAP (benign background) agrees with it on the top feature only 10.1% of the time.

**Method.** Reference vector = per-feature median of `train_benign_only.csv` (training data; never an evaluation stream). For every flagged alert of S10, S30 and S58 (full rows from the amendment 9 cache), each of the 43 features is replaced in turn by its benign median and the alert re-scored; contribution = original score minus new score. Deletion test as amendment 9 part C, with the median as the reset value: top-k (k = 1, 3, 5) by the new ranking, versus k random features (20 seeded draws per alert, seed as amendment 9) and the k lowest-ranked. SHAP comparison as amendment 9 part D: same 296 S30 alerts, same 200-alert benign background, top-1 agreement and top-5 overlap of the new ranking with SHAP.

**Pre-stated reading.** The benign-reference explanation is called faithful beyond its top feature if, on all three streams, joint removal of the top 3 and top 5 lowers the score on average (positive share removed) and top-k minus random has a 95% bootstrap interval above 0 at k = 1, 3 and 5. SHAP agreement is reported against the amendment 9 values (10.1% top-1, 26.4% top-5). Descriptive: the live explanation (`model_service.py`, reference 0) is not changed by this amendment.

## Amendment 15 (2026-11-15): score-gated ATT&CK context

Post hoc; written and committed before any code, tuning or test-stream build. Motivation: with the frozen guarded mapping (amendment 12, g1-scan-only), 73% of flagged benign alerts on S10b still receive a technique, mostly from TF-IDF on flood-looking false alarms, which sit closer to the threshold than most attacks.

**Method.** On top of TF-IDF + guarded mapping (g1) + v2 filter, show no technique when the alert's anomaly score is below a gate of k times the deployed threshold (0.0614). Variants fixed now, none other tried: `gate-1.5x`, `gate-2x`, `gate-3x`. Labels are used only after retrieval, to score.

**Tuning.** On S58 and S10 only; metric and rule as amendments 7 and 12 (highest mean primary balanced score; ties follow the order above). The selected gate is frozen in a commit before the test stream is built.

**One-time test.** S10c: share 0.10, seed 5, minimum 300 attacks, built from the original snapshot after the freeze, excluding S58, S10, S30 and the original-snapshot S10b; evaluated once. Methods reported: TF-IDF only; TF-IDF + v2; guarded mapping (g1); gated guarded mapping. Metrics as amendment 12, plus the share of each attack family's alerts that lose all context because of the gate.

**Success rule.** Gated minus guarded mapping (g1) on the primary score above 0 with the 95% stratified paired-bootstrap interval (2,000 resamples, seed 20261115) entirely above 0. Reported whatever the outcome. The gate stays off by default; `backend/main.py` is unchanged.
