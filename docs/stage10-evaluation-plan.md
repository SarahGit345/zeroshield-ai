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
