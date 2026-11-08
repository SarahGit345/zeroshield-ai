# Stage 10 results: response-policy comparison

Method fixed in advance in `docs/stage10-evaluation-plan.md` (committed `74d0f89`, amendment 1 committed `0393804` before any confirmatory stream was built). Streams: `docs/stage10-streams.md`. Raw outputs: `backend/experiments/replay_study_share10_seed2/`, `replay_study_share30_seed3/`, `replay_study_seed1_all_policies/` (`study_summary.json` / `.md`, per-run metrics and configs; per-alert decision files are gitignored and regenerable).

Everything is a simulated prototype. Rewards are designed values (`designed-simulation-v2` unless stated), not measured costs. No real network or host action was executed.

## Method in one paragraph

Only detector-flagged flows reach the response policies. On each stream, the flagged alerts are split into 5 folds; every policy that learns (the LinUCB bandit, and baselines B3-B5) is trained or fitted on four folds and decides the fifth, so every alert is decided once per seed by a policy that never saw it. This is repeated for seeds 1-5 (different fold splits, bandit exploration and random draws; the same alerts). No label, outcome or reward is in any decision's input; tests check that flipping the held-out labels changes no held-out decision and that baselines are fitted on the training folds only. For each comparison, each alert's reward is averaged over the 5 seeds, the bandit-minus-baseline difference is bootstrapped over alerts (10,000 resamples within family, seed 20261108), and a verdict is "better"/"worse" only if the 95% interval excludes 0.

Policies: P0 contextual bandit (LinUCB, alpha 0.25); B1 always HUMAN_REVIEW; B2 seeded random; B3 best constant action chosen on the training folds; B4 supervised expected-reward policy (logistic regression on the same 6 context features, training folds); B5 score-tier rule tuned on the training folds; B6 the old verification-gate rule, a **strawman on these streams** (template reasoning marks every alert VERIFIED at 1.0, so it auto-remediates every alert). B3-B5 learn from full-information labels; the bandit only sees the reward of the action it chose.

## Primary results (reward table v2)

S10 and S30 are confirmatory. S58 is exploratory: its earlier results were seen before the plan was written.

### Mean reward per flagged alert (mean ± std over 5 seeds)

| policy | S10 (10% attacks, 3,010 alerts) | S30 (30% attacks, 1,003 alerts) | S58 exploratory (58% attacks, 720 alerts) |
|---|---|---|---|
| Contextual bandit | 0.591 ± 0.010 | -0.260 ± 0.333 | 0.755 ± 0.175 |
| B1 Always HUMAN_REVIEW | -1.600 | -0.800 | 0.333 |
| B2 Random | -3.493 ± 0.013 | -2.518 ± 0.149 | -1.033 ± 0.144 |
| B3 Best constant action (training folds) | 0.300 (MONITOR_ONLY) | -0.800 (HUMAN_REVIEW) | 0.500 (CONFIRM_TO_ACT) |
| B4 Supervised expected-reward | 0.568 ± 0.005 | **0.184 ± 0.022** | **1.202 ± 0.018** |
| B5 Tuned score-tier rule | 0.428 | 0.126 ± 0.028 | 1.070 ± 0.047 |
| B6 Verification-gate rule (strawman) | -10.300 | -6.898 | -2.083 |
| *Oracle: best single action chosen with labels* | *0.300* | *-0.800* | *0.500* |
| *Oracle: per-alert best action* | *1.400* | *2.200* | *3.333* |

Oracle rows use labels and are references, not baselines.

### Bandit minus each baseline: mean difference [95% paired-bootstrap interval], verdict

| baseline | S10 | S30 | S58 (exploratory) |
|---|---|---|---|
| B1 Always HUMAN_REVIEW | +2.191 [+2.150, +2.231] **better** | +0.540 [+0.462, +0.618] **better** | +0.422 [+0.342, +0.499] better |
| B2 Random | +4.084 [+3.996, +4.172] **better** | +2.258 [+2.107, +2.409] **better** | +1.788 [+1.624, +1.955] better |
| B3 Best constant action | +0.291 [+0.250, +0.331] **better** | +0.540 [+0.462, +0.618] **better** | +0.255 [+0.176, +0.332] better |
| B4 Supervised expected-reward | +0.023 [+0.005, +0.041] **better** (not under Bonferroni) | -0.444 [-0.538, -0.347] **worse** | -0.447 [-0.606, -0.287] worse |
| B5 Tuned score-tier rule | +0.164 [+0.117, +0.208] **better** | -0.386 [-0.470, -0.301] **worse** | -0.315 [-0.444, -0.181] worse |
| B6 Verification-gate rule (strawman) | +10.891 **better** (not informative) | +6.638 **better** (not informative) | +2.838 better (not informative) |

Every verdict agrees with the per-seed direction on all 5 seeds. All verdicts except S10 vs B4 also hold at the Bonferroni-adjusted level (6 comparisons per stream; information only, per the plan).

**Reading.** The bandit is reliably better than every non-learning baseline (always-review, random, the best constant action chosen on training data) at all three attack shares. Against the two learned baselines it depends on the attack share: at 30% (confirmatory) and 58% (exploratory) the supervised policy and the tuned score-tier rule are better than the bandit, by about 0.3-0.45 reward per alert. At 10% the bandit is ahead of both, but its lead over the supervised policy is 0.023 per alert, its interval starts at +0.005, it does not survive the Bonferroni check, and it reverses under three of the six alternative reward tables (below). **No general advantage of the bandit over a supervised policy using the same features is shown.** Beating the verification-gate rule says nothing, because on template-reasoning streams that rule auto-remediates every alert.

### The bandit's mistakes (v2)

| | S10 | S30 | S58 (exploratory) |
|---|---|---|---|
| False positives auto-remediated (wrongful simulated blocks) | 0.0% (0 per seed) | 0.1% (about 0.8 per seed) | 4.7% (about 14 per seed) |
| Attacks left at MONITOR_ONLY (missed) | **51.4%** | 18.1% | 0.9% |
| Mean reward on benign alerts: bandit vs always-review | +0.885 vs -2.000; diff +2.885 [+2.864, +2.905], better | -0.665 vs -2.000; diff +1.335 [+1.268, +1.400], better | -2.493 vs -2.000; diff -0.493 [-0.659, -0.337], **worse** |
| For comparison: supervised policy, FP auto-remediated / attacks missed | 0.0% / 56.2% | 1.1% / 26.6% | 3.0% / 11.4% |
| For comparison: score-tier rule, FP auto-remediated / attacks missed | 0.0% / 34.6% | 0.0% / 32.8% | 11.1% / 3.3% |

The bandit adapts its caution to the mix it was trained on, as all learned policies here do: when 90% of alerts are false positives it mostly monitors and misses half of the attacks; when attacks are the majority it rarely misses attacks but wrongly blocks about 1 in 20 false positives, and on benign alerts it then does worse than plain human review. Under v2, monitoring a flagged flow is the right call below an attack share of about 0.27, so many missed attacks at 10% is what the designed rewards ask for, not a bug. Whether that trade-off is acceptable is a design question about the reward table, not something this experiment can settle.

### Per family (v2, mean reward per alert averaged over seeds)

| family | S10 bandit | S10 supervised | S30 bandit | S30 supervised | S58 bandit | S58 supervised |
|---|---|---|---|---|---|---|
| Benign | 0.89 | 0.88 | -0.67 | -0.01 | -2.49 | -1.23 |
| Brute Force | -3.77 | -3.48 | -0.99 | -1.94 | 2.63 | 1.46 |
| DDoS | 0.16 | 0.39 | 2.12 | 3.08 | 3.60 | 4.58 |
| DoS | 0.47 | 0.86 | 2.20 | 2.88 | 3.86 | 4.82 |
| Mirai | -0.27 | -2.04 | 2.16 | 2.63 | 3.52 | 4.65 |
| Recon | -1.42 | -1.74 | 0.84 | 1.48 | 2.85 | 2.28 |
| Spoofing | -5.81 | -5.81 | -0.75 | -2.05 | 2.36 | 0.36 |
| Web-Based | -3.73 | -3.69 | -0.78 | -1.66 | 2.71 | 2.42 |

Per-family n: 43 alerts per attack family on S10 and S30, 60 on S58; benign 2,709 / 702 / 300. Family results are descriptive (no per-family test). The pattern is consistent: flood families (DDoS, DoS, Mirai) separate well from benign flows on anomaly score and both learners do best there; Spoofing, Brute Force and Web-Based look like benign traffic to this detector's features, so at low attack shares they are mostly monitored (S10 bandit: 98% of Spoofing and 72% of Web-Based alerts left at MONITOR_ONLY). The supervised policy is better than the bandit on the floods and on benign flows at 30% and 58%; the bandit is better on Spoofing, Brute Force and Web-Based there (it sends most of them to HUMAN_REVIEW; the supervised policy's action shares were not inspected, so the cause is not established). The full per-policy tables and the bandit's action shares per family are in each `study_summary.md`.

## Sensitivity: other reward tables (not evidence for the primary question)

Counts of verdicts for bandit minus baseline across the six other tables (`designed-simulation-v1` and five named perturbations of v2), as better / no difference shown / worse:

| baseline | S10 | S30 | S58 (exploratory) |
|---|---|---|---|
| B1 Always HUMAN_REVIEW | 6 / 0 / 0 | 6 / 0 / 0 | 6 / 0 / 0 |
| B2 Random | 6 / 0 / 0 | 6 / 0 / 0 | 6 / 0 / 0 |
| B3 Best constant action | 6 / 0 / 0 | 6 / 0 / 0 | 5 / 1 / 0 |
| B4 Supervised expected-reward | 2 / 1 / 3 | 0 / 0 / 6 | 0 / 0 / 6 |
| B5 Tuned score-tier rule | 5 / 1 / 0 | 0 / 1 / 5 | 0 / 0 / 6 |
| B6 Verification-gate rule (strawman) | 6 / 0 / 0 | 6 / 0 / 0 | 6 / 0 / 0 |

The ordering against non-learning baselines does not depend on the reward values tried. Against the supervised policy, the bandit loses under every table at 30% and 58%, and at 10% the sign flips with the table (worse under v1, missed-attack x2 and analyst-time x2; no difference with false-remediation -6; better under false-remediation -24 and automation-gain 3). Cell-level intervals are in each `study_summary.md`.

## How many times results were looked at

- S58: the bandit / fixed rule / always-review / random results were seen before the plan (exploratory study and `e2e_check.py`); the all-policy study was read once, after it finished.
- S30: read once, after its study finished.
- S10: read once, after its study finished.
- `e2e_check.py` also printed replay numbers for S58 with the new baselines during the pre-run check; they were not read before the plan amendment was committed.
- Nothing was tuned on any of these results. No reward table, policy definition, setting, seed or stream was changed after results were seen.

## Limits

- **Same alerts reused across seeds.** Each stream is one fixed sample; the seeds only change the fold split, the bandit's exploration and the random baseline. The intervals describe uncertainty over these alerts (resampled within family), not over new traffic, and the small std across seeds (for example 0.010 for the bandit on S10) is not evidence of stability on other data.
- **One dataset.** All rows come from CIC-IoT-2023 (one lab testbed), one detector checkpoint and one threshold. Nothing here shows the results hold on other networks or traffic.
- **Designed rewards.** The reward tables are designed trade-offs, not measured operational costs. Which policy is "best" depends on them; the sensitivity table shows the bandit-versus-supervised verdict at 10% changes sign with the table.
- **Controlled attack shares.** The streams fix the share of attacks among flagged alerts at 10%, 30% and 58%. In the full data, flagged attacks outnumber flagged benign flows by about 4,000 to 1; deployment traffic would have a different, unknown mix.
- **Template reasoning, no verification signal.** Reasoning was the labelled template; verification marked every alert VERIFIED at 1.0, so verification gave the policies no information and the verification-gate rule degenerates to always auto-remediate. Verification on a real LLM (Stage 10 step 3) has not been measured.
- **Information advantage of the baselines.** B3-B5 learn from full labels; the bandit learns from the reward of its own choices only. This makes them strong comparators, but it also means the comparison is not between equally informed learners.
- **Simulator assumptions.** CONFIRM_TO_ACT is assumed approved so a reward can be observed; rejected approvals are never simulated. No asset criticality or analyst history exists, and none was invented.
- **Small families.** 43 alerts per attack family on S10 and S30 (60 on S58); per-family numbers are descriptive only.
- **Environment.** scikit-learn 1.6.1 was installed while `requirements.txt` pins 1.7.2 (the version the retrieval index was saved with). Retrieval reproduced its documented held-out result (19 of 53) in `e2e_check.py`, but the version mismatch remains.

## What can be claimed

- On these streams and reward tables, the learned bandit beats every non-learning baseline (always-review, random, best constant action chosen on training data) at attack shares of 10%, 30% and 58%, with 95% intervals well clear of zero.
- It does **not** beat a supervised expected-reward policy or a tuned score-tier rule that use the same features: it loses to both at 30% (confirmatory) and 58% (exploratory), and at 10% its edge over the supervised policy is tiny and depends on the reward values.
- The bandit's errors move with the attack share: about half of attacks are left at monitor-only at 10%, and about 5% of false positives are auto-remediated at 58%.
