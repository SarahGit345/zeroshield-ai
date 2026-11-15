# Ablations of the policy inputs, exploration, and the explanation (plan amendment 9)

Descriptive ablations, run once each on the already-used streams S58, S10 and S30 (never S10b). No LLM call; the live bandit and detector are unchanged. Plan: `docs/stage10-evaluation-plan.md`, amendment 9 (committed `19db3f6` before any code). Code: `backend/ablate_policy_xai.py` (tests in `backend/tests/test_ablation_amendment9.py`). Full tables: `backend/experiments/ablation_amendment9/`.

## A. Which policy inputs matter (context ablation)

The LinUCB bandit was retrained with one input group held constant (equivalent to removing it), on the same folds and seeds as the published study (seeds 1 to 5, 5 folds, reward v2). **Harness check passed:** with the full context it reproduces the published bandit mean exactly on all three streams (S10 0.591296, S30 -0.260020, S58 0.755000).

Mean reward per flagged alert, change versus the full context [95% paired bootstrap]:

| Input removed | S10 (10% attacks) | S30 (30%) | S58 (58%, exploratory) |
|---|---|---|---|
| Verification confidence | +0.000 (no effect) | +0.000 (no effect) | +0.000 (no effect) |
| Anomaly score | **-0.096** [-0.119, -0.074] | -0.071 [-0.143, +0.002] | **-0.259** [-0.341, -0.180] |
| XAI strength (feature share, leading contribution) | **-0.191** [-0.239, -0.140] | **+0.139** [+0.097, +0.178] | -0.080 [-0.161, +0.004] |
| ATT&CK context present | **-0.158** [-0.203, -0.117] | -0.037 [-0.079, +0.002] | +0.012 [-0.039, +0.064] |
| All but the score | **-0.291** [-0.357, -0.230] | **+0.089** [+0.037, +0.137] | **-0.173** [-0.260, -0.081] |

- **Verification adds nothing to the policy**, because `verification_confidence` is 1.0 for every alert in every stream (the streams were built with template reasoning, which always verifies). The policy experiments therefore never tested verification as a signal. Testing it needs a stream verified with real LLM reports.
- **At 10% attacks, the XAI and ATT&CK inputs clearly help.** Without the XAI inputs the bandit misses 85.8% of attacks (full: 51.4%); with only the score it falls back to monitoring everything (100% missed, reward 0.300 = the best constant action).
- **At 30% attacks, the XAI inputs hurt:** removing them raises the reward by 0.139 (analyst workload falls from 62.2% to 53.7%, attacks missed rise from 18.1% to 21.1%). The value of each input depends on the attack share; only the score helps on every stream.

## B. Exploration setting (alpha)

| alpha | S10 | S30 | S58 |
|---|---|---|---|
| 0 (no exploration) | 0.577 (-0.015 [-0.024, -0.007]) | -0.264 (-0.004, n.s.) | 0.776 (+0.021, n.s.) |
| 0.25 (current) | 0.591 | -0.260 | 0.755 |
| 1.0 | 0.594 (+0.002, n.s.) | **-0.044 (+0.216 [+0.170, +0.260])** | 0.747 (-0.008, n.s.) |

More exploration helps markedly at 30% attacks and makes no clear difference elsewhere. Alpha stays 0.25: choosing it from these results would be tuning on streams already used for evaluation. A different alpha would need its own plan and a fresh test stream.

## C. Is the explanation faithful? (deletion test)

For every flagged alert, the top-k features named by the occlusion explanation were reset to 0 together and the flow re-scored; compared with k random features (20 seeded draws per alert) and the k lowest-ranked features. Full 43-feature rows were read from the source CSVs (streams store only the top 10); re-scoring them reproduces the stored scores to a relative error of at most 1.6e-5, with 100% agreement on the flag decision.

| S10 (3,010 alerts) | top-k removed | random k removed | top minus random [95% CI] | alerts below threshold after top-k |
|---|---|---|---|---|
| k = 1 | **71.8%** | -107.7% | +179.6% [+174.9%, +184.2%] | **78.6%** |
| k = 3 | -39.4% | -391.9% | +352.6% [+334.3%, +370.3%] | 37.5% |
| k = 5 | -202.0% | -761.7% | +559.7% [+529.0%, +592.0%] | 26.0% |

S30 and S58 show the same pattern (k = 1: 69.3% and 67.0% removed; 69.2% and 59.7% of alerts fall below the threshold).

- **By the pre-stated rule the explanation is faithful at k = 1, 3 and 5:** resetting the named features always changes the score far more in the anomaly-reducing direction than resetting random features, with intervals well clear of zero.
- **The top feature alone carries most of the anomaly:** resetting it removes about 70% of the score and brings 60 to 79% of alerts back below the threshold.
- **Limit exposed:** resetting random features *raises* the score (by about 100% for one feature), and resetting the top 3 or 5 together usually raises it too. The reference value 0 is the scaled mean, which for many features (for example binary protocol indicators) is not a value a real benign flow takes, so resetting several features moves the flow away from normal traffic. Single-feature occlusion contributions therefore do not add up, and the explanation is reliable mainly for its top feature.

## D. Does SHAP agree with occlusion?

On 296 flagged S30 alerts (37 per family), SHAP values from `shap.GradientExplainer` (reference: 200 unflagged benign alerts) were compared with the occlusion explanation.

| | top-1 agreement | top-5 overlap |
|---|---|---|
| Overall | **10.1%** | **26.4%** |
| Recon (highest) | 29.7% | 34.6% |
| Mirai (lowest) | 0.0% | 6.5% |

The two methods largely disagree. The main reason is the reference point: occlusion compares each feature with 0 (the scaled mean), SHAP with typical benign traffic. Together with part C, this means the explanation depends strongly on the chosen reference. A benign-reference occlusion (replace a feature with its benign median instead of 0) is the natural next step; it is not done here.

## What changes, and what does not

- No default changes: occlusion stays the explanation method, alpha stays 0.25, the policy context is unchanged.
- Claims to correct in slides and reports: "verification informs the response policy" is not supported (constant input); "the explanation shows why a flow is anomalous" holds firmly for the top feature, less so for the full top 10.
- Run once each. The policy part was looked at once; parts C and D were looked at once.

## Follow-up, amendment 14: benign-median reference (descriptive, run once)

Plan: amendment 14 (`218986b`, before code). Reference = per-feature median of 878,328 `train_benign_only.csv` rows; otherwise identical to parts C and D. Result: `backend/experiments/xai_benign_reference/summary.md`.

- **Pre-stated reading: NO.** Top-k minus random stays far above 0 at k = 1, 3, 5 on all streams, but joint removal of the top 3 or top 5 still raises the score on S10 and S30 (top-3: -12.2% and -6.2%; top-5: -103.6% and -84.7%); only S58 top-3 is positive (+13.7%). The top feature alone still removes about 72-73%.
- **Interpretation.** A realistic reference reduces but does not remove the problem: the detector is strongly non-additive, so single-feature contributions do not add up whatever the reference. The explanation remains reliable for its top feature.
- **SHAP agreement improves** with the benign reference: top-1 8.4% to 15.5%, top-5 26.0% to 35.9% (DDoS 61.1%, DoS 70.8% top-5), though not for Benign, Spoofing or Web-Based. Note: the zero-reference values recomputed here (8.4% / 26.0%) differ from part D's 10.1% / 26.4% because `shap.GradientExplainer` samples randomly; part D is not edited.
- The live explanation (reference 0) is unchanged.
