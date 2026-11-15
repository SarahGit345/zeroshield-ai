# Replay study

Stream `experiments\replay_streams\replay_stream_seed1.jsonl`; seeds [1, 2, 3, 4, 5]; 5 folds. Routed alerts: 720 (420 attacks, 300 benign false positives; attack share 0.583). By family: {'Benign': 300, 'Brute Force': 60, 'DDoS': 60, 'DoS': 60, 'Mirai': 60, 'Recon': 60, 'Spoofing': 60, 'Web-Based': 60}.

## Primary comparison (designed-simulation-v2)

| policy | mean reward per alert (mean ± std over seeds) |
|---|---|
| Contextual bandit (greedy held-out) | 0.755 ± 0.175 |
| Always HUMAN_REVIEW | 0.333 ± 0.000 |
| Random (seeded) | -1.033 ± 0.144 |
| Best constant action (training folds) | 0.500 ± 0.000 |
| Supervised expected-reward (logistic, training folds) | 1.202 ± 0.018 |
| Tuned score-tier rule (training folds) | 1.070 ± 0.047 |
| Verification-gate rule (strawman on this stream) | -2.083 ± 0.000 |

| bandit minus | mean difference | 95% paired-bootstrap interval | verdict | Bonferroni verdict (info) | seeds higher / tied / lower |
|---|---|---|---|---|---|
| Always HUMAN_REVIEW | +0.422 | [+0.342, +0.499] | **bandit better** | bandit better | 5 / 0 / 0 |
| Random (seeded) | +1.788 | [+1.624, +1.955] | **bandit better** | bandit better | 5 / 0 / 0 |
| Best constant action (training folds) | +0.255 | [+0.176, +0.332] | **bandit better** | bandit better | 5 / 0 / 0 |
| Supervised expected-reward (logistic, training folds) | -0.447 | [-0.606, -0.287] | **bandit worse** | bandit worse | 0 / 0 / 5 |
| Tuned score-tier rule (training folds) | -0.315 | [-0.444, -0.181] | **bandit worse** | bandit worse | 0 / 0 / 5 |
| Verification-gate rule (strawman on this stream) | +2.838 | [+2.759, +2.916] | **bandit better** | bandit better | 5 / 0 / 0 |

### The bandit's mistakes

- False positives auto-remediated: 4.7% (about 14.2 per seed).
- Attacks left at MONITOR_ONLY: 0.9%.
- Mean reward on benign alerts: bandit -2.493 vs always-review -2.000; difference -0.493, 95% interval [-0.659, -0.337]: bandit worse.

### Oracle references (labels used; not baselines)

- Best single action chosen with labels: CONFIRM_TO_ACT (0.500).
- Per-alert best action: 3.333.

### Per family (designed-simulation-v2), mean reward per alert averaged over seeds

| family | n | Contextual bandit (greedy held-out) | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|---|---|
| Benign | 300 | -2.49 | -2.00 | -3.98 | -3.00 | -1.23 | -2.64 | -12.00 |
| Brute Force | 60 | 2.63 | 2.00 | 1.01 | 3.00 | 1.46 | 2.59 | 5.00 |
| DDoS | 60 | 3.60 | 2.00 | 0.90 | 3.00 | 4.58 | 4.95 | 5.00 |
| DoS | 60 | 3.86 | 2.00 | 1.35 | 3.00 | 4.82 | 4.95 | 5.00 |
| Mirai | 60 | 3.52 | 2.00 | 1.12 | 3.00 | 4.65 | 4.95 | 5.00 |
| Recon | 60 | 2.85 | 2.00 | 1.01 | 3.00 | 2.28 | 3.40 | 5.00 |
| Spoofing | 60 | 2.36 | 2.00 | 0.98 | 3.00 | 0.36 | 2.30 | 5.00 |
| Web-Based | 60 | 2.71 | 2.00 | 1.13 | 3.00 | 2.42 | 2.93 | 5.00 |

Bandit action shares per family:

| family | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|
| Benign | 0.05 | 0.14 | 0.78 | 0.04 |
| Brute Force | 0.16 | 0.22 | 0.60 | 0.01 |
| DDoS | 0.41 | 0.38 | 0.21 | 0.00 |
| DoS | 0.49 | 0.39 | 0.12 | 0.00 |
| Mirai | 0.38 | 0.37 | 0.25 | 0.00 |
| Recon | 0.24 | 0.27 | 0.48 | 0.02 |
| Spoofing | 0.11 | 0.20 | 0.67 | 0.02 |
| Web-Based | 0.17 | 0.30 | 0.51 | 0.01 |

## Sensitivity: other reward tables (not evidence for the primary question)

| reward table | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|
| designed-simulation-v1 | +0.67 [+0.605, +0.732] bandit better | +1.93 [+1.772, +2.089] bandit better | +0.09 [+0.021, +0.148] bandit better | -0.42 [-0.577, -0.252] bandit worse | -0.27 [-0.403, -0.140] bandit worse | +3.09 [+3.021, +3.148] bandit better |
| sens-v2-false-remediation-6 | +0.73 [+0.653, +0.803] bandit better | +1.47 [+1.335, +1.613] bandit better | +0.60 [+0.521, +0.673] bandit better | -0.23 [-0.375, -0.077] bandit worse | -0.26 [-0.341, -0.184] bandit worse | +0.64 [+0.570, +0.720] bandit better |
| sens-v2-false-remediation-24 | +0.24 [+0.169, +0.309] bandit better | +2.85 [+2.613, +3.094] bandit better | +0.08 [+0.002, +0.142] bandit better | -0.30 [-0.488, -0.107] bandit worse | -0.14 [-0.230, -0.048] bandit worse | +7.66 [+7.585, +7.726] bandit better |
| sens-v2-missed-attack-12 | +0.42 [+0.346, +0.488] bandit better | +2.63 [+2.428, +2.838] bandit better | +0.25 [+0.179, +0.322] bandit better | -0.44 [-0.511, -0.371] bandit worse | -0.34 [-0.471, -0.190] bandit worse | +2.84 [+2.763, +2.905] bandit better |
| sens-v2-analyst-time-x2 | +1.46 [+1.258, +1.665] bandit better | +1.84 [+1.589, +2.078] bandit better | +1.30 [+1.091, +1.498] bandit better | -0.77 [-0.889, -0.644] bandit worse | -0.82 [-0.964, -0.675] bandit worse | +1.88 [+1.675, +2.081] bandit better |
| sens-v2-automation-gain-3 | +0.17 [+0.130, +0.208] bandit better | +1.83 [+1.690, +1.976] bandit better | +0.00 [-0.036, +0.041] no difference shown | -0.17 [-0.317, -0.031] bandit worse | -0.21 [-0.286, -0.134] bandit worse | +3.75 [+3.714, +3.791] bandit better |

Cells: bandit minus baseline, mean difference, 95% paired-bootstrap interval, verdict.
Rewards are designed simulation values, not measured costs. The same routed alerts are reused across seeds.
