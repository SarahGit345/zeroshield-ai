# Replay study

Stream `experiments\replay_streams\replay_stream_share30_seed3.jsonl`; seeds [1, 2, 3, 4, 5]; 5 folds. Routed alerts: 1003 (301 attacks, 702 benign false positives; attack share 0.300). By family: {'Benign': 702, 'Brute Force': 43, 'DDoS': 43, 'DoS': 43, 'Mirai': 43, 'Recon': 43, 'Spoofing': 43, 'Web-Based': 43}.

## Primary comparison (designed-simulation-v2)

| policy | mean reward per alert (mean ± std over seeds) |
|---|---|
| Contextual bandit (greedy held-out) | -0.260 ± 0.333 |
| Always HUMAN_REVIEW | -0.800 ± 0.000 |
| Random (seeded) | -2.518 ± 0.149 |
| Best constant action (training folds) | -0.800 ± 0.000 |
| Supervised expected-reward (logistic, training folds) | 0.184 ± 0.022 |
| Tuned score-tier rule (training folds) | 0.126 ± 0.028 |
| Verification-gate rule (strawman on this stream) | -6.898 ± 0.000 |

| bandit minus | mean difference | 95% paired-bootstrap interval | verdict | Bonferroni verdict (info) | seeds higher / tied / lower |
|---|---|---|---|---|---|
| Always HUMAN_REVIEW | +0.540 | [+0.462, +0.618] | **bandit better** | bandit better | 5 / 0 / 0 |
| Random (seeded) | +2.258 | [+2.107, +2.409] | **bandit better** | bandit better | 5 / 0 / 0 |
| Best constant action (training folds) | +0.540 | [+0.462, +0.618] | **bandit better** | bandit better | 5 / 0 / 0 |
| Supervised expected-reward (logistic, training folds) | -0.444 | [-0.538, -0.347] | **bandit worse** | bandit worse | 0 / 0 / 5 |
| Tuned score-tier rule (training folds) | -0.386 | [-0.470, -0.301] | **bandit worse** | bandit worse | 0 / 0 / 5 |
| Verification-gate rule (strawman on this stream) | +6.638 | [+6.561, +6.716] | **bandit better** | bandit better | 5 / 0 / 0 |

### The bandit's mistakes

- False positives auto-remediated: 0.1% (about 0.8 per seed).
- Attacks left at MONITOR_ONLY: 18.1%.
- Mean reward on benign alerts: bandit -0.665 vs always-review -2.000; difference +1.335, 95% interval [+1.268, +1.400]: bandit better.

### Oracle references (labels used; not baselines)

- Best single action chosen with labels: HUMAN_REVIEW (-0.800).
- Per-alert best action: 2.200.

### Per family (designed-simulation-v2), mean reward per alert averaged over seeds

| family | n | Contextual bandit (greedy held-out) | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|---|---|
| Benign | 702 | -0.67 | -2.00 | -4.00 | -2.00 | -0.01 | 0.17 | -12.00 |
| Brute Force | 43 | -0.99 | 2.00 | 0.74 | 2.00 | -1.94 | -2.71 | 5.00 |
| DDoS | 43 | 2.12 | 2.00 | 1.13 | 2.00 | 3.08 | 2.52 | 5.00 |
| DoS | 43 | 2.20 | 2.00 | 1.07 | 2.00 | 2.88 | 3.00 | 5.00 |
| Mirai | 43 | 2.16 | 2.00 | 1.16 | 2.00 | 2.63 | 2.79 | 5.00 |
| Recon | 43 | 0.84 | 2.00 | 0.85 | 2.00 | 1.48 | 0.53 | 5.00 |
| Spoofing | 43 | -0.75 | 2.00 | 0.97 | 2.00 | -2.05 | -2.53 | 5.00 |
| Web-Based | 43 | -0.78 | 2.00 | 0.62 | 2.00 | -1.66 | -3.38 | 5.00 |

Bandit action shares per family:

| family | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|
| Benign | 0.00 | 0.02 | 0.52 | 0.46 |
| Brute Force | 0.00 | 0.03 | 0.60 | 0.38 |
| DDoS | 0.01 | 0.15 | 0.82 | 0.01 |
| DoS | 0.03 | 0.22 | 0.73 | 0.01 |
| Mirai | 0.02 | 0.13 | 0.85 | 0.00 |
| Recon | 0.00 | 0.05 | 0.79 | 0.15 |
| Spoofing | 0.00 | 0.06 | 0.58 | 0.35 |
| Web-Based | 0.01 | 0.06 | 0.57 | 0.36 |

## Sensitivity: other reward tables (not evidence for the primary question)

| reward table | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|
| designed-simulation-v1 | +0.66 [+0.579, +0.741] bandit better | +2.20 [+2.050, +2.360] bandit better | +0.36 [+0.279, +0.441] bandit better | -0.42 [-0.510, -0.322] bandit worse | -0.39 [-0.465, -0.323] bandit worse | +6.76 [+6.678, +6.840] bandit better |
| sens-v2-false-remediation-6 | +0.73 [+0.624, +0.831] bandit better | +1.40 [+1.265, +1.531] bandit better | +0.73 [+0.624, +0.831] bandit better | -0.44 [-0.511, -0.364] bandit worse | -0.19 [-0.298, -0.069] bandit worse | +2.63 [+2.524, +2.730] bandit better |
| sens-v2-false-remediation-24 | +0.67 [+0.573, +0.767] bandit better | +4.48 [+4.220, +4.744] bandit better | +0.67 [+0.573, +0.767] bandit better | -0.28 [-0.363, -0.191] bandit worse | -0.26 [-0.328, -0.184] bandit worse | +15.17 [+15.071, +15.264] bandit better |
| sens-v2-missed-attack-12 | +0.25 [+0.149, +0.342] bandit better | +2.43 [+2.248, +2.611] bandit better | +0.25 [+0.149, +0.342] bandit better | -0.33 [-0.458, -0.206] bandit worse | -0.25 [-0.395, -0.098] bandit worse | +6.34 [+6.248, +6.441] bandit better |
| sens-v2-analyst-time-x2 | +2.42 [+2.303, +2.536] bandit better | +3.14 [+2.972, +3.304] bandit better | +0.72 [+0.605, +0.837] bandit better | -0.48 [-0.576, -0.378] bandit worse | +0.11 [-0.020, +0.247] no difference shown | +6.52 [+6.402, +6.634] bandit better |
| sens-v2-automation-gain-3 | +0.66 [+0.566, +0.759] bandit better | +2.53 [+2.370, +2.691] bandit better | +0.66 [+0.566, +0.759] bandit better | -0.31 [-0.378, -0.250] bandit worse | -0.26 [-0.334, -0.194] bandit worse | +7.36 [+7.264, +7.457] bandit better |

Cells: bandit minus baseline, mean difference, 95% paired-bootstrap interval, verdict.
Rewards are designed simulation values, not measured costs. The same routed alerts are reused across seeds.
