# Replay study

Stream `experiments\replay_streams\replay_stream_share10_seed2.jsonl`; seeds [1, 2, 3, 4, 5]; 5 folds. Routed alerts: 3010 (301 attacks, 2709 benign false positives; attack share 0.100). By family: {'Benign': 2709, 'Brute Force': 43, 'DDoS': 43, 'DoS': 43, 'Mirai': 43, 'Recon': 43, 'Spoofing': 43, 'Web-Based': 43}.

## Primary comparison (designed-simulation-v2)

| policy | mean reward per alert (mean ± std over seeds) |
|---|---|
| Contextual bandit (greedy held-out) | 0.591 ± 0.010 |
| Always HUMAN_REVIEW | -1.600 ± 0.000 |
| Random (seeded) | -3.493 ± 0.013 |
| Best constant action (training folds) | 0.300 ± 0.000 |
| Supervised expected-reward (logistic, training folds) | 0.568 ± 0.005 |
| Tuned score-tier rule (training folds) | 0.428 ± 0.000 |
| Verification-gate rule (strawman on this stream) | -10.300 ± 0.000 |

| bandit minus | mean difference | 95% paired-bootstrap interval | verdict | Bonferroni verdict (info) | seeds higher / tied / lower |
|---|---|---|---|---|---|
| Always HUMAN_REVIEW | +2.191 | [+2.150, +2.231] | **bandit better** | bandit better | 5 / 0 / 0 |
| Random (seeded) | +4.084 | [+3.996, +4.172] | **bandit better** | bandit better | 5 / 0 / 0 |
| Best constant action (training folds) | +0.291 | [+0.250, +0.331] | **bandit better** | bandit better | 5 / 0 / 0 |
| Supervised expected-reward (logistic, training folds) | +0.023 | [+0.005, +0.041] | **bandit better** | no difference shown | 5 / 0 / 0 |
| Tuned score-tier rule (training folds) | +0.164 | [+0.117, +0.208] | **bandit better** | bandit better | 5 / 0 / 0 |
| Verification-gate rule (strawman on this stream) | +10.891 | [+10.850, +10.931] | **bandit better** | bandit better | 5 / 0 / 0 |

### The bandit's mistakes

- False positives auto-remediated: 0.0% (about 0.0 per seed).
- Attacks left at MONITOR_ONLY: 51.4%.
- Mean reward on benign alerts: bandit 0.885 vs always-review -2.000; difference +2.885, 95% interval [+2.864, +2.905]: bandit better.

### Oracle references (labels used; not baselines)

- Best single action chosen with labels: MONITOR_ONLY (0.300).
- Per-alert best action: 1.400.

### Per family (designed-simulation-v2), mean reward per alert averaged over seeds

| family | n | Contextual bandit (greedy held-out) | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|---|---|
| Benign | 2709 | 0.89 | -2.00 | -3.99 | 1.00 | 0.88 | 0.56 | -12.00 |
| Brute Force | 43 | -3.77 | 2.00 | 0.73 | -6.00 | -3.48 | -3.40 | 5.00 |
| DDoS | 43 | 0.16 | 2.00 | 0.80 | -6.00 | 0.39 | 2.00 | 5.00 |
| DoS | 43 | 0.47 | 2.00 | 1.00 | -6.00 | 0.86 | 1.81 | 5.00 |
| Mirai | 43 | -0.27 | 2.00 | 1.13 | -6.00 | -2.04 | 2.00 | 5.00 |
| Recon | 43 | -1.42 | 2.00 | 0.92 | -6.00 | -1.74 | -0.42 | 5.00 |
| Spoofing | 43 | -5.81 | 2.00 | 1.00 | -6.00 | -5.81 | -4.70 | 5.00 |
| Web-Based | 43 | -3.73 | 2.00 | 1.31 | -6.00 | -3.69 | -2.65 | 5.00 |

Bandit action shares per family:

| family | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|
| Benign | 0.00 | 0.00 | 0.04 | 0.96 |
| Brute Force | 0.00 | 0.03 | 0.24 | 0.73 |
| DDoS | 0.00 | 0.10 | 0.66 | 0.24 |
| DoS | 0.00 | 0.14 | 0.65 | 0.21 |
| Mirai | 0.00 | 0.07 | 0.64 | 0.29 |
| Recon | 0.00 | 0.04 | 0.53 | 0.43 |
| Spoofing | 0.00 | 0.00 | 0.02 | 0.98 |
| Web-Based | 0.00 | 0.03 | 0.25 | 0.72 |

## Sensitivity: other reward tables (not evidence for the primary question)

| reward table | Always HUMAN_REVIEW | Random (seeded) | Best constant action (training folds) | Supervised expected-reward (logistic, training folds) | Tuned score-tier rule (training folds) | Verification-gate rule (strawman on this stream) |
|---|---|---|---|---|---|---|
| designed-simulation-v1 | +2.22 [+2.173, +2.257] bandit better | +3.88 [+3.794, +3.972] bandit better | +0.32 [+0.273, +0.357] bandit better | -0.02 [-0.035, -0.010] bandit worse | +0.12 [+0.075, +0.168] bandit better | +10.92 [+10.873, +10.957] bandit better |
| sens-v2-false-remediation-6 | +2.19 [+2.153, +2.234] bandit better | +2.74 [+2.683, +2.804] bandit better | +0.29 [+0.253, +0.334] bandit better | +0.02 [-0.001, +0.047] no difference shown | +0.17 [+0.120, +0.212] bandit better | +5.49 [+5.453, +5.534] bandit better |
| sens-v2-false-remediation-24 | +2.19 [+2.150, +2.231] bandit better | +6.77 [+6.614, +6.929] bandit better | +0.29 [+0.250, +0.331] bandit better | +0.02 [+0.005, +0.041] bandit better | +0.16 [+0.117, +0.208] bandit better | +21.69 [+21.650, +21.731] bandit better |
| sens-v2-missed-attack-12 | +1.76 [+1.698, +1.822] bandit better | +3.80 [+3.697, +3.904] bandit better | +0.46 [+0.398, +0.522] bandit better | -0.09 [-0.135, -0.050] bandit worse | -0.06 [-0.124, +0.002] no difference shown | +10.46 [+10.398, +10.522] bandit better |
| sens-v2-analyst-time-x2 | +3.96 [+3.930, +3.984] bandit better | +4.86 [+4.780, +4.937] bandit better | +0.06 [+0.030, +0.084] bandit better | -0.11 [-0.143, -0.074] bandit worse | +0.06 [+0.030, +0.084] bandit better | +10.66 [+10.630, +10.684] bandit better |
| sens-v2-automation-gain-3 | +2.19 [+2.150, +2.231] bandit better | +4.13 [+4.044, +4.218] bandit better | +0.29 [+0.250, +0.331] bandit better | +0.03 [+0.008, +0.044] bandit better | +0.16 [+0.117, +0.208] bandit better | +11.09 [+11.050, +11.131] bandit better |

Cells: bandit minus baseline, mean difference, 95% paired-bootstrap interval, verdict.
Rewards are designed simulation values, not measured costs. The same routed alerts are reused across seeds.
