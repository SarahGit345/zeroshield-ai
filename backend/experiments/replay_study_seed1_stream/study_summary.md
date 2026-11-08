# Replay study

Stream: `experiments\replay_streams\replay_stream_seed1.jsonl`. Seeds [1, 2, 3, 4, 5], 5 folds.
Routed (detector-flagged) alerts: 720 = 420 attacks + 300 benign false positives. By family: {'Benign': 300, 'Brute Force': 60, 'DDoS': 60, 'DoS': 60, 'Mirai': 60, 'Recon': 60, 'Spoofing': 60, 'Web-Based': 60}. Not routed: 280 attack, 150 benign flows (never alerts, not scored).

## Bandit vs fixed rule, per reward version

| reward version | bandit mean ± std | fixed rule mean ± std | always HUMAN_REVIEW | random | bandit − fixed (mean ± std) | seeds |
|---|---|---|---|---|---|---|
| designed-simulation-v1 | 1.003 ± 0.136 | -2.083 ± 0.000 | 0.333 ± 0.000 | -0.929 ± 0.150 | +3.086 ± 0.136 | bandit higher on every seed |
| designed-simulation-v2 | 0.755 ± 0.175 | -2.083 ± 0.000 | 0.333 ± 0.000 | -1.033 ± 0.144 | +2.838 ± 0.175 | bandit higher on every seed |
| sens-v2-false-remediation-6 | 1.061 ± 0.292 | 0.417 ± 0.000 | 0.333 ± 0.000 | -0.411 ± 0.122 | +0.644 ± 0.292 | bandit higher on every seed |
| sens-v2-false-remediation-24 | 0.576 ± 0.104 | -7.083 ± 0.000 | 0.333 ± 0.000 | -2.276 ± 0.213 | +7.659 ± 0.104 | bandit higher on every seed |
| sens-v2-missed-attack-12 | 0.752 ± 0.160 | -2.083 ± 0.000 | 0.333 ± 0.000 | -1.879 ± 0.227 | +2.836 ± 0.160 | bandit higher on every seed |
| sens-v2-analyst-time-x2 | -0.202 ± 0.565 | -2.083 ± 0.000 | -1.667 ± 0.000 | -2.038 ± 0.109 | +1.881 ± 0.565 | bandit higher on every seed |
| sens-v2-automation-gain-3 | 0.504 ± 0.123 | -3.250 ± 0.000 | 0.333 ± 0.000 | -1.327 ± 0.139 | +3.754 ± 0.123 | bandit higher on every seed |

Std is the sample standard deviation across seeds (same alerts, different fold splits).

## Hindsight references (labels used; not policies)

| reward version | Oracle (hindsight, labels) | Always AUTO_REMEDIATE (hindsight reference) | Always CONFIRM_TO_ACT (hindsight reference) | Always HUMAN_REVIEW (hindsight reference) | Always MONITOR_ONLY (hindsight reference) |
|---|---|---|---|---|---|
| designed-simulation-v1 | 3.333 | -2.083 | 0.917 | 0.333 | -3.083 |
| designed-simulation-v2 | 3.333 | -2.083 | 0.500 | 0.333 | -3.083 |
| sens-v2-false-remediation-6 | 3.333 | 0.417 | 0.500 | 0.333 | -3.083 |
| sens-v2-false-remediation-24 | 3.333 | -7.083 | 0.500 | 0.333 | -3.083 |
| sens-v2-missed-attack-12 | 3.333 | -2.083 | 0.500 | 0.333 | -6.583 |
| sens-v2-analyst-time-x2 | 3.333 | -2.083 | -1.500 | -1.667 | -3.083 |
| sens-v2-automation-gain-3 | 2.167 | -3.250 | 0.500 | 0.333 | -3.083 |

## Per family (designed-simulation-v2)

Mean reward per alert (mean ± std over seeds) and the share of each action, routed alerts only.

### Contextual bandit (greedy held-out)

| family | mean reward | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|---|
| Benign | -2.493 ± 0.452 | 0.05 | 0.14 | 0.78 | 0.04 |
| Brute Force | 2.633 ± 0.450 | 0.16 | 0.22 | 0.60 | 0.01 |
| DDoS | 3.600 ± 1.019 | 0.41 | 0.38 | 0.21 | 0.00 |
| DoS | 3.857 ± 0.943 | 0.49 | 0.39 | 0.12 | 0.00 |
| Mirai | 3.517 ± 1.055 | 0.38 | 0.37 | 0.25 | 0.00 |
| Recon | 2.847 ± 0.444 | 0.24 | 0.27 | 0.48 | 0.02 |
| Spoofing | 2.360 ± 0.307 | 0.11 | 0.20 | 0.67 | 0.02 |
| Web-Based | 2.713 ± 0.428 | 0.17 | 0.30 | 0.51 | 0.01 |

### Fixed rules

| family | mean reward | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|---|
| Benign | -12.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| Brute Force | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| DDoS | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| DoS | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| Mirai | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| Recon | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| Spoofing | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |
| Web-Based | 5.000 ± 0.000 | 1.00 | 0.00 | 0.00 | 0.00 |

### Always HUMAN_REVIEW

| family | mean reward | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|---|
| Benign | -2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| Brute Force | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| DDoS | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| DoS | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| Mirai | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| Recon | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| Spoofing | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |
| Web-Based | 2.000 ± 0.000 | 0.00 | 0.00 | 1.00 | 0.00 |

### Random (seeded)

| family | mean reward | AUTO_REMEDIATE | CONFIRM_TO_ACT | HUMAN_REVIEW | MONITOR_ONLY |
|---|---|---|---|---|---|
| Benign | -3.978 ± 0.191 | 0.25 | 0.25 | 0.25 | 0.25 |
| Brute Force | 1.007 ± 0.709 | 0.23 | 0.28 | 0.24 | 0.25 |
| DDoS | 0.900 ± 0.524 | 0.23 | 0.25 | 0.26 | 0.26 |
| DoS | 1.350 ± 0.574 | 0.29 | 0.20 | 0.29 | 0.22 |
| Mirai | 1.120 ± 0.761 | 0.28 | 0.22 | 0.26 | 0.24 |
| Recon | 1.010 ± 0.300 | 0.21 | 0.30 | 0.25 | 0.24 |
| Spoofing | 0.977 ± 0.392 | 0.25 | 0.25 | 0.24 | 0.25 |
| Web-Based | 1.133 ± 0.203 | 0.26 | 0.24 | 0.26 | 0.24 |

Rewards are designed simulation values, not measured costs. The stream is quota-sampled (false positives over-sampled), so mean rewards depend on that mix and are not deployment estimates.
