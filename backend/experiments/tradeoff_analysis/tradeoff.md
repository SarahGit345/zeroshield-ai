# Trade-off and break-even analysis (post hoc, descriptive)

POST HOC, descriptive (plan amendment 4). Decisions are the saved reward-v2 replay decisions; break-even holds them fixed, so a policy retrained under another table could choose differently.

## S10

Mean ± std over 5 seeds (shares).

| policy | attacks missed (MONITOR_ONLY) | attacks to HUMAN_REVIEW | attacks actioned (CONFIRM or AUTO) | benign wrongly AUTO_REMEDIATED | benign to CONFIRM_TO_ACT | analyst workload (REVIEW or CONFIRM, all alerts) |
|---|---|---|---|---|---|---|
| Contextual bandit (greedy held-out) | 51.4% ± 2.8% | 42.7% ± 10.9% | 5.9% ± 8.3% | 0.0% ± 0.0% | 0.2% ± 0.3% | 8.2% ± 0.6% |
| Always HUMAN_REVIEW | 0.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% |
| Best constant action (training folds) | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% |
| Random (seeded) | 24.6% ± 1.4% | 27.1% ± 2.0% | 48.3% ± 2.8% | 24.9% ± 0.2% | 25.0% ± 0.5% | 50.4% ± 0.6% |
| Supervised expected-reward (logistic, training folds) | 56.2% ± 0.9% | 18.3% ± 1.8% | 25.5% ± 1.3% | 0.0% ± 0.0% | 1.1% ± 0.0% | 7.6% ± 0.1% |
| Tuned score-tier rule (training folds) | 34.6% ± 0.0% | 65.4% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 19.7% ± 0.0% |
| Verification-gate rule (strawman on this stream) | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% |

Break-even (decisions fixed; one entry varied, others at v2):

**wrongful block (benign AUTO_REMEDIATE value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +2.191 | same decisions on this entry: difference does not depend on it |
| Best constant action (training folds) | +0.291 | same decisions on this entry: difference does not depend on it |
| Random (seeded) | +4.084 | bandit better when value < +6.24 |
| Supervised expected-reward (logistic, training folds) | +0.023 | same decisions on this entry: difference does not depend on it |
| Tuned score-tier rule (training folds) | +0.164 | same decisions on this entry: difference does not depend on it |
| Verification-gate rule (strawman on this stream) | +10.891 | bandit better when value < +0.10 |

**missed attack (attack MONITOR_ONLY value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +2.191 | bandit better when value > -48.61 |
| Best constant action (training folds) | +0.291 | bandit better when value < -0.00 |
| Random (seeded) | +4.084 | bandit better when value > -158.14 |
| Supervised expected-reward (logistic, training folds) | +0.023 | bandit better when value < -1.15 |
| Tuned score-tier rule (training folds) | +0.164 | bandit better when value > -15.69 |
| Verification-gate rule (strawman on this stream) | +10.891 | bandit better when value > -217.78 |

**analyst cost (shift added to both HUMAN_REVIEW values)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +2.191 | bandit better when shift < +2.37 |
| Best constant action (training folds) | +0.291 | bandit better when shift > -3.92 |
| Random (seeded) | +4.084 | bandit better when shift < +22.66 |
| Supervised expected-reward (logistic, training folds) | +0.023 | bandit better when shift > -0.72 |
| Tuned score-tier rule (training folds) | +0.164 | bandit better when shift < +1.33 |
| Verification-gate rule (strawman on this stream) | +10.891 | bandit better when shift > -146.74 |

## S30

Mean ± std over 5 seeds (shares).

| policy | attacks missed (MONITOR_ONLY) | attacks to HUMAN_REVIEW | attacks actioned (CONFIRM or AUTO) | benign wrongly AUTO_REMEDIATED | benign to CONFIRM_TO_ACT | analyst workload (REVIEW or CONFIRM, all alerts) |
|---|---|---|---|---|---|---|
| Contextual bandit (greedy held-out) | 18.1% ± 12.8% | 70.6% ± 19.9% | 11.2% ± 11.9% | 0.1% ± 0.3% | 2.4% ± 2.5% | 62.2% ± 25.1% |
| Always HUMAN_REVIEW | 0.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% |
| Best constant action (training folds) | 0.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% |
| Random (seeded) | 25.8% ± 3.1% | 24.2% ± 3.4% | 50.0% ± 2.6% | 24.9% ± 1.3% | 24.7% ± 1.1% | 50.0% ± 1.9% |
| Supervised expected-reward (logistic, training folds) | 26.6% ± 0.3% | 21.5% ± 0.5% | 51.8% ± 0.7% | 1.1% ± 0.1% | 5.2% ± 0.3% | 37.4% ± 0.4% |
| Tuned score-tier rule (training folds) | 32.8% ± 0.6% | 1.4% ± 0.6% | 65.8% ± 0.0% | 0.0% ± 0.0% | 17.9% ± 0.0% | 35.4% ± 1.5% |
| Verification-gate rule (strawman on this stream) | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% |

Break-even (decisions fixed; one entry varied, others at v2):

**wrongful block (benign AUTO_REMEDIATE value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.540 | bandit better when value > -688.50 |
| Best constant action (training folds) | +0.540 | bandit better when value > -688.50 |
| Random (seeded) | +2.258 | bandit better when value < +1.01 |
| Supervised expected-reward (logistic, training folds) | -0.444 | bandit better when value < -79.48 |
| Tuned score-tier rule (training folds) | -0.386 | bandit better when value > +472.25 |
| Verification-gate rule (strawman on this stream) | +6.638 | bandit better when value < -2.50 |

**missed attack (attack MONITOR_ONLY value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.540 | bandit better when value > -15.91 |
| Best constant action (training folds) | +0.540 | bandit better when value > -15.91 |
| Random (seeded) | +2.258 | bandit better when value < +91.60 |
| Supervised expected-reward (logistic, training folds) | -0.444 | bandit better when value < -23.40 |
| Tuned score-tier rule (training folds) | -0.386 | bandit better when value < -14.76 |
| Verification-gate rule (strawman on this stream) | +6.638 | bandit better when value > -127.95 |

**analyst cost (shift added to both HUMAN_REVIEW values)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.540 | bandit better when shift < +1.27 |
| Best constant action (training folds) | +0.540 | bandit better when shift < +1.27 |
| Random (seeded) | +2.258 | bandit better when shift > -7.01 |
| Supervised expected-reward (logistic, training folds) | -0.444 | bandit better when shift > +1.25 |
| Tuned score-tier rule (training folds) | -0.386 | bandit better when shift > +0.71 |
| Verification-gate rule (strawman on this stream) | +6.638 | bandit better when shift > -11.55 |

## S58 (exploratory)

Mean ± std over 5 seeds (shares).

| policy | attacks missed (MONITOR_ONLY) | attacks to HUMAN_REVIEW | attacks actioned (CONFIRM or AUTO) | benign wrongly AUTO_REMEDIATED | benign to CONFIRM_TO_ACT | analyst workload (REVIEW or CONFIRM, all alerts) |
|---|---|---|---|---|---|---|
| Contextual bandit (greedy held-out) | 0.9% ± 1.3% | 40.8% ± 17.8% | 58.4% ± 17.5% | 4.7% ± 6.2% | 13.8% ± 10.9% | 79.6% ± 22.8% |
| Always HUMAN_REVIEW | 0.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% |
| Best constant action (training folds) | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% | 100.0% ± 0.0% |
| Random (seeded) | 24.2% ± 2.7% | 25.7% ± 1.6% | 50.1% ± 2.2% | 24.9% ± 1.8% | 24.9% ± 2.1% | 50.3% ± 2.3% |
| Supervised expected-reward (logistic, training folds) | 11.4% ± 0.3% | 12.4% ± 0.6% | 76.1% ± 0.4% | 3.0% ± 0.2% | 23.1% ± 0.9% | 42.1% ± 0.9% |
| Tuned score-tier rule (training folds) | 3.3% ± 1.8% | 30.5% ± 1.8% | 66.2% ± 0.0% | 11.1% ± 0.3% | 0.0% ± 0.0% | 48.3% ± 2.8% |
| Verification-gate rule (strawman on this stream) | 0.0% ± 0.0% | 0.0% ± 0.0% | 100.0% ± 0.0% | 100.0% ± 0.0% | 0.0% ± 0.0% | 0.0% ± 0.0% |

Break-even (decisions fixed; one entry varied, others at v2):

**wrongful block (benign AUTO_REMEDIATE value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.422 | bandit better when value > -33.38 |
| Best constant action (training folds) | +0.255 | bandit better when value > -24.93 |
| Random (seeded) | +1.788 | bandit better when value < +9.31 |
| Supervised expected-reward (logistic, training folds) | -0.447 | bandit better when value > +49.92 |
| Tuned score-tier rule (training folds) | -0.315 | bandit better when value < -23.82 |
| Verification-gate rule (strawman on this stream) | +2.838 | bandit better when value < -4.85 |

**missed attack (attack MONITOR_ONLY value)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.422 | bandit better when value > -90.33 |
| Best constant action (training folds) | +0.255 | bandit better when value > -57.00 |
| Random (seeded) | +1.788 | bandit better when value < +7.13 |
| Supervised expected-reward (logistic, training folds) | -0.447 | bandit better when value < -13.25 |
| Tuned score-tier rule (training folds) | -0.315 | bandit better when value < -28.25 |
| Verification-gate rule (strawman on this stream) | +2.838 | bandit better when value > -573.67 |

**analyst cost (shift added to both HUMAN_REVIEW values)**

| baseline | bandit − baseline at v2 | verdict |
|---|---|---|
| Always HUMAN_REVIEW | +0.422 | bandit better when shift < +0.96 |
| Best constant action (training folds) | +0.255 | bandit better when shift > -0.45 |
| Random (seeded) | +1.788 | bandit better when shift > -5.82 |
| Supervised expected-reward (logistic, training folds) | -0.447 | bandit better when shift > +1.24 |
| Tuned score-tier rule (training folds) | -0.315 | bandit better when shift > +4.05 |
| Verification-gate rule (strawman on this stream) | +2.838 | bandit better when shift > -5.06 |
