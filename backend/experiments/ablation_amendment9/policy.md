# Policy-context ablation and exploration setting (amendment 9, parts A and B)

Descriptive. Bandit retrained per condition on the same folds and seeds (1-5, 5 folds, reward v2). A removed context group is held constant. Difference to full: mean over alerts of (condition - full), each alert averaged over seeds, 95% paired bootstrap.

**Known before running:** `verification_confidence` is 1.0 for every alert in every stream (template reasoning), so removing it cannot change anything.

## S10

Harness check: full context reproduces the published bandit mean (0.591296 vs 0.591296): **yes**.

| condition | mean reward ± std | minus full [95% CI] | attacks missed | benign auto-remediated | analyst workload |
|---|---|---|---|---|---|
| alpha=0.0 | 0.577 ± 0.017 | -0.015 [-0.024, -0.007] | 52.8% | 0.0% | 8.2% |
| full | 0.591 ± 0.010 | +0.000 [+0.000, +0.000] | 51.4% | 0.0% | 8.2% |
| alpha=1.0 | 0.594 ± 0.023 | +0.002 [-0.006, +0.011] | 50.2% | 0.0% | 8.6% |
| no_score | 0.496 ± 0.084 | -0.096 [-0.119, -0.074] | 52.1% | 0.0% | 11.0% |
| no_xai | 0.401 ± 0.078 | -0.191 [-0.239, -0.140] | 85.8% | 0.0% | 2.0% |
| no_attack | 0.433 ± 0.008 | -0.158 [-0.203, -0.117] | 69.6% | 0.0% | 6.7% |
| no_verification | 0.591 ± 0.010 | +0.000 [+0.000, +0.000] | 51.4% | 0.0% | 8.2% |
| score_only | 0.300 ± 0.000 | -0.291 [-0.357, -0.230] | 100.0% | 0.0% | 0.0% |

## S30

Harness check: full context reproduces the published bandit mean (-0.260020 vs -0.260020): **yes**.

| condition | mean reward ± std | minus full [95% CI] | attacks missed | benign auto-remediated | analyst workload |
|---|---|---|---|---|---|
| alpha=0.0 | -0.264 ± 0.335 | -0.004 [-0.017, +0.009] | 18.6% | 0.1% | 61.8% |
| full | -0.260 ± 0.333 | +0.000 [+0.000, +0.000] | 18.1% | 0.1% | 62.2% |
| alpha=1.0 | -0.044 ± 0.283 | +0.216 [+0.170, +0.260] | 22.9% | 0.3% | 49.9% |
| no_score | -0.331 ± 0.366 | -0.071 [-0.143, +0.002] | 16.3% | 0.0% | 66.7% |
| no_xai | -0.121 ± 0.328 | +0.139 [+0.097, +0.178] | 21.1% | 0.3% | 53.7% |
| no_attack | -0.297 ± 0.381 | -0.037 [-0.079, +0.002] | 17.2% | 0.1% | 64.8% |
| no_verification | -0.260 ± 0.333 | +0.000 [+0.000, +0.000] | 18.1% | 0.1% | 62.2% |
| score_only | -0.171 ± 0.366 | +0.089 [+0.037, +0.137] | 22.1% | 0.0% | 55.2% |

## S58 (exploratory)

Harness check: full context reproduces the published bandit mean (0.755000 vs 0.755000): **yes**.

| condition | mean reward ± std | minus full [95% CI] | attacks missed | benign auto-remediated | analyst workload |
|---|---|---|---|---|---|
| alpha=0.0 | 0.776 ± 0.207 | +0.021 [-0.034, +0.073] | 3.0% | 6.3% | 70.6% |
| full | 0.755 ± 0.175 | +0.000 [+0.000, +0.000] | 0.9% | 4.7% | 79.6% |
| alpha=1.0 | 0.747 ± 0.260 | -0.008 [-0.103, +0.084] | 6.0% | 5.6% | 66.4% |
| no_score | 0.496 ± 0.054 | -0.259 [-0.341, -0.180] | 0.0% | 1.9% | 94.6% |
| no_xai | 0.675 ± 0.143 | -0.080 [-0.161, +0.004] | 2.7% | 1.0% | 84.6% |
| no_attack | 0.767 ± 0.141 | +0.012 [-0.039, +0.064] | 2.1% | 4.7% | 78.1% |
| no_verification | 0.755 ± 0.175 | +0.000 [+0.000, +0.000] | 0.9% | 4.7% | 79.6% |
| score_only | 0.583 ± 0.134 | -0.173 [-0.260, -0.081] | 3.9% | 0.6% | 89.7% |

