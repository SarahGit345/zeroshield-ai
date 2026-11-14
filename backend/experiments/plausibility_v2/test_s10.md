# Plausibility rules v2: test on S10 (run once)

Plan amendment 6. Test set S10 evaluated once with v2 frozen (rules plausibility-rules-v2). Unit: flagged alert x retrieved candidate; benign candidates are all irrelevant.

**Verdict: improvement over v1.** Balanced accuracy v2 minus v1 = +0.185, 95% paired-bootstrap interval [+0.123, +0.245]; v2 minus no rules interval [+0.101, +0.183].

| rules | relevant kept [95% CI] | irrelevant removed [95% CI] | balanced accuracy | attacks keeping a relevant candidate | benign left with no candidate |
|---|---|---|---|---|---|
| no rules | 139/139 = 100.0% [97.3%, 100.0%] | 0/7433 = 0.0% [0.0%, 0.1%] | 0.500 | 81 of 81 with one before (of 301 attacks) | 405 of 2709 |
| v1 | 56/139 = 40.3% [32.5%, 48.6%] | 3855/7433 = 51.9% [50.7%, 53.0%] | 0.461 | 30 of 81 with one before (of 301 attacks) | 829 of 2709 |
| v2 | 126/139 = 90.6% [84.7%, 94.5%] | 2856/7433 = 38.4% [37.3%, 39.5%] | 0.645 | 76 of 81 with one before (of 301 attacks) | 706 of 2709 |

## Per family

**Benign**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | n/a | 0/6915 (0.0%) | n/a |
| v1 | n/a | 3529/6915 (51.0%) | n/a |
| v2 | n/a | 2572/6915 (37.2%) | n/a |

**Brute Force**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | 50/50 (100.0%) | 0/55 (0.0%) | 0.500 |
| v1 | 0/50 (0.0%) | 7/55 (12.7%) | 0.064 |
| v2 | 37/50 (74.0%) | 6/55 (10.9%) | 0.425 |

**DDoS**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | 34/34 (100.0%) | 0/46 (0.0%) | 0.500 |
| v1 | 24/34 (70.6%) | 29/46 (63.0%) | 0.668 |
| v2 | 34/34 (100.0%) | 29/46 (63.0%) | 0.815 |

**DoS**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | 17/17 (100.0%) | 0/10 (0.0%) | 0.500 |
| v1 | 17/17 (100.0%) | 7/10 (70.0%) | 0.850 |
| v2 | 17/17 (100.0%) | 7/10 (70.0%) | 0.850 |

**Mirai**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | 38/38 (100.0%) | 0/111 (0.0%) | 0.500 |
| v1 | 15/38 (39.5%) | 111/111 (100.0%) | 0.697 |
| v2 | 38/38 (100.0%) | 111/111 (100.0%) | 1.000 |

**Recon**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | n/a | 0/111 (0.0%) | n/a |
| v1 | n/a | 60/111 (54.1%) | n/a |
| v2 | n/a | 50/111 (45.0%) | n/a |

**Spoofing**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | n/a | 0/108 (0.0%) | n/a |
| v1 | n/a | 67/108 (62.0%) | n/a |
| v2 | n/a | 41/108 (38.0%) | n/a |

**Web-Based**

| rules | relevant kept | irrelevant removed | balanced |
|---|---|---|---|
| no rules | n/a | 0/77 (0.0%) | n/a |
| v1 | n/a | 45/77 (58.4%) | n/a |
| v2 | n/a | 40/77 (51.9%) | n/a |

