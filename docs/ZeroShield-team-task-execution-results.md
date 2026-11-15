# ZeroShield task execution results

**Date:** 15 November 2026  
**Branch:** `codex/task1-amendment7`  
**Base:** `SarahGit345/zeroshield-ai` `stage10-evaluation` at `f1ca522`

## Data basis and protocol note

The repository-root `validation_set.csv` was confirmed by the teammate as the correct current validation file and matches the 31,159,073-row dataset identified in `CLAUDE.md`. Its SHA-256 is `E661CC9C6861A7692BD77918D79315D7B1CD814F46E55BAAD54288167C890AC8`; `zero_day_test_scaled_v2.csv` is 2,658,953 rows with SHA-256 `1FE72BC723CD46106A57DE29012C3EE23FC7A504D931230269BCE2E2791A87BA`.

The original replay metadata records a different, larger validation snapshot, so the local stream hashes and population counts cannot match that snapshot. Before any new implementation or tuning, I committed the revised-data-basis note in [stage10-evaluation-plan.md](stage10-evaluation-plan.md) (commits `af31d5f` and `8e745fd`). The rerun preserves amendment 7's mapping method, tuning/test split, metrics and success rule, and is reported as a revised-data-basis replication rather than evidence on the older snapshot.

## Part A catch-up

- Read the review guide, amendment 7 guide and plan, `CLAUDE.md`, stream docs, and prior results.
- Python 3.11.9 and scikit-learn 1.7.2 were present in the project environment.
- The full backend suite passed with the six new mapping tests included.

## Task 1: behaviour-to-technique mapping

- Rebuilt S58, S10 and S30 from the hash-pinned current files. Each full scan read 33,818,026 rows and skipped one non-finite row; bulk-screen and per-alert detection had zero mismatches. Rebuilt hashes and counts are in [stage10-streams.md](stage10-streams.md) and its committed metadata.
- S10's disjoint sample had 29 unflagged DoS rows rather than 40; S30 had zero after exclusions because the source contained only 69. All flagged quotas were met. These unflagged rows are never routed. This shortfall was documented and committed before building S30.
- Implemented the opt-in `behaviour_mapping` path, candidate source labels, v2 filtering, and tests. The live API default remains off; `main.py` does not pass the option.
- Compared three variants on S58 and S10 only. `v1-core-scan` and `v2-icmp-short-scan` tied for the best mean primary score (0.2640); the predeclared variant order selected `v1-core-scan`. `v3-broad-scan` scored 0.2537. Full tuning output is in `backend/experiments/mapping/tune.txt` and `.json`.
- The map was frozen and pushed in commit `8659cbf` **before S10b was built**.
- Built S10b from the same current files, excluding S58/S10/S30, then evaluated it once. Its stream SHA-256 is `bc579188c3d132264fddcf8eef13a95ab85498a6feb8aeaca216a10e406ca095`.
- **Final verdict: no improvement.** The mapping primary score was 0.2665 versus 0.2759 for TF-IDF + v2. The paired difference was -0.0094, with a 95% bootstrap interval [-0.0264, +0.0086], which includes zero. Recon coverage was 17/43 (39.5%); Spoofing was 1/43 (2.3%); Web-Based remained out of scope.
- The one-time test result is in `backend/experiments/mapping/test_s10b.md` and `.json`. S10b's `.meta.json` was recorded; its `.jsonl` and source CSVs were not committed.

## Shared tasks and final checks

| Task | Result |
|---|---|
| Full backend suite | Passed; 182 existing tests plus 6 new mapping tests. |
| E2E check | **63 PASS, 2 WARN, 0 FAIL**, with ledger writes skipped. The warnings were 66.7% of sampled benign rows flagged and only 23% of Mirai-udpplain flagged; both are data diagnostics for this source snapshot. Replay invariants passed, including exactly-once policy evaluation and the auto-remediation safety mask. |
| Presentation | Updated, rendered and reviewed all 22 slides: [ZeroShield_Evaluation_3_amended.pptx](../Documentation/ZeroShield_Evaluation_3_amended.pptx). Its closing slide labels the E2E numbers as functional diagnostics, not Stage 10 evidence. |
| Blind human check | Still requires an independent reviewer and returned CSV; the existing packet was left unchanged. |
| Optional Qwen run | Not run. |

The freeze and result commits are on the pushed branch `codex/task1-amendment7` in Sarah's repository. The mapping is off by default. No message was sent to Sarah outside the repository push.
