# Review guide: work done on 2026-11-14

For an AI assistant (or a person) asked to review this work critically. Branch `stage10-evaluation`. Find mistakes, overclaims and leaks; do not change results files or switch features on. Read `CLAUDE.md` first for the project rules.

## What was done

| # | Work | Plan | Code | Results |
|---|---|---|---|---|
| 1 | Trade-off table and break-even for the response policy | Amendment 4 | `backend/analyze_tradeoffs.py` | `backend/experiments/tradeoff_analysis/tradeoff.md`; section in `docs/stage10-results.md` |
| 2 | Plausibility rules v1: optional 12th verifier check and retrieval abstention | Amendment 5 | `backend/services/technique_plausibility.py` (`SIGNATURES`), `mitre_service.retrieve_behavior(abstain_implausible=)`, `verification_service.verify_record(plausibility=)`, `backend/evaluate_plausibility.py` | `backend/experiments/plausibility/summary.md`; sections in `docs/stage10-llm-verification.md` and `docs/mitre-retrieval-evaluation.md` |
| 3 | Plausibility rules v2: tuned on S58, tested once on S10 | Amendment 6 | `technique_plausibility.py` (`V2_CANDIDATES`, `SIGNATURES_V2`), `backend/evaluate_plausibility_v2.py` | `backend/experiments/plausibility_v2/tune_s58.txt`, `test_s10.md`; section in `docs/mitre-retrieval-evaluation.md` |

All plans are in `docs/stage10-evaluation-plan.md`. Headline claims to verify: (1) at S30 the supervised policy beats the bandit unless a missed attack is penalised beyond -23.4 or a wrongful block beyond -79.5; (2) v1 removed 8 of 30 false positives but downgraded 23 attacks, and cut held-out relevant retrieval from 19 to 3 of 53; (3) on S10, v2 balanced accuracy 0.645 vs v1 0.461 vs none 0.500, v2 - v1 = +0.185, 95% paired bootstrap [+0.123, +0.245].

## Checks you can run

1. **Order of commits (plan before analysis).** `git log --oneline -20`. Expected order: amendment 4 `ede4575` before script `17c562e` before results `2200285`; amendment 5 `2c064c1` before rules `b3a9337` before results `8157764`; amendment 6 `5099f39` and its wording fix `ac49c2b` before frozen v2 `ee5af0e` before S10 results `ea63f5e`. Use `git show <hash> --stat` to confirm what each commit contains.
2. **Tests.** `cd backend; python -m unittest discover -s tests` should report 177 tests, OK.
3. **S10 was not used for tuning.** In `evaluate_plausibility_v2.py`, `--tune` must read only `TUNE` (S58) and `--test` only `TEST` (S10). `tune_s58.txt` must list exactly the variants in `V2_CANDIDATES` (three).
4. **Features are off by default.** `retrieve_behavior(..., abstain_implausible=False)` and `verify_record(..., plausibility=False)`; `backend/main.py` must not pass either argument.
5. **v1 unchanged.** `plausible()` with no `rules` argument must use `SIGNATURES` (v1), so amendment 5 reproduces.
6. **No labels in rules or policy.** The rules use only XAI feature values and contributions; labels are used only to score. Check nothing in `technique_plausibility.py` reads a label.
7. **Numbers in docs match result files.** Compare each number in the doc sections above with `tradeoff.md`, `plausibility/summary.md` and `plausibility_v2/test_s10.md`.

You cannot rerun the three evaluation scripts: their inputs (replay decision CSVs and stream JSONL files) are gitignored and exist only on Sarah's laptop. Review the code and the committed outputs instead.

## Known weaknesses to scrutinise

- All three pieces are **post hoc**: designed after earlier results were seen. The docs say so; check they never present them as pre-registered findings.
- **Amendment 6's success rule was reworded once** (`ac49c2b`) before any v2 rule or S58 data existed. Check the timestamps and that the change only clarified the test.
- **Amendment 5 says the rules are "frozen by this commit"**, but the rules file was committed in the next commit (`b3a9337`), still before the evaluation run (`8157764`). The wording is inaccurate; the order of events is not affected.
- **Relevance sets are generous and family-level** for most families (`measure_llm_verification.RELEVANT_BY_FAMILY`, `evaluate_retrieval.EXPECTED`). Every candidate on a benign alert counts as irrelevant.
- **Balanced accuracy is dominated by a few families.** Relevant candidates exist only for DDoS, DoS, Mirai and Brute Force (139 on S10); Recon, Spoofing and Web-Based never receive a relevant candidate, so the rules can only remove their wrong ones.
- **v2 keeps 61.6% of irrelevant candidates** on S10 (removes 38.4%), mostly flood techniques on flood-looking benign flows.
- **The verifier check with v2 was not measured on real LLM reports.** Only v1 was (amendment 5). Any claim that v2 fixes the verifier trade-off is unsupported until a fresh LLM run.
- **Break-even holds decisions fixed.** A policy retrained under a different reward table would choose differently; the six-table reruns in `docs/stage10-results.md` cover that case.
- **Labels in the trade-off script are recovered from (action, reward) pairs** under the reward-v2 table; the script refuses an ambiguous table. Check `label_lookup`.
- **The held-out retrieval half has now been looked at three times** (twice before, once in amendment 5); v2 was not evaluated on it.

## What a good review reports

Each finding with file and line, what is wrong, why it matters, and severity (blocks the claim / weakens it / cosmetic). Say plainly if a headline number is not supported by the files. Do not edit `backend/experiments/` or the results sections; propose changes instead.
