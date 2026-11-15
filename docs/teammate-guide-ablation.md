# Teammate guide: ablation study of the LLM stage and the ATT&CK retrieval stage

For the teammate running the ablation study, and the AI assistant helping her. Read `CLAUDE.md` first; its rules apply here.

## Which repository and branch

**Repository:** https://github.com/SarahGit345/zeroshield-ai  **Branch:** `stage10-evaluation` (not `main`; `main` and the original `sashank2304/zeroshield-ai` do not have this work).

```powershell
git clone https://github.com/SarahGit345/zeroshield-ai.git
cd zeroshield-ai
git checkout stage10-evaluation
git checkout -b ablation-study          # work on your own branch
python -m pip install -r backend\requirements.txt
cd backend; python -m unittest discover -s tests   # 177 tests, OK
```

Another teammate is doing **amendment 7** (behaviour-to-technique mapping, `docs/teammate-guide-amendment-7.md`) on the retrieval code at the same time. Work on your own branch, do not edit the same functions, and coordinate before merging.

## What already exists (read before designing anything)

| Topic | Read | What it already shows |
|---|---|---|
| Whole project | `docs/review-guide-2026-11-14.md`, `README_STAGE10.md` | What was done, how to rerun it |
| Plans | `docs/stage10-evaluation-plan.md` (amendments 1 to 7) | How every experiment was fixed in advance |
| ATT&CK retrieval | `docs/mitre-retrieval-evaluation.md` | Held-out result 19 of 53; plausibility filter v1 (worse) and v2 (better on unseen S10) |
| LLM + verifier | `docs/stage10-llm-verification.md` | qwen3:8b on 100 alerts: 98 VERIFIED; damage test 1,333 of 1,372; 0 of 30 false positives removed; 47 faithful-but-wrong |
| Code | `backend/services/mitre_service.py`, `llm_service.py`, `verification_service.py`, `technique_plausibility.py` | The stages you will ablate |
| Scripts | `backend/evaluate_retrieval.py`, `measure_llm_verification.py`, `damage_llm_reports.py`, `evaluate_plausibility_v2.py` | Patterns to copy |

Ablation-style results that already exist (cite them, do not redo them): plausibility filter none / v1 / v2 (retrieval); verifier with and without the plausibility check (LLM); the damage test per error type (verifier). Every other ablation below is new.

## The ablation study: what to compare

An ablation removes or changes **one component at a time** and measures the effect, holding everything else fixed. Results are descriptive: you are not choosing a new setting, so nothing here becomes the default without a separate decision.

### Part 1: ATT&CK retrieval (no LLM, minutes per run)

| ID | Component varied | Settings | Current |
|---|---|---|---|
| R1 | Number of candidates kept (cap) | 3, 5, 10, 15 | 5 (never tested) |
| R2 | Similarity floor | 0, 0.10, 0.15, 0.20, 0.25 | 0.15 |
| R3 | Query form | behaviour phrases (ontology) vs raw feature names and values | behaviour phrases |
| R4 | Features used to build the query | top 3, 5, 8, 10 | 8 |
| R5 | Network-tactic filter | on / off | on |
| R6 | Plausibility filter | none / v1 / v2 | none (already measured: cite) |

Code: `MitreService._retrieve` hard-codes the cap (5), `MIN_SIMILARITY`, `top_n=8` in `build_behavior_query`, and `NETWORK_TACTICS`. Add keyword arguments with the current values as defaults (for example `retrieve_behavior(analysis, cap=5, floor=MIN_SIMILARITY, top_n=8, tactic_filter=True, query="behaviour")`), so the live app and all tests are unchanged. Add a test that the defaults reproduce today's output exactly.

Data and metrics: recompute candidates from each flagged alert's `xai_evidence` (like `evaluate_plausibility_v2.py` loads streams). Per family and overall, with 95% Wilson intervals: **coverage** (attack alerts with at least one relevant candidate, using `measure_llm_verification.relevant_set`), **precision** (relevant / all attack candidates), **benign alerts with any candidate**, **mean candidates per alert**. Report Web-Based separately, marked out of scope.

Streams: run on **S58, S10 and S30** (all already used; ablations are descriptive). **Do not use S10b**: it is reserved as the one-time test set of amendment 7. You need the CSV datasets to rebuild the streams: see `docs/teammate-guide-amendment-7.md`, Step 1, for the exact commands and SHA-256 checks.

Also run R1 to R5 on the 200-sample labelled evidence of `evaluate_retrieval.py` (both halves) so results connect to the published 19 of 53.

### Part 2: LLM stage (needs Ollama, about 3 minutes per alert on CPU)

| ID | Component varied | Settings | Needs code? |
|---|---|---|---|
| L1 | XAI evidence in the prompt | with / without top features | yes |
| L2 | ATT&CK candidates in the prompt | with / without | yes |
| L3 | Both removed (score and threshold only) | | yes |
| L4 | Model | qwen3:8b vs one other local model of similar size (for example `llama3.1:8b`) and one smaller (`qwen3:4b`) | no: `--model` |
| L5 | Temperature | 0 vs 0.7 | small |
| L6 | JSON schema constraint | on / off | small |
| V1 | Verifier, leave one check out | remove each of the 11 checks in turn | no LLM: rerun on saved reports and the damage test |

Sample: a **fixed 40-alert subset of the 100 main-run alerts** (seeded, stratified: 12 benign + 4 per attack family), so the existing main run (`backend/experiments/llm_verification/main_qwen3_8b/raw/`) is the "full" condition for free. 40 alerts x 3 min = about 2 hours per condition; run each condition as one background job overnight, one at a time, nothing else heavy alongside (16 GB RAM).

Code: add an option to `llm_service` prompt building (for example `ablate={"xai","mitre"}`) and pass it through `measure_llm_verification.py` (new flags such as `--ablate xai`, `--temperature`, `--no-schema`, `--sample-file`). Defaults must reproduce today's behaviour; add tests (the existing `tests/test_ollama_provider.py` has a fake Ollama server to copy). Save every raw prompt and reply, as the main run does.

Important for L1 to L3: the verifier checks the report against the evidence. When the XAI evidence is removed from the prompt, still verify against the full evidence, and expect `feature_claims_supported` and `numeric_claims_grounded` to behave differently; report which checks fail, not only the verdict.

Metrics per condition: verdict shares (VERIFIED / UNCERTAIN / REJECTED with Wilson intervals), failed checks by name, invalid JSON / retries / timeouts, mean seconds per alert, technique citations (relevant / irrelevant / benign citing one, the name-or-ID count of `posthoc_llm_analysis.py`), and the faithful-but-wrong count.

V1 (no LLM, do first, about an hour): for each of the 11 checks, rerun `verify_record` on the 100 saved reports and on the damage test with that check removed; report how the verdicts and catch rates change. This shows which checks do the work.

## Order of work

1. Part A: pull, install, run tests, read the docs above.
2. **Write plan amendment 8** in `docs/stage10-evaluation-plan.md`: the ablations you will run (from the tables), data, sample, metrics, and that results are descriptive. **Commit it before running anything.** Send it to Sarah to check.
3. V1 (verifier leave-one-out) and Part 1 (retrieval): code with defaults unchanged, tests, full suite, commit, then run.
4. Part 2 LLM conditions: code and tests first, commit, then one condition per night.
5. Write results into a new `docs/ablation-study.md`: method, sample, one table per ablation, what each component contributes, limits. Commit raw outputs under `backend/experiments/ablation/`.
6. Run the full test suite and `e2e_check.py` (README_STAGE10.md step 2); push your branch; open a pull request into `stage10-evaluation` for Sarah to review.

## Rules

- Plan before runs; each run once; say how many times you looked at results.
- Defaults unchanged: the live app (`backend/main.py`) must behave exactly as before.
- Never put labels or outcomes into a prompt or the policy context (a test enforces the policy side).
- Do not use S10b. Do not edit earlier results files or earlier doc sections.
- Do not commit CSV datasets, `.jsonl` streams, `.env` or the SQLite ledger.
- Report results that make our system look worse as plainly as those that make it look better.

## What to expect

- R1: larger caps raise coverage slightly and lower precision; whether Recon (T1046) or Spoofing (T1557) appear depends on whether they clear the similarity floor.
- R3: the raw-feature query is expected to be much worse (that is why the behaviour vocabulary was built); this ablation measures by how much.
- L1 to L3: without evidence the LLM should write vaguer reports, cite fewer real features, and fail grounding checks more often.
- L4: other models may be faster or slower, and may break the JSON format more often.
