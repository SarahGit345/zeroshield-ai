# ZeroShield AI: project rules and facts

Final-year project: explainable zero-day network-threat detection with a response policy.
Pipeline: Deep SVDD detector -> occlusion XAI -> MITRE ATT&CK retrieval -> LLM report -> verification -> LinUCB response policy -> simulated action ledger -> dashboard.
Everything is a simulated prototype. No real network or host action is ever executed. Be honest in every claim; this is graded work.

## Start here
- Branch `stage10-evaluation` (identical to `main` as of 2026-11-15). `pip install -r backend/requirements.txt`, then `cd backend; python -m unittest discover -s tests` (182 tests, all OK).
- Read `README_STAGE10.md`, `docs/stage10-evaluation-plan.md` (amendments 1 to 9), `docs/stage10-results.md`, `docs/stage10-llm-verification.md`, `docs/mitre-retrieval-evaluation.md`, `docs/ablation-amendment9.md`.
- Task guides: `docs/teammate-guide-amendment-7.md` (ATT&CK mapping), `docs/teammate-guide-ablation.md` (LLM and ATT&CK ablations), `docs/review-guide-2026-11-14.md` (reviewing the 2026-11-14 work).

## Repo map
- `backend/main.py` FastAPI. `backend/services/`: `model_service.py` (detector + occlusion XAI), `mitre_service.py` (behaviour retrieval), `technique_plausibility.py` (rules v1/v2), `llm_service.py` (Ollama qwen3:8b if `ZEROSHIELD_LLM_PROVIDER=ollama`, OpenAI if `OPENAI_API_KEY`, else a labelled template), `verification_service.py` (11 rule checks), `bandit_service.py` (LinUCB, reward tables, SQLite ledger).
- Experiments: `build_replay_stream.py`, `run_replay_study.py`, `measure_llm_verification.py`, `evaluate_retrieval.py`, `analyze_tradeoffs.py`, `evaluate_plausibility*.py`, `ablate_policy_xai.py`, `e2e_check.py`.
- `model_training/outputs/Deep_SVDD_Tuned.pt` is the active detector (43 features, hidden [128, 64], latent 16, threshold 0.06141921002417763 = 95th percentile of benign scores).
- `LLM/` is legacy; do not use its outputs for results. `frontend/` is the React + Vite dashboard.
- Datasets (`validation_set.csv`, `zero_day_test_scaled_v2.csv`) and replay streams (`*.jsonl`) are gitignored; rebuild streams with the commands in `docs/stage10-streams.md`.

## Verified facts (quote these, do not inflate)
- Detector, validation (31,159,073 rows): recall 0.9877, precision 0.9997, F1 0.9937, FPR 0.0501. Zero-day 0.9938 overall, but always per family (Mirai about 100%; web families 12-48%).
- ATT&CK retrieval, held-out flagged: relevant technique for 19 of 53 (19 of 30 Mirai, 0 of 23 web). Rules v2 on unseen S10 keep 90.6% of relevant candidates, remove 38.4% of irrelevant ones; off by default.
- LLM (qwen3:8b, 100 alerts): 98 VERIFIED, 2 UNCERTAIN; damage test 1,333 of 1,372 caught; 0 of 30 false positives removed by verification; 47 faithful-but-wrong.
- Policy (reward v2): bandit beats always-review, random and best constant action on S10, S30, S58; loses to a supervised policy and a tuned score-tier rule at 30% and 58% attacks.
- `verification_confidence` is 1.0 for every alert in every replay stream, so the policy experiments never used verification as a signal (amendment 9).
- Occlusion explanation: the top feature removes about 70% of the score; resetting several features together usually raises it (reference 0 is not a realistic normal flow). SHAP agrees poorly (top-1 10%).
- Reward tables are designed, not measured costs.

## Rules
- Write or amend `docs/stage10-evaluation-plan.md` and commit it before running anything new. Run each confirmatory experiment once; say how many times you looked.
- Do not tune on held-out data. S10b is reserved as the one-time test set of amendment 7.
- Never put labels, outcomes or rewards in the policy context or an LLM prompt (tests enforce the policy side). Labels are read only after an action is chosen.
- New features stay off by default; `backend/main.py` behaviour changes only by a separate decision.
- Never fabricate asset criticality, analyst history or costs. If simulated, say so everywhere it appears.
- Any change to a reward table needs a new version name.
- Run the full test suite before saying anything is done; add a test for every bug fixed; report failures plainly. Run `e2e_check.py` after changes (README_STAGE10.md step 2).
- Do not edit earlier results files in `backend/experiments/` or earlier results sections in `docs/`.
- Do not commit datasets, `.jsonl` streams, `.env` or the SQLite ledger.
