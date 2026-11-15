# Handover: demo and Evaluation 3 slides

For the teammate (and their AI assistant) running the demo and building the slides for the guide's review. Read this file first, then `README_STAGE10.md` (how to rerun everything) and `CLAUDE.md` (project rules). Branch: `stage10-evaluation`. Run `git pull` first; the latest commit adds `dpkt` to the requirements and a timeout to `e2e_check.py`.

**The one rule:** every number shown to ma'am must come from a file in this repo (paths given below). Nothing is rounded up, nothing is invented, and anything simulated is called simulated. The project is a prototype: no real network or host action is ever executed.

---

## 1. What exists today

| Stage | What it does | Status | Evidence |
|---|---|---|---|
| Detector | Deep SVDD scores each flow (43 scaled features); flagged if score ≥ 0.0614 (95th percentile of benign validation scores) | done | `model_training/outputs/Deep_SVDD_Tuned_evaluation_results.json`, `docs/thresholds.md` |
| XAI | Occlusion: each feature set to 0, score change = contribution; top 10 features | done | `backend/services/model_service.py` |
| ATT&CK retrieval | TF-IDF match from the XAI behaviour to MITRE ATT&CK techniques | done | `docs/mitre-retrieval-evaluation.md` |
| LLM report | qwen3:8b via Ollama (local), or a labelled template if no LLM | done | `backend/services/llm_service.py` |
| Verification | 11 rule checks that the report is faithful to the evidence | done | `docs/stage10-llm-verification.md` |
| Response policy | LinUCB contextual bandit picks MONITOR_ONLY / HUMAN_REVIEW / CONFIRM_TO_ACT / AUTO_REMEDIATE (all simulated) | done | `docs/stage10-results.md` |
| Ledger | SQLite record of every alert, action and reward | done | `backend/services/bandit_service.py` |
| Dashboard | React + Vite, already connected to the backend | done | `frontend/src/main.jsx` |
| HTTP content check for web attacks | Code and frozen rules done; **not run** (no web-attack PCAPs yet) | code only | `README_STAGE10.md` step 7 |

**The dashboard is already connected to the backend.** `frontend/src/main.jsx` calls `http://localhost:8000/api/...` (health, model-info, demo-samples, analyze, response/alerts, approvals, feedback, replay), and the backend allows `localhost:5173`. "Integration" means starting both. Do not rewrite the API layer the night before a demo; fix only what breaks.

---

## 2. Run it (Windows, PowerShell)

```powershell
git pull
python -m pip install -r backend\requirements.txt
cd frontend; npm install; cd ..
```

Terminal 1 (backend):
```powershell
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```
Terminal 2 (dashboard):
```powershell
cd frontend
npm run dev        # open http://localhost:5173
```

Quick check: open http://localhost:8000/api/health; it should report the model loaded and threshold 0.06141921002417763. The datasets (CSV files) are **not** needed for the demo; the dashboard uses 10 cached samples.

---

## 3. Install Ollama and qwen3:8b

1. Download and install Ollama for Windows from https://ollama.com. It starts in the background.
2. `ollama pull qwen3:8b` (5.2 GB download; needs about 6.5 GB of free RAM; no GPU needed).
3. `ollama list` should show `qwen3:8b` (our runs used digest `500a1f067a9f…`, Ollama 0.40.15).
4. Start the backend with the LLM switched on (same terminal, before uvicorn):
   ```powershell
   $env:ZEROSHIELD_LLM_PROVIDER = "ollama"
   python -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```
   Without that variable the app uses the template report, which is labelled "Demo Fallback Reasoning".

**Speed warning, important for the demo:** on a CPU laptop qwen3:8b took **176 s per alert on average (max 281 s)** in our 100-alert run. A live LLM call during the demo means about 3 minutes of waiting. Plan:
- Run the live demo in **template mode** (instant), and say clearly that it is the template.
- Show one real qwen3 report: either run one alert with Ollama before the demo starts and keep the tab open, or open a saved one from `backend/experiments/llm_verification/smoke_qwen3_8b/raw/` (smoke set).
- **Do not use reports from `main_qwen3_8b/` in slides or the demo** until the blind human check comes back; 32 of those reports are in the blind packet.
- Close browsers and other heavy apps while Ollama runs. 16 GB RAM is tight.

---

## 4. Demo script (about 8 minutes)

1. **Pipeline strip** (30 s): detector → XAI → ATT&CK → LLM report → verification → response policy → ledger. Say "simulated actions only".
2. **Mirai sample** (2 min): click a cached Mirai sample → Analyze. Show the anomaly score above threshold, the top XAI features (e.g. flood-like rates), retrieved techniques (Network Denial of Service, T1498/T1499), the report, the 11 verification checks, and the policy's action. Point at the ledger row.
3. **Web-attack sample** (1 min): most of these score **below** the threshold → `MONITOR_ONLY`, not recorded. Say it honestly: flow statistics cannot see application-layer attacks (detector recall 12–48% for web families). That is why the HTTP content check exists (next phase).
4. **Benign sample** (1 min): shows a normal flow. If it is flagged, that is a false positive; say the policy is designed to send uncertain ones to human review instead of auto-blocking.
5. **Human approval queue** (1 min): approve or reject a CONFIRM_TO_ACT alert; show feedback updating the ledger.
6. **Offline replay comparison** (1.5 min): run the replay panel; explain bandit vs fixed rule. Note the 10 cached samples cannot separate policies (5 flagged, all attacks, both get +5.0); the real comparison is on the S10/S30/S58 streams (slides).
7. **One real qwen3 report** (1 min), prepared in advance (section 3).

Backup: record a screen video of this run tonight (Win+G, or OBS) in case the laptop or Ollama fails tomorrow.

---

## 5. The slides: structure and the numbers to use

Aim for 18–22 slides. Each results slide: one table or chart, one sentence of takeaway, one line of limitation.

1. **Title**: ZeroShield AI, team, guide.
2. **Problem**: unknown (zero-day) attacks, too many alerts, black-box detectors. Cite any statistic or drop it.
3. **Objectives**: detect without attack labels; explain; map to ATT&CK; write a faithful report; choose a safe response; evaluate honestly.
4. **Architecture**: the pipeline diagram (section 1 table).
5. **Dataset**: CIC-IoT-2023, scaled, 43 features. Trained on benign only (`train_benign_only.csv`). Validation 31,159,073 rows; zero-day test set 2,658,953 rows of attack families held out from training.
6. **Detector**: Deep SVDD, encoder 43 → 128 → 64 → latent 16, threshold 0.0614 = 95th percentile.
7. **Evaluation metrics (detector, validation)**: from `Deep_SVDD_Tuned_evaluation_results.json`:

   | accuracy | precision | recall | F1 | FPR | specificity |
   |---|---|---|---|---|---|
   | 0.9875 | 0.9997 | 0.9877 | 0.9937 | 0.0501 | 0.9499 |

   TP 30,619,320 · FN 380,099 · FP 8,003 · TN 151,651. Note: precision is high partly because benign rows are a small share of validation; FPR 5% is the honest benign cost.
8. **Zero-day detection per family** (always per family, never only the blend):

   | family | rows | detected |
   |---|---|---|
   | Mirai-greeth_flood | 991,866 | 100.0% |
   | Mirai-greip_flood | 751,682 | 100.0% |
   | Mirai-udpplain | 890,576 | 99.98% |
   | SqlInjection | 5,245 | 48.1% |
   | Backdoor_Malware | 3,218 | 43.2% |
   | CommandInjection | 5,409 | 34.8% |
   | XSS | 3,846 | 27.9% |
   | BrowserHijacking | 5,859 | 23.8% |
   | Uploading_Attack | 1,252 | 12.4% |

   Overall 99.38%, but 99% of zero-day rows are Mirai floods. Takeaway: volumetric attacks are caught; web/application attacks mostly are not.
9. **Ablation 1: detector choice and threshold**: six models at five percentiles, same pipeline (`model_training/outputs/percentile_comparison_experiment/`: `best_operating_points.csv`, the PNG charts). Best F1 at the 90th percentile: Deep SVDD 0.993, AE 0.951, DAE 0.927, OCSVM 0.912, VAE 0.888, CAE 0.845. Use `f1_vs_percentile.png`, `fpr_vs_percentile.png`, `zero_day_percentile_heatmap.png`. Say this used a 500,000-row training sample and 100,000 reference rows (see `experiment_config.json`), not the full 31M rows.
10. **Ablation 2: Deep SVDD size** (`Deep_SVDD_tuning_candidates.csv`, on the tuning sample): small [64,32]/8 recall 0.718; medium [128,64]/16 recall 0.809 (chosen); wide [128,64]/32 recall 0.622; all at about 5% FPR.
11. **XAI example**: top features for one Mirai flow (dashboard screenshot).
12. **ATT&CK retrieval**: held-out flagged flows: relevant technique for 19 of 53 (19 of 30 Mirai floods, 0 of 23 web attacks); when it answers, 51% precision (`docs/mitre-retrieval-evaluation.md`).
13. **LLM report + verification (real LLM, qwen3:8b, 100 flagged alerts)**: 98 VERIFIED, 2 UNCERTAIN, 0 REJECTED; 0 invalid JSON, 0 timeouts; mean 176 s per alert. Both UNCERTAIN were correct catches (the LLM got a feature direction wrong).
14. **Ablation 3: verification gate on vs off** (the honest one): false positives reaching the policy without the gate 30 of 30, with the gate 30 of 30, so **0% reduction**. Attacks passing: 70 → 68. Verification checks faithfulness to the evidence, not truth.
15. **Ablation 4: verifier damage test**: we broke the 98 verified reports 14 ways; caught 1,333 of 1,372. Every damage type caught 100% except a fake-rounded threshold ("about 0.1"): 59 of 98 (60%). Table in `docs/stage10-llm-verification.md`.
16. **Faithful is not true**: 47 VERIFIED reports cite a technique that is wrong for the flow (21 benign flows citing one, 26 attacks citing an irrelevant one). Post-hoc count, labelled as such.
17. **Response policy results** (`docs/stage10-results.md`, reward v2, mean ± std over 5 seeds):

    | policy | S10 (10% attacks) | S30 (30%) | S58 (58%, exploratory) |
    |---|---|---|---|
    | Contextual bandit | 0.591 ± 0.010 | −0.260 ± 0.333 | 0.755 ± 0.175 |
    | Always human review | −1.600 | −0.800 | 0.333 |
    | Random | −3.493 | −2.518 | −1.033 |
    | Best constant action | 0.300 | −0.800 | 0.500 |
    | Supervised expected-reward | 0.568 | **0.184** | **1.202** |
    | Tuned score-tier rule | 0.428 | 0.126 | 1.070 |

    Takeaway: the bandit beats always-review, random and the best constant action on all three streams (paired bootstrap, 95% intervals), but **loses** to the supervised policy and the score-tier rule at 30% and 58% attacks.
18. **Ablation 5: attack share and reward sensitivity**: results across three attack shares, and across the six other reward tables (v1 and five perturbations of v2): vs the supervised policy the bandit is better in 2, no difference in 1, worse in 3 at S10, and worse in 6 of 6 at S30 and S58 (table "Sensitivity" in `docs/stage10-results.md`). The reward table is designed, not measured cost.
19. **Bandit's mistakes**: attacks left at MONITOR_ONLY 51.4% at S10, 18.1% at S30; wrongful simulated auto-blocks 0.0% / 0.1% / 4.7%.
20. **Limitations**: one dataset; no scaler artifact (accepts already-scaled rows only, so no live traffic yet); web attacks weak at every stage; verification never proven to reduce false positives; rewards designed; everything simulated.
21. **Phase 2 plan**: live capture to features, HTTP content check fused with the detector, mitigation playbooks (ATT&CK mitigations, allowlist, approval, reversible actions in a lab only), Docker product, analyst study.
22. **Demo** then **Thank you / questions**.

**Ablations we did NOT run (do not claim them):** removing XAI or retrieval from the LLM prompt, a second LLM, a second dataset, real-traffic testing, a human analyst study. If asked, say "planned for Phase 2".

**Fixes carried over from the Evaluation 2 slides:** recall is 98.77% (not 91.2%); threshold is the 95th percentile (not 90th); architecture [128, 64], latent 16; detector is Deep SVDD (not Isolation Forest or autoencoder); XAI is occlusion (not SHAP/LIME); retrieval is TF-IDF (not a vector database); asset criticality and analyst history are not implemented; remove "CICIDS" and invented sample rows; reword "reduces false positives" (we did not show that).

---

## 6. If your AI assistant edits code

- Work on a new branch off `stage10-evaluation`; do not push to `main` without the team agreeing.
- After any change: `cd backend; python -m unittest discover -s tests` (161 tests, all OK, about 3–4 min), then `e2e_check.py` (README_STAGE10.md step 2). Report failures as they are.
- Do not edit anything in `backend/experiments/` or `docs/stage10-*.md` results; those are the record of what was run.
- Never put labels or rewards into the policy's input (a test enforces it). Never invent asset criticality, analyst history or costs.
- Do not commit the CSV datasets, `.jsonl` streams, `.env` or the SQLite ledger.

## 7. Still open

1. Blind human check of 32 reports (someone who has not seen the results; Sarah has the key).
2. HTTP content check run (needs web-attack PCAPs).
3. Dashboard alert-detail view, action allowlist, simulated asset criticality (labelled simulated).
