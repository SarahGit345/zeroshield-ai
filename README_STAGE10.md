# Stage 10: how to reproduce the evaluation

This is for teammates who want to rerun or extend the Stage 10 work. It says what was done, where the results are, and the exact commands, in order. Everything is a simulated prototype: no real network or host action is ever executed, and the rewards are designed values, not measured costs.

Branch: `stage10-evaluation` on https://github.com/SarahGit345/zeroshield-ai (a fork of `sashank2304/zeroshield-ai`).

## What is done and where to read it

| Item | Status | Read |
|---|---|---|
| Evaluation plan, fixed before the runs (with two dated amendments) | done | `docs/stage10-evaluation-plan.md` |
| Replay streams: S10 (10% attacks), S30 (30%), S58 (58%, exploratory) | built | `docs/stage10-streams.md` |
| Policy comparison: bandit vs 6 baselines, 5 seeds, 7 reward tables, paired bootstrap | done | `docs/stage10-results.md` |
| End-to-end check (`e2e_check.py`) | 68 PASS, 6 WARN (expected), 0 FAIL | run it yourself (below) |
| LLM verification (Ollama `qwen3:8b`): pilot 0 (1 alert) and smoke test (10 alerts) | done | `backend/experiments/llm_verification/*/summary.md` |
| LLM verification main run (100 alerts) | done: 98 VERIFIED, 2 UNCERTAIN; gate removed 0 of 30 false positives | `docs/stage10-llm-verification.md` |
| Dashboard alert-detail view, action allowlist, simulated asset criticality (CLAUDE.md step 5) | not started | |

Headline result (v2 rewards): the bandit beats always-review, random and the best constant action on all three streams, but loses to a supervised logistic policy and a tuned score-tier rule at 30% and 58% attacks; at 10% its edge over the supervised policy is tiny and depends on the reward values. Web-Based attacks are weak at every stage (detector flags 33.9%; retrieval gives no relevant technique). Details and limits are in `docs/stage10-results.md`.

## 0. Setup

- Python 3.11 or newer (the runs here used 3.13), 64-bit. From the repo root:

  ```powershell
  python -m pip install -r backend\requirements.txt
  ```

  `requirements.txt` pins scikit-learn 1.7.2 (the version the MITRE TF-IDF index was saved with). Use it; an older version loads the index with a warning.
- Data files (scaled, not in git; get them from the team drive): `validation_set.csv` (30 GB) and `zero_day_test_scaled_v2.csv` (2 GB). Put them in the repo root, or anywhere and set `$env:ZEROSHIELD_DATA_DIR = "D:\path\to\csv"`. The scripts also look in `..\Dataset\Dataset\csv\`.
- Machine notes from the runs here (16 GB RAM laptop, no GPU):
  - Close browsers and other heavy apps during long runs. Two jobs at once ran out of memory.
  - If C: is nearly full, point temp files to another drive first: `$env:TMP = "D:\tmp"; $env:TEMP = "D:\tmp"` (create the folder). A full C: made the tests fail.
  - Keep the PC plugged in and set Sleep to Never; a sleeping PC pauses the runs.

## 1. Tests

```powershell
Set-Location backend
python -m unittest discover -s tests          # 177 tests, all OK expected (about 3-4 min)
```

## 2. End-to-end check

Start the backend in one terminal, run the check in another:

```powershell
# terminal 1 (from backend\)
python -m uvicorn main:app --host 127.0.0.1 --port 8000
# terminal 2 (from backend\)
python -u e2e_check.py --stream experiments\replay_streams\replay_stream_seed1.jsonl --tests --seeds 1 2 3 --prevalence 0.1 0.3 0.5 0.8
```

Expect 0 FAIL. The 6 WARNs are expected: three for data files not in the repo root, and three because the streams over-sample unflagged rows on purpose (see `docs/stage10-streams.md`). The API section writes ten tagged demo alerts to the local ledger; add `--skip-ledger` to avoid that. Takes about 15 minutes. Stop the backend afterwards.

## 3. Build the replay streams (about 13 minutes each)

Stream files are gitignored (they contain scaled rows of the dataset); rebuild them and compare the SHA-256 with `docs/stage10-streams.md`. Run from `backend\`, one at a time, in this order (S30 excludes S10's rows):

```powershell
python -u build_replay_stream.py --seed 1
python -u build_replay_stream.py --seed 2 --attack-share 0.1 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --out experiments/replay_streams/replay_stream_share10_seed2.jsonl
python -u build_replay_stream.py --seed 3 --attack-share 0.3 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --exclude-stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --out experiments/replay_streams/replay_stream_share30_seed3.jsonl
Get-FileHash experiments\replay_streams\*.jsonl -Algorithm SHA256
```

The S10 and S30 hashes should match exactly. The seed-1 stream committed hash is for a file with CRLF line endings (written before the builder switched to LF), so a rebuild gives LF and a different hash; its content is the same.

## 4. Policy comparison (run once; about 15 min, 10 min, 1 h)

From `backend\`, one at a time:

```powershell
$env:OMP_NUM_THREADS = "1"; $env:OPENBLAS_NUM_THREADS = "1"
python -u run_replay_study.py --stream experiments/replay_streams/replay_stream_share30_seed3.jsonl --seeds 1 2 3 4 5 --folds 5 --jobs 4 --out experiments/replay_study_share30_seed3_rerun
python -u run_replay_study.py --stream experiments/replay_streams/replay_stream_seed1.jsonl --seeds 1 2 3 4 5 --folds 5 --jobs 4 --out experiments/replay_study_seed1_rerun
python -u run_replay_study.py --stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --seeds 1 2 3 4 5 --folds 5 --jobs 4 --out experiments/replay_study_share10_seed2_rerun
```

Each writes `study_summary.md` and `.json`. The committed results are in `experiments/replay_study_share10_seed2/`, `replay_study_share30_seed3/` and `replay_study_seed1_all_policies/`. Per-alert decision files are gitignored (regenerable).

## 5. Install the local LLM (once)

1. Install Ollama from https://ollama.com (the runs here used 0.40.15).
2. `ollama pull qwen3:8b` (5.2 GB; needs about 6.5 GB free RAM; CPU is fine). The digest used is `500a1f067a9f…`; `ollama list` shows it.
3. Ollama must be running (it starts with Windows, or run `ollama serve`). The backend does not need to run.

## 6. LLM verification measurement

From `backend\`:

```powershell
python -u measure_llm_verification.py --phase smoke     # the 10 pilot alerts, about 30 min
python -u measure_llm_verification.py --phase main      # 100 alerts, about 5 h; resumes if interrupted
```

Settings (fixed in `docs/stage10-evaluation-plan.md`, amendment 2): temperature 0, seed 20261108, JSON schema output, thinking off, 600 s budget per alert, 768-token output cap. The sample comes from S30's flagged alerts: 30 benign plus 10 per attack family, disjoint from the pilot alerts. Every raw output and prompt is saved under `experiments/llm_verification/<phase>_qwen3_8b/raw/`; the summary reports verdicts per family, failed checks, invalid JSON, repairs, timeouts, time per alert, and false positives with and without the verification gate. Rerunning the same command skips alerts that are already saved.

To use the LLM in the dashboard instead of the template: set `$env:ZEROSHIELD_LLM_PROVIDER = "ollama"` (and optionally `OLLAMA_MODEL`) before starting the backend. Without it the app behaves as before (OpenAI if `OPENAI_API_KEY` is set, otherwise the labelled template).

## 7. HTTP content check for Web-Based attacks (code ready, not run)

Signature rules on plaintext HTTP from the original captures; complementary to the flow detector, not zero-day detection. Method fixed in `docs/stage10-evaluation-plan.md`, amendment 3 (rules frozen as `content-rules-v1`, SHA-256 `4275b674…9635`).

1. Get the CIC-IoT-2023 PCAPs for the web attacks (SqlInjection, XSS, CommandInjection, Uploading_Attack, BrowserHijacking, Backdoor_Malware) from the dataset's download page. `BenignTraffic3.pcap` is already in `..\Dataset\`.
2. Optional quick look at one capture (0 requests means no plaintext HTTP: the go/no-go fails for that attack):

   ```powershell
   python pcap_http_extract.py path\SqlInjection.pcap --out ..\..\tmp\sqli_requests.jsonl --label SqlInjection
   ```

3. Run once, from `backend\`:

   ```powershell
   python -u evaluate_content_check.py --benign ..\..\Dataset\BenignTraffic3.pcap --attack SqlInjection=path\SqlInjection.pcap --attack XSS=path\XSS.pcap --attack CommandInjection=path\CommandInjection.pcap --attack Uploading_Attack=path\Uploading_Attack.pcap --attack BrowserHijacking=path\BrowserHijacking.pcap --attack Backdoor_Malware=path\Backdoor_Malware.pcap --out experiments\content_check
   ```

   Output: `experiments/content_check/summary.md` (hit rate per capture, benign false positives with a 95% interval, the flow detector's flag rate per family next to it) and one `*_hits.jsonl` per capture with every matching request and snippet. Do not edit the rules after seeing the results.

## Rules that keep the results honest

- Write or amend `docs/stage10-evaluation-plan.md` and commit it **before** running anything new. Run each confirmatory experiment once and say how many times you looked at its results.
- Labels, outcomes and rewards never go into a policy's input (tests enforce this). Keys starting with `_` in a stream are simulator-only.
- Do not tune anything on the confirmatory streams. Any change to a reward table needs a new version name.
- Never invent asset criticality, analyst history or costs; if something is simulated, say so wherever it appears.
- Run the full test suite and `e2e_check.py` after any change, and report failures plainly.
- Do not commit the CSVs, stream `.jsonl` files, `.env` or the SQLite ledger.

## Known issues

- Memory: on 16 GB, running a stream build and a study at the same time crashed with out-of-memory. Run one heavy job at a time.
- The verification gate gives no signal with template reasoning (every alert is VERIFIED at 1.0), and in the 10-alert LLM smoke test every report was VERIFIED too. Verification checks faithfulness to the evidence, not truth: a report that faithfully repeats a wrong retrieved technique passes.
- Web-Based attacks: low detector recall (33.9%), no relevant ATT&CK retrieval (0 of 23), and the bandit mostly monitors them at low attack shares.
- No scaler artifact: the app only accepts already-scaled rows.

## Open work

1. Human check of the 32 reports in `backend/experiments/llm_verification/main_qwen3_8b/human_check_packet.html` (blind; get the key from the person who built it); add the result to `docs/stage10-llm-verification.md`.
2. CLAUDE.md step 5: dashboard alert-detail view, action allowlist, simulated asset criticality (labelled as simulated).
3. HTTP content check (step 7): code and tests done, rules frozen; needs the web-attack PCAPs and one run. Then write the results into `docs/` next to the flow detector's per-family recall.
