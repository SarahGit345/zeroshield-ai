# Teammate guide: catch up, then do amendment 7

For the teammate continuing the work, and the AI assistant helping them. Branch `stage10-evaluation`. Read `CLAUDE.md` first; its rules apply to everything below. Part A catches up on the work pushed on 2026-11-14; Part B is the new task.

**The one rule:** every number we report comes from a committed file; the plan is committed before the analysis runs; a test set is evaluated once; failures are reported, not hidden.

---

## Part A: catch up on the 2026-11-14 work (about 30 minutes)

1. `git pull` on `stage10-evaluation`, then `python -m pip install -r backend\requirements.txt` (scikit-learn must be 1.7.2, and `dpkt` is now required).
2. Read, in order:
   - `docs/review-guide-2026-11-14.md`: what was done, the commits to check, the known weaknesses.
   - `docs/stage10-evaluation-plan.md`, amendments 4 to 7.
   - The new sections at the end of `docs/stage10-results.md`, `docs/stage10-llm-verification.md` and `docs/mitre-retrieval-evaluation.md`.
3. Run the tests: `cd backend; python -m unittest discover -s tests` should print 177 tests, OK.
4. Optional: ask your AI to review that work by following `docs/review-guide-2026-11-14.md`. Send any findings to Sarah before changing anything.
5. For the slides, the two new results worth a slide each:
   - Trade-off (S30): the bandit misses fewer attacks than the supervised policy (18.1% vs 26.6%) but sends more alerts to analysts (62% vs 37%).
   - Plausibility rules on unseen S10: correct techniques kept 40.3% (v1) to 90.6% (v2); wrong removed 38.4%.

Summary of what those commits did:

| Work | Outcome | Default in app |
|---|---|---|
| Trade-off and break-even (amendment 4) | The S30 "supervised beats bandit" result holds unless penalties are 4 to 7 times harsher | n/a (analysis only) |
| Plausibility rules v1 (amendment 5) | Failed: rejected correct flood techniques | off |
| Plausibility rules v2 (amendment 6) | Passed on unseen S10: balanced accuracy 0.645 vs v1 0.461 | off |

---

## Part B: amendment 7, behaviour-to-technique mapping (about 4 to 5 hours)

The plan is already committed: `docs/stage10-evaluation-plan.md`, **Amendment 7**. Read it fully before starting; follow it exactly. Do not change it after you see any result. If something in it is impossible, stop and tell Sarah; a change needs a new dated note committed before running.

**Goal.** Retrieval never suggests the right technique for Recon (T1046, T1595) or Spoofing (T1557). Add a direct mapping from observed behaviours to techniques so those can be suggested, without hurting floods and brute force. Web-Based attacks are out of scope (still shown in tables, marked "out of scope").

### Step 1: rebuild the streams you need (about 40 minutes, one at a time)

Stream files are gitignored. You need S58, S10 and S30 locally (S10b must exclude all three). From `backend\`, close heavy apps, run one at a time, and check each SHA-256 against `docs/stage10-streams.md`:

```powershell
python -u build_replay_stream.py --seed 1
python -u build_replay_stream.py --seed 2 --attack-share 0.1 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --out experiments/replay_streams/replay_stream_share10_seed2.jsonl
python -u build_replay_stream.py --seed 3 --attack-share 0.3 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --exclude-stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --out experiments/replay_streams/replay_stream_share30_seed3.jsonl
Get-FileHash experiments\replay_streams\*.jsonl -Algorithm SHA256
```

S10 and S30 must match exactly. S58 (seed 1) was committed with CRLF line endings, so a rebuild gives a different hash with the same content; you already rebuilt it once with 0 score mismatches.

**Do not build S10b yet.** Build it only in Step 5, after the mapping is frozen.

### Step 2: implement the mapping (default off)

Keep every existing behaviour unchanged; all current tests must still pass.

1. In `backend/services/technique_plausibility.py` add a direct map (name it `DIRECT_MAP_V1` or similar) from technique ID to the behaviours that indicate it, reusing `observed_behaviours()`. Starting point, written from ATT&CK descriptions (adjust only on the tuning sets, at most three variants):
   - T1046 Network Service Discovery and T1595 Active Scanning: RST packets high (`rst_flag_number`, `rst_count`, `RSTRatio`), SYN high with SYN-to-ACK ratio high, ICMP present, very short flows.
   - T1557 Adversary-in-the-Middle: ARP present, DNS present, DHCP present.
   - T1498 / T1499 floods: the v2 flood signature (volumetric or one-way).
   - T1110 Brute Force: the v2 login signature.
   Use full technique IDs that exist in the TF-IDF index (`LLM/rag_store/mitre_tfidf.pkl`, `store["documents"]`, each with `id`, `name`, `text`, `tactics`) so names and descriptions come from ATT&CK, not typed by hand.
2. In `backend/services/mitre_service.py`, add `behaviour_mapping: bool = False` to `retrieve_behavior`. When on: take the TF-IDF candidates, add mapped techniques not already present (look them up in the index documents), apply the `SIGNATURES_V2` plausibility filter, put candidates supported by an observed behaviour first, keep at most five, and mark each candidate with its source (`tfidf`, `mapped`, or both). When off, the output must be identical to today's.
3. `backend/main.py` must not pass the new argument (default off).

### Step 3: tests

Add `backend/tests/test_behaviour_mapping.py` with at least: a scan-like flow (RST high) gets T1046 or T1595; an ARP flow gets T1557; a one-way flood still gets T1498/T1499; with the flag off the output equals the current output; the result never exceeds five candidates; no label is read anywhere. Run the full suite; it must stay all OK.

### Step 4: tune on S58 and S10 only

Write `backend/evaluate_mapping.py` modelled on `backend/evaluate_plausibility_v2.py` (reuse its `load`, `wilson` and `paired_bootstrap` patterns), but **recompute candidates** for every method by calling `MitreService.retrieve_behavior({"top_features": alert["xai_evidence"]}, ...)` (amendment 7, item 2), instead of reading the stored `retrieved_techniques`. Methods: TF-IDF only; TF-IDF + v2 filter; TF-IDF + mapping + v2 filter. Metrics exactly as amendment 7, item 6 (coverage per attack family except Web-Based, benign clean rate, primary balanced score; secondary precision and mean candidates per alert).

Run `--tune` on S58 and S10. Compare at most three mapping variants; save the printed output to `backend/experiments/mapping/tune.txt`. Pick the variant with the best primary score on the tuning sets.

**Freeze:** set the chosen variant as the final map in the code, run the full test suite, and **commit and push** (message must say "frozen before S10b is built"). Only then continue.

### Step 5: build S10b and test once

```powershell
python -u build_replay_stream.py --seed 4 --attack-share 0.1 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --exclude-stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --exclude-stream experiments/replay_streams/replay_stream_share30_seed3.jsonl --out experiments/replay_streams/replay_stream_share10_seed4.jsonl
Get-FileHash experiments\replay_streams\replay_stream_share10_seed4.jsonl -Algorithm SHA256
```

Add S10b (command, counts from its `.meta.json`, SHA-256) to `docs/stage10-streams.md`; commit the `.meta.json` (not the `.jsonl`).

Then run the test **once**: `python evaluate_mapping.py --test` on S10b. Do not rerun it after changing anything. Write outputs to `backend/experiments/mapping/test_s10b.md` and `.json`.

### Step 6: report and commit

Add a section to `docs/mitre-retrieval-evaluation.md`, labelled "post hoc, amendment 7", with: the method in two sentences; the variants tried on tuning; the S10b table (three methods: coverage per family, benign clean rate, primary score, precision); the verdict under the success rule with the bootstrap interval; Recon and Spoofing coverage on their own line; Web-Based marked out of scope; limits. If it is not an improvement, say so plainly.

Run the full test suite and `e2e_check.py` (README_STAGE10.md step 2). Commit results and docs, push, and tell Sarah the verdict.

### Do not

- Tune anything on S10b, or look at S10b before the freeze commit.
- Change amendment 7 after seeing results.
- Switch the mapping or the v2 filter on in `main.py`.
- Edit any earlier results files in `backend/experiments/` or earlier doc sections.
- Commit `.jsonl` streams, CSV datasets, `.env` or the SQLite ledger.
- Put labels anywhere except the scoring step.

### What to expect (so nobody is surprised)

Scan rules overlap with flood rules (many SYN packets appear in both), so some DDoS alerts will also get T1046 and some Recon alerts flood techniques. Benign flows often look flood-like, so the benign clean rate may drop. That is why the primary score balances coverage against benign cleanliness. A result of "no improvement" is acceptable and must be reported as such.
