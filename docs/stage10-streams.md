# Stage 10 replay streams

Three labelled replay streams used by the Stage 10 policy comparison (`docs/stage10-evaluation-plan.md`, amendment 1). The stream files are gitignored (they hold scaled feature values for real dataset rows); each can be rebuilt with the command below and checked against its SHA-256. Each stream's `.meta.json` (committed) records quotas, population counts per family and label, and excluded rows.

All three: detector `model_training/outputs/Deep_SVDD_Tuned.pt`, threshold 0.06141921002417763; sources `validation_set.csv` (43,149,298 rows) and `zero_day_test_scaled_v2.csv` (2,658,953 rows), read in full (45,808,251 rows, 0 non-finite rows skipped); template reasoning (no LLM); 0 disagreements between bulk screening and the per-alert pipeline on whether a sampled row is flagged. Run from `backend/`; the data files were in `../Dataset/Dataset/csv/` on the build machine (found automatically; set `ZEROSHIELD_DATA_DIR` otherwise). `--chunk-rows` changes memory use only, not the sample (tested).

| stream | role | command | flagged alerts | attack share among flagged | SHA-256 of the `.jsonl` |
|---|---|---|---|---|---|
| S58 `replay_stream_seed1.jsonl` | exploratory (results seen before the plan) | `python build_replay_stream.py --seed 1` | 720 = 420 attacks + 300 benign | 0.583 | `fb07d3f7e8e7ba18aa05879e71786328d5f95eba8079fba17e8f5c26ea336aa3` (CRLF line endings: built before the builder switched to LF) |
| S10 `replay_stream_share10_seed2.jsonl` | confirmatory | `python build_replay_stream.py --seed 2 --attack-share 0.1 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --out experiments/replay_streams/replay_stream_share10_seed2.jsonl` | 3,010 = 301 attacks + 2,709 benign | 0.1000 | `81cf6c5d86bceea087a9773906dc2cb65a01177013f69b2de2bf0818fcf09604` |
| S30 `replay_stream_share30_seed3.jsonl` | confirmatory | `python build_replay_stream.py --seed 3 --attack-share 0.3 --min-attacks 300 --chunk-rows 200000 --exclude-stream experiments/replay_streams/replay_stream_seed1.jsonl --exclude-stream experiments/replay_streams/replay_stream_share10_seed2.jsonl --out experiments/replay_streams/replay_stream_share30_seed3.jsonl` | 1,003 = 301 attacks + 702 benign | 0.3001 | `1fb74980c8574b1c9df66eea6f8a911534cd19c2dbd2060758242a4320665e13` |

S10 shares no row with S58 (1,150 candidate rows excluded); S30 shares no row with S58 or S10 (4,590 excluded).

## Rows per family (flagged / unflagged)

Only flagged rows are routed to the policies; unflagged rows are counted by the replay as never-alerts.

| family | S58 | S10 | S30 | population flagged / unflagged (all rows) | population flag rate |
|---|---|---|---|---|---|
| Benign | 300 / 150 | 2,709 / 150 | 702 / 150 | 10,989 / 208,878 | 0.0500 |
| DDoS | 60 / 40 | 43 / 40 | 43 / 40 | 33,984,020 / 540 | 1.0000 |
| DoS | 60 / 40 | 43 / 40 | 43 / **18** | 8,090,640 / 98 | 1.0000 |
| Recon | 60 / 40 | 43 / 40 | 43 / 40 | 200,720 / 153,845 | 0.5661 |
| Brute Force | 60 / 40 | 43 / 40 | 43 / 40 | 2,719 / 10,345 | 0.2081 |
| Spoofing | 60 / 40 | 43 / 40 | 43 / 40 | 125,169 / 361,335 | 0.2573 |
| Mirai | 60 / 40 | 43 / 40 | 43 / 40 | 2,633,942 / 182 | 0.9999 |
| Web-Based | 60 / 40 | 43 / 40 | 43 / 40 | 8,420 / 16,409 | 0.3391 |

Each attack family is 1/7 (14.3%) of a stream's flagged attacks, so no family exceeds 25%. S30 has only 18 unflagged DoS rows because only 98 exist and S58 and S10 already used 80; unflagged rows are never routed, so this does not affect the policy comparison.

## What the strata mean

The streams are **not** at natural prevalence. Benign rows are about 0.5% of the validation file; flagged attacks outnumber flagged benign flows by about 4,000 to 1 in the full data. The streams fix the share of attacks among flagged alerts (10%, 30%, and 58% for S58) so that the response policies face a controlled false-positive load. Results describe those mixes, not deployment traffic. The population columns above are the detector's real flag rates over the full files (benign 5.00% matches the documented FPR 0.0501; zero-day overall (2,633,942 + 8,420) / 2,658,953 = 0.9938 matches the documented 0.9938, while Web-Based alone is 0.339).
