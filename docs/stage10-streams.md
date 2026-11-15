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

## Amendment 10 local snapshot (revised-data-basis replication)

Built 2026-11-15 from the hash-pinned local inputs recorded in amendments 10-11 of `docs/stage10-evaluation-plan.md`: validation SHA-256 `E661CC9C6861A7692BD77918D79315D7B1CD814F46E55BAAD54288167C890AC8`; zero-day SHA-256 `1FE72BC723CD46106A57DE29012C3EE23FC7A504D931230269BCE2E2791A87BA`. This current validation file has 31,159,073 rows, versus 43,149,298 in the original stream metadata. These replacement streams are not the original snapshot's confirmatory streams; amendment 7's method and success rule are being replicated on this revised basis.

| stream | sampled flagged (attack + benign) | attack share | excluded source rows | stream SHA-256 |
|---|---:|---:|---:|---|
| S58 | 720 (420 + 300) | 0.5833 | 0 | `3bdd7ff4dd076868335c999c472112d37dc649ae8b6a30e46466dcb90efe8cfa` |
| S10 | 3,010 (301 + 2,709) | 0.1000 | 1,150 | `a1310e7b2be2284d650108063f88aff016d4a3b0f47bba8ad0d3099d4ea7d40d` |
| S30 | 1,003 (301 + 702) | 0.3001 | 4,579 | `640ff280a9a7cf0e422f40b027d20295e4976a402d44139b115a64418b20fb70` |

Each builder read 33,818,026 rows and skipped one non-finite row. Flagged quotas matched the plan. The source contained 69 unflagged DoS rows: S58 used 40, S10 used the remaining 29, and S30 had none after exclusions. The unflagged DoS shortfall is recorded in amendment 11; unflagged rows are not routed. Per-family counts and source paths are in the accompanying committed `.meta.json` files. The `.jsonl` streams remain local and uncommitted.

## S10b under the amendment 10 local snapshot

Built after freeze commit `8659cbf`; seed 4, target attack share 0.1, minimum 300 attacks, and exclusions for S58/S10/S30. The stream contained 3,400 rows: 3,010 flagged (301 attacks, 2,709 benign) and 390 unflagged; 5,972 source rows had already appeared in the earlier streams. One non-finite source row was skipped. The stream SHA-256 is `bc579188c3d132264fddcf8eef13a95ab85498a6feb8aeaca216a10e406ca095`. The source/population counts are in `backend/experiments/replay_streams/replay_stream_share10_seed4.meta.json`; the `.jsonl` remains uncommitted.

Metadata note (2026-11-15): the amendment 10 snapshot's metadata is stored as `backend/experiments/replay_streams/*_amend10.meta.json` (S58, S10, S30 and its S10b). The unsuffixed `.meta.json` files describe the original streams in the first table, which all earlier Stage 10 results used.

## S10b, original snapshot (amendment 12)

Built after freeze commit `caaa512` with the amendment 7 S10b command (seed 4, share 0.1, min 300 attacks, excluding S58, S10 and S30). Read 45,808,251 rows, 0 non-finite skipped, 6,001 excluded rows skipped, 0 screen/pipeline mismatches. 3,400 rows: 3,010 flagged (301 attacks + 2,709 benign) and 390 unflagged (0 unflagged DoS: the 98 in the population were used by earlier streams; unflagged rows are never routed). SHA-256 `93fe6dab564504cdf4e49adb8345bbe660432d83b6081f57c3a1043d1ef0aa18`. Metadata: `replay_stream_share10_seed4.meta.json`. Used once, by amendment 12.
