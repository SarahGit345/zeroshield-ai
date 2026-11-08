"""Build a labelled replay stream for run_response_experiment.py from the prepared CSVs.

    python build_replay_stream.py --seed 1
    python build_replay_stream.py --seed 1 --validation PATH --zero-day PATH --out FILE.jsonl

What it does:
  1. Streams validation_set.csv and zero_day_test_scaled_v2.csv in chunks and scores EVERY row
     with the active Deep SVDD detector (batched; the threshold is the checkpoint's).
  2. Maps each fine-grained label to a family (Benign, DDoS, DoS, Recon, Brute Force, Spoofing,
     Mirai, Web-Based) and keeps a seeded, uniform random sample of fixed size from every
     (family, flagged/unflagged) stratum. Each row gets a random key from one seeded generator;
     each stratum keeps the rows with the smallest keys. The result does not depend on chunk size.
  3. Runs every sampled row through the same per-alert pipeline as the demo cache
     (run_response_experiment.pipeline_alert): perturbation XAI, behaviour retrieval, reasoning,
     verification. No dataset label is passed to any of these steps.
  4. Writes JSONL with the demo-stream fields plus `_`-prefixed simulator keys
     (`_simulator_attack`, `_attack_label`, `_family`, `_source`, `_source_row`). Keys starting
     with `_` are stripped before the policy sees an alert (run_response_experiment.clean).
     A `.meta.json` next to the stream records seed, quotas, sources and population counts.

The stream is deliberately NOT at natural prevalence: benign rows are about 0.5% of the validation
file, and flagged benign flows (false positives) are over-sampled on purpose. Rates computed on the
stream describe the stream, not deployment traffic. Population counts in the meta file give the
detector's flag rate per family over the full files.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_response_experiment import pipeline_alert  # noqa: E402

FAMILIES = ("Benign", "DDoS", "DoS", "Recon", "Brute Force", "Spoofing", "Mirai", "Web-Based")
WEB_LABELS = {"SqlInjection", "XSS", "CommandInjection", "Uploading_Attack", "BrowserHijacking", "Backdoor_Malware"}
DEFAULT_QUOTAS = {"benign_flagged": 300, "benign_unflagged": 150, "attack_flagged": 60, "attack_unflagged": 40}
CHUNK_ROWS = 500_000
STREAM_VERSION = "replay-stream-v1"


def label_family(label) -> str:
    """CIC-IoT-2023 fine label -> family. Unknown labels go to 'Other' (reported, never silently merged)."""
    label = str(label).strip()
    if label == "BenignTraffic": return "Benign"
    if label.startswith("DDoS-"): return "DDoS"
    if label.startswith("DoS-"): return "DoS"
    if label.startswith("Recon-") or label == "VulnerabilityScan": return "Recon"
    if label == "DictionaryBruteForce": return "Brute Force"
    if label in {"DNS_Spoofing", "MITM-ArpSpoofing"}: return "Spoofing"
    if label.startswith("Mirai-"): return "Mirai"
    if label in WEB_LABELS: return "Web-Based"
    return "Other"


def quota_for(family: str, flagged: bool, quotas: dict) -> int:
    kind = "benign" if family == "Benign" else "attack"
    return int(quotas[f"{kind}_{'flagged' if flagged else 'unflagged'}"])


ATTACK_FAMILIES = tuple(f for f in FAMILIES if f != "Benign")


def attack_share_quotas(share: float, min_attacks: int, quotas: dict | None = None) -> dict:
    """Flagged quotas giving about `share` attacks among flagged rows, with at least `min_attacks`
    flagged attacks split evenly over the 7 attack families (each family 1/7 of attacks, so none
    above 25%). Unflagged quotas are left as they are; unflagged rows are never routed."""
    if not 0 < share < 1: raise ValueError("attack share must be strictly between 0 and 1")
    per_family = -(-int(min_attacks) // len(ATTACK_FAMILIES))            # ceiling division
    attacks = per_family * len(ATTACK_FAMILIES)
    return {**DEFAULT_QUOTAS, **(quotas or {}), "attack_flagged": per_family,
            "benign_flagged": int(round(attacks * (1 - share) / share))}


def sha256_file(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""): digest.update(block)
    return digest.hexdigest()


def load_exclusions(paths) -> dict:
    """(source, row) pairs already used by earlier streams, so a new stream shares no row with them."""
    excluded: dict[str, set] = {}
    for path in paths or []:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                excluded.setdefault(row["_source"], set()).add(int(row["_source_row"]))
    return excluded


def default_data_paths():
    """CLAUDE.md says the CSVs live in the repo root; on this machine they are in ../Dataset/Dataset/csv."""
    env = os.getenv("ZEROSHIELD_DATA_DIR")
    for base in ([Path(env)] if env else []) + [ROOT, ROOT.parent / "Dataset" / "Dataset" / "csv"]:
        if (base / "validation_set.csv").exists():
            return base / "validation_set.csv", base / "zero_day_test_scaled_v2.csv"
    return ROOT / "validation_set.csv", ROOT / "zero_day_test_scaled_v2.csv"


def offline_reason(result, family, mitre):
    """Labelled template reasoning whatever LLM provider is configured (keeps the stream offline and reproducible)."""
    from services.llm_service import template_report
    return template_report(result, mitre)


def screen(sources, detector, quotas, seed, chunk_rows=CHUNK_ROWS, max_rows=None, log=print, exclude=None):
    """Score every row, keep a seeded uniform sample per (family, flagged) stratum.
    Rows in `exclude` ({source: set(row)}) are counted in the population but never sampled.
    Returns (sample DataFrame, population Counter by stratum, label Counter, stats)."""
    features = list(detector.features)
    exclude = exclude or {}
    rng = np.random.default_rng(seed)
    kept: dict[tuple, pd.DataFrame] = {}
    population, labels = Counter(), Counter()
    stats = {"rows_read": 0, "non_finite_rows_skipped": 0, "excluded_rows_skipped": 0}
    for source_name, path in sources:
        offset, started = 0, time.time()
        reader = pd.read_csv(path, usecols=features + ["label"], chunksize=chunk_rows, nrows=max_rows,
                             dtype={**{f: np.float32 for f in features}, "label": str})
        for chunk in reader:
            n = len(chunk)
            keys = rng.random(n)                       # drawn for every row, so chunking cannot change them
            matrix = chunk[features].to_numpy(dtype=np.float32)
            finite = np.isfinite(matrix).all(axis=1)
            stats["non_finite_rows_skipped"] += int((~finite).sum())
            scores = np.full(n, np.nan)
            if finite.any(): scores[finite] = detector.score_batch(matrix[finite])
            frame = pd.DataFrame({"_key": keys, "_source": source_name, "_source_row": offset + np.arange(n),
                                  "_attack_label": chunk["label"].astype(str).to_numpy(), "_screen_score": scores})
            frame["_family"] = frame["_attack_label"].map(label_family)
            frame["_flagged"] = frame["_screen_score"] >= detector.threshold
            frame = pd.concat([frame, chunk[features].reset_index(drop=True)], axis=1)[finite]
            labels.update(frame["_attack_label"].to_numpy())
            for (family, flagged), group in frame.groupby(["_family", "_flagged"], sort=False):
                stratum = (family, bool(flagged))
                population[stratum] += len(group)
                if source_name in exclude:
                    used = group["_source_row"].isin(exclude[source_name])
                    stats["excluded_rows_skipped"] += int(used.sum())
                    group = group[~used]
                quota = quota_for(family, stratum[1], quotas)
                if quota <= 0: continue
                pool = group if stratum not in kept else pd.concat([kept[stratum], group])
                kept[stratum] = pool.nsmallest(quota, "_key")
            offset += n
            stats["rows_read"] += n
            log(f"  {source_name}: {offset:,} rows scored ({offset / max(time.time() - started, 1e-9):,.0f} rows/s)")
    sample = pd.concat(kept.values()) if kept else pd.DataFrame()
    if len(sample):
        order = {name: i for i, (name, _) in enumerate(sources)}
        sample = sample.assign(_order=sample["_source"].map(order)).sort_values(["_order", "_source_row"]).drop(columns="_order")
    return sample, population, labels, stats


def build_stream(sources, detector, mitre, quotas=None, seed=1, chunk_rows=CHUNK_ROWS, max_rows=None,
                 reason_fn=offline_reason, verify_fn=None, timestamp=None, log=print,
                 attack_share=None, min_attacks=None, exclude_streams=None):
    """Return (alerts, meta). `sources` is a list of (name, path).
    With `attack_share` (and `min_attacks`), flagged quotas are set by attack_share_quotas()."""
    quotas = {**DEFAULT_QUOTAS, **(quotas or {})}
    if attack_share is not None:
        quotas = attack_share_quotas(attack_share, min_attacks or 300, quotas)
    exclude = load_exclusions(exclude_streams)
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    sample, population, labels, stats = screen(sources, detector, quotas, seed, chunk_rows, max_rows, log, exclude)
    features = list(detector.features)
    alerts, mismatches = [], 0
    for _, row in sample.iterrows():
        values = {f: float(row[f]) for f in features}
        sample_id = f"{row['_source']}:{int(row['_source_row'])}"
        alert = pipeline_alert(detector, mitre, values, str(uuid.uuid5(uuid.NAMESPACE_URL, f"zeroshield-replay:{sample_id}")),
                               sample_id, timestamp=timestamp, reason_fn=reason_fn, verify_fn=verify_fn)
        mismatches += bool(alert["detected"]) != bool(row["_flagged"])   # batch vs single-row float rounding at the threshold
        alerts.append({**alert, "_simulator_attack": row["_family"] != "Benign", "_attack_label": row["_attack_label"],
                       "_family": row["_family"], "_source": row["_source"], "_source_row": int(row["_source_row"])})
    sampled = Counter((a["_family"], bool(a["detected"])) for a in alerts)
    flagged_attacks = sum(n for (fam, flg), n in sampled.items() if flg and fam != "Benign")
    flagged_total = sum(n for (fam, flg), n in sampled.items() if flg)
    meta = {"stream_version": STREAM_VERSION, "seed": seed, "chunk_rows": chunk_rows, "max_rows_per_source": max_rows,
            "quotas": quotas, "threshold": detector.threshold, "built_at": timestamp,
            "target_attack_share": attack_share, "min_attacks": min_attacks,
            "flagged_attack_share": flagged_attacks / max(flagged_total, 1),
            "excluded_streams": [{"path": str(p), "sha256": sha256_file(p)} for p in (exclude_streams or [])],
            "reasoning_mode": sorted({a["llm_explanation"].get("mode", "?") for a in alerts}),
            "sources": [{"name": name, "path": str(path), "bytes": Path(path).stat().st_size} for name, path in sources],
            **stats, "screen_vs_pipeline_detection_mismatches": mismatches,
            "population": {f"{fam}|{'flagged' if flg else 'unflagged'}": n for (fam, flg), n in sorted(population.items())},
            "sampled": {f"{fam}|{'flagged' if flg else 'unflagged'}": n for (fam, flg), n in sorted(sampled.items())},
            "population_labels": dict(sorted(labels.items())),
            "note": "Strata are sampled to fixed quotas, not at natural prevalence. False positives are over-sampled on purpose. "
                    "Keys starting with '_' are simulator-only and never reach the policy."}
    return alerts, meta


def counts_table(meta) -> str:
    families = list(FAMILIES) + sorted({k.split("|")[0] for k in meta["population"]} - set(FAMILIES))
    get = lambda d, fam, state: d.get(f"{fam}|{state}", 0)
    lines = [f"{'family':<12}{'pop flagged':>14}{'pop unflagged':>15}{'flag rate':>11}{'sampled flagged':>17}{'sampled unflagged':>19}"]
    for fam in families:
        pf, pu = get(meta["population"], fam, "flagged"), get(meta["population"], fam, "unflagged")
        if pf + pu == 0: continue
        lines.append(f"{fam:<12}{pf:>14,}{pu:>15,}{pf / (pf + pu):>11.4f}{get(meta['sampled'], fam, 'flagged'):>17}{get(meta['sampled'], fam, 'unflagged'):>19}")
    sf = sum(v for k, v in meta["sampled"].items() if k.endswith("|flagged"))
    su = sum(v for k, v in meta["sampled"].items() if k.endswith("|unflagged"))
    fp = meta["sampled"].get("Benign|flagged", 0)
    lines.append(f"sampled total: {sf + su} rows, {sf} flagged ({fp} benign false positives, {sf - fp} attacks), {su} unflagged")
    return "\n".join(lines)


def write_stream(alerts, meta, out: Path):
    """Write the JSONL (LF line endings, so the SHA-256 is platform-independent) and its meta file."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as f:
        f.write("".join(json.dumps(a, sort_keys=True) + "\n" for a in alerts))
    meta["stream_sha256"] = sha256_file(out)
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta["stream_sha256"]


def main(argv=None):
    validation, zero_day = default_data_paths()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--validation", type=Path, default=validation)
    p.add_argument("--zero-day", type=Path, default=zero_day)
    p.add_argument("--out", type=Path)
    p.add_argument("--chunk-rows", type=int, default=CHUNK_ROWS)
    p.add_argument("--max-rows", type=int, help="read at most this many rows per file (smoke tests only)")
    p.add_argument("--attack-share", type=float, help="target share of attacks among flagged rows (sets the flagged quotas)")
    p.add_argument("--min-attacks", type=int, default=300, help="with --attack-share: at least this many flagged attacks, split evenly over 7 families")
    p.add_argument("--exclude-stream", type=Path, action="append", default=[], help="earlier stream whose rows must not be reused (repeatable)")
    for name, value in DEFAULT_QUOTAS.items():
        p.add_argument(f"--{name.replace('_', '-')}", type=int, default=value, help=f"rows per stratum (default {value})")
    args = p.parse_args(argv)
    from services.mitre_service import MitreService
    from services.model_service import Detector
    detector = Detector(ROOT)
    if not detector.loaded:
        raise SystemExit("Detector checkpoint did not load; see the log above.")
    for path in (args.validation, args.zero_day):
        if not path.exists(): raise SystemExit(f"Missing data file: {path}")
    out = args.out or ROOT / "backend" / "experiments" / "replay_streams" / f"replay_stream_seed{args.seed}.jsonl"
    print(f"Detector threshold {detector.threshold}; seed {args.seed}; writing {out}")
    alerts, meta = build_stream([("validation", args.validation), ("zero_day", args.zero_day)], detector, MitreService(ROOT),
                                quotas={k: getattr(args, k) for k in DEFAULT_QUOTAS}, seed=args.seed,
                                chunk_rows=args.chunk_rows, max_rows=args.max_rows, attack_share=args.attack_share,
                                min_attacks=args.min_attacks if args.attack_share is not None else None,
                                exclude_streams=args.exclude_stream)
    digest = write_stream(alerts, meta, out)
    print(counts_table(meta))
    print(f"rows read {meta['rows_read']:,}; non-finite skipped {meta['non_finite_rows_skipped']}; "
          f"excluded rows skipped {meta['excluded_rows_skipped']}; "
          f"screen/pipeline detection mismatches {meta['screen_vs_pipeline_detection_mismatches']}; reasoning {meta['reasoning_mode']}")
    print(f"flagged attack share {meta['flagged_attack_share']:.4f}; SHA-256 {digest}")
    return meta


if __name__ == "__main__":
    main()
