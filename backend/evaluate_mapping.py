"""Evaluate amendment 7 behaviour-to-technique mapping.

    python evaluate_mapping.py --tune   # S58 and S10 only; at most three fixed variants
    python evaluate_mapping.py --test   # S10b once, after the mapping freeze commit

Labels are read only after all candidate lists for an alert have been recomputed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_llm_verification as measure  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services.mitre_service import MitreService  # noqa: E402
from services.technique_plausibility import DIRECT_MAP_VARIANTS, RULES_VERSION_V2  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STREAMS = HERE / "experiments" / "replay_streams"
TUNE_STREAMS = {"S58": STREAMS / "replay_stream_seed1.jsonl",
                "S10": STREAMS / "replay_stream_share10_seed2.jsonl"}
TEST_STREAM = STREAMS / "replay_stream_share10_seed4.jsonl"
ATTACK_FAMILIES = ("DDoS", "DoS", "Recon", "Brute Force", "Spoofing", "Mirai")
WEB_FAMILY = "Web-Based"
BOOTSTRAP_SEED, BOOTSTRAP_RESAMPLES = 20261115, 2000
METHOD_TFIDF = "TF-IDF only"
METHOD_V2 = "TF-IDF + v2 filter"
METHOD_MAPPING = "TF-IDF + mapping + v2 filter"


def wilson(k: int, n: int, z: float = 1.96):
    if not n:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    center = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [(center - half) / d, (center + half) / d]


def stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_alerts(path: Path, service: MitreService):
    """Recompute TF-IDF and v2 candidates from xai_evidence once for all comparisons."""
    prepared = []
    for alert in replay.load_stream(path):
        if not alert["detected"]:
            continue
        analysis = {"top_features": alert["xai_evidence"]}
        base_result = service.retrieve_behavior(analysis)
        v2_result = service.retrieve_behavior(analysis, plausibility_v2=True, _base_result=base_result)

        # Scoring labels enter only after both baseline candidate-generation calls above.
        family = alert["_family"]
        relevant = (measure.relevant_set({"attack_label": alert["_attack_label"], "family": family})
                    if family != "Benign" else set())
        prepared.append({"analysis": analysis, "base_result": base_result, "family": family,
                         "relevant": sorted(relevant),
                         "candidates": {METHOD_TFIDF: [item["technique_id"]
                                                        for item in base_result.get("techniques", [])],
                                        METHOD_V2: [item["technique_id"]
                                                    for item in v2_result.get("techniques", [])]}})
    return prepared


def add_mapping(prepared, service: MitreService, mapping_variant: str | None = None):
    """Apply one map to already recomputed per-alert TF-IDF candidates."""
    rows = []
    for item in prepared:
        mapped = service.retrieve_behavior(item["analysis"], behaviour_mapping=True,
                                           mapping_variant=mapping_variant,
                                           _base_result=item["base_result"]).get("techniques", [])
        rows.append({"family": item["family"], "relevant": item["relevant"],
                     "candidates": {**item["candidates"],
                                    METHOD_MAPPING: [candidate["technique_id"] for candidate in mapped]}})
    return rows


def metric_for(rows, method: str):
    attack_rows = [r for r in rows if r["family"] not in ("Benign", WEB_FAMILY)]
    families = sorted({r["family"] for r in attack_rows})
    per_family = {}
    family_coverage = []
    for family in families:
        group = [r for r in attack_rows if r["family"] == family]
        covered = sum(any(tid.split(".")[0] in r["relevant"] for tid in r["candidates"][method]) for r in group)
        rate = covered / len(group) if group else float("nan")
        family_coverage.append(rate)
        per_family[family] = {"covered": covered, "alerts": len(group), "coverage": rate,
                               "wilson_95": wilson(covered, len(group))}
    benign = [r for r in rows if r["family"] == "Benign"]
    benign_clean = sum(not r["candidates"][method] for r in benign)
    benign_rate = benign_clean / len(benign) if benign else float("nan")
    relevant_candidates = total_attack_candidates = 0
    for row in attack_rows:
        for tid in row["candidates"][method]:
            total_attack_candidates += 1
            relevant_candidates += tid.split(".")[0] in row["relevant"]
    coverage_macro = sum(family_coverage) / len(family_coverage) if family_coverage else float("nan")
    balanced = (coverage_macro + benign_rate) / 2 if family_coverage and benign else float("nan")
    per_family["Benign"] = {"clean": benign_clean, "alerts": len(benign), "clean_rate": benign_rate,
                             "wilson_95": wilson(benign_clean, len(benign))}
    web = [r for r in rows if r["family"] == WEB_FAMILY]
    return {"per_family": per_family, "attack_coverage_macro_excluding_web": coverage_macro,
            "benign_clean_rate": benign_rate, "primary_balanced_score": balanced,
            "attack_candidate_precision_excluding_web": (relevant_candidates / total_attack_candidates
                                                          if total_attack_candidates else None),
            "relevant_attack_candidates": relevant_candidates,
            "total_attack_candidates": total_attack_candidates,
            "mean_candidates_per_alert": (sum(len(r["candidates"][method]) for r in rows) / len(rows)
                                           if rows else 0.0),
            "alerts": len(rows), "web_based_alerts_out_of_scope": len(web)}


def paired_bootstrap(rows, method_a=METHOD_V2, method_b=METHOD_MAPPING):
    """Stratified paired alert bootstrap of mapping minus v2 primary score."""
    groups = defaultdict(list)
    for row in rows:
        if row["family"] == WEB_FAMILY:
            continue
        groups[row["family"]].append(row)
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    family_pairs = []
    benign_pair = None
    for family, group in groups.items():
        if family == "Benign":
            a = np.asarray([not row["candidates"][method_a] for row in group], dtype=float)
            b = np.asarray([not row["candidates"][method_b] for row in group], dtype=float)
            benign_pair = (a, b)
        else:
            a = np.asarray([any(tid.split(".")[0] in row["relevant"]
                                for tid in row["candidates"][method_a]) for row in group], dtype=float)
            b = np.asarray([any(tid.split(".")[0] in row["relevant"]
                                for tid in row["candidates"][method_b]) for row in group], dtype=float)
            family_pairs.append((a, b))
    differences = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        family_differences = []
        for a, b in family_pairs:
            indices = rng.integers(0, len(a), size=len(a))
            family_differences.append(float(b[indices].mean() - a[indices].mean()))
        if benign_pair is None or not family_differences:
            raise ValueError("paired bootstrap requires benign alerts and at least one in-scope attack family")
        a, b = benign_pair
        indices = rng.integers(0, len(a), size=len(a))
        benign_difference = float(b[indices].mean() - a[indices].mean())
        differences.append((sum(family_differences) / len(family_differences) + benign_difference) / 2)
    differences.sort()
    return [differences[int(0.025 * len(differences))], differences[int(0.975 * len(differences)) - 1]]


def evaluate_prepared_stream(path: Path, prepared, service: MitreService, mapping_variant: str):
    rows = add_mapping(prepared, service, mapping_variant)
    return {"stream": path.name, "stream_sha256": stream_sha256(path), "mapping_variant": mapping_variant,
            "methods": {method: metric_for(rows, method) for method in (METHOD_TFIDF, METHOD_V2, METHOD_MAPPING)},
            "mapping_minus_v2_paired_bootstrap_95": paired_bootstrap(rows)}


def tune(service: MitreService):
    result = {"data_basis": "Amendment 10 current local CSV hashes; revised-data-basis replication",
              "variants": {}, "selection": None}
    prepared_streams = {name: prepare_alerts(path, service) for name, path in TUNE_STREAMS.items()}
    for variant in DIRECT_MAP_VARIANTS:
        by_stream = {name: evaluate_prepared_stream(TUNE_STREAMS[name], prepared, service, variant)
                     for name, prepared in prepared_streams.items()}
        score = sum(by_stream[name]["methods"][METHOD_MAPPING]["primary_balanced_score"] for name in by_stream) / len(by_stream)
        result["variants"][variant] = {"mean_tuning_primary_score": score, "streams": by_stream}
    winner = max(result["variants"], key=lambda name: result["variants"][name]["mean_tuning_primary_score"])
    result["selection"] = {"variant": winner,
                           "rule": "highest mean primary balanced score across S58 and S10; ties follow variant order",
                           "held_out_stream_seen": False}
    return result


def test_once(service: MitreService):
    if not TEST_STREAM.exists():
        raise FileNotFoundError(f"S10b has not been built: {TEST_STREAM}")
    prepared = prepare_alerts(TEST_STREAM, service)
    rows = add_mapping(prepared, service)
    return {"data_basis": "Amendment 10 current local CSV hashes; revised-data-basis replication",
            "stream": TEST_STREAM.name, "stream_sha256": stream_sha256(TEST_STREAM),
            "methods": {method: metric_for(rows, method) for method in (METHOD_TFIDF, METHOD_V2, METHOD_MAPPING)},
            "mapping_minus_v2_paired_bootstrap_95": paired_bootstrap(rows)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tune", action="store_true")
    group.add_argument("--test", action="store_true")
    parser.add_argument("--out", type=Path, default=HERE / "experiments" / "mapping")
    args = parser.parse_args(argv)
    service = MitreService(ROOT)
    args.out.mkdir(parents=True, exist_ok=True)
    if args.tune:
        result = tune(service)
        (args.out / "tune.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        lines = ["Amendment 7 tune: S58 and S10 only; three fixed mapping variants.",
                 "Data basis: revised local CSV snapshot, see amendments 10-11."]
        for variant, data in result["variants"].items():
            lines.append(f"\n{variant}: mean primary score={data['mean_tuning_primary_score']:.4f}")
            for name, stream in data["streams"].items():
                lines.append(f"  {name} sha256={stream['stream_sha256']}")
                for method, metrics in stream["methods"].items():
                    lines.append(f"    {method}: primary={metrics['primary_balanced_score']:.4f}; "
                                 f"coverage={metrics['attack_coverage_macro_excluding_web']:.4f}; "
                                 f"benign_clean={metrics['benign_clean_rate']:.4f}; "
                                 f"precision={metrics['attack_candidate_precision_excluding_web']}")
        lines.append(f"\nSelected: {result['selection']['variant']}")
        (args.out / "tune.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))
        return
    result = test_once(service)
    (args.out / "test_s10b.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
