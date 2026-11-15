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
from services.technique_plausibility import A12_VARIANTS  # noqa: E402
from services import technique_plausibility as _tp  # noqa: E402

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
                         "score": float(alert["anomaly_score"]),
                         "relevant": sorted(relevant),
                         "candidates": {METHOD_TFIDF: [item["technique_id"]
                                                        for item in base_result.get("techniques", [])],
                                        METHOD_V2: [item["technique_id"]
                                                    for item in v2_result.get("techniques", [])]}})
    return prepared


def add_mapping(prepared, service: MitreService, mapping_variant: str | None = None, method: str = METHOD_MAPPING):
    """Apply one map to already recomputed per-alert TF-IDF candidates (rows may already hold other methods)."""
    rows = []
    for item in prepared:
        mapped = service.retrieve_behavior(item["analysis"], behaviour_mapping=True,
                                           mapping_variant=mapping_variant,
                                           _base_result=item["base_result"]).get("techniques", [])
        rows.append({**item, "candidates": {**item["candidates"],
                                            method: [candidate["technique_id"] for candidate in mapped]}})
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


A12_BASIS = "Original snapshot (validation 43,149,298 rows; zero-day 2,658,953 rows), see amendment 12"
METHOD_GUARDED = "TF-IDF + guarded mapping + v2 filter"
A12_METHODS = (METHOD_TFIDF, METHOD_V2, METHOD_MAPPING, METHOD_GUARDED)
A12_OUT = HERE / "experiments" / "mapping_a12"


def tune12(service: MitreService):
    """Amendment 12: the three guarded variants, on S58 and S10 only. S10b is never read here."""
    result = {"data_basis": A12_BASIS, "variants": {}, "selection": None}
    prepared_streams = {name: prepare_alerts(path, service) for name, path in TUNE_STREAMS.items()}
    for variant in A12_VARIANTS:
        by_stream = {}
        for name, prepared in prepared_streams.items():
            rows = add_mapping(prepared, service, variant, METHOD_GUARDED)
            by_stream[name] = {"stream": TUNE_STREAMS[name].name, "stream_sha256": stream_sha256(TUNE_STREAMS[name]),
                               "methods": {m: metric_for(rows, m) for m in (METHOD_TFIDF, METHOD_V2, METHOD_GUARDED)},
                               "guarded_minus_v2_paired_bootstrap_95": paired_bootstrap(rows, METHOD_V2, METHOD_GUARDED)}
        score = sum(s["methods"][METHOD_GUARDED]["primary_balanced_score"] for s in by_stream.values()) / len(by_stream)
        result["variants"][variant] = {"mean_tuning_primary_score": score, "streams": by_stream}
    winner = max(result["variants"], key=lambda name: result["variants"][name]["mean_tuning_primary_score"])
    result["selection"] = {"variant": winner, "held_out_stream_seen": False,
                           "rule": "highest mean primary balanced score across S58 and S10; ties follow variant order"}
    return result


def test12_once(service: MitreService, out_dir: Path = A12_OUT):
    """Amendment 12 one-time test on the original-snapshot S10b. Refuses before the freeze or a second run."""
    frozen = _tp.A12_FROZEN_VARIANT
    if frozen not in A12_VARIANTS:
        raise RuntimeError("Freeze first: set A12_FROZEN_VARIANT in technique_plausibility.py and commit it.")
    if (out_dir / "test_s10b.json").exists():
        raise RuntimeError(f"The one-time test has already been run: {out_dir / 'test_s10b.json'}")
    if not TEST_STREAM.exists():
        raise FileNotFoundError(f"S10b has not been built: {TEST_STREAM}")
    prepared = prepare_alerts(TEST_STREAM, service)
    rows = add_mapping(prepared, service, None, METHOD_MAPPING)               # amendment 7 map, frozen in 8659cbf
    rows = add_mapping(rows, service, frozen, METHOD_GUARDED)     # amendment 12 frozen guarded map
    return {"data_basis": A12_BASIS, "frozen_variant": frozen,
            "stream": TEST_STREAM.name, "stream_sha256": stream_sha256(TEST_STREAM),
            "methods": {m: metric_for(rows, m) for m in A12_METHODS},
            "guarded_minus_v2_paired_bootstrap_95": paired_bootstrap(rows, METHOD_V2, METHOD_GUARDED),
            "mapping_v1_minus_v2_paired_bootstrap_95": paired_bootstrap(rows, METHOD_V2, METHOD_MAPPING)}


def fmt_rate(k, n, ci):
    return f"{k}/{n} {100 * k / n:.1f}% [{100 * ci[0]:.1f}%, {100 * ci[1]:.1f}%]" if n else "-"


def markdown12(result):
    fams = ATTACK_FAMILIES
    head = "| Method | " + " | ".join(fams) + " | Benign clean | Primary score | Precision | Mean candidates |"
    lines = [f"# Amendment 12 one-time test on S10b (original snapshot)", "",
             f"Frozen guarded variant: `{result['frozen_variant']}`. Stream SHA-256: `{result['stream_sha256']}`.",
             f"Data basis: {result['data_basis']}.", "", head, "|" + "---|" * (len(fams) + 5)]
    for method, m in result["methods"].items():
        pf = m["per_family"]
        cells = [fmt_rate(pf[f]["covered"], pf[f]["alerts"], pf[f]["wilson_95"]) if f in pf else "-" for f in fams]
        b = pf["Benign"]
        prec = m["attack_candidate_precision_excluding_web"]
        lines.append(f"| {method} | " + " | ".join(cells) + f" | {fmt_rate(b['clean'], b['alerts'], b['wilson_95'])} | "
                     f"{m['primary_balanced_score']:.4f} | {'-' if prec is None else f'{100 * prec:.1f}%'} | "
                     f"{m['mean_candidates_per_alert']:.2f} |")
    g, v2, v1 = (result["methods"][k]["primary_balanced_score"] for k in (METHOD_GUARDED, METHOD_V2, METHOD_MAPPING))
    lo, hi = result["guarded_minus_v2_paired_bootstrap_95"]
    lo1, hi1 = result["mapping_v1_minus_v2_paired_bootstrap_95"]
    verdict = "SUCCESS" if lo > 0 else "no improvement under the pre-stated rule"
    lines += ["", f"**Guarded mapping minus TF-IDF + v2 filter: {g - v2:+.4f}, 95% paired bootstrap "
                  f"[{lo:+.4f}, {hi:+.4f}]. Verdict: {verdict}.**",
              f"Replication of the amendment 7 map on this snapshot: {v1 - v2:+.4f} [{lo1:+.4f}, {hi1:+.4f}].",
              f"Web-Based alerts (out of scope): {result['methods'][METHOD_V2]['web_based_alerts_out_of_scope']}.",
              "Run once. Labels used only after retrieval, to score relevance."]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ amendment 15: score gate
A15_OUT = HERE / "experiments" / "mapping_a15"
S10C_STREAM = STREAMS / "replay_stream_share10_seed5.jsonl"
METHOD_GATED = "TF-IDF + guarded mapping + v2 filter + score gate"
A15_METHODS = (METHOD_TFIDF, METHOD_V2, METHOD_GUARDED, METHOD_GATED)


def add_gate(rows, gate, threshold):
    """Gated candidates = guarded candidates if the alert's score passes the gate, else none."""
    return [{**r, "candidates": {**r["candidates"],
                                 METHOD_GATED: (r["candidates"][METHOD_GUARDED]
                                                if _tp.passes_score_gate(r["score"], threshold, gate) else [])}}
            for r in rows]


def lost_context(rows):
    """Per attack family: share of alerts with guarded candidates that the gate leaves with none."""
    out = {}
    for fam in sorted({r["family"] for r in rows if r["family"] != "Benign"}):
        g = [r for r in rows if r["family"] == fam and r["candidates"][METHOD_GUARDED]]
        out[fam] = (sum(not r["candidates"][METHOD_GATED] for r in g) / len(g)) if g else None
    return out


def gated_rows(prepared, service, gate, threshold):
    rows = add_mapping(prepared, service, _tp.A12_FROZEN_VARIANT, METHOD_GUARDED)
    return add_gate(rows, gate, threshold)


def tune15(service, threshold):
    result = {"data_basis": A12_BASIS, "guarded_variant": _tp.A12_FROZEN_VARIANT, "threshold": threshold,
              "variants": {}, "selection": None}
    prepared_streams = {name: prepare_alerts(path, service) for name, path in TUNE_STREAMS.items()}
    for name_gate, gate in _tp.A15_GATES.items():
        by_stream = {}
        for name, prepared in prepared_streams.items():
            rows = gated_rows(prepared, service, gate, threshold)
            by_stream[name] = {"stream_sha256": stream_sha256(TUNE_STREAMS[name]),
                               "methods": {m: metric_for(rows, m) for m in A15_METHODS},
                               "lost_context": lost_context(rows),
                               "gated_minus_guarded_95": paired_bootstrap(rows, METHOD_GUARDED, METHOD_GATED)}
        score = sum(s["methods"][METHOD_GATED]["primary_balanced_score"] for s in by_stream.values()) / len(by_stream)
        result["variants"][name_gate] = {"mean_tuning_primary_score": score, "streams": by_stream}
    winner = max(result["variants"], key=lambda n: result["variants"][n]["mean_tuning_primary_score"])
    result["selection"] = {"variant": winner, "held_out_stream_seen": False,
                           "rule": "highest mean primary balanced score across S58 and S10; ties follow variant order"}
    return result


def test15_once(service, threshold, out_dir: Path = A15_OUT):
    frozen = _tp.A15_FROZEN_GATE
    if frozen not in _tp.A15_GATES:
        raise RuntimeError("Freeze first: set A15_FROZEN_GATE in technique_plausibility.py and commit it.")
    if (out_dir / "test_s10c.json").exists():
        raise RuntimeError(f"The one-time test has already been run: {out_dir / 'test_s10c.json'}")
    if not S10C_STREAM.exists():
        raise FileNotFoundError(f"S10c has not been built: {S10C_STREAM}")
    rows = gated_rows(prepare_alerts(S10C_STREAM, service), service, _tp.A15_GATES[frozen], threshold)
    return {"data_basis": A12_BASIS, "frozen_gate": frozen, "guarded_variant": _tp.A12_FROZEN_VARIANT,
            "stream": S10C_STREAM.name, "stream_sha256": stream_sha256(S10C_STREAM),
            "methods": {m: metric_for(rows, m) for m in A15_METHODS}, "lost_context": lost_context(rows),
            "gated_minus_guarded_95": paired_bootstrap(rows, METHOD_GUARDED, METHOD_GATED)}


def markdown15(result):
    fams = ATTACK_FAMILIES
    L = ["# Amendment 15 one-time test on S10c (original snapshot)", "",
         f"Frozen gate: `{result['frozen_gate']}` on guarded mapping `{result['guarded_variant']}`. "
         f"Stream SHA-256: `{result['stream_sha256']}`.", "",
         "| Method | " + " | ".join(fams) + " | Benign clean | Primary score | Precision | Mean candidates |",
         "|" + "---|" * (len(fams) + 5)]
    for method, m in result["methods"].items():
        pf = m["per_family"]
        cells = [fmt_rate(pf[f]["covered"], pf[f]["alerts"], pf[f]["wilson_95"]) if f in pf else "-" for f in fams]
        b = pf["Benign"]
        prec = m["attack_candidate_precision_excluding_web"]
        L.append(f"| {method} | " + " | ".join(cells) + f" | {fmt_rate(b['clean'], b['alerts'], b['wilson_95'])} | "
                 f"{m['primary_balanced_score']:.4f} | {'-' if prec is None else f'{100 * prec:.1f}%'} | "
                 f"{m['mean_candidates_per_alert']:.2f} |")
    g, base = (result["methods"][k]["primary_balanced_score"] for k in (METHOD_GATED, METHOD_GUARDED))
    lo, hi = result["gated_minus_guarded_95"]
    verdict = "SUCCESS" if lo > 0 else "no improvement under the pre-stated rule"
    lost = "; ".join(f"{f} {100 * v:.0f}%" for f, v in result["lost_context"].items() if v is not None)
    L += ["", f"**Gated minus guarded mapping: {g - base:+.4f}, 95% paired bootstrap [{lo:+.4f}, {hi:+.4f}]. "
              f"Verdict: {verdict}.**", f"Attack alerts that lose all context because of the gate: {lost}.",
          "Run once. Labels used only after retrieval, to score relevance."]
    return "\n".join(L) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tune", action="store_true")
    group.add_argument("--test", action="store_true")
    group.add_argument("--tune12", action="store_true", help="amendment 12: guarded variants on S58 and S10")
    group.add_argument("--test12", action="store_true", help="amendment 12: one-time S10b test after the freeze")
    group.add_argument("--tune15", action="store_true", help="amendment 15: score gates on S58 and S10")
    group.add_argument("--test15", action="store_true", help="amendment 15: one-time S10c test after the freeze")
    parser.add_argument("--out", type=Path, default=HERE / "experiments" / "mapping")
    args = parser.parse_args(argv)
    service = MitreService(ROOT)
    if args.tune15 or args.test15:
        from services.model_service import Detector
        threshold = float(Detector(ROOT).threshold)
        A15_OUT.mkdir(parents=True, exist_ok=True)
        if args.tune15:
            result = tune15(service, threshold)
            (A15_OUT / "tune.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            lines = ["Amendment 15 tune: S58 and S10 only; three fixed score gates on guarded mapping g1."]
            for name_gate, data in result["variants"].items():
                lines.append(f"\n{name_gate}: mean primary score={data['mean_tuning_primary_score']:.4f}")
                for name, s in data["streams"].items():
                    lo, hi = s["gated_minus_guarded_95"]
                    lost = ", ".join(f"{f} {0 if v is None else 100 * v:.0f}%" for f, v in s["lost_context"].items())
                    lines.append(f"  {name}: gated-guarded 95% [{lo:+.4f}, {hi:+.4f}]; lost context {lost}")
                    for method, m in s["methods"].items():
                        lines.append(f"    {method}: primary={m['primary_balanced_score']:.4f}; "
                                     f"coverage={m['attack_coverage_macro_excluding_web']:.4f}; "
                                     f"benign_clean={m['benign_clean_rate']:.4f}")
            lines.append(f"\nSelected: {result['selection']['variant']}")
            (A15_OUT / "tune.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            print("\n".join(lines))
        else:
            result = test15_once(service, threshold)
            (A15_OUT / "test_s10c.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            text = markdown15(result)
            (A15_OUT / "test_s10c.md").write_text(text, encoding="utf-8")
            print(text)
        return
    if args.tune12 or args.test12:
        A12_OUT.mkdir(parents=True, exist_ok=True)
        if args.tune12:
            result = tune12(service)
            (A12_OUT / "tune.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            lines = ["Amendment 12 tune: S58 and S10 only; three fixed guarded variants.", f"Data basis: {A12_BASIS}."]
            for variant, data in result["variants"].items():
                lines.append(f"\n{variant}: mean primary score={data['mean_tuning_primary_score']:.4f}")
                for name, stream in data["streams"].items():
                    lo, hi = stream["guarded_minus_v2_paired_bootstrap_95"]
                    lines.append(f"  {name} sha256={stream['stream_sha256']}  guarded-v2 95% [{lo:+.4f}, {hi:+.4f}]")
                    for method, m in stream["methods"].items():
                        lines.append(f"    {method}: primary={m['primary_balanced_score']:.4f}; "
                                     f"coverage={m['attack_coverage_macro_excluding_web']:.4f}; "
                                     f"benign_clean={m['benign_clean_rate']:.4f}; "
                                     f"recon={m['per_family'].get('Recon', {}).get('coverage')}")
            lines.append(f"\nSelected: {result['selection']['variant']}")
            (A12_OUT / "tune.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            print("\n".join(lines))
        else:
            result = test12_once(service)
            (A12_OUT / "test_s10b.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            text = markdown12(result)
            (A12_OUT / "test_s10b.md").write_text(text, encoding="utf-8")
            print(text)
        return
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
