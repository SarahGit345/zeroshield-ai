"""Ollama provider and the step-3 measurement script, against a fake local Ollama server (no model needed):
request format (JSON schema, temperature 0, fixed seed, thinking off, field meanings in the prompt),
parse-and-repair with one retry, labelled fallback when both attempts fail, the real model name in the
mode, no dataset label in the prompt, and deterministic stratified sampling with saved raw outputs."""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import build_replay_stream as brs
import measure_llm_verification as measure
from services import llm_service
from services.verification_service import verify_record

ANALYSIS = {"anomaly_score": 0.2345678, "threshold": 0.0614192, "detected": True,
            "top_features": [{"feature": "Rate", "value": 2.5, "contribution": 0.08, "rank": 1},
                             {"feature": "SYNRatio", "value": -0.4, "contribution": -0.01, "rank": 2}],
            "feature_names": ["Rate", "SYNRatio"], "all_feature_names": ["Rate", "SYNRatio", "IAT"]}
MITRE = {"techniques": [{"technique_id": "T1498.001", "technique_name": "Direct Network Flood"}], "query": "q"}


def good_report(analysis=ANALYSIS):
    return {"incident_summary": "The detector flagged this flow as anomalous because its score exceeded the threshold.",
            "evidence": [f"Anomaly score {analysis['anomaly_score']} exceeded the threshold {analysis['threshold']}.",
                         "Rate had the largest positive contribution."],
            "attack_context": "T1498.001 is a retrieved candidate and may suggest flooding; it is not confirmed.",
            "interpretation": "Flow statistics alone cannot establish an attack.",
            "recommended_action": "An analyst should correlate this flow with host telemetry.",
            "limitations": "Perturbation importance describes model sensitivity, not causation."}


class FakeOllama:
    """Serves queued /api/chat replies (strings) and records every request payload."""
    def __init__(self, replies, delay=0.0):
        self.replies, self.requests, self.delay = list(replies), [], delay
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _send(self, obj):
                body = json.dumps(obj).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/tags": self._send({"models": [{"name": "fake:1b", "digest": "abc123", "size": 1}]})
                else: self._send({"version": "0.0-test"})

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(payload)
                if outer.delay:
                    import time; time.sleep(outer.delay)
                content = outer.replies.pop(0) if outer.replies else json.dumps(good_report())
                self._send({"message": {"role": "assistant", "content": content}, "total_duration": 1, "eval_count": 5,
                            "prompt_eval_count": 7, "eval_duration": 1})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown(); self.server.server_close()


class OllamaProviderTests(unittest.TestCase):
    def run_with(self, replies, **kw):
        fake = FakeOllama(replies); self.addCleanup(fake.close)
        result = llm_service.ollama_reason(ANALYSIS, None, MITRE, host=fake.host, model="fake:1b", seed=7, **kw)
        return result, fake

    def test_request_format_and_mode(self):
        result, fake = self.run_with([json.dumps(good_report())])
        self.assertEqual(result["mode"], "Ollama LLM (fake:1b)")
        self.assertEqual((result["attempts"], result["repaired"]), (1, False))
        payload = fake.requests[0]
        self.assertEqual(payload["format"], llm_service.REPORT_SCHEMA)
        self.assertEqual(payload["options"]["temperature"], 0)
        self.assertEqual(payload["options"]["seed"], 7)
        self.assertIs(payload["stream"], False)
        self.assertIs(payload["think"], False)
        system = payload["messages"][0]["content"]
        for field in llm_service.FIELDS + ("anomaly_score", "threshold", "top_features", "mitre_candidates", "contribution"):
            self.assertIn(field, system)
        evidence = json.loads(payload["messages"][1]["content"])
        self.assertIsNone(evidence["attack_family"])                 # no dataset label reaches the model
        self.assertEqual(result["raw_outputs"], [json.dumps(good_report())])

    def test_prompt_asks_for_concise_evidence_and_descriptions_are_capped(self):
        long = {"techniques": [{"technique_id": "T1498", "description": "x" * 1200, "technique_name": "Network DoS"}]}
        payload = llm_service.evidence_payload(ANALYSIS, None, long)
        self.assertEqual(len(payload["mitre_candidates"][0]["description"]), llm_service.MITRE_DESCRIPTION_CHARS)
        self.assertEqual(payload["mitre_candidates"][0]["technique_id"], "T1498")
        self.assertEqual(len(long["techniques"][0]["description"]), 1200)           # caller's data untouched
        self.assertIn("three to six short strings", llm_service.SYSTEM_PROMPT)
        self.assertIn("Do not copy the whole input", llm_service.SYSTEM_PROMPT)

    def test_output_cap_is_sent(self):
        _, fake = self.run_with([json.dumps(good_report())], num_predict=123)
        self.assertEqual(fake.requests[0]["options"]["num_predict"], 123)
        _, fake = self.run_with([json.dumps(good_report())])
        self.assertEqual(fake.requests[0]["options"]["num_predict"], llm_service.DEFAULT_NUM_PREDICT)

    def test_slow_model_raises_a_timeout_not_a_parse_failure(self):
        fake = FakeOllama([json.dumps(good_report())], delay=3); self.addCleanup(fake.close)
        with self.assertRaises(llm_service.LLMTimeout):
            llm_service.ollama_reason(ANALYSIS, None, MITRE, host=fake.host, model="fake:1b", seed=7, timeout=1.5)

    def test_budget_covers_the_retry_too(self):
        # First reply is invalid and arrives after 1 s; the 1.5 s budget leaves too little for the retry.
        fake = FakeOllama(["{bad", json.dumps(good_report())], delay=1.0); self.addCleanup(fake.close)
        with self.assertRaises(llm_service.LLMTimeout) as ctx:
            llm_service.ollama_reason(ANALYSIS, None, MITRE, host=fake.host, model="fake:1b", seed=7, timeout=1.5)
        self.assertEqual(ctx.exception.args[1], ["{bad"])            # the raw output so far is kept

    def test_invalid_reply_gets_exactly_one_retry_with_the_error(self):
        result, fake = self.run_with(["{not json", json.dumps(good_report())])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(len(result["parse_errors"]), 1)
        retry = fake.requests[1]["messages"]
        self.assertEqual(retry[-2], {"role": "assistant", "content": "{not json"})
        self.assertIn("could not be used", retry[-1]["content"])
        self.assertEqual(result["raw_outputs"][0], "{not json")

    def test_fenced_or_wrapped_json_is_repaired_without_retry(self):
        wrapped = "Here is the report:\n```json\n" + json.dumps(good_report()) + "\n```"
        result, fake = self.run_with([wrapped])
        self.assertEqual((result["attempts"], result["repaired"], len(fake.requests)), (1, True, 1))

    def test_single_string_evidence_is_repaired_to_a_list(self):
        report = {**good_report(), "evidence": "Score 0.2345678 exceeded threshold 0.0614192."}
        result, _ = self.run_with([json.dumps(report)])
        self.assertEqual(result["report"]["evidence"], ["Score 0.2345678 exceeded threshold 0.0614192."])
        self.assertTrue(result["repaired"])

    def test_missing_field_counts_as_invalid(self):
        report = good_report(); del report["limitations"]
        result, fake = self.run_with([json.dumps(report), json.dumps(good_report())])
        self.assertEqual(result["attempts"], 2)
        self.assertIn("missing fields: limitations", result["parse_errors"][0])

    def test_two_failures_fall_back_to_the_labelled_template(self):
        fake = FakeOllama(["nope", "still nope"]); self.addCleanup(fake.close)
        env = {"ZEROSHIELD_LLM_PROVIDER": "ollama", "OLLAMA_HOST": fake.host, "OLLAMA_MODEL": "fake:1b"}
        with patch.dict(os.environ, env), self.assertLogs(level="ERROR"):
            result = llm_service.reason(ANALYSIS, None, MITRE)
        self.assertEqual(result["mode"], "Demo Fallback Reasoning")      # never presented as LLM output
        self.assertEqual(result["raw_outputs"], ["nope", "still nope"])
        self.assertIn("no valid report after 2 attempts", result["llm_error"])
        self.assertEqual(len(fake.requests), 2)

    def test_unreachable_server_falls_back(self):
        env = {"ZEROSHIELD_LLM_PROVIDER": "ollama", "OLLAMA_HOST": "http://127.0.0.1:9", "ZEROSHIELD_LLM_TIMEOUT": "2"}
        with patch.dict(os.environ, env), self.assertLogs(level="ERROR"):
            result = llm_service.reason(ANALYSIS, None, MITRE)
        self.assertEqual(result["mode"], "Demo Fallback Reasoning")
        self.assertIn("llm_error", result)

    def test_provider_selection(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(llm_service.provider(), "template")
            self.assertEqual(llm_service.llm_status(), "Demo Fallback Reasoning")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "x"}, clear=True):
            self.assertEqual(llm_service.provider(), "openai")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "x", "ZEROSHIELD_LLM_PROVIDER": "ollama", "OLLAMA_MODEL": "m:1"}, clear=True):
            self.assertEqual(llm_service.provider(), "ollama")
            self.assertEqual(llm_service.llm_status(), "Ollama configured (m:1)")

    def test_llm_report_is_verified_as_llm_not_template(self):
        result, _ = self.run_with([json.dumps(good_report())])
        verdict = verify_record(ANALYSIS, MITRE, result)
        self.assertEqual(verdict["verdict"], "VERIFIED", verdict["failed_checks"])
        self.assertEqual(verdict["reasoning_mode"], "Ollama LLM (fake:1b)")
        self.assertNotIn("limitation", verdict)                        # the template-only caveat does not apply

    def test_stream_builder_stays_on_the_template_when_ollama_is_configured(self):
        with patch.dict(os.environ, {"ZEROSHIELD_LLM_PROVIDER": "ollama", "OLLAMA_HOST": "http://127.0.0.1:9"}):
            self.assertEqual(brs.offline_reason(ANALYSIS, None, MITRE)["mode"], "Demo Fallback Reasoning")


def synthetic_stream():
    stream, i = [], 0
    for family, n in [("Benign", 40)] + [(f, 12) for f in measure.ATTACK_FAMILIES]:
        for _ in range(n):
            stream.append({"alert_id": f"id{i:04d}", "sample_id": f"s:{i}", "anomaly_score": 0.2 + i * 1e-4, "threshold": 0.0614,
                           "detected": True, "xai_evidence": ANALYSIS["top_features"], "retrieved_techniques": MITRE["techniques"],
                           "retrieval_query": "q", "verification_result": "VERIFIED", "verification_confidence": 1.0,
                           "_family": family, "_attack_label": family, "_simulator_attack": family != "Benign"})
            i += 1
        stream.append({**stream[-1], "alert_id": f"un{i:04d}", "detected": False}); i += 1      # unflagged rows are ignored
    return stream


class MeasurementScriptTests(unittest.TestCase):
    def test_sampling_is_stratified_deterministic_and_disjoint(self):
        stream = synthetic_stream()
        a, b = measure.select(stream), measure.select(stream)
        self.assertEqual([x["alert_id"] for x in a["main"]], [x["alert_id"] for x in b["main"]])
        self.assertFalse({x["alert_id"] for x in a["pilot"]} & {x["alert_id"] for x in a["main"]})
        for phase in ("pilot", "main"):
            from collections import Counter
            self.assertEqual(dict(Counter(x["_family"] for x in a[phase])), measure.PLAN[phase])
            self.assertTrue(all(x["detected"] for x in a[phase]))
        self.assertEqual(len(a["pilot"]), 10); self.assertEqual(len(a["main"]), 100)

    def test_run_saves_raw_outputs_summarises_and_resumes(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        stream_path = Path(tmp.name) / "s.jsonl"
        stream_path.write_text("".join(json.dumps(x) + "\n" for x in synthetic_stream()), encoding="utf-8")
        report = {**good_report(), "evidence": ["Anomaly score is high.", "The threshold was exceeded."]}   # cites no score: REJECTED
        fake = FakeOllama(["garbage", json.dumps(report)]); self.addCleanup(fake.close)   # first alert: retry, then a report
        # After the queue, the fake returns good_report() with ANALYSIS's score, which is not these alerts' score.
        with patch.object(measure, "feature_names", return_value=ANALYSIS["all_feature_names"]):
            measure.main(["--phase", "pilot", "--stream", str(stream_path), "--out", tmp.name, "--host", fake.host,
                          "--model", "fake:1b", "--limit", "3"])
        out = Path(tmp.name) / "pilot_fake_1b"
        raws = sorted((out / "raw").glob("*.json"))
        self.assertEqual(len(raws), 3)
        first = next(r for r in (json.loads(p.read_text()) for p in raws) if r["raw_outputs"][0] == "garbage")
        self.assertEqual(len(first["raw_outputs"]), 2)                 # both raw outputs kept
        self.assertIn("prompt_messages", first)
        summary = json.loads((out / "summary.json").read_text())
        self.assertEqual(summary["alerts_completed"], 3)
        self.assertEqual(summary["parsing"]["retry_succeeded"], 1)
        self.assertEqual(summary["parsing"]["first_attempt_invalid"], 1)
        self.assertEqual(summary["parsing"]["timeouts"], 0)
        self.assertEqual(sum(summary["verdicts"].values()), 3)
        self.assertEqual(summary["model_info"]["digest"], "abc123")
        self.assertIn("detector_score", summary["failed_check_counts"])
        g = summary["gate"]
        self.assertEqual(g["false_positives_reaching_automation_without_gate"], g["benign_alerts"])
        n_before = len(fake.requests)
        with patch.object(measure, "feature_names", return_value=ANALYSIS["all_feature_names"]):
            measure.main(["--phase", "pilot", "--stream", str(stream_path), "--out", tmp.name, "--host", fake.host,
                          "--model", "fake:1b", "--limit", "3"])
        self.assertEqual(len(fake.requests), n_before)                 # resumed: no alert re-sent

    def test_pilot0_alert_is_never_in_the_main_set(self):
        stream = synthetic_stream()
        benign_ids = sorted(a["alert_id"] for a in stream if a["_family"] == "Benign" and a["detected"])
        with patch.object(measure, "SEEN_BEFORE_MAIN", frozenset(benign_ids[:5])):
            chosen = measure.select(stream)
        self.assertFalse(set(benign_ids[:5]) & {a["alert_id"] for a in chosen["main"]})
        self.assertIn("7b4cbfff-746d-54af-ab94-f43232d90c78", measure.SEEN_BEFORE_MAIN)
        self.assertEqual(measure.PHASE_SAMPLE["smoke"], "pilot")

    def test_timeouts_are_recorded_separately(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        stream_path = Path(tmp.name) / "s.jsonl"
        stream_path.write_text("".join(json.dumps(x) + "\n" for x in synthetic_stream()), encoding="utf-8")
        fake = FakeOllama([], delay=2.5); self.addCleanup(fake.close)
        with patch.object(measure, "feature_names", return_value=ANALYSIS["all_feature_names"]):
            measure.main(["--phase", "smoke", "--stream", str(stream_path), "--out", tmp.name, "--host", fake.host,
                          "--model", "fake:1b", "--limit", "1", "--timeout", "1"])
        summary = json.loads((Path(tmp.name) / "smoke_fake_1b" / "summary.json").read_text())
        self.assertEqual(summary["verdicts"], {"TIMEOUT": 1})
        self.assertEqual(summary["parsing"]["timeouts"], 1)
        self.assertEqual(summary["gate"]["false_positives_reaching_automation_with_gate"], 0)

    def test_wilson_interval(self):
        lo, hi = measure.wilson(0, 30)
        self.assertEqual(lo, 0.0); self.assertGreater(hi, 0.05)
        lo, hi = measure.wilson(15, 30)
        self.assertLess(lo, 0.5); self.assertGreater(hi, 0.5)


if __name__ == "__main__":
    unittest.main()


class MainRunHelpers(unittest.TestCase):
    def rec(self, family, label, attack, text, verdict="VERIFIED", status="ok"):
        r = {"alert_id": f"{family}-{label}-{text}", "family": family, "attack_label": label, "is_attack": attack,
             "status": status, "verdict": verdict}
        if status == "ok": r["reasoning"] = {"report": {"attack_context": text}}
        return r

    def test_technique_relevance_classes(self):
        recs = [self.rec("Web-Based", "SqlInjection", True, "maybe T1499.001"),      # flood technique for SQLi: irrelevant
                self.rec("DDoS", "DDoS-SYN_Flood", True, "maybe T1498"),             # relevant
                self.rec("Recon", "Recon-PortScan", True, "none retrieved"),
                self.rec("Benign", "BenignTraffic", False, "T1499"),
                self.rec("Benign", "BenignTraffic", False, "none"),
                self.rec("DoS", "DoS-UDP_Flood", True, "", verdict="TIMEOUT", status="timeout")]
        t = measure.technique_relevance(recs)["total"]
        self.assertEqual((t["irrelevant"], t["relevant"], t["none"]), (1, 1, 1))
        self.assertEqual((t["benign_cites_technique"], t["benign_none"], t["no_report"]), (1, 1, 1))
        self.assertEqual(t["faithful_but_wrong"], 2)

    def test_round_robin_keeps_membership_and_interleaves(self):
        alerts = [{"_family": f, "alert_id": f + str(i)} for f in ("Benign", "DDoS", "Mirai") for i in range(3)]
        rr = measure.round_robin(alerts)
        self.assertEqual(sorted(a["alert_id"] for a in rr), sorted(a["alert_id"] for a in alerts))
        self.assertEqual([a["_family"] for a in rr[:3]], ["Benign", "DDoS", "Mirai"])

    def test_human_check_sample_is_seeded(self):
        recs = [self.rec("DDoS", "x", True, str(i)) for i in range(50)]
        self.assertEqual(measure.human_check_sample(recs), measure.human_check_sample(recs))
        self.assertEqual(len(measure.human_check_sample(recs)), 30)
