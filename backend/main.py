from __future__ import annotations

import logging
import uuid
import subprocess
import sys
import threading
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from services.model_service import Detector
from services.mitre_service import MitreService
from services.sample_service import SampleService
from services.llm_service import llm_status, reason
from schemas.analysis import AnalysisRequest
from schemas.response import ApprovalRequest, FeedbackRequest
from security import require_operator
from services.bandit_service import BanditService
from services.verification_service import verify_record
from services.live_service import DEMO_FILE, LiveReplay
from services.llm_service import template_report
from schemas.live import LiveStepRequest

ROOT = Path(__file__).resolve().parents[1]
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
services: dict = {}
replay_process = None
replay_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    detector = Detector(ROOT)
    services.update(detector=detector, samples=SampleService(ROOT, detector.features), mitre=MitreService(ROOT),
                    bandit=BanditService(ROOT / "backend" / "data" / "zeroshield_ledger.sqlite3"),
                    live=LiveReplay(DEMO_FILE, detector.features),
                    live_bandit=BanditService(ROOT / "backend" / "data" / "live_demo_ledger.sqlite3"))
    yield


app = FastAPI(title="ZeroShield AI", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
def health():
    d = services.get("detector")
    if not d or not d.loaded:
        return {"status": "degraded", "model": "Deep SVDD", "threshold": None, "features": None}
    return {"status": "ok", "model": "Deep SVDD", "threshold": d.threshold, "features": len(d.features)}


@app.get("/api/model-info")
def model_info():
    d = services["detector"]
    return {"model": "Deep SVDD", "architecture": {"input": len(d.features), "hidden": d.hidden, "latent": d.latent_dim}, "feature_count": len(d.features), "features": d.features, "threshold": d.threshold, "model_loaded": d.loaded, "scaler_loaded": False, "preprocessing": "Input must use the project's existing StandardScaler-prepared feature space; no scaler artifact was present.", "xai_available": d.loaded, "mitre_available": services["mitre"].available, "mitre_behavior_index_available": services["mitre"].index is not None, "llm_status": llm_status(), "response_actions": ["AUTO_REMEDIATE", "CONFIRM_TO_ACT", "HUMAN_REVIEW", "MONITOR_ONLY"]}


@app.get("/api/demo-samples")
def demo_samples():
    return services["samples"].available()


ATTACK_MODES = ("default", "guarded", "gated")


def retrieve_context(result: dict, attack_mode: str = "default") -> dict:
    """ATT&CK context. 'default' is the published retrieval (unchanged). 'guarded' adds amendment 12's frozen
    scan/spoofing mapping with the v2 filter; 'gated' additionally withholds context below amendment 15's frozen
    score gate. Both options are off unless the live monitor asks for them."""
    mitre = services["mitre"]
    if attack_mode == "default":
        return mitre.retrieve_behavior(result)
    from services import technique_plausibility as tp
    mapping = mitre.retrieve_behavior(result, behaviour_mapping=True, mapping_variant=tp.A12_FROZEN_VARIANT)
    mapping["attack_mode"] = attack_mode
    if attack_mode == "gated":
        gate = tp.A15_GATES[tp.A15_FROZEN_GATE]
        mapping["score_gate"] = {"gate": tp.A15_FROZEN_GATE, "minimum_score": gate * result["threshold"]}
        if not tp.passes_score_gate(result["anomaly_score"], result["threshold"], gate):
            mapping.update(techniques=[], status="withheld_low_score",
                           message="Score below the context gate: no ATT&CK technique is shown for this alert.")
    return mapping


def analyze(features: dict[str, float], label: str | None = None, *, bandit=None, reasoner=None,
            attack_mode: str = "default"):
    d = services["detector"]
    bandit = bandit or services["bandit"]
    reasoner = reasoner or reason
    if not d.loaded:
        raise HTTPException(503, "Deep SVDD model is unavailable. Check backend logs and model file.")
    if len(features) != len(d.features) or set(features) != set(d.features):
        missing = [x for x in d.features if x not in features]
        extra = [x for x in features if x not in d.features]
        raise HTTPException(422, {"message": "Expected exactly the 43 project features.", "missing": missing, "extra": extra})
    try:
        result = d.analyze(features)
        mapping = retrieve_context(result, attack_mode)
        reasoning = reasoner(result, None, mapping)
        verification = verify_record({**result, "feature_names": [x["feature"] for x in result["top_features"]], "all_feature_names": [x["feature"] for x in result["all_contributions"]]}, mapping, reasoning)
        alert_id = str(uuid.uuid4())
        alert = {"alert_id": alert_id, "sample_id": label or "user_input", "timestamp": datetime.now(timezone.utc).isoformat(),
                 "feature_summary": {x["feature"]: x["value"] for x in result["top_features"]},
                 "anomaly_score": result["anomaly_score"], "threshold": result["threshold"], "detected": result["detected"],
                 "xai_evidence": result["top_features"], "retrieval_query": mapping.get("query"), "retrieved_techniques": mapping.get("techniques", []),
                 "llm_explanation": reasoning, "verification_result": verification["verdict"],
                 "verification_checks": verification["checks"], "verification_confidence": verification["verification_confidence"]}
        # A flow below the threshold is not an alert: nothing is proposed, nothing is recorded, and the policy does not learn from it.
        # No response policy runs on a failed/uncertain Stage 6 record either.
        if not result["detected"]:
            bandit_record = {"selected_action": "MONITOR_ONLY", "policy_version": "no-alert-v1",
                             "action_scores": {}, "context_features": {}, "selection_mode": "no alert raised",
                             "reason": "The detector did not flag this flow, so no alert was raised and no response is proposed.",
                             "approval_status": "NOT_REQUIRED", "simulated_execution_status": "NOT_EXECUTED_NO_ALERT",
                             "observed_outcome": None, "reward": None, "policy_update_status": "NOT_ELIGIBLE"}
        elif verification["verdict"] == "VERIFIED":
            bandit_record = bandit.record(alert)
        else:
            bandit_record = {"selected_action": "HUMAN_REVIEW", "policy_version": "safety-fallback-v1",
                             "action_scores": {}, "context_features": {}, "selection_mode": "verification safety fallback",
                             "reason": "Stage 6 did not verify this alert; response selection is restricted to human review.",
                             "approval_status": "NOT_REQUIRED", "simulated_execution_status": "NOT_EXECUTED_UNVERIFIED",
                             "observed_outcome": None, "reward": None, "policy_update_status": "NOT_ELIGIBLE"}
        result.update(alert_id=alert_id, attack_family=label, mitre=mapping, reasoning=reasoning,
                      verification=verification, bandit=bandit_record)
        return result
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except Exception:
        logging.exception("Analysis failed")
        raise HTTPException(500, "Analysis failed. See backend terminal for details.")


@app.post("/api/analyze")
def analyze_request(request: AnalysisRequest):
    return analyze(request.features, request.attack_family)


@app.post("/api/analyze-csv")
async def analyze_csv(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(415, "Upload a CSV file.")
    try:
        import pandas as pd
        frame = pd.read_csv(file.file, nrows=2)
        d = services["detector"]
        if len(frame) != 1:
            raise HTTPException(422, "CSV must contain exactly one flow row.")
        result = analyze({name: float(frame.iloc[0][name]) for name in d.features if name in frame.columns})
        return result
    except HTTPException:
        raise
    except Exception:
        logging.exception("CSV analysis failed")
        raise HTTPException(422, "CSV must contain one row with all 43 named feature columns and numeric values.")


@app.get("/api/response/alerts")
def response_alerts():
    return {"alerts": services["bandit"].list_alerts()}


@app.get("/api/response/approvals")
def response_approvals():
    return {"pending": [x for x in services["bandit"].list_alerts() if x.get("approval_status") == "PENDING"]}


@app.post("/api/response/approval/{alert_id}", dependencies=[Depends(require_operator)])
def response_approval(alert_id: str, payload: ApprovalRequest):
    try:
        return services["bandit"].decide_approval(alert_id, payload.choice)
    except KeyError as exc:
        raise HTTPException(404, "Alert not found.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/response/feedback/{alert_id}", dependencies=[Depends(require_operator)])
def response_feedback(alert_id: str, payload: FeedbackRequest):
    try:
        return services["bandit"].feedback(alert_id, payload.ground_truth_attack, payload.reviewer_choice)
    except KeyError as exc:
        raise HTTPException(404, "Alert not found.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/response/reset-policy", dependencies=[Depends(require_operator)])
def reset_policy():
    services["bandit"].reset_policy()
    return {"status": "policy_reset", "policy_version": "linucb-v1", "ledger_preserved": True}


@app.get("/api/response/experiment")
def response_experiment():
    root = ROOT / "backend" / "experiments" / "contextual_bandit_replay_v1"
    runs = sorted((p for p in root.glob("run_*") if p.is_dir()), key=lambda p: p.name, reverse=True) if root.exists() else []
    for run in runs:
        metrics = run / "policy_comparison_metrics.json"
        if metrics.exists():
            import json
            return {"status": "completed", "run_id": run.name,
                    "summary_path": str(run / "summary.md"), "metrics": json.loads(metrics.read_text(encoding="utf-8"))}
    return {"status": "not_run", "metrics": None}


@app.get("/api/response/experiment/{plot_name}.svg")
def response_experiment_plot(plot_name: str):
    if plot_name not in ("learning_curve", "action_distribution"):
        raise HTTPException(404, "Unknown experiment plot.")
    root = ROOT / "backend" / "experiments" / "contextual_bandit_replay_v1"
    runs = sorted((p for p in root.glob("run_*") if p.is_dir()), key=lambda p: p.name, reverse=True) if root.exists() else []
    for run in runs:
        path = run / f"{plot_name}.svg"
        if path.exists(): return FileResponse(path, media_type="image/svg+xml")
    raise HTTPException(404, "No completed replay plot is available.")


@app.post("/api/response/replay/start", dependencies=[Depends(require_operator)])
def start_response_replay():
    global replay_process
    with replay_lock:
        if replay_process is not None and replay_process.poll() is None:
            raise HTTPException(409, "A replay job is already running.")
        log_path = ROOT / "backend" / "experiments" / "replay_job.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("ab") as log:
            replay_process = subprocess.Popen([sys.executable, "run_response_experiment.py"],
                cwd=ROOT / "backend", stdout=log, stderr=subprocess.STDOUT)
        return {"status": "running", "pid": replay_process.pid, "log": str(log_path)}


@app.get("/api/response/replay/status")
def response_replay_status():
    process = replay_process
    if process is None: return {"status": "idle"}
    code = process.poll()
    return {"status": "running" if code is None else "completed" if code == 0 else "failed", "exit_code": code}


# ------------------------------------------------------------------ live monitor (recorded-flow replay)
def _template_reasoner(result, _family, mitre):
    return template_report(result, mitre)


@app.get("/api/live/status")
def live_status():
    live = services.get("live")
    if live is None:
        return {"available": False, "error": "Live replay service not started."}
    from services import technique_plausibility as tp
    return {**live.status(), "llm_status": llm_status(), "attack_modes": list(ATTACK_MODES),
            "guarded_variant": tp.A12_FROZEN_VARIANT, "score_gate": tp.A15_FROZEN_GATE,
            "policy_updates": services["live_bandit"].updates}


@app.post("/api/live/next", dependencies=[Depends(require_operator)])
def live_next(payload: LiveStepRequest):
    live = services.get("live")
    if live is None or not live.available:
        raise HTTPException(503, (live.error if live else None) or "No demo traffic loaded. Run: python build_live_demo.py")
    count = max(1, min(int(payload.count), 50))
    reasoner = None if payload.report == "configured" else _template_reasoner
    out = []
    for _ in range(count):
        index, features, truth = live.next()
        # The label is never passed to the pipeline; it is attached only after the decision below.
        result = analyze(features, None, bandit=services["live_bandit"], reasoner=reasoner, attack_mode=payload.attack_mode)
        is_attack = truth["family"] != "Benign"
        feedback = None
        record = result.get("bandit") or {}
        if payload.learn and result["detected"] and record.get("policy_update_status") == "WAITING_FOR_FEEDBACK":
            reviewer = ("APPROVED" if is_attack else "REJECTED") if record.get("selected_action") == "CONFIRM_TO_ACT" else None
            updated = services["live_bandit"].feedback(result["alert_id"], is_attack, reviewer)
            result["bandit"] = updated
            feedback = {"source": "simulated analyst: dataset label applied after the action was chosen",
                        "reviewer_choice": reviewer, "reward": updated.get("reward"),
                        "observed_outcome": updated.get("observed_outcome")}
        result.update(replay_index=index, ground_truth={**truth, "is_attack": is_attack}, simulated_feedback=feedback)
        out.append(result)
    return {"results": out, "cursor": live.cursor, "total": live.status()["total"],
            "policy_updates": services["live_bandit"].updates}


@app.post("/api/live/reset", dependencies=[Depends(require_operator)])
def live_reset(reset_policy: bool = False):
    live = services.get("live")
    if live is None:
        raise HTTPException(503, "Live replay service not started.")
    live.reset()
    if reset_policy:
        services["live_bandit"].reset_policy()
    return {"cursor": live.cursor, "policy_reset": reset_policy, "policy_updates": services["live_bandit"].updates}
