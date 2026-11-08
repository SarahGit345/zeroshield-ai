"""Stage 5 reasoning: an evidence-bound incident report, from an LLM or a labelled template.

Provider selection (environment):
  ZEROSHIELD_LLM_PROVIDER = "ollama" | "openai" | "template"   (default: openai if OPENAI_API_KEY is set, else template)
  Ollama:  OLLAMA_HOST (default http://127.0.0.1:11434), OLLAMA_MODEL (default qwen3:8b),
           ZEROSHIELD_LLM_SEED (default 20261108), ZEROSHIELD_LLM_TIMEOUT seconds (default 900),
           OLLAMA_NUM_CTX (default 8192)
  OpenAI:  OPENAI_API_KEY, OPENAI_MODEL (default gpt-4o-mini)

The Ollama path asks for JSON constrained by REPORT_SCHEMA, temperature 0 and a fixed seed, with the
meaning of every field restated in the prompt. The reply is parsed; if parsing fails a light repair is
tried (code fences, text around the JSON object, a single string where a list is expected); if that
still fails the model is asked once more with the error. If both attempts fail, the labelled template
is returned with `llm_error` set, so a failed LLM call is never presented as LLM reasoning.
The reasoning mode names the real model, e.g. "Ollama LLM (qwen3:8b)".
"""
import json
import logging
import os
import re
import urllib.request

FIELDS = ("incident_summary", "evidence", "attack_context", "interpretation", "recommended_action", "limitations")
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_summary": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "attack_context": {"type": "string"},
        "interpretation": {"type": "string"},
        "recommended_action": {"type": "string"},
        "limitations": {"type": "string"},
    },
    "required": list(FIELDS),
}
DEFAULT_OLLAMA_MODEL = "qwen3:8b"
DEFAULT_SEED = 20261108

SYSTEM_PROMPT = """You are an evidence-bound SOC analyst writing a short incident report about one network flow.
Use ONLY the JSON evidence you are given. Do not invent evidence, scores, attack labels, features, MITRE techniques,
IP addresses, ports, hosts, dates or URLs. Distinguish observation from interpretation and state uncertainty.
Nothing has been done about this flow yet: never say that it was blocked, isolated, remediated or investigated.

Meaning of the evidence fields:
- detected: true if the Deep SVDD detector's anomaly_score is at or above threshold (the flow was flagged as anomalous), false otherwise.
- anomaly_score: the detector's distance from its learned benign centre. Quote it exactly as given, with all digits.
- threshold: the frozen detector threshold. Quote it exactly as given.
- top_features: the 10 features whose replacement by 0 (in the prepared, scaled feature space) changed the score most.
  feature = feature name; value = the flow's prepared (scaled) value; contribution = score minus the score with that
  feature replaced by 0 (positive: the feature pushed the score up; negative: it pushed the score down); rank = 1 is largest.
- attack_family: a dataset label if one was supplied, otherwise null. The detector does not infer it.
- mitre_candidates: ATT&CK techniques retrieved by text similarity from the feature behaviour. They are context
  suggestions, not confirmed classifications. Mention a technique ID only if it appears here; it may be empty.

Return one JSON object with exactly these fields:
- incident_summary (string): one or two sentences on what the detector decided for this flow.
- evidence (array of strings): observations copied from the evidence, including the exact anomaly_score and threshold
  and the top contributing features with their contributions.
- attack_context (string): what the retrieved ATT&CK candidates might suggest, hedged; say if there are none.
- interpretation (string): what the evidence may and may not mean; flow statistics alone cannot confirm an attack.
- recommended_action (string): a proposed next step for an analyst, phrased as a recommendation.
- limitations (string): the uncertainty and limits of this evidence."""


def provider() -> str:
    chosen = os.getenv("ZEROSHIELD_LLM_PROVIDER", "").strip().lower()
    if chosen in {"ollama", "openai", "template"}: return chosen
    return "openai" if os.getenv("OPENAI_API_KEY") else "template"


def llm_status() -> str:
    p = provider()
    if p == "ollama": return f"Ollama configured ({os.getenv('OLLAMA_MODEL', DEFAULT_OLLAMA_MODEL)})"
    if p == "openai": return f"OpenAI configured ({os.getenv('OPENAI_MODEL', 'gpt-4o-mini')})"
    return "Demo Fallback Reasoning"


def evidence_payload(result, family, mitre) -> dict:
    return {"detected": result["detected"], "anomaly_score": result["anomaly_score"], "threshold": result["threshold"],
            "top_features": result["top_features"], "attack_family": family, "mitre_candidates": mitre.get("techniques", [])}


def template_report(result, mitre) -> dict:
    state = "exceeded" if result["detected"] else "did not exceed"
    return {"mode": "Demo Fallback Reasoning", "report": {"incident_summary": f"The observed flow score {state} the configured Deep SVDD threshold.", "evidence": [f"Score {result['anomaly_score']:.6f}; threshold {result['threshold']:.6f}."] + [f"{x['feature']} contributed {x['contribution']:.6f}." for x in result["top_features"][:3]], "attack_context": mitre.get("message", "Insufficient evidence for a confident ATT&CK mapping."), "interpretation": "This is a flow-level anomaly result; it does not establish the underlying application or host behavior.", "recommended_action": "Correlate this flow with device, endpoint, and adjacent network telemetry." if result["detected"] else "Continue monitoring and correlate with surrounding flows.", "limitations": "Feature perturbation describes model score sensitivity. Dataset family labels, when present, are context and not inferred by Deep SVDD."}}


# ---------------------------------------------------------------- parsing
class ReportError(ValueError):
    """args: (message, raw_outputs, parse_errors) when raised after both attempts."""


def _validate(obj) -> dict:
    if not isinstance(obj, dict): raise ReportError("top-level value is not a JSON object")
    missing = [f for f in FIELDS if f not in obj]
    if missing: raise ReportError(f"missing fields: {', '.join(missing)}")
    report = {}
    for f in FIELDS:
        value = obj[f]
        if f == "evidence":
            if isinstance(value, str): value = [value]                     # repair: single string -> list
            if not isinstance(value, list) or not all(isinstance(v, (str, int, float)) for v in value):
                raise ReportError("evidence must be a list of strings")
            value = [str(v) for v in value]
        elif not isinstance(value, str):
            raise ReportError(f"{f} must be a string")
        report[f] = value
    return report


def parse_report(text: str) -> tuple[dict, bool]:
    """Return (report, repaired). Raises ReportError if no valid report can be recovered."""
    try:
        obj = json.loads(text)
        return _validate(obj), isinstance(obj, dict) and isinstance(obj.get("evidence"), str)
    except json.JSONDecodeError:
        pass
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    cleaned = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", cleaned.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start: raise ReportError("no JSON object found in the reply")
    try:
        obj = json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON: {exc}") from exc
    return _validate(obj), True


# ---------------------------------------------------------------- Ollama
def _ollama_chat(host, payload, timeout):
    request = urllib.request.Request(host.rstrip("/") + "/api/chat", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def ollama_reason(result, family, mitre, *, host=None, model=None, seed=None, timeout=None) -> dict:
    host = host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    if not host.startswith("http"): host = "http://" + host
    model = model or os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    seed = int(seed if seed is not None else os.getenv("ZEROSHIELD_LLM_SEED", DEFAULT_SEED))
    timeout = float(timeout or os.getenv("ZEROSHIELD_LLM_TIMEOUT", 900))
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(evidence_payload(result, family, mitre))}]
    options = {"temperature": 0, "seed": seed, "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", 8192))}
    raw_outputs, errors, timings = [], [], []
    for attempt in (1, 2):
        payload = {"model": model, "messages": messages, "stream": False, "format": REPORT_SCHEMA,
                   "options": options, "think": False}
        reply = _ollama_chat(host, payload, timeout)
        content = reply.get("message", {}).get("content", "")
        raw_outputs.append(content)
        timings.append({k: reply.get(k) for k in ("total_duration", "prompt_eval_count", "eval_count", "eval_duration")})
        try:
            report, repaired = parse_report(content)
            return {"mode": f"Ollama LLM ({model})", "report": report, "provider": "ollama", "model": model,
                    "seed": seed, "temperature": 0, "attempts": attempt, "repaired": repaired,
                    "raw_outputs": raw_outputs, "parse_errors": errors, "timings": timings}
        except ReportError as exc:
            errors.append(str(exc))
            messages = messages + [{"role": "assistant", "content": content},
                                   {"role": "user", "content": f"Your reply could not be used: {exc}. Return only one JSON object "
                                                               f"with exactly the fields {', '.join(FIELDS)}, as described."}]
    raise ReportError(f"no valid report after 2 attempts: {errors}", raw_outputs, errors)


# ---------------------------------------------------------------- entry point
def reason(result, family, mitre):
    p = provider()
    if p == "ollama":
        try:
            return ollama_reason(result, family, mitre)
        except Exception as exc:
            logging.exception("Ollama reasoning failed; using labelled fallback")
            out = template_report(result, mitre)
            out.update(llm_error=str(exc.args[0] if exc.args else exc), llm_provider="ollama",
                       llm_model=os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
                       raw_outputs=exc.args[1] if isinstance(exc, ReportError) and len(exc.args) > 1 else [])
            return out
    if p == "openai":
        try:
            from openai import OpenAI
            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            response = OpenAI().chat.completions.create(model=model, temperature=0, response_format={"type": "json_object"}, messages=[{"role": "system", "content": "You are an evidence-bound SOC analyst. DO NOT invent evidence, anomaly scores, attack labels, features, or MITRE techniques. Use only supplied evidence. Clearly distinguish observation from interpretation and state uncertainty. Return JSON fields: incident_summary, evidence, attack_context, interpretation, recommended_action, limitations."}, {"role": "user", "content": json.dumps(evidence_payload(result, family, mitre))}])
            return {"mode": f"OpenAI LLM ({model})", "report": json.loads(response.choices[0].message.content)}
        except Exception:
            logging.exception("Optional OpenAI reasoning failed; using labeled fallback")
    return template_report(result, mitre)
