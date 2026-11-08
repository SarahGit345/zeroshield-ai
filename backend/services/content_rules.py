"""Signature-based HTTP content check (plan amendment 3). A complementary layer, NOT zero-day detection.

The rules were written from general web-security knowledge (OWASP-style attack patterns) before any
CIC-IoT-2023 attack capture was parsed, and are frozen as RULESET_VERSION. Do not edit them after
seeing evaluation results; a change needs a new version name and a plan amendment.

Each rule matches the URL-decoded request line, query and body (case-insensitive). A hit reports the
rule, its category, an ATT&CK technique where one fits, and the matching snippet as evidence.
Technique mapping: SQL injection, command injection and path traversal -> T1190 (Exploit Public-Facing
Application); web-shell upload or web-shell code -> T1505.003 (Server Software Component: Web Shell);
cross-site scripting -> no confident technique (client-side; reported as a content hit only).
Known limits: plaintext HTTP only (TLS is unreadable); obfuscation beyond two rounds of URL decoding
is not handled; signatures catch known patterns, not new ones.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import unquote_plus

RULESET_VERSION = "content-rules-v1"
MAX_SCAN_CHARS = 65536
SNIPPET_CONTEXT = 40

_RULES = [
    # SQL injection
    ("sqli-union-select", "sql_injection", r"\bunion\b(?:\s|/\*.*?\*/)+(?:all(?:\s|/\*.*?\*/)+)?select\b"),
    ("sqli-tautology", "sql_injection", r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+"),
    ("sqli-numeric-tautology", "sql_injection", r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b"),
    ("sqli-comment-terminator", "sql_injection", r"['\"]\s*(?:--|#|/\*)"),
    ("sqli-stacked-query", "sql_injection", r";\s*(?:drop|delete|insert|update|alter|create)\s+(?:table|from|into|database)?\b"),
    ("sqli-time-function", "sql_injection", r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    ("sqli-schema-probe", "sql_injection", r"\binformation_schema\b|\bsysobjects\b|\bsqlite_master\b"),
    # Cross-site scripting
    ("xss-script-tag", "xss", r"<\s*/?\s*script\b"),
    ("xss-javascript-uri", "xss", r"javascript\s*:"),
    ("xss-event-handler", "xss", r"<[^>]*\bon(?:error|load|mouseover|click|focus|submit)\s*="),
    ("xss-cookie-access", "xss", r"document\s*\.\s*cookie"),
    ("xss-alert-call", "xss", r"\b(?:alert|prompt|confirm)\s*\(\s*['\"\d]"),
    # Command injection
    ("cmdi-separator-command", "command_injection",
     r"(?:[;&|`]|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|nslookup|ifconfig|ipconfig|net\s+user)\b"),
    ("cmdi-windows-shell", "command_injection", r"\bcmd(?:\.exe)?\s+/c\b|\bpowershell(?:\.exe)?\s+-"),
    # Path traversal
    ("traversal-dot-dot", "path_traversal", r"(?:\.\.[/\\]){2,}"),
    ("traversal-sensitive-file", "path_traversal", r"/etc/(?:passwd|shadow|hosts)\b|\b(?:boot|win)\.ini\b"),
    # Web shells and malicious uploads
    ("upload-executable-file", "web_shell", r"filename\s*=\s*\"?[^\"\r\n;]+\.(?:php\d?|phtml|jsp|jspx|asp|aspx|cgi|pl|sh|exe)\b"),
    ("webshell-code", "web_shell", r"\b(?:eval|assert|system|passthru|shell_exec|exec)\s*\(\s*\$_(?:get|post|request|cookie)\b"),
    ("webshell-encoded-eval", "web_shell", r"\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\("),
    ("webshell-known-names", "web_shell", r"\b(?:c99|r57|b374k|wso)(?:shell)?\.php\b"),
]
TECHNIQUES = {"sql_injection": "T1190", "command_injection": "T1190", "path_traversal": "T1190",
              "web_shell": "T1505.003", "xss": None}
RULES = tuple({"rule_id": rid, "category": cat, "pattern": pat, "technique": TECHNIQUES[cat]} for rid, cat, pat in _RULES)
_COMPILED = [(r, re.compile(r["pattern"], re.I | re.S)) for r in RULES]


def ruleset_sha256() -> str:
    """Fingerprint of the frozen rules; recorded with every evaluation."""
    return hashlib.sha256(json.dumps([RULESET_VERSION, RULES], sort_keys=True).encode()).hexdigest()


def normalise(text: str) -> str:
    """Two rounds of URL decoding ('+' as space), capped length."""
    text = (text or "")[:MAX_SCAN_CHARS]
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text: break
        text = decoded
    return text


def scan_request(method: str = "", uri: str = "", body: str = "", headers: dict | None = None) -> list[dict]:
    """All rule hits for one HTTP request. Headers are scanned only for Content-Disposition (uploads)."""
    parts = [f"{method} {normalise(uri)}", normalise(body)]
    if headers:
        parts.append(" ".join(f"{k}: {v}" for k, v in headers.items() if k.lower() == "content-disposition"))
    text = "\n".join(parts)
    hits = []
    for rule, pattern in _COMPILED:
        m = pattern.search(text)
        if m:
            lo, hi = max(0, m.start() - SNIPPET_CONTEXT), min(len(text), m.end() + SNIPPET_CONTEXT)
            hits.append({"rule_id": rule["rule_id"], "category": rule["category"], "technique": rule["technique"],
                         "snippet": text[lo:hi].replace("\n", " ")[:160]})
    return hits


def evidence_tier(flow_flagged: bool | None, hits: list) -> str:
    """Tiers, not probabilities: both layers agree, content only, flow only, or nothing."""
    if hits and flow_flagged: return "strong evidence (flow anomaly and content signature)"
    if hits: return "alert on content (signature only)"
    if flow_flagged: return "flow anomaly only"
    return "no alert"
