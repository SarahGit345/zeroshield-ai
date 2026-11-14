"""Technique plausibility rules (plan amendment 5; post hoc, `plausibility-rules-v1`).

Each ATT&CK technique family (root ID) lists the flow behaviours that could support it. A behaviour is a
(feature, "high" | "low") pair, observed under the behaviour ontology's own rule in mitre_service: the feature
pushed the score up (contribution > 0) and sits clearly outside the benign range (value >= +1 high, <= -1 low);
protocol indicators count only when present (high). The entries are written from what each ATT&CK technique
describes and what flow statistics can show; they are not fitted to dataset labels and have no threshold.

A technique with no entry is "not judged" (None) and is never removed or failed.
"""
from __future__ import annotations

RULES_VERSION = "plausibility-rules-v1"

_FLOOD = {("Rate", "high"), ("Drate", "high"), ("PacketDensity", "high"), ("Number", "high"), ("Weight", "high"),
          ("IAT", "low"), ("syn_flag_number", "high"), ("syn_count", "high"), ("SYNRatio", "high"),
          ("SYN_ACK_Ratio", "high"), ("psh_flag_number", "high"), ("ack_count", "high"), ("ack_flag_number", "high"),
          ("UDP", "high"), ("ICMP", "high"), ("Header_Length", "high")}
_WEB = {("HTTP", "high"), ("HTTPS", "high")}
_LOGIN = {("SSH", "high"), ("Telnet", "high"), ("HTTP", "high"), ("HTTPS", "high"), ("flow_duration", "low")}
_SCAN = {("rst_flag_number", "high"), ("rst_count", "high"), ("RSTRatio", "high"), ("syn_flag_number", "high"),
         ("syn_count", "high"), ("SYNRatio", "high"), ("SYN_ACK_Ratio", "high"), ("ICMP", "high"), ("ARP", "high"),
         ("flow_duration", "low"), ("fin_count", "high"), ("FINRatio", "high")}
_UNUSUAL_PROTOCOL = {("Protocol Type", "high"), ("Protocol Type", "low")}

SIGNATURES = {
    "T1498": _FLOOD,                       # Network Denial of Service: volumetric floods
    "T1499": _FLOOD,                       # Endpoint Denial of Service: exhaustion floods
    "T1110": _LOGIN,                       # Brute Force: repeated login attempts on remote-login or web services
    "T1046": _SCAN,                        # Network Service Discovery
    "T1595": _SCAN,                        # Active Scanning
    "T1018": _SCAN,                        # Remote System Discovery
    "T1590": _SCAN,                        # Gather Victim Network Information
    "T1557": {("ARP", "high"), ("DNS", "high"), ("DHCP", "high")},   # Adversary-in-the-Middle: ARP/DNS/DHCP spoofing
    "T1040": {("ARP", "high")},            # Network Sniffing: only visible on the wire through ARP poisoning
    "T1020": {("Weight", "high"), ("AVG", "high"), ("flow_duration", "high")},   # Automated Exfiltration: sustained large outbound data
    "T1132": _UNUSUAL_PROTOCOL | {("Std", "high")},                   # Data Encoding in C2
    "T1205": {("IAT", "high"), ("urg_count", "high"), ("ece_flag_number", "high"), ("cwr_flag_number", "high"),
              ("fin_count", "high"), ("rst_count", "high")},           # Traffic Signaling: port knocking, unusual flag patterns
    "T1571": _UNUSUAL_PROTOCOL,            # Non-Standard Port
    "T1071": _WEB | {("DNS", "high"), ("SMTP", "high"), ("IRC", "high")},   # Application Layer Protocol
    "T1190": _WEB,                         # Exploit Public-Facing Application
    "T1059": _WEB,                         # Command and Scripting Interpreter (via a web application)
    "T1505": _WEB,                         # Server Software Component (web shell)
    "T1185": _WEB,                         # Browser Session Hijacking
    "T1189": _WEB,                         # Drive-by Compromise
    "T1584": {("Telnet", "high"), ("IRC", "high")},                   # Compromise Infrastructure (botnet spread, C2)
}

HIGH_Z, LOW_Z = 1.0, -1.0   # same as mitre_service: "clearly outside the benign range"
PROTOCOLS = frozenset({"HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "DHCP", "ARP", "ICMP", "IPv", "TCP", "UDP"})


def observed_behaviours(top_features, top_n: int = 8) -> set:
    """(feature, direction) pairs that pushed the score up and sit clearly outside the benign range."""
    seen = set()
    for item in list(top_features)[:top_n]:
        if float(item.get("contribution", 0)) <= 0:
            continue
        value = float(item["value"])
        if value >= HIGH_Z:
            seen.add((item["feature"], "high"))
        elif value <= LOW_Z and item["feature"] not in PROTOCOLS:
            seen.add((item["feature"], "low"))
    return seen


def plausible(technique_id: str, top_features, rules: dict | None = None) -> bool | None:
    """True if an observed behaviour supports the technique, False if none does, None if the technique has no rule.
    rules defaults to v1 (SIGNATURES), so amendment 5 results stay reproducible."""
    signature = (SIGNATURES if rules is None else rules).get(str(technique_id).split(".")[0])
    if signature is None:
        return None
    return bool(signature & observed_behaviours(top_features))


# ---- v2 candidates (plan amendment 6): compared on the S58 tuning set only; every variant listed here is counted.
# Floods of non-TCP traffic (UDP, GRE, ICMP) and one-way floods have no handshakes and no replies, so they appear
# as ACK/SYN packets or inbound packets far BELOW the benign range ("no TCP acknowledgement one-way traffic").
_ONE_WAY = {("ack_flag_number", "low"), ("ack_count", "low"), ("ACKRatio", "low"), ("Drate", "low"), ("syn_count", "low")}
# Brute force against a login service can also run inside one sustained session: pauses between attempts,
# credentials pushed as application data, a long connection.
_SESSION_LOGIN = {("IAT", "high"), ("psh_flag_number", "high"), ("flow_duration", "high")}


def _with(base, **changes):
    rules = dict(base)
    for root, extra in changes.items():
        rules[root] = rules[root] | extra
    return rules


_V2A = _with(SIGNATURES, T1498=_ONE_WAY, T1499=_ONE_WAY)
V2_CANDIDATES = {
    "v2a one-way floods": _V2A,
    "v2b + session login": _with(_V2A, T1110=_SESSION_LOGIN),
    "v2c + session login without long flows": _with(_V2A, T1110=_SESSION_LOGIN - {("flow_duration", "high")}),
}

# ---- Frozen v2 (plan amendment 6): the candidate with the highest balanced accuracy on S58 (0.682 vs v1 0.493),
# chosen after 3 variants. Committed before S10 is evaluated.
RULES_VERSION_V2 = "plausibility-rules-v2"
SIGNATURES_V2 = V2_CANDIDATES["v2c + session login without long flows"]
