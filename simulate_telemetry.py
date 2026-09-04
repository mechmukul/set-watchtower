#!/usr/bin/env python3
"""Generate sample security-tool health telemetry and an intake queue as JSON.

In production this would be replaced by real collectors (each tool's health API,
Sentinel `Usage`/`SentinelHealth`, and the Service Management queue). The dashboard
applies the same health rules to whatever feeds it. Run:  python3 simulate_telemetry.py
"""
import json
import random
from datetime import datetime, timezone

TOOLS = [
    ("Microsoft Sentinel", "SIEM"),
    ("Microsoft Defender", "Endpoint / XDR"),
    ("Email Gateway", "Mail security"),
    ("IDPS", "Intrusion detection"),
    ("Greenbone GVM", "Vulnerability mgmt"),
    ("Malware Protection", "Anti-malware"),
    ("Netskope", "SSE / DLP"),
]

# Health rules (kept identical to the dashboard so behaviour matches)
HEARTBEAT_RED_MINS = 10      # no heartbeat beyond this = SILENT
INGESTION_AMBER_DROP = 50    # ingestion drop % at/above this = DEGRADED


def health(hb_mins: int, drop_pct: int) -> str:
    if hb_mins > HEARTBEAT_RED_MINS:
        return "red"
    if drop_pct >= INGESTION_AMBER_DROP:
        return "amber"
    return "green"


def make_tools():
    out = []
    for name, cat in TOOLS:
        hb = random.choice([1, 1, 2, 2, 3, 4])          # mostly fresh
        drop = random.choice([0, 0, 0, 0, 15, 55])       # occasional degrade
        out.append({"name": name, "cat": cat, "hb": hb, "drop": drop,
                    "status": health(hb, drop)})
    return out


def make_queue():
    templates = [
        ("Service Mgmt Intake", "New starter access request for Security stack", 3),
        ("Engineering Mailbox", "Tune Email Gateway rule: supplier-domain false positives", 2),
        ("Sentinel", "Possible data exfiltration to personal cloud (DLP)", 1),
        ("Engineering Mailbox", "Enable new Defender ASR rule set for pilot group", 3),
        ("Service Mgmt Intake", "GVM scan schedule change for Derby site", 4),
    ]
    q = []
    for i, (src, txt, pri) in enumerate(random.sample(templates, k=4)):
        prefix = "INC" if src in ("Sentinel",) else "REQ"
        q.append({"id": f"{prefix}-{4000+i}", "src": src, "txt": txt,
                  "pri": pri, "owner": None})
    return q


if __name__ == "__main__":
    data = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tools": make_tools(),
        "queue": make_queue(),
    }
    print(json.dumps(data, indent=2))
