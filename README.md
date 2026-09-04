# SET Watchtower

A small, working model of what a **Security Engineering Team** does day to day: keep the security
toolkit healthy (**Run**), react when something breaks (**Respond**), and triage incoming requests
so everything has an owner (**Triage**). Built as an interview portfolio piece for a Senior Security
Engineer role, using the exact toolset in the brief.

**Open `index.html` in a browser** (no install, no server). Try the buttons.

## Why this, for this role
The role is defined by three activities and a specific toolset. This project maps to all of them:

| Role responsibility | In SET Watchtower |
|---|---|
| **Run** — monitor the health of security tools, "keep the lights green" | Live health grid for Sentinel, Defender, Email Gateway, IDPS, Greenbone GVM, Malware Protection, Netskope, with green/amber/red status from heartbeat + ingestion rules |
| **Incident Response** — act on health alerts from the security infrastructure | "Simulate tool outage" raises a **P1 incident** when a control goes silent, because a SIEM that stops ingesting fails quietly |
| **Triage** — own the mailbox / Service Management intake queue | Intake queue with source, priority, and **auto-assign ownership** across the team |
| **Tune and enable policies** in response to incidents | `detections/detections.md`: Sentinel/Defender KQL with tuning notes for each rule |
| **DLP** track record | 4 dedicated **DLP** detections (personal-cloud upload, external email, mass SharePoint download, USB copy) |
| **MS Cloud Security** (Sentinel, Defender, E5) + **Netskope** | Tooling and detections written against that stack |

## What's in here
- `index.html` — the interactive console (runs offline; simulated telemetry, real health logic).
- `detections/detections.md` — 14 KQL analytic/hunting rules incl. 4 DLP and 2 tool-health, each with tuning notes.
- `simulate_telemetry.py` — sample telemetry generator; in production this is replaced by real tool health APIs and the intake queue. Run `python3 simulate_telemetry.py`.

## The point I would make in an interview
A blind security tool is worse than none, because it fails silently and everyone assumes they are
covered. Most detection work focuses on threats; **SET Watchtower focuses first on whether the
detections are even running**, then on responding and making sure nothing sits unowned. That is the
Run + Respond + Triage loop this team lives in.

## Not included on purpose
No real tenant data, credentials, or client information. Thresholds are starting points to tune
against a live environment.

Built by Mukul Mech.
