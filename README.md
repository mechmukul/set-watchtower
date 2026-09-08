# SET Watchtower

**▶ Live demo: https://mechmukul.github.io/set-watchtower/** (opens in your browser, nothing to install)

A working model of what a Security Engineering Team does day to day: keep the security toolkit
healthy (**Run**), react when something breaks (**Respond**), and triage incoming work so everything
has an owner (**Triage**).

![SET Watchtower screenshot](docs/screenshot.png)

## Try it live (30 seconds)
1. Open the live demo link above.
2. Watch the **health grid**: each security tool shows green / amber / red from heartbeat and ingestion rules (one tool starts "degraded" on purpose).
3. Click **Simulate tool outage** — a tool goes silent and a **P1 incident** is raised automatically.
4. Click **Auto-assign intake** — every unowned request in the queue gets an owner.
5. Click **Reset demo** to start over.

## What it does
- **Health grid** for the toolset a SET supports: Sentinel (SIEM), Defender, Email Gateway, IDPS, Greenbone GVM, malware protection, Netskope.
- **Incident queue** fed by the mailbox and Service Management intake, with priority and ownership.
- **Detection coverage** summary; full KQL (incl. 4 DLP rules) in [`detections/detections.md`](detections/detections.md).

## Why it matters
A blind security tool is worse than none, because it fails silently and everyone assumes they are
covered. Watchtower checks first whether the detections are even running, then helps respond and
make sure nothing sits unowned. That is the Run + Respond + Triage loop.

## Run locally
No build step. Clone and open `index.html`, or:
```bash
python3 -m http.server 8000   # then visit http://localhost:8000
```

## Notes
Demo uses simulated telemetry so it runs offline; a production build ingests each tool's health API
and the intake queue. No real data. Companion projects: **set-triage-atlas**, **gvm-triage**, **set-runbooks**.
