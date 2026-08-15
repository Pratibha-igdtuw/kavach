# KAVACH — Detect Module ("The Sentinel Eye")

Real-time cross-sector anomaly detection dashboard prototype.

## Run locally
```
pip install -r requirements.txt
python3 app.py
```
Then open http://localhost:5000

## What it does
- `simulator.py` generates synthetic telemetry (network traffic, failed logins,
  CPU usage, data egress, active connections) for 3 sectors: Hospital, Power Grid, Bank.
  It occasionally injects attack-like spikes.
- `detector.py` trains an IsolationForest per sector on normal baseline behavior,
  scores incoming readings in real time, and converts model output into a 0-100
  risk score + identifies the top contributing metric (explainability).
- `app.py` runs the simulate-detect loop in a background thread and pushes
  updates over Socket.IO every 2 seconds. It also models cross-sector
  dependencies (Power Grid / Bank attacks raise Hospital's risk) — this is
  the "Siege Map" propagation logic, the core idea from the KAVACH proposal
  that one system's compromise cascades into another's.
- The dashboard (`templates/index.html`, `static/`) shows live risk gauges,
  a siege map that lights up red when an attack propagates between sectors,
  and a scrolling anomaly log.

## Next steps to extend
- Swap simulator.py for a real data source (SIEM logs, network flow data).
- Persist anomaly log to a database instead of in-memory list.
- Add auth + the Predict/Contain/Recover modules as separate services.
