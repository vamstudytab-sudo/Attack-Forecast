# AttackForecast — Folder-Driven SIH Prototype

A ready-to-run, one-server prototype for **AI-Based Network Attack Forecasting from Network Traffic Data**.

## What this build guarantees

After you upload a CICIDS-style **dataset folder**, the application rebuilds the current analysis from the uploaded files:

`Folder → CSV discovery → flow sampling → graph → timeline → ML detection → MITRE state → risk → forecast → SOC Copilot context`

The graph and event timeline are produced from the **same timestamp-ordered uploaded flow sample**. No fake process/file/registry/user entities are generated.

## Run in VS Code (Windows)

Open this folder in VS Code and run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

Open:

- Dashboard: `http://127.0.0.1:8000`
- API docs: `http://127.0.0.1:8000/docs`

There is **one server only**. Do not open ports 5173 or 5175.

## Main workflow

1. Click **Upload Dataset Folder**.
2. Select the folder containing CICIDS `GeneratedLabelledFlows` CSV files.
3. The browser sends the CSV files to the local FastAPI server.
4. The backend ignores non-CSV files and CSVs that do not contain `Source IP` + `Destination IP`.
5. Compatible CSVs are sampled deterministically to keep the SIH dashboard responsive.
6. Samples are sorted by `Timestamp` when available.
7. The same sampled rows generate the graph and timeline.
8. The Random Forest runs only when at least 90% of its 68 required features are present.
9. Risk, attack state, forecast, likely target, and Copilot retrieval context are rebuilt.

## Folder upload

The frontend uses browser folder selection (`webkitdirectory`, supported by Edge/Chrome). Nested relative file names are sent for display, while server-side files are stored using safe generated names.

API endpoint:

`POST /api/upload-folder`

The application also supports a single `.csv` or `.zip` via `POST /api/upload`.

## Graph views

- **Full overview** — the complete analyzed network, grouped by subnet/network so thousands of IPs fit inside one graph panel.
- **Host view** — highest-security-relevance exact IP nodes.
- **Attack path** — a small readable set of the highest-risk observed malicious relationships plus the predicted target edge.
- **Normal edges** — toggle benign relationships.
- **Fit graph** — restores the complete current view to the graph box.

Repeated Source IP → Destination IP flows are aggregated into one relationship.

## Scores

The dashboard keeps these separate:

- **Detection confidence** — Random Forest class probability for supported detections.
- **Network risk** — explainable derived 0–100 score.
- **Forecast confidence** — transition/context score for the MVP forecast.
- **Target risk** — graph-based ranking score, not a calibrated probability.

## Event timeline

Timeline rows are generated from uploaded flow evidence such as:

- Timestamp
- Source IP
- Destination IP
- destination port
- protocol
- dataset label
- model category/confidence when supported
- MITRE mapping when supported

Unsupported CICIDS attack labels remain visible as **dataset-labelled evidence** without inventing model confidence.

## SOC Copilot

The local Copilot retrieves from the current:

- graph
- timeline
- selected host/event
- risk breakdown
- model detections
- MITRE mappings
- attack state
- forecast
- predicted target

It supports **1 line / 2 lines / Detailed**, browser speech-to-text where supported, and browser text-to-speech.

It does not claim endpoint evidence (processes, files, registry keys, employees) that CICIDS flow data does not contain.

## Model scope

The included portable Random Forest currently supports:

- `NORMAL`
- `RECONNAISSANCE`
- `CREDENTIAL_ATTACK`

Mappings used by the prototype:

- Reconnaissance → `T1046 Network Service Scanning`
- Credential attack → `T1110 Brute Force`

The model is loaded from the included portable `models/random_forest_export.json`, avoiding a runtime scikit-learn/scipy dependency.

## Large-file behavior

The app does **not** load every row of every CICIDS CSV into browser memory. It uploads the files locally, then the backend retains the first 150 rows and every 100th flow (up to 10,000 sampled rows per CSV). This is a deterministic SIH-friendly analysis mode; the dashboard reports the number of analyzed samples and source files.

## Acceptance check

After folder upload, verify:

- backend remains online
- dataset name changes
- host/relationship counts are nonzero
- Full Overview shows the complete grouped graph
- Attack Path is readable
- Timeline contains uploaded flow timestamps/IPs
- detection confidence is visible where the model is supported
- network risk is visible
- forecast confidence is visible
- predicted target is an actual graph node
- clicking a host opens its real metrics/risk breakdown
- Chat and Timeline drawers resize the graph and Fit works
- Copilot answers questions using current dataset evidence
- Reset clears the analysis
