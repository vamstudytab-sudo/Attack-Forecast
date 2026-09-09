# Verified test results

This build was tested against the supplied `GeneratedLabelledFlows (2).zip` content and against the folder-upload API using real CICIDS2017 CSV rows.

## Full supplied archive analysis

Deterministic analysis completed successfully with:

- 17,807 processed flow samples
- 3,117 observed IP/host nodes
- 5,232 aggregated Source IP → Destination IP relationships
- 261 timeline entries
- 4 full-network overview groups
- current state: Credential Access
- next-stage forecast: Lateral Movement
- forecast confidence: 76% (transition/context score)
- network risk: 71.2 / 100 (High)
- predicted next target: `192.168.10.3`

These counts are outputs of the included deterministic sampling configuration and may change if the sampling constants are changed.

## Folder API smoke test

`POST /api/upload-folder` was tested with four real CICIDS CSV extracts sent as separate multipart files with their relative folder paths. The endpoint returned HTTP 200 and rebuilt:

- dataset state
- graph
- timeline
- model detections
- risk
- forecast
- chat retrieval context

## Static/runtime checks

- all Python backend files compile successfully
- frontend JavaScript passes `node --check`
- all JavaScript DOM IDs referenced by the app exist in `index.html`
- `/api/health`, `/api/graph`, `/api/timeline`, `/api/chat` and folder-upload processing were exercised

The main user workflow remains: run `python run.py`, open `http://127.0.0.1:8000`, then choose **Upload Dataset Folder**.
