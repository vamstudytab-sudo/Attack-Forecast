from pathlib import Path
import asyncio
import shutil
import tempfile

import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.runtime.runtime_state import runtime
from backend.runtime.dataset_processor import analyze_path, analyze_paths
from backend.chat.rag_engine import answer_question
from backend.runtime.snapshot import load_snapshot

BASE_DIR = Path(__file__).resolve().parents[2]
DEMO_FILE = BASE_DIR / "data" / "demo" / "demo_replay.csv"
BUNDLED_FLOW_DATASET = BASE_DIR / "data" / "raw" / "GeneratedLabelledFlows.zip"
BUNDLED_SNAPSHOT = BASE_DIR / "data" / "processed" / "bundled_analysis_snapshot.json.gz"
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
UPLOAD_CHUNK_SIZE = 8 * 1024 * 1024
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024

app = FastAPI(
    title="AttackForecast API",
    description="Data-grounded CIC-IDS2017 network graph, detection, risk, forecast and SOC Copilot backend.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# This build starts with an empty analysis so every visible metric after upload
# belongs to the folder/CSV/ZIP selected by the user. A bundled snapshot can
# still be loaded only if one is intentionally placed in data/processed.
SNAPSHOT_LOADED = load_snapshot(runtime, BUNDLED_SNAPSHOT) if BUNDLED_SNAPSHOT.exists() else False


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    response_mode: str = Field(default="detailed", pattern="^(one_line|two_lines|detailed)$")
    selected_node: str | None = None
    selected_event: str | None = None


@app.get("/api")
def root():
    return {
        "message": "AttackForecast backend is running",
        "docs": "/docs",
        "status": runtime.status(),
    }


@app.get("/api/health")
def health():
    graph = runtime.graph_payload()
    return {
        "ok": True,
        "snapshot_loaded": SNAPSHOT_LOADED,
        "dataset": runtime.dataset_name,
        "hosts": graph.get("summary", {}).get("total_nodes_in_dataset", 0),
        "relationships": graph.get("summary", {}).get("total_edges_in_dataset", 0),
        "timeline_events": len(runtime.timeline),
        "chat_ready": True,
    }


@app.get("/api/status")
def status():
    return runtime.status()


@app.get("/api/summary")
def summary():
    return runtime.summary_payload()


@app.get("/api/detection")
def detection():
    return runtime.detection_payload()


@app.get("/api/graph")
def graph():
    return runtime.graph_payload()


@app.get("/api/timeline")
def timeline():
    return {"events": runtime.timeline}


@app.get("/api/forecast")
def forecast():
    return runtime.forecast()


@app.get("/api/risk")
def risk():
    return runtime.risk_payload()


@app.get("/api/node/{node_id}")
def node(node_id: str):
    detail = runtime.graph.get_node(node_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Node not found")
    return detail


@app.post("/api/chat")
def chat(request: ChatRequest):
    return answer_question(
        runtime,
        request.message,
        mode=request.response_mode,
        selected_node=request.selected_node,
        selected_event=request.selected_event,
    )


@app.post("/api/reset")
def reset():
    return runtime.reset()


@app.get("/api/datasets")
def datasets():
    return {
        "bundled_available": BUNDLED_SNAPSHOT.exists() or BUNDLED_FLOW_DATASET.exists(),
        "bundled_name": BUNDLED_FLOW_DATASET.name if BUNDLED_FLOW_DATASET.exists() else "bundled analysis snapshot",
        "bundled_size_bytes": BUNDLED_FLOW_DATASET.stat().st_size if BUNDLED_FLOW_DATASET.exists() else 0,
        "snapshot_loaded": SNAPSHOT_LOADED,
        "accepted_extensions": [".csv", ".zip", "folder of .csv files"],
        "folder_upload_endpoint": "/api/upload-folder",
    }


@app.post("/api/datasets/load-bundled")
async def load_bundled_dataset():
    # Prefer the verified snapshot generated from the user's supplied archive.
    # It contains the real graph, timeline, model detections, scores and forecast
    # and reloads in milliseconds.
    if BUNDLED_SNAPSHOT.exists():
        load_snapshot(runtime, BUNDLED_SNAPSHOT)
        return {
            "message": "Bundled real-data analysis loaded successfully",
            "dataset_name": runtime.dataset_name,
            "processed_rows": runtime.processed_rows,
            "source_files": runtime.source_files,
            "skipped_files": [],
            "graph_nodes": len(runtime.graph.nodes),
            "graph_edges": len(runtime.graph.edges),
            "current_stage": runtime.attack_state.current_stage,
            "forecast": runtime.forecast(),
            "risk": runtime.risk_payload(),
        }

    if not BUNDLED_FLOW_DATASET.exists():
        raise HTTPException(status_code=404, detail="Bundled dataset was not found.")
    try:
        result = await asyncio.to_thread(
            analyze_path, BUNDLED_FLOW_DATASET, "GeneratedLabelledFlows.zip (bundled)", True
        )
        return {"message": "Bundled dataset processed successfully", **result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/upload-folder")
async def upload_dataset_folder(
    files: list[UploadFile] = File(...),
    relative_paths: list[str] = Form(default=[]),
    folder_name: str = Form(default="Uploaded dataset folder"),
):
    """Analyze every uploaded CSV in a browser-selected folder as one session.

    The browser sends files selected using webkitdirectory. We preserve only the
    relative names for display; all server-side paths are generated safely.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files were selected.")

    csv_items = []
    ignored = []
    tmp_dir = Path(tempfile.mkdtemp(prefix="attackforecast_folder_"))
    total_bytes = 0

    try:
        for i, upload in enumerate(files):
            rel = relative_paths[i] if i < len(relative_paths) else (upload.filename or f"file-{i}")
            rel = str(rel).replace("\\", "/")
            display_name = rel or (upload.filename or f"file-{i}")
            suffix = Path(upload.filename or display_name).suffix.lower()
            if suffix != ".csv":
                ignored.append({"file": display_name, "reason": "Non-CSV file ignored"})
                try:
                    await upload.close()
                except Exception:
                    pass
                continue

            # Use a generated local filename rather than the untrusted relative
            # path. This prevents path traversal while preserving display_name.
            local_path = tmp_dir / f"{i:04d}.csv"
            with local_path.open("wb") as out:
                while True:
                    chunk = await upload.read(UPLOAD_CHUNK_SIZE)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > 4 * 1024 * 1024 * 1024:
                        raise HTTPException(
                            status_code=413,
                            detail="Folder is larger than the 4 GB prototype upload limit.",
                        )
                    out.write(chunk)
            try:
                await upload.close()
            except Exception:
                pass
            if local_path.stat().st_size > 0:
                csv_items.append((local_path, display_name))

        if not csv_items:
            raise HTTPException(status_code=400, detail="The selected folder contains no CSV files.")

        safe_folder_name = Path(str(folder_name).replace("\\", "/")).name or "Uploaded dataset folder"
        result = await asyncio.to_thread(analyze_paths, csv_items, safe_folder_name, True)
        if ignored:
            result["skipped_files"] = list(result.get("skipped_files", [])) + ignored
        return {
            "message": "Dataset folder uploaded and processed successfully",
            "uploaded_bytes": total_bytes,
            "files_received": len(files),
            "csv_files_received": len(csv_items),
            **result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        for upload in files:
            try:
                await upload.close()
            except Exception:
                pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/api/upload")
async def upload_dataset(file: UploadFile = File(...)):
    filename = Path(file.filename or "upload.csv").name
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".zip"}:
        raise HTTPException(status_code=400, detail="Upload a CSV or ZIP file.")

    tmp_dir = Path(tempfile.mkdtemp(prefix="attackforecast_"))
    tmp_path = tmp_dir / filename
    bytes_written = 0

    try:
        # Stream the browser upload to disk in chunks instead of reading the
        # entire CICIDS archive into RAM. This is intentionally tolerant of
        # large ZIPs such as GeneratedLabelledFlows.
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Dataset is larger than the 2 GB prototype upload limit.",
                    )
                out.write(chunk)

        if bytes_written == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")

        result = await asyncio.to_thread(analyze_path, tmp_path, filename, True)
        return {
            "message": "Dataset uploaded and processed successfully",
            "uploaded_bytes": bytes_written,
            **result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        try:
            await file.close()
        except Exception:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _run_demo_replay():
    runtime.reset()
    runtime.dataset_name = "CIC-IDS2017 evidence-grounded demo replay"
    runtime.analysis_mode = "curated replay of real labelled CICIDS2017 flows"
    runtime.replay_active = True

    df = pd.read_csv(DEMO_FILE, low_memory=False)
    df.columns = df.columns.str.strip()

    # This replay orders real labelled flow samples into a demonstration scenario.
    # The individual rows/metrics are real dataset records; the scenario ordering is curated.
    groups = [
        ("NORMAL", df[df["DemoCategory"] == "NORMAL"]),
        ("RECONNAISSANCE", df[df["DemoCategory"] == "RECONNAISSANCE"]),
        ("CREDENTIAL_ATTACK", df[df["DemoCategory"] == "CREDENTIAL_ATTACK"]),
    ]
    total = sum(len(group) for _, group in groups)
    processed = 0

    for label, group in groups:
        for start in range(0, len(group), 75):
            chunk = group.iloc[start:start + 75]
            runtime.process_sample(chunk, f"demo:{label}")
            processed += len(chunk)
            runtime.replay_progress = round(100 * processed / total)
            await asyncio.sleep(0.35)

    runtime.replay_active = False
    runtime.replay_progress = 100
    runtime.append_timeline(
        event="Evidence-grounded replay complete",
        severity="LOW",
        description=(
            "Replay used real CICIDS2017 flow rows. The scenario order is curated for demonstration; "
            "displayed hosts, ports, detections, confidence and risk metrics come from processed data/model output."
        ),
        event_type="system",
    )


@app.post("/api/replay/start")
async def start_replay():
    if runtime.replay_active:
        return {"message": "Replay already running", "status": runtime.status()}
    asyncio.create_task(_run_demo_replay())
    return {"message": "Demo replay started", "status": runtime.status()}


@app.post("/api/replay/reset")
def replay_reset():
    return runtime.reset()


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({
                "status": runtime.status(),
                "summary": runtime.summary_payload(),
                "risk": runtime.risk_payload(),
                "forecast": runtime.forecast(),
                "timeline": {"events": runtime.timeline[-30:]},
            })
            await asyncio.sleep(1)
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


# Serve the prebuilt React dashboard from the same FastAPI process.
# This removes the fragile two-server/CORS setup: the user runs one Python
# command and opens http://127.0.0.1:8000.
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def frontend_spa(full_path: str):
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.exists() and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
