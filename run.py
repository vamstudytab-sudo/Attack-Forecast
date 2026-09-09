from __future__ import annotations

import threading
import webbrowser


def main() -> None:
    try:
        import uvicorn
        import fastapi  # noqa: F401
        import pandas  # noqa: F401
        import numpy  # noqa: F401
        import multipart  # noqa: F401
    except Exception as exc:
        print("\nMissing Python dependencies. Run:\n")
        print("    python -m pip install -r requirements.txt\n")
        print(f"Import error: {exc}\n")
        raise SystemExit(1)

    try:
        from backend.api.app import runtime, SNAPSHOT_LOADED
        graph = runtime.graph_payload()
        summary = runtime.summary_payload()
        print("\nAttackForecast startup self-test: OK")
        print(f"  Snapshot loaded : {SNAPSHOT_LOADED}")
        print(f"  Graph hosts     : {graph['summary']['total_nodes_in_dataset']}")
        print(f"  Relationships   : {graph['summary']['total_edges_in_dataset']}")
        print(f"  Timeline events : {len(runtime.timeline)}")
        print(f"  Current stage   : {summary['current_stage']}")
        if graph['summary']['total_nodes_in_dataset'] == 0:
            print("  Ready           : upload a GeneratedLabelledFlows folder in the dashboard")
    except Exception as exc:
        print("\nStartup self-test failed before the web server could start.")
        print(f"Reason: {exc}")
        raise

    print("\nONE server runs the dashboard + API")
    print("Dashboard : http://127.0.0.1:8000")
    print("API docs : http://127.0.0.1:8000/docs")
    print("Do NOT open port 5173/5175 for this build.")
    print("Press Ctrl+C to stop.\n")

    def open_browser():
        try:
            webbrowser.open("http://127.0.0.1:8000")
        except Exception:
            pass

    threading.Timer(1.0, open_browser).start()
    uvicorn.run("backend.api.app:app", host="127.0.0.1", port=8000, reload=False, log_level="info")


if __name__ == "__main__":
    main()
