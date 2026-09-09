from __future__ import annotations

from collections import Counter
from pathlib import Path
import gzip
import json


def _node_to_json(node: dict) -> dict:
    out = dict(node)
    for key in ("out_peers", "in_peers", "connections", "behaviors"):
        out[key] = sorted(out.get(key, []))
    for key in ("ports", "protocols", "labels"):
        out[key] = dict(out.get(key, {}))
    return out


def _edge_to_json(edge: dict) -> dict:
    out = dict(edge)
    for key in ("ports", "protocols", "labels"):
        out[key] = dict(out.get(key, {}))
    return out


def save_snapshot(runtime, path: str | Path) -> None:
    path = Path(path)
    payload = {
        "version": 1,
        "dataset_name": runtime.dataset_name,
        "analysis_mode": runtime.analysis_mode,
        "processed_rows": runtime.processed_rows,
        "source_files": list(runtime.source_files),
        "timeline": runtime.timeline,
        "class_counts": dict(runtime.class_counts),
        "malicious_conf_sum": runtime.malicious_conf_sum,
        "malicious_conf_count": runtime.malicious_conf_count,
        "latest_detection": runtime.latest_detection,
        "flow_event_count": getattr(runtime, "flow_event_count", 0),
        "normal_timeline_count": getattr(runtime, "normal_timeline_count", 0),
        "unsupported_label_counts": dict(getattr(runtime, "unsupported_label_counts", {})),
        "last_forecast": runtime.last_forecast,
        "attack_state": runtime.attack_state.get_state(),
        "graph_nodes": [_node_to_json(n) for n in runtime.graph.nodes.values()],
        "graph_edges": [_edge_to_json(e) for e in runtime.graph.edges.values()],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))


def load_snapshot(runtime, path: str | Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False
    with gzip.open(path, "rt", encoding="utf-8") as f:
        payload = json.load(f)

    runtime.reset()
    runtime.dataset_name = payload.get("dataset_name")
    runtime.analysis_mode = payload.get("analysis_mode")
    runtime.processed_rows = int(payload.get("processed_rows", 0))
    runtime.source_files = list(payload.get("source_files", []))
    runtime.timeline = list(payload.get("timeline", []))
    runtime.seen_event_keys = set()
    runtime.class_counts = Counter(payload.get("class_counts", {}))
    runtime.malicious_conf_sum = float(payload.get("malicious_conf_sum", 0.0))
    runtime.malicious_conf_count = int(payload.get("malicious_conf_count", 0))
    runtime.latest_detection = payload.get("latest_detection")
    runtime.flow_event_count = int(payload.get("flow_event_count", 0))
    runtime.normal_timeline_count = int(payload.get("normal_timeline_count", 0))
    runtime.unsupported_label_counts = Counter(payload.get("unsupported_label_counts", {}))
    runtime.last_forecast = payload.get("last_forecast")

    state = payload.get("attack_state", {})
    runtime.attack_state.current_stage = state.get("current_stage", "NORMAL")
    runtime.attack_state.observed_stages = list(state.get("observed_stages", []))
    runtime.attack_state.history = list(state.get("history", []))
    runtime.attack_state.stage_counts = dict(state.get("stage_counts", {}))

    runtime.graph.nodes = {}
    for raw in payload.get("graph_nodes", []):
        node = dict(raw)
        for key in ("out_peers", "in_peers", "connections", "behaviors"):
            node[key] = set(node.get(key, []))
        for key in ("ports", "protocols", "labels"):
            # JSON object keys are strings; ports need to be integers for risk checks.
            if key == "ports":
                converted = {}
                for k, v in node.get(key, {}).items():
                    try:
                        k = int(k)
                    except Exception:
                        pass
                    converted[k] = v
                node[key] = Counter(converted)
            else:
                node[key] = Counter(node.get(key, {}))
        runtime.graph.nodes[node["id"]] = node

    runtime.graph.edges = {}
    for raw in payload.get("graph_edges", []):
        edge = dict(raw)
        for key in ("ports", "protocols", "labels"):
            if key == "ports":
                converted = {}
                for k, v in edge.get(key, {}).items():
                    try:
                        k = int(k)
                    except Exception:
                        pass
                    converted[k] = v
                edge[key] = Counter(converted)
            else:
                edge[key] = Counter(edge.get(key, {}))
        runtime.graph.edges[(edge["source"], edge["target"])] = edge

    runtime.replay_active = False
    runtime.replay_progress = 100
    return True
