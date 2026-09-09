from collections import Counter
from datetime import datetime, timezone
from threading import RLock
import pandas as pd

from backend.ml.predictor import predict_dataframe, top_model_features
from backend.detection.mitre_mapper import map_to_mitre
from backend.state.attack_state import AttackState
from backend.graph.graph_builder import NetworkGraph
from backend.forecasting.forecast_engine import generate_forecast


DETECTION_THRESHOLD = 0.60

# CICIDS2017 labels covered by the current three-class detector. Other labelled
# attacks still contribute network relationships and timeline evidence, but they
# are not forced into Recon/Credential classes or MITRE mappings.
MODEL_SUPPORTED_LABELS = {
    "BENIGN",
    "PORTSCAN",
    "FTP-PATATOR",
    "SSH-PATATOR",
}
NORMAL_TIMELINE_EVERY = 250
MAX_FLOW_TIMELINE_EVENTS = 260


class RuntimeState:
    def __init__(self):
        self.lock = RLock()
        self.attack_state = AttackState()
        self.graph = NetworkGraph()
        self.reset()

    def reset(self):
        with getattr(self, "lock", RLock()):
            if hasattr(self, "attack_state"):
                self.attack_state.reset()
            if hasattr(self, "graph"):
                self.graph.reset()
            self.timeline = []
            self.seen_event_keys = set()
            self.processed_rows = 0
            self.source_files = []
            self.dataset_name = None
            self.analysis_mode = None
            self.last_forecast = None
            self.replay_active = False
            self.replay_progress = 0
            self.class_counts = Counter()
            self.malicious_conf_sum = 0.0
            self.malicious_conf_count = 0
            self.latest_detection = None
            self.flow_event_count = 0
            self.normal_timeline_count = 0
            self.unsupported_label_counts = Counter()
        return self.status()

    def append_timeline(
        self,
        event,
        severity="LOW",
        description=None,
        timestamp=None,
        source=None,
        destination=None,
        port=None,
        protocol=None,
        category=None,
        confidence=None,
        mitre_id=None,
        mitre_technique=None,
        dataset_label=None,
        event_type="network",
    ):
        timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        item = {
            "id": f"event-{len(self.timeline)+1}",
            "timestamp": timestamp,
            "event": event,
            "event_type": event_type,
            "severity": severity,
            "status": (
                "malicious" if severity in {"HIGH", "CRITICAL"}
                else "suspicious" if severity == "MEDIUM"
                else "normal"
            ),
            "description": description,
            "source": source,
            "destination": destination,
            "port": port,
            "protocol": protocol,
            "category": category,
            "confidence": confidence,
            "mitre_id": mitre_id,
            "mitre_technique": mitre_technique,
            "dataset_label": dataset_label,
        }
        self.timeline.append(item)
        self.timeline = self.timeline[-300:]
        return item

    def process_sample(self, df: pd.DataFrame, source_name: str):
        if df.empty:
            return 0

        work = df.copy()
        work.columns = work.columns.str.strip()

        # Some uploaded folders may contain graph-compatible CSVs that do not
        # contain enough of the 68 training features for a trustworthy model
        # inference. Those rows still build the real graph/timeline, but their
        # detection confidence stays unavailable instead of silently treating
        # missing features as zeros.
        model_mask = (
            work["__model_compatible"].fillna(False).astype(bool)
            if "__model_compatible" in work.columns
            else pd.Series(True, index=work.index)
        )
        predictions = pd.DataFrame(index=work.index)
        predictions["category"] = "NORMAL"
        predictions["confidence"] = 0.0
        predictions["model_supported"] = False
        if model_mask.any():
            model_predictions = predict_dataframe(work.loc[model_mask])
            predictions.loc[model_mask, "category"] = model_predictions["category"]
            predictions.loc[model_mask, "confidence"] = model_predictions["confidence"]
            predictions.loc[model_mask, "model_supported"] = True

        required = {"Source IP", "Destination IP"}
        if not required.issubset(work.columns):
            missing = sorted(required - set(work.columns))
            raise ValueError(
                "Graph metadata missing from dataset. Required columns: "
                + ", ".join(sorted(required))
                + f". Missing: {', '.join(missing)}"
            )

        for row_number, (idx, row) in enumerate(work.iterrows(), start=1):
            pred = predictions.loc[idx]
            raw_category = str(pred["category"])
            confidence = float(pred["confidence"])
            model_supported = bool(pred.get("model_supported", True))
            dataset_label = str(row.get("Label", "") or "").strip()
            dataset_label_upper = dataset_label.upper()

            # The trained model has a three-class scope. If CICIDS explicitly labels
            # a row as another attack family (DoS, DDoS, Web Attack, Bot, etc.), we
            # retain the flow in the graph and timeline but do not pretend that the
            # current model can map it to Recon/Credential Access.
            unsupported_label = bool(
                dataset_label_upper
                and dataset_label_upper not in MODEL_SUPPORTED_LABELS
                and dataset_label_upper not in {"NAN", "NONE", "UNKNOWN"}
            )

            category = (
                "NORMAL"
                if (unsupported_label or not model_supported)
                else raw_category if (raw_category == "NORMAL" or confidence >= DETECTION_THRESHOLD)
                else "NORMAL"
            )

            self.class_counts[category] += 1
            if unsupported_label:
                self.unsupported_label_counts[dataset_label] += 1

            if category != "NORMAL":
                self.malicious_conf_sum += confidence
                self.malicious_conf_count += 1
                self.latest_detection = {
                    "category": category,
                    "confidence": round(confidence, 4),
                }

            metadata = self.graph.add_flow(row.to_dict(), category, confidence)
            if metadata is None:
                continue

            self.flow_event_count += 1
            event_added = False

            if category != "NORMAL":
                mitre = map_to_mitre(category)
                transition = self.attack_state.update(
                    mitre,
                    confidence,
                    source=metadata["source"],
                    target=metadata["target"],
                    timestamp=metadata["timestamp"],
                )

                # Keep multiple real events instead of collapsing an entire attack
                # into one source/destination row. This makes the timeline useful.
                if len(self.timeline) < MAX_FLOW_TIMELINE_EVENTS:
                    severity = "HIGH" if category == "CREDENTIAL_ATTACK" else "MEDIUM"
                    self.append_timeline(
                        event=f"{category.replace('_', ' ').title()} detected",
                        severity=severity,
                        description=(
                            f"{metadata['source']} → {metadata['target']}"
                            + (f" on port {metadata['port']}" if metadata.get("port") is not None else "")
                            + f"; model confidence {confidence*100:.1f}%."
                        ),
                        timestamp=metadata["timestamp"],
                        source=metadata["source"],
                        destination=metadata["target"],
                        port=metadata.get("port"),
                        protocol=metadata.get("protocol"),
                        category=category,
                        confidence=round(confidence, 4),
                        mitre_id=mitre.get("technique_id"),
                        mitre_technique=mitre.get("technique"),
                        dataset_label=metadata.get("dataset_label"),
                    )
                    event_added = True

                if transition and mitre["stage"] == self.attack_state.current_stage:
                    self.append_timeline(
                        event=f"Current attack stage set to {mitre['stage'].replace('_',' ').title()}",
                        severity="CRITICAL" if mitre["stage"] == "CREDENTIAL_ACCESS" else "HIGH",
                        description=f"{mitre.get('technique_id')}: {mitre.get('technique')}",
                        timestamp=metadata["timestamp"],
                        source=metadata["source"],
                        destination=metadata["target"],
                        port=metadata.get("port"),
                        protocol=metadata.get("protocol"),
                        category=category,
                        confidence=round(confidence, 4),
                        mitre_id=mitre.get("technique_id"),
                        mitre_technique=mitre.get("technique"),
                        dataset_label=metadata.get("dataset_label"),
                        event_type="stage_transition",
                    )

            elif (unsupported_label or (not model_supported and dataset_label_upper not in {"", "BENIGN", "NAN", "NONE", "UNKNOWN"})) and len(self.timeline) < MAX_FLOW_TIMELINE_EVENTS:
                # Ground-truth dataset evidence outside the model's current class
                # scope. No ML confidence or MITRE technique is invented.
                self.append_timeline(
                    event=f"Dataset-labelled {dataset_label}",
                    severity="MEDIUM",
                    description=(
                        f"Observed dataset label '{dataset_label}' for "
                        f"{metadata['source']} → {metadata['target']}. This row is shown as dataset evidence "
                        "without inventing an ML confidence because its model feature coverage/class is unsupported."
                    ),
                    timestamp=metadata["timestamp"],
                    source=metadata["source"],
                    destination=metadata["target"],
                    port=metadata.get("port"),
                    protocol=metadata.get("protocol"),
                    category="DATASET_ATTACK",
                    confidence=None,
                    mitre_id=None,
                    mitre_technique=None,
                    dataset_label=dataset_label,
                    event_type="dataset_label",
                )
                event_added = True

            # Even a completely benign upload gets a real timeline. We add
            # deterministic normal-flow evidence at a controlled cadence.
            if (
                not event_added
                and category == "NORMAL"
                and not unsupported_label
                and len(self.timeline) < MAX_FLOW_TIMELINE_EVENTS
                and (self.normal_timeline_count < 20 or self.flow_event_count % NORMAL_TIMELINE_EVERY == 0)
            ):
                self.normal_timeline_count += 1
                self.append_timeline(
                    event="Network flow observed",
                    severity="LOW",
                    description=f"Observed {metadata['source']} → {metadata['target']} from uploaded flow data.",
                    timestamp=metadata["timestamp"],
                    source=metadata["source"],
                    destination=metadata["target"],
                    port=metadata.get("port"),
                    protocol=metadata.get("protocol"),
                    category="NORMAL",
                    confidence=round(confidence, 4),
                    mitre_id=None,
                    mitre_technique=None,
                    dataset_label=metadata.get("dataset_label"),
                )

        self.processed_rows += len(work)
        if source_name not in self.source_files:
            self.source_files.append(source_name)

        self.graph.finalize_risk()
        self.last_forecast = generate_forecast(
            self.attack_state.get_state(),
            self.graph,
            contributing_features=top_model_features(5),
        )
        return len(work)

    def status(self):
        attack = self.attack_state.get_state()
        return {
            "status": "online",
            "dataset_name": self.dataset_name,
            "analysis_mode": self.analysis_mode,
            "processed_rows": self.processed_rows,
            "source_files": list(self.source_files),
            "current_stage": attack["current_stage"],
            "observed_stages": attack["observed_stages"],
            "events": len(self.timeline),
            "replay_active": self.replay_active,
            "replay_progress": self.replay_progress,
        }

    def forecast(self):
        if self.last_forecast is None:
            self.last_forecast = generate_forecast(
                self.attack_state.get_state(),
                self.graph,
                contributing_features=top_model_features(5),
            )
        return {k: v for k, v in self.last_forecast.items() if not k.startswith("_")}

    def graph_payload(self):
        forecast = self.last_forecast or generate_forecast(
            self.attack_state.get_state(), self.graph, top_model_features(5)
        )
        return self.graph.get_graph(forecast.get("_target_detail"))

    def detection_payload(self):
        avg_conf = (
            self.malicious_conf_sum / self.malicious_conf_count
            if self.malicious_conf_count else 0.0
        )
        return {
            "latest": self.latest_detection,
            "average_malicious_confidence": round(avg_conf, 4),
            "class_counts": dict(self.class_counts),
            "processed_rows": self.processed_rows,
            "malicious_detection_threshold": DETECTION_THRESHOLD,
            "dataset_labels_outside_model_scope": dict(self.unsupported_label_counts),
        }

    def risk_payload(self):
        self.graph.finalize_risk()
        max_node = max((n["risk_score"] for n in self.graph.nodes.values()), default=0.0)
        avg_node = (
            sum(n["risk_score"] for n in self.graph.nodes.values()) / len(self.graph.nodes)
            if self.graph.nodes else 0.0
        )
        forecast = self.forecast()
        forecast_component = float(forecast.get("confidence") or 0) * 100
        score = round(min(100, 0.65 * max_node + 0.20 * avg_node + 0.15 * forecast_component), 1)
        suspicious = sum(1 for e in self.timeline if e["severity"] in {"MEDIUM", "HIGH", "CRITICAL"})
        active = self.attack_state.current_stage != "NORMAL"
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"
        return {
            "level": level,
            "score": score,
            "activeAttack": active,
            "suspiciousEvents": suspicious,
            "components": {
                "highest_host_risk": round(max_node, 1),
                "average_host_risk": round(avg_node, 1),
                "forecast_component": round(forecast_component, 1),
            },
            "method": "65% highest-host risk + 20% average-host risk + 15% forecast confidence",
        }

    def summary_payload(self):
        forecast = self.forecast()
        risk = self.risk_payload()
        detection = self.detection_payload()
        graph = self.graph_payload()
        latest = detection.get("latest") or {}
        # Make the top detection card correspond to the current attack stage,
        # so a later scan in a different capture does not visually contradict
        # a current Credential Access state. Values still come from real model
        # detections in the timeline.
        current_stage_raw = self.attack_state.current_stage
        stage_category = {
            "CREDENTIAL_ACCESS": "CREDENTIAL_ATTACK",
            "RECONNAISSANCE": "RECONNAISSANCE",
        }.get(current_stage_raw)
        stage_event = None
        if stage_category:
            stage_event = next(
                (e for e in reversed(self.timeline) if e.get("category") == stage_category and e.get("confidence") is not None),
                None,
            )
        display_category = stage_category if stage_event else latest.get("category", "NO MALICIOUS DETECTION")
        display_confidence = stage_event.get("confidence", 0.0) if stage_event else latest.get("confidence", 0.0)
        return {
            "current_stage": forecast.get("current_stage", "Normal"),
            "detection_category": display_category,
            "detection_confidence": display_confidence,
            "average_malicious_confidence": detection.get("average_malicious_confidence", 0.0),
            "network_risk_score": risk.get("score", 0),
            "network_risk_level": risk.get("level", "LOW"),
            "forecast_stage": forecast.get("predicted_stage", "No Further Stage"),
            "forecast_confidence": forecast.get("confidence", 0.0),
            "predicted_target": forecast.get("predicted_target"),
            "target_risk_score": forecast.get("target_risk_score"),
            "hosts": graph.get("summary", {}).get("total_nodes_in_dataset", 0),
            "relationships": graph.get("summary", {}).get("total_edges_in_dataset", 0),
            "processed_rows": self.processed_rows,
        }


runtime = RuntimeState()
