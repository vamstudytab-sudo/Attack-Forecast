from collections import Counter, defaultdict
import ipaddress

from backend.risk.risk_engine import (
    SENSITIVE_PORTS,
    REMOTE_MOVEMENT_PORTS,
    node_risk_score,
    node_risk_components,
    edge_risk_score,
    risk_level,
)

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _clean_text(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none"}:
        return None
    return text


def _port(value):
    try:
        return int(float(value))
    except Exception:
        return None


def _protocol(value):
    try:
        numeric = int(float(value))
        return PROTOCOL_NAMES.get(numeric, str(numeric))
    except Exception:
        return _clean_text(value) or "UNKNOWN"


def _subnet_key(ip):
    """Compact full-network grouping.

    Private/internal hosts stay grouped by subnet so enterprise structure remains
    visible. Public destinations are represented by one External / Internet
    group; every observed host is still counted in the overview.
    """
    try:
        address = ipaddress.ip_address(ip)
        if address.is_loopback:
            return "Loopback"
        if address.is_link_local:
            return "Link-local"
        if not address.is_private:
            return "External / Internet"
        if address.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except Exception:
        return "Other / unresolved"


def _new_node(ip):
    return {
        "id": ip,
        "label": ip,
        "type": "ip",
        "outgoing_flows": 0,
        "incoming_flows": 0,
        "malicious_out": 0,
        "malicious_in": 0,
        "malicious_out_conf_sum": 0.0,
        "malicious_in_conf_sum": 0.0,
        "recon_out": 0,
        "recon_in": 0,
        "credential_out": 0,
        "credential_in": 0,
        "sensitive_out": 0,
        "sensitive_in": 0,
        "out_peers": set(),
        "in_peers": set(),
        "connections": set(),
        "behaviors": set(),
        "ports": Counter(),
        "protocols": Counter(),
        "labels": Counter(),
        "first_seen": None,
        "last_seen": None,
        "risk_score": 0.0,
        "risk": "LOW",
    }


def _new_edge(source, target):
    return {
        "source": source,
        "target": target,
        "flow_count": 0,
        "malicious_count": 0,
        "malicious_conf_sum": 0.0,
        "recon_count": 0,
        "credential_count": 0,
        "ports": Counter(),
        "protocols": Counter(),
        "labels": Counter(),
        "first_seen": None,
        "last_seen": None,
        "risk_score": 0.0,
        "risk": "LOW",
    }


class NetworkGraph:
    def __init__(self):
        self.reset()

    def reset(self):
        self.nodes = {}
        self.edges = {}

    def _node(self, ip):
        if ip not in self.nodes:
            self.nodes[ip] = _new_node(ip)
        return self.nodes[ip]

    def add_flow(self, row: dict, category: str, confidence: float):
        source = _clean_text(row.get("Source IP"))
        target = _clean_text(row.get("Destination IP"))
        if not source or not target:
            return None

        dst_port = _port(row.get("Destination Port"))
        protocol = _protocol(row.get("Protocol"))
        timestamp = _clean_text(row.get("Timestamp"))
        original_label = _clean_text(row.get("Label")) or "UNKNOWN"

        src_node = self._node(source)
        dst_node = self._node(target)

        src_node["outgoing_flows"] += 1
        dst_node["incoming_flows"] += 1
        src_node["out_peers"].add(target)
        dst_node["in_peers"].add(source)
        src_node["connections"].add(target)
        dst_node["connections"].add(source)
        src_node["protocols"][protocol] += 1
        dst_node["protocols"][protocol] += 1
        src_node["labels"][original_label] += 1
        dst_node["labels"][original_label] += 1
        if dst_port is not None:
            src_node["ports"][dst_port] += 1
            dst_node["ports"][dst_port] += 1

        if dst_port in SENSITIVE_PORTS:
            src_node["sensitive_out"] += 1
            dst_node["sensitive_in"] += 1

        for node in (src_node, dst_node):
            if timestamp:
                if node["first_seen"] is None:
                    node["first_seen"] = timestamp
                node["last_seen"] = timestamp

        key = (source, target)
        edge = self.edges.setdefault(key, _new_edge(source, target))
        edge["flow_count"] += 1
        if dst_port is not None:
            edge["ports"][dst_port] += 1
        edge["protocols"][protocol] += 1
        edge["labels"][original_label] += 1
        if timestamp:
            if edge["first_seen"] is None:
                edge["first_seen"] = timestamp
            edge["last_seen"] = timestamp

        category = str(category)
        confidence = float(confidence)
        if category != "NORMAL":
            edge["malicious_count"] += 1
            edge["malicious_conf_sum"] += confidence
            src_node["malicious_out"] += 1
            src_node["malicious_out_conf_sum"] += confidence
            dst_node["malicious_in"] += 1
            dst_node["malicious_in_conf_sum"] += confidence

        if category == "RECONNAISSANCE":
            edge["recon_count"] += 1
            src_node["recon_out"] += 1
            dst_node["recon_in"] += 1
            src_node["behaviors"].add("Network service scanning / reconnaissance")
            dst_node["behaviors"].add("Targeted by reconnaissance traffic")
        elif category == "CREDENTIAL_ATTACK":
            edge["credential_count"] += 1
            src_node["credential_out"] += 1
            dst_node["credential_in"] += 1
            src_node["behaviors"].add("Credential / brute-force attack traffic")
            dst_node["behaviors"].add("Targeted by credential attack traffic")

        return {
            "source": source,
            "target": target,
            "port": dst_port,
            "protocol": protocol,
            "timestamp": timestamp,
            "dataset_label": original_label,
        }

    def finalize_risk(self):
        for node in self.nodes.values():
            score = node_risk_score(node)
            node["risk_score"] = score
            node["risk"] = risk_level(score)
        for edge in self.edges.values():
            score = edge_risk_score(edge)
            edge["risk_score"] = score
            edge["risk"] = risk_level(score)

    def _edge_attack(self, edge):
        # If the same observed source→destination relationship contains both
        # scanning and credential-attack evidence, keep that progression visible
        # instead of hiding one category behind a single dominant label.
        if edge["credential_count"] > 0 and edge["recon_count"] > 0:
            return "MULTI_STAGE"
        if edge["credential_count"] > 0:
            return "CREDENTIAL_ATTACK"
        if edge["recon_count"] > 0:
            return "RECONNAISSANCE"
        return "NORMAL"

    def dominant_credential_edge(self):
        candidates = [e for e in self.edges.values() if e["credential_count"] > 0]
        if not candidates:
            return None
        return max(candidates, key=lambda e: (e["credential_count"], e["risk_score"], e["flow_count"]))

    def highest_risk_source(self):
        candidates = [n for n in self.nodes.values() if n["malicious_out"] > 0]
        return max(candidates, key=lambda n: n["risk_score"], default=None)

    def predict_target(self):
        """Graph-based heuristic target selection. The score is explicitly a risk score, not a calibrated probability."""
        if not self.nodes:
            return None
        credential_edge = self.dominant_credential_edge()
        compromised_host = credential_edge["target"] if credential_edge else None

        candidate_edges = []
        if compromised_host:
            candidate_edges = [
                e for e in self.edges.values()
                if e["source"] == compromised_host and e["target"] != compromised_host
            ]
        if not candidate_edges:
            source_node = self.highest_risk_source()
            if source_node:
                candidate_edges = [e for e in self.edges.values() if e["source"] == source_node["id"]]
        if not candidate_edges:
            return None

        max_flows = max(e["flow_count"] for e in candidate_edges) or 1
        max_centrality = max(
            self.nodes[e["target"]]["incoming_flows"] + self.nodes[e["target"]]["outgoing_flows"]
            for e in candidate_edges
        ) or 1

        scored = []
        for edge in candidate_edges:
            target_node = self.nodes[edge["target"]]
            remote = 1.0 if set(edge["ports"]) & REMOTE_MOVEMENT_PORTS else 0.0
            activity = min(edge["flow_count"] / max_flows, 1.0)
            centrality = min(
                (target_node["incoming_flows"] + target_node["outgoing_flows"]) / max_centrality,
                1.0,
            )
            target_exposure = min(target_node["risk_score"] / 100.0, 1.0)
            score = 35 * activity + 25 * remote + 20 * centrality + 20 * target_exposure
            scored.append((score, edge, target_node))

        score, edge, _target_node = max(scored, key=lambda item: item[0])
        return {
            "source": edge["source"],
            "target": edge["target"],
            "score": round(min(100.0, score), 1),
            "risk": risk_level(score),
            "reasons": [
                f"Observed communication from {edge['source']} to {edge['target']}",
                f"Observed flow activity contributes {round(35 * min(edge['flow_count']/max_flows, 1.0), 1)}/35",
                "Remote-service port observed" if set(edge["ports"]) & REMOTE_MOVEMENT_PORTS else "No remote-service port observed",
                "Target connectivity contributes to graph-based exposure",
            ],
        }

    def _node_payload(self, node):
        return {
            "id": node["id"],
            "label": node["label"],
            "type": node["type"],
            "risk": node["risk"],
            "risk_score": node["risk_score"],
            "role": (
                "suspected_source" if node["malicious_out"] > node["malicious_in"] and node["malicious_out"] > 0
                else "target" if node["malicious_in"] > 0
                else "host"
            ),
            "flows": node["outgoing_flows"] + node["incoming_flows"],
            "malicious_flows": node["malicious_out"] + node["malicious_in"],
        }

    def _edge_payload(self, edge):
        attack = self._edge_attack(edge)
        malicious = edge["malicious_count"]
        avg_conf = edge["malicious_conf_sum"] / malicious if malicious else 0.0
        relation = {
            "MULTI_STAGE": "T1046 Scan → T1110 Brute Force",
            "CREDENTIAL_ATTACK": "T1110 Brute Force",
            "RECONNAISSANCE": "T1046 Network Scan",
            "NORMAL": "Network Flow",
        }[attack]
        return {
            "id": f"{edge['source']}->{edge['target']}",
            "source": edge["source"],
            "target": edge["target"],
            "relationship": relation,
            "attack": attack,
            "confidence": round(avg_conf, 4),
            "risk": edge["risk"],
            "risk_score": edge["risk_score"],
            "flow_count": edge["flow_count"],
            "malicious_count": edge["malicious_count"],
            "destination_ports": [p for p, _ in edge["ports"].most_common(8)],
            "protocols": [p for p, _ in edge["protocols"].most_common(5)],
            "first_seen": edge["first_seen"],
            "last_seen": edge["last_seen"],
            "predicted": False,
        }

    def _overview_graph(self):
        """Represent the complete observed network compactly by subnet groups.
        Every host contributes to exactly one subnet node, so the full dataset is represented.
        """
        groups = {}
        membership = {}
        for ip, node in self.nodes.items():
            key = _subnet_key(ip)
            membership[ip] = key
            if key not in groups:
                groups[key] = {
                    "id": f"subnet:{key}",
                    "label": key,
                    "type": "subnet",
                    "host_count": 0,
                    "flow_count": 0,
                    "internal_flow_count": 0,
                    "malicious_flows": 0,
                    "risk_score": 0.0,
                    "risk": "LOW",
                    "top_hosts": [],
                }
            g = groups[key]
            g["host_count"] += 1
            g["flow_count"] += node["outgoing_flows"] + node["incoming_flows"]
            g["malicious_flows"] += node["malicious_out"] + node["malicious_in"]
            g["risk_score"] = max(g["risk_score"], node["risk_score"])

        for key, g in groups.items():
            hosts = [n for ip, n in self.nodes.items() if membership[ip] == key]
            hosts.sort(key=lambda n: (n["risk_score"], n["malicious_out"] + n["malicious_in"]), reverse=True)
            g["risk"] = risk_level(g["risk_score"])
            g["top_hosts"] = [n["id"] for n in hosts[:5]]

        merged = defaultdict(lambda: {
            "flow_count": 0,
            "malicious_count": 0,
            "risk_score": 0.0,
            "attacks": Counter(),
        })
        for edge in self.edges.values():
            s = membership[edge["source"]]
            t = membership[edge["target"]]
            key = (s, t)
            m = merged[key]
            m["flow_count"] += edge["flow_count"]
            m["malicious_count"] += edge["malicious_count"]
            m["risk_score"] = max(m["risk_score"], edge["risk_score"])
            m["attacks"][self._edge_attack(edge)] += edge["flow_count"]

        overview_edges = []
        for (s, t), m in merged.items():
            if s == t:
                if s in groups:
                    groups[s]["internal_flow_count"] += m["flow_count"]
                continue
            if m["attacks"].get("MULTI_STAGE", 0) > 0:
                dominant = "MULTI_STAGE"
            elif m["attacks"].get("CREDENTIAL_ATTACK", 0) > 0:
                dominant = "CREDENTIAL_ATTACK"
            elif m["attacks"].get("RECONNAISSANCE", 0) > 0:
                dominant = "RECONNAISSANCE"
            else:
                dominant = "NORMAL"
            overview_edges.append({
                "id": f"overview:{s}->{t}",
                "source": f"subnet:{s}",
                "target": f"subnet:{t}",
                "relationship": dominant,
                "attack": dominant,
                "confidence": None,
                "risk": risk_level(m["risk_score"]),
                "risk_score": round(m["risk_score"], 1),
                "flow_count": m["flow_count"],
                "malicious_count": m["malicious_count"],
                "predicted": False,
            })
        return list(groups.values()), overview_edges

    def get_graph(self, predicted_target=None, max_host_nodes=90, max_host_edges=220):
        self.finalize_risk()
        ranked_nodes = sorted(
            self.nodes.values(),
            key=lambda n: (
                n["risk_score"],
                n["malicious_out"] + n["malicious_in"],
                n["outgoing_flows"] + n["incoming_flows"],
            ),
            reverse=True,
        )
        selected_ids = {n["id"] for n in ranked_nodes[:max_host_nodes]}
        if predicted_target:
            selected_ids.update(x for x in [predicted_target.get("source"), predicted_target.get("target")] if x)

        host_nodes = [self._node_payload(self.nodes[node_id]) for node_id in selected_ids if node_id in self.nodes]
        candidate_edges = [e for e in self.edges.values() if e["source"] in selected_ids and e["target"] in selected_ids]
        candidate_edges.sort(key=lambda e: (e["risk_score"], e["malicious_count"], e["flow_count"]), reverse=True)
        host_edges = [self._edge_payload(e) for e in candidate_edges[:max_host_edges]]

        if predicted_target:
            s = predicted_target.get("source")
            t = predicted_target.get("target")
            if s in selected_ids and t in selected_ids and s != t:
                host_edges.append({
                    "id": f"prediction:{s}->{t}",
                    "source": s,
                    "target": t,
                    "relationship": "Predicted Lateral Movement",
                    "attack": "LATERAL_MOVEMENT",
                    "confidence": None,
                    "risk": predicted_target.get("risk", "HIGH"),
                    "risk_score": predicted_target.get("score", 0),
                    "flow_count": 0,
                    "malicious_count": 0,
                    "destination_ports": [],
                    "protocols": [],
                    "predicted": True,
                })

        overview_nodes, overview_edges = self._overview_graph()
        return {
            "nodes": host_nodes,
            "edges": host_edges,
            "overview_nodes": overview_nodes,
            "overview_edges": overview_edges,
            "summary": {
                "total_nodes_in_dataset": len(self.nodes),
                "total_edges_in_dataset": len(self.edges),
                "displayed_host_nodes": len(host_nodes),
                "displayed_host_edges": len(host_edges),
                "overview_groups": len(overview_nodes),
            },
        }

    def get_node(self, node_id):
        self.finalize_risk()
        node = self.nodes.get(str(node_id))
        if not node:
            return None
        malicious = node["malicious_out"] + node["malicious_in"]
        total = node["outgoing_flows"] + node["incoming_flows"]
        conf_sum = node["malicious_out_conf_sum"] + node["malicious_in_conf_sum"]
        risk = node_risk_components(node)
        return {
            "id": node["id"],
            "name": node["label"],
            "type": "IP",
            "host": node["label"],
            "risk": node["risk"],
            "risk_score": node["risk_score"],
            "risk_breakdown": risk,
            "connections": sorted(node["connections"]),
            "connected_host_count": len(node["connections"]),
            "suspicious_behaviors": sorted(node["behaviors"]),
            "outgoing_flows": node["outgoing_flows"],
            "incoming_flows": node["incoming_flows"],
            "total_flows": total,
            "malicious_flows": malicious,
            "malicious_ratio": round(malicious / total, 4) if total else 0.0,
            "recon_flows": node["recon_out"] + node["recon_in"],
            "credential_flows": node["credential_out"] + node["credential_in"],
            "average_detection_confidence": round(conf_sum / malicious, 4) if malicious else 0.0,
            "top_ports": [{"port": p, "count": c} for p, c in node["ports"].most_common(8)],
            "top_protocols": [{"protocol": p, "count": c} for p, c in node["protocols"].most_common(5)],
            "top_dataset_labels": [{"label": p, "count": c} for p, c in node["labels"].most_common(5)],
            "first_seen": node["first_seen"],
            "last_seen": node["last_seen"],
        }
