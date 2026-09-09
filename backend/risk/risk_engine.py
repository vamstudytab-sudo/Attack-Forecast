SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389}
REMOTE_MOVEMENT_PORTS = {22, 135, 139, 445, 3389}


def risk_level(score: float) -> str:
    score = float(score)
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def stage_severity(recon_count: int, credential_count: int) -> float:
    if credential_count > 0:
        return 1.0
    if recon_count > 0:
        return 0.65
    return 0.0


def node_risk_components(node: dict) -> dict:
    outgoing = max(1, int(node.get("outgoing_flows", 0)))
    incoming = max(1, int(node.get("incoming_flows", 0)))
    malicious_out = int(node.get("malicious_out", 0))
    malicious_in = int(node.get("malicious_in", 0))

    source_conf = (
        float(node.get("malicious_out_conf_sum", 0.0)) / malicious_out
        if malicious_out else 0.0
    )
    inbound_conf = (
        float(node.get("malicious_in_conf_sum", 0.0)) / malicious_in
        if malicious_in else 0.0
    )

    source_ratio = malicious_out / outgoing
    inbound_ratio = malicious_in / incoming
    severity = stage_severity(
        int(node.get("recon_out", 0)) + int(node.get("recon_in", 0)),
        int(node.get("credential_out", 0)) + int(node.get("credential_in", 0)),
    )
    fanout = min(len(node.get("out_peers", ())) / 10.0, 1.0)
    fanin = min(len(node.get("in_peers", ())) / 8.0, 1.0)
    sensitive_out = min(float(node.get("sensitive_out", 0)) / outgoing, 1.0)
    sensitive_in = min(float(node.get("sensitive_in", 0)) / incoming, 1.0)

    source = {
        "detection_confidence": round(45 * source_conf, 1),
        "attack_stage_severity": round(20 * severity, 1),
        "malicious_activity_ratio": round(15 * source_ratio, 1),
        "network_fanout": round(10 * fanout, 1),
        "sensitive_services": round(10 * sensitive_out, 1),
    }
    exposure = {
        "detection_confidence": round(40 * inbound_conf, 1),
        "attack_stage_severity": round(20 * severity, 1),
        "malicious_activity_ratio": round(20 * inbound_ratio, 1),
        "network_fanin": round(10 * fanin, 1),
        "sensitive_services": round(10 * sensitive_in, 1),
    }

    source_total = round(sum(source.values()), 1)
    exposure_total = round(sum(exposure.values()), 1)
    if source_total >= exposure_total:
        return {
            "perspective": "source_behavior",
            "components": source,
            "total": min(100.0, source_total),
        }
    return {
        "perspective": "target_exposure",
        "components": exposure,
        "total": min(100.0, exposure_total),
    }


def node_risk_score(node: dict) -> float:
    return round(node_risk_components(node)["total"], 1)


def edge_risk_score(edge: dict) -> float:
    flow_count = max(1, int(edge.get("flow_count", 0)))
    malicious = int(edge.get("malicious_count", 0))
    if not malicious:
        return 0.0

    avg_conf = float(edge.get("malicious_conf_sum", 0.0)) / malicious
    malicious_ratio = malicious / flow_count
    severity = stage_severity(
        int(edge.get("recon_count", 0)), int(edge.get("credential_count", 0))
    )

    score = 60 * avg_conf + 20 * malicious_ratio + 20 * severity
    return round(min(100.0, score), 1)
