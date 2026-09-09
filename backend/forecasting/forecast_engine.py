def _pretty(stage: str) -> str:
    return str(stage or "").replace("_", " ").title()


TRANSITIONS = {
    "RECONNAISSANCE": {"CREDENTIAL_ACCESS": 0.72, "INITIAL_ACCESS": 0.20},
    "CREDENTIAL_ACCESS": {"LATERAL_MOVEMENT": 0.76, "DISCOVERY": 0.18},
    "DISCOVERY": {"LATERAL_MOVEMENT": 0.70},
    "LATERAL_MOVEMENT": {"IMPACT": 0.68, "EXFILTRATION": 0.22},
}

RECOMMENDATIONS = {
    "CREDENTIAL_ACCESS": [
        "Review authentication and remote-service activity for affected hosts.",
        "Reset or disable suspected credentials and enforce MFA where possible.",
        "Investigate repeated SSH/FTP authentication behavior.",
    ],
    "LATERAL_MOVEMENT": [
        "Isolate the highest-risk affected host from unnecessary internal peers.",
        "Restrict unnecessary SMB, SSH and RDP connectivity.",
        "Disable compromised credentials and investigate communications to the predicted target.",
    ],
    "IMPACT": [
        "Contain affected systems and preserve incident evidence.",
        "Validate backups and restrict malicious communications.",
    ],
}


def generate_forecast(attack_state: dict, graph, contributing_features=None) -> dict:
    current = attack_state.get("current_stage", "NORMAL")
    observed = attack_state.get("observed_stages", [])
    options = TRANSITIONS.get(current, {})

    if not options:
        predicted = None
        probability = 0.0
    else:
        predicted = max(options, key=options.get)
        probability = float(options[predicted])

    reasons = []
    if "RECONNAISSANCE" in observed:
        reasons.append("Reconnaissance behavior has already been observed.")
    if "CREDENTIAL_ACCESS" in observed:
        reasons.append("Credential-access behavior indicates usable access may have been obtained.")

    history_stages = [item.get("stage") for item in attack_state.get("history", [])]
    recon_before_credential = (
        "RECONNAISSANCE" in history_stages
        and "CREDENTIAL_ACCESS" in history_stages
        and history_stages.index("RECONNAISSANCE") < history_stages.index("CREDENTIAL_ACCESS")
    )
    if current == "CREDENTIAL_ACCESS" and recon_before_credential:
        probability = min(0.95, probability + 0.05)
        reasons.append("Reconnaissance was observed before credential activity, increasing progression risk.")

    predicted_target = graph.predict_target() if predicted == "LATERAL_MOVEMENT" else None
    if predicted_target:
        reasons.append(
            f"Graph context ranks {predicted_target['target']} as the highest-risk reachable observed target."
        )

    if probability >= 0.8:
        risk = "CRITICAL"
    elif probability >= 0.6:
        risk = "HIGH"
    elif probability >= 0.3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if predicted == "LATERAL_MOVEMENT":
        lead_time = {"min": 6, "max": 14, "unit": "minutes", "method": "prototype rule-based risk window"}
    elif predicted == "CREDENTIAL_ACCESS":
        lead_time = {"min": 10, "max": 25, "unit": "minutes", "method": "prototype rule-based risk window"}
    else:
        lead_time = {"min": None, "max": None, "unit": "minutes", "method": "prototype rule-based risk window"}

    contributing_nodes = []
    if predicted_target:
        contributing_nodes = [
            {"node_id": predicted_target["source"], "name": predicted_target["source"], "importance": 0.82},
            {"node_id": predicted_target["target"], "name": predicted_target["target"], "importance": 0.71},
        ]

    if predicted is None:
        reason = "No malicious progression has been observed yet, so no next-stage probability is displayed."
    else:
        reason = " ".join(reasons) if reasons else "Forecast is based on the current configured attack-state transition model."

    return {
        "current_stage": _pretty(current),
        "predicted_stage": _pretty(predicted) if predicted else "No Forecast Yet",
        "confidence": round(probability, 2),
        "confidence_type": "transition_context_score" if predicted else "none",
        "risk": risk,
        "reason": reason,
        "predicted_target": predicted_target["target"] if predicted_target else None,
        "target_risk_score": predicted_target["score"] if predicted_target else None,
        "target_reason": predicted_target["reasons"] if predicted_target else [],
        "lead_time": lead_time,
        "recommendations": RECOMMENDATIONS.get(predicted or current, []),
        "contributing_nodes": contributing_nodes,
        "contributing_features": contributing_features or [],
        "_target_detail": predicted_target,
    }
