MITRE_MAPPING = {
    "NORMAL": {
        "stage": "NORMAL",
        "tactic": None,
        "technique": None,
        "technique_id": None,
        "description": "No malicious behavior detected.",
    },
    "RECONNAISSANCE": {
        "stage": "RECONNAISSANCE",
        "tactic": "Discovery",
        "technique": "Network Service Scanning",
        "technique_id": "T1046",
        "description": "Scanning behavior indicates discovery of reachable hosts, ports, or services.",
    },
    "CREDENTIAL_ATTACK": {
        "stage": "CREDENTIAL_ACCESS",
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "description": "Repeated authentication behavior indicates credential guessing or brute force.",
    },
}


def map_to_mitre(prediction: str) -> dict:
    key = str(prediction or "").strip().upper()
    return MITRE_MAPPING.get(
        key,
        {
            "stage": "UNKNOWN",
            "tactic": "Unknown",
            "technique": "Unknown",
            "technique_id": None,
            "description": f"No MITRE mapping exists for prediction: {key}",
        },
    )
