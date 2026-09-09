from datetime import datetime, timezone

STAGE_ORDER = {
    "NORMAL": 0,
    "RECONNAISSANCE": 1,
    "INITIAL_ACCESS": 2,
    "EXECUTION": 3,
    "PERSISTENCE": 4,
    "CREDENTIAL_ACCESS": 5,
    "DISCOVERY": 6,
    "LATERAL_MOVEMENT": 7,
    "COMMAND_AND_CONTROL": 8,
    "EXFILTRATION": 9,
    "IMPACT": 10,
}


class AttackState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.current_stage = "NORMAL"
        self.observed_stages = []
        self.history = []
        self.stage_counts = {}
        return self.get_state()

    def update(self, mitre_result: dict, confidence: float, source=None, target=None, timestamp=None):
        stage = mitre_result.get("stage", "UNKNOWN")
        if stage in ("NORMAL", "UNKNOWN"):
            return None

        self.stage_counts[stage] = self.stage_counts.get(stage, 0) + 1

        transition = False
        if stage not in self.observed_stages:
            self.observed_stages.append(stage)
            transition = True

        current_rank = STAGE_ORDER.get(self.current_stage, 0)
        new_rank = STAGE_ORDER.get(stage, 0)
        if new_rank >= current_rank and stage != self.current_stage:
            self.current_stage = stage
            transition = True

        if transition:
            event = {
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
                "stage": stage,
                "tactic": mitre_result.get("tactic"),
                "technique": mitre_result.get("technique"),
                "technique_id": mitre_result.get("technique_id"),
                "confidence": float(confidence),
                "source": source,
                "target": target,
            }
            self.history.append(event)
            return event
        return None

    def get_state(self):
        return {
            "current_stage": self.current_stage,
            "observed_stages": list(self.observed_stages),
            "history": list(self.history),
            "stage_counts": dict(self.stage_counts),
        }
