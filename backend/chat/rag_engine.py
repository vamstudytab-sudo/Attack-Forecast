"""Small local evidence-grounded retrieval assistant.

This is intentionally offline and deterministic for the prototype. It retrieves
from live graph/timeline/forecast evidence plus a compact MITRE knowledge base,
then composes an answer only from those retrieved facts. It does not invent
endpoint/file/user telemetry that CICIDS2017 does not contain.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any



MITRE_KB = [
    {
        "id": "mitre-t1046",
        "text": "T1046 Network Service Scanning is a MITRE ATT&CK Discovery technique used to identify services listening on remote hosts. In this prototype reconnaissance detections are mapped to T1046.",
    },
    {
        "id": "mitre-t1110",
        "text": "T1110 Brute Force is a MITRE ATT&CK Credential Access technique involving repeated attempts to obtain valid account credentials. In this prototype credential-attack detections are mapped to T1110.",
    },
    {
        "id": "lateral-movement",
        "text": "Lateral Movement is attacker movement from an accessed system toward other reachable systems. For this MVP it is forecast after credential-access evidence, using configured transition confidence and graph context.",
    },
    {
        "id": "defense-credential",
        "text": "For credential-access evidence, defensive priorities include isolating the affected host, resetting or disabling suspected credentials, enforcing MFA where possible, and reviewing authentication and remote-service activity.",
    },
    {
        "id": "defense-lateral",
        "text": "For lateral-movement risk, defensive priorities include isolating affected systems, restricting unnecessary SMB/SSH/RDP exposure, disabling compromised accounts, and investigating communications to likely target hosts.",
    },
]

UNSUPPORTED_HINTS = {
    "employee": "The supplied CICIDS2017 flow data does not contain employee identity information.",
    "username": "The supplied CICIDS2017 flow data does not contain user-account identities.",
    "user account": "The supplied CICIDS2017 flow data does not contain user-account identities.",
    "file": "The supplied CICIDS2017 flow data is network-flow telemetry and does not contain file creation/execution events.",
    "process": "The supplied CICIDS2017 flow data is network-flow telemetry and does not contain process telemetry.",
    "registry": "The supplied CICIDS2017 flow data does not contain registry events.",
    "powershell": "The supplied CICIDS2017 flow data does not contain PowerShell process telemetry.",
}


def _pct(value):
    try:
        value = float(value)
        return f"{value * 100:.1f}%" if value <= 1 else f"{value:.1f}%"
    except Exception:
        return "—"


def _extract_ip(text: str):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return match.group(0) if match else None


def _docs(runtime, selected_node=None, selected_event=None):
    docs: list[dict[str, Any]] = []
    summary = runtime.summary_payload()
    risk = runtime.risk_payload()
    forecast = runtime.forecast()
    detection = runtime.detection_payload()

    docs.append({"id": "summary", "kind": "live", "text": (
        f"Current attack stage is {summary['current_stage']}. Latest detection is {summary['detection_category']} "
        f"with confidence {_pct(summary['detection_confidence'])}. Network risk is {summary['network_risk_score']}/100 "
        f"({summary['network_risk_level']}). Forecast is {summary['forecast_stage']} with confidence "
        f"{_pct(summary['forecast_confidence'])}. Predicted target is {summary.get('predicted_target') or 'none'}."
    )})
    docs.append({"id": "risk", "kind": "live", "text": (
        f"Network risk score is {risk['score']}/100 {risk['level']}. The score method is {risk.get('method')}. "
        f"Risk components are {risk.get('components')}."
    )})
    docs.append({"id": "forecast", "kind": "live", "text": (
        f"Forecast: current stage {forecast.get('current_stage')}; predicted next stage {forecast.get('predicted_stage')}; "
        f"forecast confidence {_pct(forecast.get('confidence', 0))}; predicted target {forecast.get('predicted_target')}; "
        f"target risk score {forecast.get('target_risk_score')}; reason: {forecast.get('reason')}."
    )})
    docs.append({"id": "detection", "kind": "live", "text": (
        f"Detector processed {detection.get('processed_rows', 0)} flows. Class counts are {detection.get('class_counts', {})}. "
        f"Average confidence over malicious detections is {_pct(detection.get('average_malicious_confidence', 0))}."
    )})

    node_id = selected_node
    if not node_id:
        node_id = _extract_ip("")
    if node_id:
        node = runtime.graph.get_node(node_id)
        if node:
            docs.append({"id": f"node:{node_id}", "kind": "live", "text": (
                f"Host {node_id} has risk {node['risk_score']}/100 {node['risk']}, {node['total_flows']} total flows, "
                f"{node['malicious_flows']} malicious flows, {node['recon_flows']} reconnaissance flows, "
                f"{node['credential_flows']} credential-attack flows, {node['connected_host_count']} connected hosts, "
                f"average malicious detection confidence {_pct(node['average_detection_confidence'])}, "
                f"top ports {node['top_ports']}, behaviors {node['suspicious_behaviors']}, and risk breakdown {node['risk_breakdown']}."
            )})

    if selected_event:
        event = next((e for e in runtime.timeline if e.get("id") == selected_event), None)
        if event:
            docs.append({"id": f"event:{selected_event}", "kind": "live", "text": (
                f"Selected timeline event {event.get('event')} at {event.get('timestamp')}: source {event.get('source')}, "
                f"destination {event.get('destination')}, port {event.get('port')}, protocol {event.get('protocol')}, "
                f"category {event.get('category')}, model confidence {_pct(event.get('confidence') or 0)}, "
                f"MITRE {event.get('mitre_id')} {event.get('mitre_technique')}, dataset label {event.get('dataset_label')}."
            )})

    # Highest-risk hosts and recent event evidence are searchable.
    nodes = sorted(runtime.graph.nodes.values(), key=lambda n: n.get("risk_score", 0), reverse=True)[:12]
    for node in nodes:
        docs.append({"id": f"host:{node['id']}", "kind": "live", "text": (
            f"Host {node['id']} risk {node['risk_score']}/100 {node['risk']}; outgoing flows {node['outgoing_flows']}; "
            f"incoming flows {node['incoming_flows']}; reconnaissance {node['recon_out'] + node['recon_in']}; "
            f"credential attacks {node['credential_out'] + node['credential_in']}; connected hosts {len(node['connections'])}."
        )})
    for event in runtime.timeline[-40:]:
        docs.append({"id": f"timeline:{event['id']}", "kind": "live", "text": (
            f"Timeline {event.get('timestamp')} {event.get('event')}: {event.get('source')} to {event.get('destination')}; "
            f"port {event.get('port')}; {event.get('protocol')}; status {event.get('status')}; "
            f"MITRE {event.get('mitre_id')}; confidence {_pct(event.get('confidence') or 0)}."
        )})

    docs.extend({**entry, "kind": "knowledge"} for entry in MITRE_KB)
    return docs


def _retrieve(question: str, docs: list[dict], top_k=5):
    """Lightweight local retrieval with no sklearn/scipy dependency.

    It scores overlap between normalized query terms and each evidence document,
    with small bonuses for exact IP / MITRE-token matches. This is enough for
    the prototype because the corpus is small and strongly structured.
    """
    if not docs:
        return []

    stop = {
        "the", "a", "an", "is", "are", "was", "were", "to", "of", "in",
        "on", "for", "and", "or", "this", "that", "it", "what", "why",
        "how", "show", "me", "about", "with", "from", "do", "does"
    }

    def tokens(text):
        return {t for t in re.findall(r"[a-z0-9_.:/-]+", (text or "").lower()) if len(t) > 1 and t not in stop}

    q_tokens = tokens(question)
    if not q_tokens:
        return docs[:top_k]

    ranked = []
    q_lower = (question or "").lower()
    for doc in docs:
        text = doc.get("text", "")
        d_tokens = tokens(text)
        overlap = q_tokens & d_tokens
        score = len(overlap) / max(len(q_tokens), 1)

        # Exact security identifiers and IPs are especially informative.
        for special in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|t\d{4}", q_lower):
            if special in text.lower():
                score += 1.0
        if doc.get("kind") == "live":
            score += 0.05

        if score > 0.05:
            ranked.append(({**doc, "score": round(float(score), 4)}, score))

    ranked.sort(key=lambda item: item[1], reverse=True)
    return [item[0] for item in ranked[:top_k]] or docs[:top_k]


def _format_answer(question, runtime, retrieved, mode, selected_node=None, selected_event=None):
    q = (question or "").strip().lower()
    summary = runtime.summary_payload()
    forecast = runtime.forecast()
    risk = runtime.risk_payload()
    ip = _extract_ip(question) or selected_node
    node = runtime.graph.get_node(ip) if ip else None

    for hint, message in UNSUPPORTED_HINTS.items():
        if hint in q:
            return message + " I can answer using IPs, flows, ports, protocols, timestamps, attack labels, model detections, MITRE mappings, graph risk, and forecast context."

    if ("highest" in q or "most" in q or "top" in q) and any(word in q for word in ["host", "ip", "node", "risk", "risky"]):
        top = sorted(runtime.graph.nodes.values(), key=lambda n: n.get("risk_score", 0), reverse=True)[:3]
        if top:
            lead = top[0]
            base = (
                f"The highest-risk host is {lead['id']} at {lead['risk_score']}/100 ({lead['risk']}), "
                f"with {lead['malicious_out'] + lead['malicious_in']} malicious flows and {len(lead['connections'])} connected hosts."
            )
            detail = " The next highest-risk hosts are " + ", ".join(
                f"{n['id']} ({n['risk_score']}/100)" for n in top[1:]
            ) + "." if len(top) > 1 else ""
        else:
            base = "No hosts have been analyzed yet."
            detail = " Upload a compatible dataset folder first."
    elif any(word in q for word in ["risk", "risky", "dangerous", "score"]):
        if node:
            b = node["risk_breakdown"]
            comp = b.get("components", {})
            base = (
                f"{ip} has a risk score of {node['risk_score']}/100 ({node['risk']}) based on {node['malicious_flows']} malicious "
                f"flows out of {node['total_flows']} observed flows, {node['connected_host_count']} connected hosts, and an average "
                f"malicious-detection confidence of {_pct(node['average_detection_confidence'])}."
            )
            detail = " Risk contributions: " + ", ".join(f"{k.replace('_',' ')} {v}" for k, v in comp.items()) + "."
        else:
            base = f"The current network risk is {risk['score']}/100 ({risk['level']})."
            detail = f" It is derived as {risk.get('method')}, using components {risk.get('components')}."
    elif any(word in q for word in ["forecast", "predict", "next", "lateral", "probability", "confidence"]):
        base = (
            f"The system forecasts {forecast.get('predicted_stage')} with {_pct(forecast.get('confidence', 0))} forecast confidence"
            + (f", with {forecast.get('predicted_target')} ranked as the next target at risk {forecast.get('target_risk_score')}/100" if forecast.get('predicted_target') else "")
            + "."
        )
        detail = f" {forecast.get('reason')} This forecast confidence is transition/context-derived in the MVP, not the Random Forest class probability."
    elif any(word in q for word in ["mitre", "t1046", "t1110", "technique"]):
        if "t1046" in q or "scan" in q:
            base = "T1046 is Network Service Scanning, mapped here to reconnaissance detections in the CICIDS flow data."
        elif "t1110" in q or "brute" in q or "credential" in q:
            base = "T1110 is Brute Force, mapped here to credential-attack detections in the CICIDS flow data."
        else:
            base = "The live pipeline currently maps reconnaissance to T1046 Network Service Scanning and credential attacks to T1110 Brute Force."
        detail = " These mappings are attached only when the detector observes the corresponding network-flow behavior."
    elif any(word in q for word in ["defend", "defense", "defence", "do now", "recommend", "action", "isolate", "block"]):
        base = "Prioritize containment of the highest-risk affected host and reduce the remote-service paths that could support further movement."
        if forecast.get("predicted_stage") == "Lateral Movement":
            detail = (
                f" Given the current {forecast.get('current_stage')} state and lateral-movement forecast, isolate the affected host, "
                "review/reset suspicious credentials, restrict unnecessary SMB/SSH/RDP connectivity, and investigate communications to the predicted target."
            )
        else:
            detail = " Review the suspicious source/destination pairs in the timeline, validate credentials, and restrict unnecessary exposed services."
    elif any(word in q for word in ["timeline", "before", "event", "happened", "history"]):
        events = runtime.timeline[-5:]
        if not events:
            return "No suspicious timeline events have been generated yet. Upload compatible data or run the replay first."
        base = "Recent evidence: " + "; ".join(
            f"{e.get('event')} ({e.get('source')} → {e.get('destination')})" for e in events[-3:]
        ) + "."
        detail = " Open the Event Timeline to inspect timestamps, ports, protocols, MITRE mappings, and model confidence for each event."
    elif any(word in q for word in ["host", "ip", "node", "connected", "connection"]):
        if node:
            base = (
                f"{ip} has {node['total_flows']} observed flows, {node['connected_host_count']} connected hosts, "
                f"{node['recon_flows']} reconnaissance flows, and {node['credential_flows']} credential-attack flows."
            )
            detail = f" Its top observed ports are {node['top_ports'][:5]}, and its current risk is {node['risk_score']}/100 ({node['risk']})."
        else:
            top = sorted(runtime.graph.nodes.values(), key=lambda n: n.get("risk_score", 0), reverse=True)[:3]
            base = "Highest-risk hosts currently visible in the analyzed graph are: " + ", ".join(
                f"{n['id']} ({n['risk_score']}/100)" for n in top
            ) + "." if top else "No hosts have been analyzed yet."
            detail = " Select a host in the graph and ask again for host-specific evidence."
    elif any(word in q for word in ["summary", "what is happening", "what's happening", "attack"]):
        base = (
            f"The current stage is {summary['current_stage']}; network risk is {summary['network_risk_score']}/100 "
            f"({summary['network_risk_level']}); the latest malicious detection is {summary['detection_category']} at "
            f"{_pct(summary['detection_confidence'])}."
        )
        detail = (
            f" The next-stage forecast is {summary['forecast_stage']} at {_pct(summary['forecast_confidence'])}, based on "
            f"{summary['processed_rows']} processed flow records across {summary['hosts']} hosts and {summary['relationships']} relationships."
        )
    else:
        if not retrieved:
            return "I could not find supporting evidence for that question in the current dataset context. Ask about hosts, flows, ports, timeline events, risk scores, MITRE mappings, detections, forecasts, or defensive actions."
        base = retrieved[0]["text"]
        detail = " " + " ".join(item["text"] for item in retrieved[1:3])

    if mode == "one_line":
        return base
    if mode == "two_lines":
        return base + "\n" + detail.strip()
    # detailed
    evidence_lines = [f"• {item['text']}" for item in retrieved[:4]]
    return base + detail + ("\n\nSupporting retrieved evidence:\n" + "\n".join(evidence_lines) if evidence_lines else "")


def answer_question(runtime, question: str, mode="detailed", selected_node=None, selected_event=None):
    # If the user typed an IP, retrieve that IP even if it is not the current selection.
    typed_ip = _extract_ip(question)
    node_for_context = typed_ip or selected_node
    docs = _docs(runtime, selected_node=node_for_context, selected_event=selected_event)
    retrieved = _retrieve(question, docs, top_k=5)
    answer = _format_answer(
        question, runtime, retrieved, mode, selected_node=node_for_context, selected_event=selected_event
    )
    return {
        "answer": answer,
        "mode": mode,
        "grounded": True,
        "selected_node": node_for_context,
        "selected_event": selected_event,
        "evidence": [
            {"id": item["id"], "kind": item.get("kind"), "text": item["text"], "relevance": item.get("score")}
            for item in retrieved[:4]
        ],
        "capabilities": {
            "live_graph": True,
            "timeline": True,
            "risk": True,
            "forecast": True,
            "mitre_knowledge": True,
            "endpoint_telemetry": False,
        },
    }
