"""Machine-readable findings for incomplete candidate paths."""


def trace_findings(hops, source_candidates, destination_candidates):
    findings = []
    if not source_candidates:
        findings.append({"code": "SOURCE_UNRESOLVED", "device_id": None, "message": "Source device or interface information is missing."})
    elif len(source_candidates) > 1:
        findings.append({"code": "SOURCE_AMBIGUOUS", "device_id": None, "message": "Source matches multiple devices or interfaces."})
    if not destination_candidates:
        findings.append({"code": "DESTINATION_UNRESOLVED", "device_id": None, "message": "Destination device or interface information is missing."})
    elif len(destination_candidates) > 1:
        findings.append({"code": "DESTINATION_AMBIGUOUS", "device_id": None, "message": "Destination matches multiple devices or interfaces."})
    for hop in hops:
        device = hop["device_id"]
        if hop.get("policy_coverage") in ("unknown", "partial", "conflicting"):
            findings.append({"code": "POLICY_COVERAGE_INCOMPLETE", "device_id": device,
                             "message": "Policy configuration for this device is missing, partial, or conflicting."})
        if hop.get("stop_reason") and hop["stop_reason"] != "policy denied traffic":
            findings.append({"code": "PATH_EVIDENCE_MISSING", "device_id": device, "message": hop["stop_reason"]})
        for kind, evaluation in (("POLICY_EVIDENCE_INCOMPLETE", hop.get("policy_evaluations", [])), ("NAT_EVIDENCE_INCOMPLETE", hop.get("nat_evidence", []))):
            for item in evaluation:
                if item.get("decision", item.get("status")) == "unknown":
                    findings.append({"code": kind, "device_id": device, "message": item.get("reason", "Evidence is incomplete.")})
    return findings
