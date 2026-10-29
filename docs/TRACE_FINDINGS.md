# Trace findings

`POST /v1/traces` includes a `findings` array per flow. Each finding has a stable `code`, an optional Navis `device_id`, and a human-readable `message`. `SOURCE_UNRESOLVED`, `SOURCE_AMBIGUOUS`, `DESTINATION_UNRESOLVED`, `DESTINATION_AMBIGUOUS`, `PATH_EVIDENCE_MISSING`, `POLICY_COVERAGE_INCOMPLETE`, `POLICY_EVIDENCE_INCOMPLETE`, and `NAT_EVIDENCE_INCOMPLETE` identify known gaps. An unknown device cannot have an invented ID; the finding identifies the last known device when possible.

These findings describe candidate-path evidence, not proof of complete coverage. Caller-specific external identities and detailed missing-object references are not yet added to trace findings. `examples/http_trace_findings_test.ps1` checks the HTTP unresolved-destination case against the configured test API.
