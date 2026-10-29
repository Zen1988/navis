# Project status and continuation guide

Last updated: 2026-10-29. This is a development snapshot, not a production-readiness claim. The architecture and project charter describe intended behavior; this document records current implementation and known gaps. Older sections of other documents may lag the code.

## Product boundary

External Ansible, Salt or other collectors retrieve native device data using credentials they control. Product adapters interpret the collected output and translate vendor semantics into Navis's common inventory, routing, policy and NAT models. Navis stores and analyzes normalized data; callers should not have to hand-map vendor policy. Preserve native identifiers, evidence and explicit uncertainty. Never interpret missing evidence as an allow or deny.

## Current state

| Area | Implemented or demonstrated | Remaining work |
| --- | --- | --- |
| Database | PostgreSQL schema, migrations 001–015, source and consumer scopes, device identity mappings, snapshots, raw and normalized records, trace sessions and ACI evidence views. | Migrations need a tracked migration runner, upgrade testing and operational hardening. Device/fabric identity reconciliation and richer normalized data models remain incomplete. |
| Ingestion | Authenticated API can stage submissions; a separately invoked worker verifies the normalized adapter digest, resolves device identity and writes supported interface, route, MAC, neighbor, policy, NAT and zone records. | Automate processing and identity resolution; improve validation, error reporting, lifecycle and secure artifact approval. Vendor adapter execution is not integrated as a worker plugin. |
| Authentication | Local static bearer token, principal and source-scoped permissions support isolated testing. | External OAuth/OIDC integration, credential lifecycle and production authorization, audit and deployment hardening remain incomplete. |
| Graph | Apache AGE builder creates persistent graphs from selected dataset snapshots, interfaces, routes and links, including manual links; build evidence detects changes in selected relational records. | Improve topology discovery, dataset management, evidence immutability and consistency. ACI raw fabric evidence is not yet projected as confirmed graph links. |
| Trace | Prototype path search, route selection, policy and NAT evidence, alternatives, reverse/session evidence, findings, recommendation drafts and session API exist. | Overall connectivity remains unknown when required evidence or semantics are incomplete. Validate selection, precedence, NAT stages, alternatives, reverse forwarding, stateful/stateless behavior and scope comprehensively before claiming engine completion. |
| HTTP integration | The user's isolated three-device test demonstrated graph builds, zone/policy examples, NAT route selection, trace sessions, recommendation retrieval, reverse candidate output and selected evidence checks. | These are fixture-specific checks, not proof of arbitrary networks, full end-to-end reachability or production correctness. Add repeatable API/database integration and real-device tests. |
| Web and deployment | Draft web test page, Docker image definition and Kubernetes example exist. | UX, deployment security, configuration, upgrades and production operational readiness are incomplete. The local static token is for testing. |
| Collectors | Partial read-only Ansible examples cover ACI/APIC, Check Point, IOS, NSX, Palo Alto and F5. Salt examples cover NSX and Linux/Windows host evidence. | Product/version coverage, credentials, pagination, errors and live integration must be verified. Standalone Nexus, Avi and FortiGate need complete collectors/adapters. |
| ACI adapter | Collector-side translation preserves APIC evidence, maps interfaces and derives partial contract candidates with observed address and service selectors. Partial ACI fabric evidence and candidate views can be stored/queryable. | Complete automatic translation into evaluable common policy and route records, including contract scope, direction, labels, exceptions, precedence, membership, deployment, route contexts and installed forwarding. Do not require a separate user-supplied mapping; validate with representative APIC data. Current policies remain incomplete and cannot establish allow/deny. |

## Recommended continuation

1. Finish the ACI adapter first: extend collection where native evidence is missing, resolve vendor-specific relationships inside the adapter, and emit normalized policies and routes. Identify unsupported semantics rather than silently widening selectors. Ensure native rule identity and correct enforcement/device association survive ingestion.
2. Extend the common schema, ingestion contract and evaluation engine where needed to represent resolved policy direction, source ports, statefulness, multiple next hops, priorities and coverage. Keep vendor-specific interpretation in adapters and common evaluation in the engine.
3. Add representative, sanitized APIC fixtures and repeatable tests across collection output → adapter → API → worker → PostgreSQL → graph → trace. Test ambiguity, incomplete data, different VRFs, deny rules, NAT and reverse traffic. Do not mark completion based on one fixture.
4. Apply the same adapter boundary to the remaining products, then expand live and multi-device testing and secure deployment.

## Practical test notes

The user's Windows test environment uses `navis-age-test` and `navis-api-age-test`, with AGE and migrations through 015 applied. Container-mounted source changes and database state are local and may differ elsewhere. Do not commit `navis-test.dump`, credentials, tokens or collected configurations. Adapter source changes require approving the new digest before the existing worker processes normalized submissions.

Run the local Python unit suite from the repository root with `PYTHONPATH=src` and `python -m unittest discover -s tests`. Most recent local run: 85 tests passed. SQL views 014 and 015 were separately checked by the user with rollback-based examples. No live APIC collection or full ACI policy ingestion/trace test has been confirmed.
