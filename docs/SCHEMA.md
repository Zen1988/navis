# PostgreSQL schema design

Status: Draft, conceptual v1. This document specifies the initial relational model; it is not a migration or a promise that every platform can be normalized yet. PostgreSQL is authoritative. Apache AGE is a rebuildable projection, and original submissions remain available for reprocessing.

An initial draft SQL implementation is in [001_initial.sql](../migrations/001_initial.sql). It needs PostgreSQL integration testing and further constraints before production use. In particular, temporal identity overlap, two complete link endpoints, cross-snapshot selector and zone consistency, normalization provenance for all object types, and rule-specific selector semantics need enforcement. JSON fields for flow selectors and NAT translations remain draft contracts. The migration does not implement adapter verification, graph construction, or analysis.

[002_ingestion_submission.sql](../migrations/002_ingestion_submission.sql) adds a staging record for raw submissions before device identity is resolved. The initial schema required a device snapshot before storing a payload, which could not represent unresolved imports. This staging record does not authorize the claimed device or create a snapshot.

## Conventions

All primary keys are UUIDs. `created_at` and `updated_at` use `timestamptz` where applicable. `details` means optional vendor-specific `jsonb`, not a replacement for the original payload. Foreign keys are required unless marked optional. Use `inet` for host addresses (including interface prefix lengths), `cidr` for canonical network prefixes, and `macaddr` for MAC addresses. Avoid globally unique IPs, zone names, or interface names. Use checks or lookup tables for controlled values; the values below are initial examples, not exhaustive vendor semantics.

## Collection and identity

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `source_system` | `id`, `namespace` (unique), `kind`, `name` | Collector, CMDB, or other external source. |
| `device` | `id`, `vendor`, `platform`, optional `model`, `display_name`, `first_seen_at`, `last_seen_at` | Stable Navis identity; names and addresses are not identity. |
| `device_identity_mapping` | `id`, `device_id` FK, `source_system_id` FK, `external_id`, `provenance`, `valid_from`, optional `valid_until` | Maps source identities to a device. Prevent overlapping active mappings for the same source and external ID; retain history. |
| `import_batch` | `id`, `source_system_id` FK, `external_id`, `received_at`, `status` | Groups submitted data; enforce source-scoped idempotency when an external ID is supplied. |
| `device_snapshot` | `id`, `device_id` FK, `import_batch_id` FK, `collected_at`, `received_at`, optional `firmware_version`, `platform_version`, `source_snapshot_id` | Configuration and operational evidence at a collection time. |
| `snapshot_coverage` | `snapshot_id` FK, `data_type`, `coverage` (`complete`, `partial`, `unknown`), optional `scope`, `details` | Whether absence of a record is meaningful in a given scope. |
| `raw_payload` | `id`, `snapshot_id` FK, `data_type`, `format`, optional `format_version`, `payload` JSONB, `received_at` | Preserve submitted data for audit and reprocessing. |
| `normalization_run` | `id`, `snapshot_id` FK, `adapter_name`, `adapter_version`, `started_at`, `status`, optional `details` | Records how a snapshot was interpreted. |

Normalized records below reference `snapshot_id` and, where produced by an adapter, `normalization_run_id`. A normalization run must belong to the same snapshot as its records. Enforce this and other same-snapshot relationships with composite foreign keys or equivalent constraints. Retain raw payload references and native object identifiers where available. Preserve multiple normalization versions without treating all as simultaneously active.

## Network and routing

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `routing_context` | `id`, `snapshot_id` FK, `native_id`, `name`, `details` | VRF, routing table, or equivalent, scoped to a device snapshot. |
| `network_segment` | `id`, optional `source_system_id` FK, `external_id`, `name`, `details` | Identified shared network or bridge domain; do not assume VLAN IDs are globally unique. |
| `interface` | `id`, `snapshot_id` FK, `native_id`, `name`, `kind`, optional `parent_interface_id` FK, `routing_context_id` FK, `operational_state`, `details` | Physical, VLAN/SVI, loopback, or other interface. Parent and context must belong to the snapshot. |
| `interface_address` | `id`, `interface_id` FK, `address` inet, `purpose`, `details` | Multiple addresses and prefixes per interface. Routing context follows the interface or an explicitly modeled platform-specific assignment. |
| `interface_segment` | `id`, `interface_id` FK, `network_segment_id` FK, optional `vlan_id`, `details` | Interface membership and VLAN context. |
| `route` | `id`, `snapshot_id` FK, `routing_context_id` FK, `destination` cidr, `route_type`, optional `protocol`, `preference`, `metric`, `native_id`, `details` | Candidate, selected or installed route, as identified by the collection coverage. No permanent `is_selected` field. |
| `route_next_hop` | `id`, `route_id` FK, optional `next_hop_address` inet, `interface_id` FK, `next_hop_context_id` FK, `weight`, `details` | One or more next hops; discard and connected routes may have different requirements. |
| `neighbor_entry` | `id`, `snapshot_id` FK, `routing_context_id` FK, `interface_id` FK, `ip_address` inet, `mac_address` macaddr, `state`, `observed_at` | ARP/NDP evidence; preserve state and observation time. |
| `mac_entry` | `id`, `snapshot_id` FK, `mac_address` macaddr, `interface_id` FK, optional `network_segment_id` FK, `vlan_id`, `entry_type`, `observed_at`, `details` | Layer 2 forwarding evidence, not necessarily a direct link. |
| `topology_link` | `id`, endpoint references, `origin`, `source_system_id` FK, optional `observed_at`, `valid_from`, `valid_until`, `details` | Manually declared or imported link. Endpoints can be interfaces or segments; model with a link endpoint table and enforce two valid endpoints. Preserve conflicting evidence. |
| `routing_protocol_instance` | `id`, `routing_context_id` FK, `protocol`, optional `local_asn`, `router_id`, `details` | Protocol context; ASN is not required for ordinary forwarding. |
| `routing_peer` | `id`, `routing_protocol_instance_id` FK, `peer_address` inet, optional `remote_asn`, `state`, `details` | Configuration and observed neighbor state. |
| `route_protocol_attributes` | `route_id` FK, `attributes` JSONB | Preserve protocol-specific AS path, local preference, MED and other attributes without claiming cross-protocol comparability. Exchange filters and redistribution require additional normalized models when supported; keep raw data meanwhile. |

Index `route` by snapshot and routing context, with an appropriate GiST or SP-GiST index for prefix containment. Retrieve matching prefixes and apply longest-prefix and platform-specific route eligibility in the engine. Index neighbor lookup by snapshot, context and IP; MAC lookup by snapshot, segment/VLAN and MAC. Verify index operator classes and query plans against the deployed PostgreSQL version.

## Policy and NAT

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `network_zone` | `id`, `name`, optional `source_system_id` FK, `external_id`, `details` | Organizational network classification, distinct from a firewall zone. |
| `network_zone_membership` | `id`, `network_zone_id` FK, target reference, `valid_from`, optional `valid_until` | Associates a zone with a device, segment or other supported target; validate target type. |
| `enforcement_point` | `id`, `snapshot_id` FK, `native_id`, `kind`, `details` | Policy enforcement scope within a device. |
| `security_zone` | `id`, `enforcement_point_id` FK, `native_id`, `name`, `details` | Device-specific zone; names are scoped, not global. |
| `security_zone_member` | `security_zone_id` FK, interface or other supported member reference, `details` | Zone membership as interpreted by the adapter. |
| `address_object` | `id`, `snapshot_id` FK, `native_id`, `kind`, optional `host` inet, `prefix` cidr, `range_start` inet, `range_end` inet, `details` | Effective address selectors, preserving the original representation in raw data. Validate range and kind. |
| `address_group_member` | `group_id` FK, `member_id` FK, `is_exclusion` | Nested address groups; detect cycles during normalization/evaluation. |
| `service_object` | `id`, `snapshot_id` FK, `native_id`, optional `protocol`, source and destination port ranges, `details` | Service selectors; support groups through a related membership table. |
| `policy_rule_set` | `id`, `enforcement_point_id` FK, `native_id`, `evaluation_order`, `default_action`, `details` | Scope and default (`allow`, `deny`, `unknown`) appropriate to the platform. |
| `policy_rule` | `id`, `rule_set_id` FK, `native_rule_id`, `name`, `position`, `action`, `direction`, `enabled`, `details` | Ordered normalized rule; preserve native identifiers and unsupported semantics. |
| `policy_selector` | `id`, `policy_rule_id` FK, `role`, object reference, `negated` | Source, destination, service, zone or interface conditions. Use typed foreign keys or typed join tables; retain combinations and semantics. |
| `policy_schedule` | `id`, `policy_rule_id` FK, `kind`, optional validity bounds, timezone, recurrence, `details` | Distinguish unrestricted, absolute, recurring and unknown schedules. Preserve native definition. |
| `nat_rule_set` | `id`, `enforcement_point_id` FK, `native_id`, `processing_stage`, `evaluation_order`, `details` | Platform-specific NAT scope and order. |
| `nat_rule` | `id`, `nat_rule_set_id` FK, `native_rule_id`, `position`, `enabled`, `details` | Ordered rule; match selectors use typed related records. |
| `nat_translation` | `id`, `nat_rule_id` FK, `kind`, address and port translation specification, `details` | Source, destination, combined, dynamic pool, port translation or exemption; preserve uncertainty and processing semantics. |

The exact selector, schedule and translation structures must be refined against representative native configurations before migration. Never silently convert unsupported behavior to allow or deny. A rule set default is not a substitute for a complete collection.

## Applications, graph and results

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `application` | `id`, `name`, optional `source_system_id` FK, `external_id`, `details` | Application identity. |
| `application_member` | `application_id` FK, device or endpoint reference, `valid_from`, optional `valid_until` | Explicit static membership. |
| `application_flow` | `id`, `application_id` FK, source and destination selectors, protocol, destination port range, optional validity, `details` | Required communication; missing flows mean an incomplete application view. |
| `graph_build` | `id`, `started_at`, `completed_at`, `status`, `builder_version` | Tracks a rebuildable graph projection. |
| `graph_build_snapshot` | `graph_build_id` FK, `snapshot_id` FK | Identifies the source dataset for a graph build. Graph vertices and edges carry stable relational references and provenance. |
| `analysis_request` | `id`, optional `application_flow_id` FK, source, destination, protocol, ports, requested_at, `parameters` JSONB | Captures requested traffic and evaluation context. |
| `analysis_dataset_snapshot` | `analysis_request_id` FK, `snapshot_id` FK | Exact snapshots used across devices. |
| `analysis_result` | `id`, `analysis_request_id` FK, optional `graph_build_id` FK, `status`, `completed_at`, `engine_version`, `details` | Allowed, blocked or unknown, with reproducibility information. |
| `analysis_step` | `id`, `analysis_result_id` FK, `sequence`, optional device, route, NAT and policy references, packet state before/after, decision, explanation | Ordered evidence for each candidate path; represent branching paths with a path ID or parent step. |
| `analysis_finding` | `id`, `analysis_result_id` FK, optional `policy_rule_id` FK, `kind`, `coverage`, `confidence`, `explanation`, `details` | Rule effectiveness and cleanup candidates, scoped to evidence. |
| `recommendation` | `id`, `analysis_result_id` FK, optional enforcement point and policy references, `recommendation` JSONB, `reason`, `uncertainty` | API-ready proposal with source, destination, zones, service, action, validity and position where known. |

## API consumers and audit

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `api_consumer` | `id`, `issuer`, `subject_or_client_id`, `name`, `status` | Optional local mapping to an externally managed application identity; unique issuer and identity. |
| `consumer_data_scope` | `api_consumer_id` FK, source namespace or other boundary, permissions | Local data boundaries if required; external token scopes still need enforcement. |
| `audit_event` | `id`, optional `api_consumer_id` FK, `occurred_at`, `operation`, `resource_type`, `resource_id`, `outcome`, `details` | Records API activity without storing access tokens or device credentials. |

## Adapter artifact integrity

Navis executes product adapters to interpret submitted data. Only explicitly approved adapter artifacts may execute. Approval must come from a trusted administrative release process, separate from ingestion. An incoming request cannot register or approve its own executable or hash.

| Table | Key columns and relationships | Purpose |
| --- | --- | --- |
| `adapter_artifact` | `id`, `product`, `version`, `artifact_name`, `digest_algorithm`, `digest`, `status`, `approved_at`, `approved_by`, optional `revoked_at`, `details` | Records an approved artifact digest and its lifecycle. Enforce uniqueness for the artifact identity and digest; retain approval and revocation history. Use SHA-256 or a stronger approved algorithm. |
| `adapter_verification` | `id`, optional `adapter_artifact_id` FK, `checked_at`, `observed_digest`, `result`, `reason`, optional `import_batch_id` FK | Audits verification before execution, including failures and unknown artifacts. Never record tokens or credentials. |

Before execution, the runtime resolves an approved artifact from trusted deployment storage and verifies its bytes against the approved digest. Unknown, revoked, missing, or mismatched artifacts fail closed: do not execute the adapter or normalize the submission, and record the failure. A mismatch is an integrity failure, not proof of a man-in-the-middle attack. Bind verification to the bytes actually executed to prevent replacement between verification and execution; verify dependencies and runtime images through the trusted deployment process as well.

Hashes establish integrity only when the expected digest and approval process are trusted. Use authenticated transport and externally issued application credentials for submissions; validate payload size, structure and supported formats separately. A caller-provided hash does not authenticate the caller or establish that submitted data is trustworthy. External collectors and their executables are managed by their owners; Navis verifies only artifacts it actually runs. Product/version metadata received in a payload selects an approved adapter but does not grant approval.

## Design boundaries before implementation

Define deletion and retention policy, temporal identity matching, snapshot consistency, tenant or namespace boundaries, access-token validation, and exact vendor semantics before deploying a migration. Validate representative cases: overlapping VRFs, longest-prefix matching, NAT before and after enforcement, policy defaults, incomplete snapshots, multiple paths, and graph rebuilds. The system should return unknown when evidence is insufficient.
