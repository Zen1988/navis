# Collector to Navis contract

Discovery and submission are separate steps. The vendor examples in README identify resources to fetch; they do not transform vendor data. `submit_normalized.yml` is a fixture demonstrating the actual interface ingestion envelope. Credentials for each system remain on the collector.

The configured ingestion service requires a bearer token with `inventory:write`, an active issuer-bound consumer, and `consumer_data_scope` permission for the source namespace. A successful staging response is HTTP 202:

```json
{"ingestion_id":"<uuid>","status":"pending_identity"}
```

Staging is not normalization or graph creation. A matching time-valid device identity and approved adapter are required by the separate worker. The default API verifier and processor reject requests; configure them before running an end-to-end test. An unsuccessful request may return 401, 403, 422 or 503. No status polling endpoint exists yet.

| Data needed | Current normalized input | Gap |
| --- | --- | --- |
| Device and firmware | Staged raw | No normalized device importer or automated identity reconciliation |
| Interfaces | `entries`: `name`, `kind`, `addresses`; optional `native_id`, `parent`, `vrf`, `operational_state`, `vlans`, `config` | VLANs are details, not segment membership; separate submissions create separate snapshots |
| Route | `entries`: `vrf`, `destination`, `next_hop`, `interface` | One next hop per entry; no route selection, discard routes or metrics in this format |
| MAC | `entries`: `interface`, `mac`, `vlan` | Native interface ID must match interface inventory; no multi-VLAN/segment inference |
| Neighbor | `entries`: `interface`, `vrf`, `ip`, `mac`, `state` | No unresolved neighbors without MAC |
| Policy and NAT | Rule metadata and `selectors` as specified in `docs/API.md` | Groups, ranges, schedules, source ports, native semantics and complete rule evaluation are missing |
| Topology, F5/Avi virtual services | Staged raw only | No topology or load-balancer normalization |

Vendor-specific responses must first be transformed into the applicable normalized structure. Never report complete coverage for a partial API query or missing pagination. The schema and ingestion are not yet sufficient to analyze all listed products end to end.

The `fixtures` directory contains illustrative abbreviated vendor-shaped data, six normalized ingestion requests and a staged response. The vendor shapes are invented examples, not captured outputs or guaranteed API schemas; they cannot validate vendor adapters. All normalized fixtures are partial and are validated against the current adapter in `tests/test_fixtures.py`. They are suitable for future integration tests after authentication, source mappings, artifact approval and PostgreSQL are configured; the fixture test does not exercise the API or database.
