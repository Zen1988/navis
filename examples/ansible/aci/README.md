# Cisco ACI collection example

`collect.yml` collects selected native ACI objects from **one APIC in one fabric** using read-only GETs. APIC exposes fabric inventory, tenants, VRFs, bridge domains, EPGs, contract/filter objects, learned endpoints and selected adjacency objects. A healthy APIC cluster represents the fabric; querying every controller is not normally required to collect the same fabric model. For separate fabrics or sites, run separately with a distinct `aci_fabric_id` and output directory. Validate scope and permissions for your APIC release and account.

APIC learned endpoint records are not a complete MAC forwarding table for every Nexus switch. Standalone Nexus devices outside the fabric need separate collection. Even within a fabric, endpoint visibility is operational and may be incomplete or aged; this example does not promise per-leaf hardware MAC tables, full routes, or end-to-end topology. Gather those separately where needed and supported.

The selected classes include `uribv4Route`, `uribv4Nexthop`, `uribv6Route`, and `uribv6Nexthop` as candidate APIC operational routing data. Preserve their full native objects and distinguished names: the ACI adapter must resolve node, VRF, route and next-hop relationships rather than treating an address as globally unique. Validate class availability, scope, pagination, and actual contents for each APIC release and role. URIB data must not automatically be labeled as a complete installed forwarding table; compare it with the supported forwarding evidence before asserting a path. The collector does not yet normalize or submit these objects to Navis.

APIC also supports node-scoped queries such as `topology/pod-1/node-101/l1PhysIf`; see the [Cisco REST API guide](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/all/apic-rest-api-configuration-guide/cisco-apic-rest-api-configuration-guide/m_using_the_rest_api.html). This example queries `fabricNode`, `l1PhysIf` and `ethpmPhysIf` fabric-wide and preserves native objects; it does not yet enumerate nodes and issue dedicated per-node queries. Node-scoped queries can supplement it where fabric-wide results or permissions are incomplete.

Install the collection on the Ansible controller:

```text
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

Provide `apic_host`, `apic_username`, `apic_password`, and `aci_fabric_id` through AWX credentials or an encrypted Ansible Vault file. The controller must trust the APIC certificate. Set `aci_output_dir`, `aci_page_size`, and `aci_max_pages` as needed. The example reads a bounded number of pages and fails if the final page is full; use an appropriately scoped account and limit load. A failed or inaccessible class fails the play; APIC versions and roles differ.

Each class file contains an array of pages from the module's `current` output. Metadata marks coverage `partial`: class queries are made at different times and do not constitute a complete or atomic fabric snapshot. Output can reveal network topology and policy and is stored locally with restricted permissions. Protect and delete it according to your environment's data policy. No credentials are written to Navis.

The collector-side adapter currently converts physical interface objects and their operational status to per-device Navis normalized ingestion requests. It does not yet translate routes, contracts, EPGs, addresses or topology. The worker still accepts the built-in normalized format; it does not execute native ACI input. Contract/filter/EPG translation requires preserving direction, priorities, scope, defaults and unsupported semantics. ACI endpoints are not automatically a physical switch-to-switch path, and successful collection does not prove connectivity.

Create a JSON mapping from APIC pod/node paths to existing external IDs in the chosen Navis source namespace, for example:

```json
{"topology/pod-1/node-101": "asset001", "topology/pod-1/node-102": "asset002"}
```

From the repository root, with Python and the project package installed (or `PYTHONPATH` set to `src`), run:

```text
python examples/ansible/aci/normalize.py aci-output --namespace lab --identities node-identities.json
```

Pass `--inventory aci-inventory.json` to additionally translate every class listed in `collect.yml` into a separate typed evidence inventory. It preserves each object's APIC attributes and DN, records collected parent-child relationships and explicit `tDn` references, identifies missing classes and unresolved targets, and always marks coverage partial. Names without an explicit target DN are not resolved by guessing. This inventory is an intermediate artifact, not an ingestion request or effective forwarding or policy rules.

Pass `--semantics aci-semantics.json` to also generate candidate route prefixes and next hops, and contract subjects, filter entries and linked consumer/provider EPGs. Explicit target DNs are preferred; unqualified names are resolved only against a unique same-tenant object with no conflicting common-tenant name. Qualified and ambiguous names remain unresolved. TCP, UDP, ICMP and ICMPv6 protocol names and numeric source/destination port ranges are extracted where present; unsupported names and unspecified values remain unknown. These retain native identifiers and remain unverified: no installed-forwarding assertion, effective contract evaluation, route or policy ingestion is generated. Unsupported or unresolved relationships are recorded as findings. APIC releases may encode references differently; validate with real output.

The semantic output also associates EPGs with bridge domains, bridge domains with VRFs and subnet gateway addresses, and learned endpoints with collected IP and attachment objects. These are partial observations, not proof of endpoint reachability or physical links; missing, ambiguous and invalid references appear as findings.

L3Out mappings include external EPG prefixes and scopes, VRF associations, node and interface attachment observations, and external EPG contract references. Candidate consumer-to-provider policy records are generated from resolved subject/filter entries, but are explicitly unverified and are not installed as effective rules: labels, directional subjects, priorities, preferred groups, transit restrictions, deployment and enforcement still need additional evidence and semantics. LLDP/CDP records remain unverified observations, not automatically physical graph links.

Candidates carry contract and filter provenance, consumer/provider roles, native direction and action, extracted service fields, and unresolved reasons. `candidate_action` is a translation of an explicit native action, not an access verdict. The legacy `source_epg` and `destination_epg` fields encode consumer and provider roles and must not be interpreted as packet direction. Migration `015_aci_policy_candidate_view.sql` exposes stored candidates in `navis.aci_policy_candidate`; the view is not connected to policy evaluation or a scoped API.

The trace processor can return `aci_policy_evidence` for potentially relevant candidates from fabric topology snapshots selected in the authorized graph build. It compares collected endpoint addresses and external EPG `import-security` prefixes against the requested addresses. Evidence can be incomplete, stale or ambiguous, and protocol and port matching are not fully evaluated. No candidate changes the trace decision or coverage. Missing candidates do not imply absence of policy. Add the raw-only fabric snapshot to the dataset under `data_type = 'topology'` and rebuild the graph to include it; the fabric identity and source must be in the caller's `analysis:run` scope. The build evidence manifest does not currently fingerprint raw payloads, so this evidence does not establish snapshot immutability.

The collector also requests directional contract terms, filter relationships, labels and exceptions. The adapter preserves the native term direction, label and exception attributes, priority override, and route node/next-hop VRF information. Candidate policy evidence includes EPG and provider/consumer subject label comparisons when their classes and explicit match types are available, based on Cisco's published matching table. These comparisons remain partial because collection completeness, exceptions and enforcement are not established; they are not an allow or deny verdict. The adapter does not yet calculate effective direction or policy precedence. URIB collection is subject to APIC version, access and scope, and is not the installed forwarding table; a successful query does not guarantee all device routes were returned.

To also emit a `topology` ingestion request containing the partial fabric inventory and semantic evidence, supply `--fabric-external-id FABRIC_ID`. This must be an existing, unique, time-valid device identity mapping in the selected source namespace, representing the fabric collection identity; do not substitute a leaf identity. After API submission and manual worker processing, the existing worker stores this payload in `navis.raw_payload` with submission status `raw_only`. It does not create topology links, graph edges, route or policy records from the payload. The graph builder and trace engine do not consume this fabric evidence yet. This reuses the existing device-oriented storage contract; a dedicated fabric identity model remains future work.

Migration `014_aci_evidence_views.sql` makes stored fabric evidence queryable in `navis.aci_fabric_evidence`, `navis.aci_evidence_object`, `navis.aci_evidence_relationship` and `navis.aci_evidence_finding`. Filter by `snapshot_id` or `raw_payload_id` to avoid mixing collection times. These views expose unverified information and are not an authorized API: database roles must be restricted appropriately. The SQL integration check `examples/aci-evidence-views-check.sql` requires an existing snapshot and rolls its test insertion back.

Example after submitting and processing a fabric request:

```sql
SELECT native_dn, native_class, object_kind
FROM navis.aci_evidence_object WHERE snapshot_id = '<snapshot-uuid>';
SELECT relationship_kind, source_dn, target_dn, resolved
FROM navis.aci_evidence_relationship WHERE snapshot_id = '<snapshot-uuid>';
```

The command prints a JSON array of interface requests. Submit each array element separately to `POST /v1/ingestions` using the existing authenticated ingestion workflow; this command does not submit data. Identity mappings must already exist in Navis, and its normalized adapter must be approved before worker processing. Each request has partial coverage and no inferred addresses. Keep the output protected. Use a unique source namespace or explicit identity mapping per fabric; pod/node IDs alone are not globally unique.

References: [Cisco APIC REST guide](https://developer.cisco.com/docs/apic-rest-api-configuration-guide/), [ACI REST Ansible module](https://docs.ansible.com/projects/ansible/latest/collections/cisco/aci/aci_rest_module.html), [Cisco NX-OS Ansible collection](https://docs.ansible.com/projects/ansible/latest/collections/cisco/nxos/).

To emit a normalized policy request as well as raw fabric evidence, add `--policy --fabric-external-id FABRIC_ID`. Each candidate becomes a policy row with its ACI evidence in `details`. The adapter derives candidate selectors from learned endpoint IPs, external security prefixes and supported filter services; an unknown default, partial coverage and incomplete selector status keep evaluation unknown. Positions are deterministic storage order, not ACI precedence, and the fabric identity is not a leaf enforcement point. These records cannot establish an effective allow or deny. Because the normalized adapter changed, approve its new artifact hash before processing; rebuild or update the worker code too.


