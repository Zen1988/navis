# NSX Local Manager DFW adapter

The adapter starts from a native VM external ID and resolves its vNICs, segment-port attachments and Applied To workload membership. It emits one policy and one interface request for the selected VM, keeping all of its NICs in the same snapshot pair by default. Each NIC has its own enforcement point and rule-footprint findings. Display names are labels, not stable identities.

## Collect and translate

The read-only Ansible collector queries Local Manager domains, groups, security policies and rule pages, services, VM/VIF inventory, resolved VM group members, segments and ports. Configure `nsx_base_url`, `nsx_username`, `nsx_password`, `nsx_domain`, stable `nsx_manager_id` and the page budget through AWX/Vault. TLS validation stays enabled; credentials remain on the collector. Use a fresh protected output directory per collection.

```text
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

From the repository root with `PYTHONPATH=src` set:

```text
python examples/ansible/nsx/normalize.py nsx-output --vm-external-id NATIVE_VM_ID --namespace lab --external-device-id MAPPED_VM_ASSET --semantics nsx-semantics.json > nsx-ingestions.json
```

The external device ID must map to the selected VM in Navis. Optional `--vif-external-id` restricts the output to one NIC; otherwise all native NICs associated with the selected VM are included. Submit each JSON array element individually to `/v1/ingestions`, then select the policy/interface snapshots in the graph dataset. The CLI performs no live API calls or policy changes.

## DFW scope and packet matching

Source/destination membership and Applied To are different concepts. VM membership uses native group-member IDs joined to VM and VIF inventory. A VM/IP address match alone does not prove that DFW is attached, enabled or realized on that NIC. VLAN-backed workloads are not automatically excluded; overlay/VLAN type alone cannot establish protection. Host preparation, exclusions, realized filters and the correct NIC/direction are still needed for an end-to-end conclusion.

IP-only groups can describe packet addresses but cannot establish Applied To workload scope. The adapter never substitutes broad DFW/ANY scope when a VM group, NIC attachment or membership is missing. Supported Generic groups may mix static address and workload expressions for packet matching, while mixed IP/workload enforcement expressions remain unresolved. An IP-only declared type containing incompatible workload members is flagged. Native types and expressions remain in the export/semantics evidence; they are not silently rewritten.

Policy group scope takes precedence where explicitly established. Broad policy scope combined with narrower rule scope is flagged pending version/effective-scope evidence instead of silently broadening enforcement. Explicit broad DFW scope is retained and counted. Every rule also preserves workload-relative IN/OUT/IN_OUT and IP family; the database matcher uses actual ingress/egress NIC identity. Missing NIC context returns unknown.

## Supported translation and limits

The adapter validates cursor termination/counts, domain/path identities, policy rule counts, and category/sequence ordering. Duplicate/unknown order remains uncertain. It supports IP hosts/subnets/ranges, selected static/nested group expressions, resolved VM groups, TCP/UDP service entries and nested services, exclusions, disabled rules, statefulness and ALLOW/DROP/REJECT. L2/L7/identity/scheduling/jump behavior and incomplete dynamic expressions remain unresolved.

Per-NIC findings distinguish known applicable enabled intent rules, explicit broad-scope rules and unknown-scope rules. These are configuration footprints, not realized filter counts. No 5k/50k limit is hard-coded: validated NSX version/form-factor limits and realized per-NIC/host counts are required before a capacity verdict. There is no automatic broad-scope fallback or policy publication.

All requests remain partial and worker-imported selectors incomplete. Group resolution and VM/IP expansion are bounded for adapter resource use; these bounds are not vendor configuration maxima. Global Manager/federation/VMC-specific scopes, NIC exclusion/host-preparation/realization proof, gateway firewall/NAT/routing, and live integration remain open. See [NSX adapter design](../../../docs/NSX.md).

References: [Policy scope/order/statefulness](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_SecurityPolicy.html), [group types/expressions](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_Group.html), [workload-relative direction](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_Rule.html), [DFW capacity and broad Applied To](https://knowledge.broadcom.com/external/article/371437/dfw-rules-limit-per-host-exceeded-and-df.html).
