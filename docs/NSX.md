# NSX VM/vNIC-first DFW adapter

The collector-side adapter supports NSX Local Manager Policy `/infra` resources for one selected domain. Translation starts with a stable VM external ID, resolves all of that VM's vNICs by native ownership IDs, and joins segment ports through attachment IDs. Duplicate display names never merge VM identities. Each NIC has an independent enforcement point, while the VM's policy/interface records share a pair of data-type snapshots. The CLI can explicitly restrict output to one vNIC.

## Native evidence

Collection uses authenticated read-only GET requests for domains, groups, policies/rules, services, VM/VIF inventory, resolved group VM members, segments and segment ports. It verifies cursor termination and retains native JSON pages. Translation validates counts, resource paths/IDs, selected domain, rulebase parent paths and rule counts. Native VM/VIF IDs and full group expressions/types survive in semantic evidence; rule details preserve native group types, scope references, policy/rule identifiers and conditions.

VM group addresses come from resolved native VM membership joined to observed vNIC IP bindings. A VM-name/tag criterion is not expanded by guessing from display names. Missing members, bindings or attachments remain unresolved. Group references, selected static OR expressions, IP hosts/subnets/ranges, external VM IDs, segment/port references and nested groups are supported where their meaning can be established. AND/mixed dynamic/identity/extended expressions outside the supported native-member case remain uncertain. Failed/pending/deleted groups are not treated as established membership.

## Applied To versus packet addresses

Packet source/destination groups and Applied To enforcement are evaluated separately. IP-only groups can supply address selectors but cannot establish a vNIC enforcement scope. A Generic group can validly contain different member types for some uses; the adapter therefore does not call every mixed group malformed. Mixed IP/workload expressions used for enforcement remain unresolved, while an IP-only declared type with incompatible workload members is explicitly flagged.

VM/vNIC-based scope is the primary path. The adapter does not replace an unresolved group or NIC with broad DFW scope. Explicit broad scope is preserved and counted. An explicit policy workload scope takes precedence over rule scope; broad-policy/narrow-rule combinations require version/effective-scope evidence and are flagged without silently broadening enforcement.

VLAN or overlay transport alone establishes neither applicability nor exemption. NSX-supported VLAN-backed/DVPG workloads can also use DFW depending on version and host preparation. A unique NIC-to-port attachment proves an inventory association, not realized protection. Host preparation, DFW exclusion lists and realized filters remain independent requirements.

## Rule evaluation

The adapter preserves DFW category priority, policy/rule sequence numbers, native paths and rule IDs, ALLOW/DROP/REJECT, disabled state, exclusions, statefulness, IP family and workload-relative IN/OUT/IN_OUT. Duplicate or unknown ordering, unsupported categories/actions, L2/L7/context profiles, generated defaults not established by collected rules, and scheduling remain unresolved.

TCP/UDP service entries preserve source/destination port lists/ranges. Nested service paths are supported with cycle/expansion checks. Ambiguous ANY plus inline-service combinations are not widened into unrestricted services. A missing alternative removes the entire unresolved role rather than leaving a narrowed rule that could be skipped during first-match evaluation.

Normalized `details.workload_condition` names the exact VIF, direction, IP family and condition completeness. The common matcher requires the actual enforcement NIC; the PostgreSQL policy reader derives inbound/outbound context from the selected path's ingress/egress interface IDs. Unknown NIC context stays unknown even if addresses and services match. Imported selector completeness remains false, and no forward allow implies a realized session or end-to-end connectivity.

## Per-NIC rule footprint

Capacity evidence records known applicable enabled intent rules, explicit broad-scope enabled rules and unknown-scope enabled rules for each NIC. Counts do not claim realized hardware/filter expansion. Validated version/form-factor limits and runtime per-NIC/host counts are still required; no 5k/50k ceiling is inferred. Broad-scope findings identify possible policy replication costs without rewriting/publishing rules. Cached membership resolution and bounded expansion control adapter work; these bounds are not NSX vendor maxima.

## Validation and remaining work

Synthetic native JSON and CLI tests cover VLAN-backed attachments, duplicate VM names, native VM/VIF joins, all-NIC snapshot aggregation, policy/rule ordering, direction/family matching, native member/IP resolution, IP-only and mixed scope regressions, broad-scope counts, missing attachments/members, nested services and pagination/path validation. Mocked database-reader tests require the exact ingress/egress VIF and matching direction.

The implementation is a partial DFW adapter, not full NSX support. Realized filters, host preparation/exclusions, VM/IP binding trust/freshness, validated capacity maxima, Global Manager/federation/project/VMC scopes, L2/L7/identity behavior, gateway firewall/NAT/routing and live/database integration remain open. No live collection or end-to-end verdict has been verified. Use the [collector guide](../examples/ansible/nsx/README.md) for current supported inputs.

## Vendor references

- [Security Policy scope, category order and statefulness](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_SecurityPolicy.html)
- [Rule direction, groups and services](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_Rule.html)
- [Group types and expressions](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_Group.html)
- [Native VIF ownership and attachment fields](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_VirtualNetworkInterface.html)
- [DFW per-host/per-vNIC capacity and Applied To](https://knowledge.broadcom.com/external/article/371437/dfw-rules-limit-per-host-exceeded-and-df.html)
- [VLAN-backed VM discovery and group membership](https://knowledge.broadcom.com/external/article/428694/nsx-vms-connected-to-vlanbacked-segments.html)
