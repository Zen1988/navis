# Cisco IOS / IOS XE adapter

The partial adapter consumes the SSH/network_cli export. It targets IOS and IOS XE, not NX-OS, IOS XR or ASA. Source mappings use stable inventory/device identity.

Interfaces preserve explicit primary/secondary IPv4 and static IPv6 addresses, VRF attachments, shutdown intent and native configuration. Static routes support recursive gateways, explicit interfaces and Null0; conditional/tracked/global-lookup routes remain unresolved. Configured route evidence does not assert installation.

Active-RIB translation accepts explicit CIDR prefixes, native VRF headers, connected routes, recursive gateways, ECMP continuations and IPv6 multiline next hops. Known interface abbreviations resolve against collected identities. Interfaces in another VRF cannot become egresses. Local receive routes, implicit/classful masks and unsupported displays remain unresolved. When a RIB command was collected, configured static candidates do not fill its gaps. RIB evidence does not prove CEF/FIB coverage or implement general selection among competing candidates; distance/metric remain details.

ACL candidates preserve named/numbered identity, sequence order, interface/direction, IPv4/IPv6 family, hosts/prefixes/contiguous wildcard masks and numeric TCP/UDP source/destination ports. Established means ACK-or-RST flags, not proven session state. Discontiguous masks, named ports, object groups, ICMP conditions, time ranges and unsupported entries stay ordered unknown barriers. A later permit cannot bypass an unresolved earlier entry. Common/PostgreSQL matching requires actual ingress/egress scope; wrong/missing scope cannot apply an ACL default to another interface. Imported selectors and snapshot coverage remain incomplete.

NAT supports an explicit IPv4 inside-local/inside-global static host candidate. Dynamic/PAT/port/VRF/route-map/pool statements remain unknown records. The unverified IOS stage does not infer traversal, reverse rules, allocations or sessions. Native interface NAT roles are retained.

The CLI emits five partial envelopes: interface, route, policy, NAT and `ios_device_evidence` topology. Native output, unresolved entries and failures remain evidence. Raw topology does not establish graph links or connectivity. No migration is needed; source mapping and approval of the updated normalized adapter digest are required by the existing worker.

Remaining work includes live/version/Ansible/database integration, CEF/FIB, broader route displays/selection, PBR/ZBF/CBAC/L2 enforcement, complex ACLs, dynamic addressing, NAT stages/PAT/sessions and return paths. Synthetic unit/CLI tests include a mocked PostgreSQL ACL reader. Ansible and a YAML parser are unavailable locally; collector syntax/execution validation remains open. Begin with a controlled partial-ingestion pilot.

See [collector instructions](../examples/ansible/cisco_ios/README.md). References: [IOS command module](https://docs.ansible.com/projects/ansible/latest/collections/cisco/ios/ios_command_module.html), [Cisco route display reference](https://www.cisco.com/c/en/us/td/docs/ios/iproute_pi/command/reference/iri_book/iri_pi2.html), and [Cisco NAT command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-i3.html).
