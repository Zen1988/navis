# FortiGate adapter

The collector-side adapter translates one FortiOS VDOM REST export. It emits six partial envelopes: interface, security zone, route, policy, NAT and `fortigate_vdom_evidence` topology. See the [collector instructions](../examples/ansible/fortigate/README.md). The API token stays on the collector.

**Status:** developed against synthetic responses shaped after FortiOS 7.x REST output. No live FortiGate collection has been run. Field names, especially in routing-monitor output, must be validated against your FortiOS release before relying on any result.

## Interfaces and zones

Interfaces belonging to the selected VDOM keep static IPv4 primary/secondary and static IPv6 addresses, VLAN ID, parent, VRF number and native type. DHCP/PPPoE/dynamic IPv6 addresses remain unresolved. Interfaces from other VDOMs are excluded.

FortiOS policies reference a zone, or an interface that is not in any zone. The adapter emits each configured zone with its members, plus one pseudo-zone per unzoned interface, named after the interface. Policy `srcintf`/`dstintf` become `source_zone`/`destination_zone` selectors, so traces need resolved ingress/egress zones. SD-WAN zones, inter-VDOM links and uncollected interfaces leave the role unresolved.

A zone with `intrazone allow` lets member traffic pass without a policy. Its precedence relative to explicit policies is unverified, so the adapter places an `unknown` intrazone rule first for that zone.

## Policies

`firewall/policy` entries keep REST order (sequence order, not policy ID), with implicit deny as the default. Supported matching:

- IPv4 and IPv6 address lists (`srcaddr`/`srcaddr6`, `dstaddr`/`dstaddr6`), subnet and range objects, nested static groups and per-family negation. A negated list keeps its family universe as a positive selector so it cannot match the other family. `all` resolves per family; a policy with only IPv4 addresses never matches IPv6.
- Custom TCP/UDP services with destination and source port ranges (`dst[-hi][:src[-hi]]`), service groups, negation and the IP protocol 0 `ALL` service.
- `accept`/`deny` actions and disabled status.

Unresolved conditions stay as ordered barriers. A later policy cannot bypass an earlier one that might match:

- FQDN, geography, wildcard, dynamic/SDN or MAC address objects
- address group exclusions
- ICMP, IP protocol and SCTP services
- schedules other than `always`
- users and groups
- ISDB (internet-service) objects
- application and URL categories
- `ipsec` action

Policies whose destination is a VIP match the VIP external address (the original destination), and `vip_destinations` records the VIP names. VIP groups as policy destinations remain unresolved.

## NAT

Static-NAT VIPs with one external host and one mapped host, optionally with a single-port forward, become deterministic destination-NAT candidates. Ranged VIPs, load-balance/FQDN VIPs, port ranges and VIP service filters remain unsupported records. VIP NAT uses the `fortigate_vip_destination_nat_before_policy_unverified` stage, which the trace engine does not evaluate. The ingress interface is recorded, but it isn't a selector.

Policy source NAT (`nat enable`) is recorded per policy, with its IP pools or egress-interface-address mode, as `unsupported`. Pool allocation and PAT are runtime state. With `central-nat enable`, policy NAT flags are ignored, and central SNAT entries are retained only as findings.

## Routing

Configured IPv4/IPv6 static routes support gateway plus device, device-only and blackhole routes, with distance, priority and weight in details. The following stay unresolved:

- named or ISDB destinations
- SD-WAN members
- dynamic gateways
- disabled routes

When `monitor/router/ipv4` is collected, active monitor entries replace configured candidates, and connected and blackhole entries are recognized. Configured routes don't fill gaps in the active table. Neither source establishes FIB installation or SD-WAN/policy-route selection.

## Remaining work

- live/version validation against real FortiOS responses (especially monitor fields)
- policy routes and SD-WAN rules
- central SNAT
- IP pool and VIP stages in the trace engine
- multi-VDOM and inter-VDOM links
- transparent mode and policy-based NGFW (`firewall/security-policy`)
- local-in policy
- HA, sessions and return paths

## Vendor references

- [Fortinet Document Library: FortiGate administration and REST API guides](https://docs.fortinet.com/product/fortigate) (choose your FortiOS release)
- [Fortinet Developer Network FortiOS REST API reference](https://fndn.fortinet.net/) (requires an FNDN account)
- [FortiOS Ansible collection](https://docs.ansible.com/projects/ansible/latest/collections/fortinet/fortios/fortios_httpapi.html)
