# Palo Alto adapter

The collector-side adapter translates native firewall configuration and optional inherited/application/routing evidence for one explicit serial, device entry and VSYS. It emits five partial Navis ingestion requests: policy, security zone, NAT, interface and route. See the [collector instructions](../examples/ansible/paloalto/README.md). Device credentials remain on the collector.

## Inheritance

The preferred input is the firewall's pushed `/config/panorama` XML. Alternatively, supply Panorama's full config and native `show dg-hierarchy` response. The adapter discovers serial/VSYS device-group membership, walks its ancestry, and assembles shared/ancestor/descendant pre-rules, local rules, descendant/ancestor/shared post-rules, then defaults. Missing or ambiguous membership/ancestry and duplicate rules within one scope fail translation. Two inherited sources cannot be combined.

Identities preserve inherited scope and phase, including same-name rules. Explicit serial/VSYS targets and negated targets are evaluated. Intrazone allow and interzone deny are separate zone-relation rules; native default-rule overrides merge from shared through descendants to local scope. Generated defaults use `derived_xml`; ordinary rules retain native XML, UUID and action.

Address/service objects, nested static groups, IPv4/IPv6 hosts/subnets/ranges, negation, port lists/ranges, disabled rules and layer-3 zones remain supported. Conflicting raw Panorama objects remain unresolved because ancestor/descendant precedence can be reversed. Prefer firewall-pushed values. Assembling configuration does not prove successful push/deployment or active HA enforcement.

## App-ID

Explicit application groups and collected predefined containers (`functions/member`) expand into leaf identities. Missing definitions and dynamic filters remain unresolved. `application-default` uses collected predefined/custom definitions, preserving each application's protocol/port pairing. TCP/UDP numeric defaults are supported; missing, negotiated/dynamic or unsupported definitions remain unknown.

The common matcher and database reader preserve `details.application_condition`. Trace requests accept optional `application` for a caller-supplied application scenario. This is not proof of firewall classification. Without identity, an application-dependent match is unknown. Ports alone cannot establish App-ID, signature matches, dependencies, decryption or reclassification.

## NAT

Ordered rules preserve scope, targets, UUID and native XML. Supported deterministic translations include host static source NAT, host destination NAT, destination port translation, combined source/destination translation and explicit no-NAT rules. Dynamic IP/PAT, bidirectional static reverse mappings, NPTv6 and HA bindings retain explicit unresolved evidence; pools never become arbitrary fixed hosts or ports.

The normalized stage `original_addresses_pre_nat_zones_then_post_nat_zone_policy` requires:

1. Original-destination routing/zone for NAT matching.
2. NAT matching on original addresses, ports and zones.
3. Translated-destination routing/zone for security matching.
4. Security matching on original addresses/ports and post-NAT destination zone.
5. Translated packet forwarding.

The common staged evaluator and PostgreSQL trace reader support this distinction. Candidate-path policy evaluation previews deterministic NAT to resolve post-NAT egress while retaining original policy addresses. Unknown routing, zones, selectors or allocations prevent definitive decisions. Forward static mappings do not establish reverse sessions.

## Routing and interfaces

Configured Ethernet, aggregate, loopback, tunnel, VLAN and subinterface addresses are scoped by VSYS imports/zone membership and linked to virtual routers. Parent relationships and VLAN tags are preserved. Missing/ambiguous router associations produce findings.

Configured IPv4/IPv6 static routes include IP next hops, interface routes, recursive IP next hops and discard behavior. Next-VR recursion, monitored static-route state and unsupported next hops remain unresolved candidates. Operational XML contributes active routes only (`A` flags), including connected routes and multiple active next hops. Inactive and foreign/unknown-router entries are excluded. When operational evidence is supplied, normalized routes use it rather than duplicating configured candidates.

Configured routes and active RIB entries are not verified installed FIB entries. Advanced-routing logical routers, PBF, template-stack merge conflicts, HA and runtime sessions remain unsupported or require native evidence.

## Validation and remaining work

Synthetic fixtures test inheritance/order/targets/defaults, scoped identities, application/port pairing and containers, deterministic/unsupported NAT, original/post-NAT zone stages, static/active/recursive/discard routes, ECMP and VSYS isolation. Mocked database-reader tests verify App-ID conditions and NAT zone selectors. CLI output passes normalized validation.

All submissions remain partial. The worker forces imported policy/NAT selectors incomplete; `translated_conditions_complete` is not a coverage assertion. No live firewall/Panorama collection or database round trip has been verified. Next work is representative device validation, runtime application/object/allocation evidence, bidirectional/network NAT, advanced routing and explicit promotion of validated coverage.

## Vendor references

- [XML API, pushed policy and predefined applications](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api)
- [Inheritance and policy order](https://docs.paloaltonetworks.com/panorama/getting-started/panorama-overview/centrally-manage-firewall-configuration-and-updates-with-panorama/device-groups)
- [Object precedence](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-precedence-of-inherited-objects)
- [Application-default](https://docs.paloaltonetworks.com/ngfw/help/11-2/policies/policies-security/building-blocks-in-a-security-policy-rule)
- [NAT address/zone semantics](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)
- [Native hierarchy parser](https://pan-os-python.readthedocs.io/en/latest/_modules/panos/panorama.html)
