# Check Point management-plane adapter

The collector reads the Security Management Server Management API through a read-only session. It supports the same API boundary for Smart-1 Cloud and on-premises management. It never publishes/installs policy, executes gateway scripts or requires gateway login. [Collection and translation commands](../examples/ansible/checkpoint/README.md) use external credentials and mapped gateway identities.

## Native inputs and identity

`metadata.json` carries a stable management ID, native session domain UID and collection time. Other inputs are native paginated `objects.json`, `gateways.json`, `packages.json`, `access-layers.json`, full `package-UID.json`/`layer-UID.json`, `access-UID.json` rulebase pages and optional `nat-PACKAGE_UID.json`. The CLI selects one package and gateway/cluster by UID. It emits normalized policy and optional NAT requests while preserving native evidence in details.

The adapter verifies pagination intervals/totals, full package ordered-layer references, layer/page UIDs, package/gateway domain association and installation targets. Same-name objects remain distinct by UID. Conflicting semantic/domain evidence fails translation. Cross-domain objects require established association; unresolved references never become wildcards. Partial pages or missing/overlapping intervals fail instead of being called complete. Empty trailing responses from the bounded collector are tolerated after accounting for the native total.

## Access Control

Supported selectors include IPv4/IPv6 host, network and inclusive range objects; nested static address/service groups; source/destination/service negation; and TCP/UDP ports, ranges and numeric comparisons. Unknown members remove the entire unresolved selector role so an earlier rule cannot be skipped merely because only some alternatives resolved. FQDN/dynamic objects, exclusion groups, identities, service/application inspection, VPN/time/content constraints and unknown rule fields retain uncertainty.

Sections are presentation containers and preserve child order. Ordered layers retain package order as independent stages. Every ordered layer must allow; an Accept advances to the next layer, and a Drop stops evaluation. Inline layers remain nested under their parent rule. Parent nonmatch resumes the outer layer; parent match evaluates the child layer and its cleanup, without falling through to a later parent rule. Cycles, missing child layers and excessive expansion remain errors or unresolved inline conditions.

Native `implicit-cleanup-action` supplies each layer's cleanup behavior. A derived cleanup record preserves an otherwise empty layer in normalized storage; missing native settings produce unknown, not an assumed Drop. Explicit layer targeting, gateway/cluster UIDs, rule enabled state, native rule UIDs/numbers, and statefulness survive translation. Configuration does not prove a supported session exists.

The common policy matcher supports nested `details.inline_rules`, `inline_default` and `inline_complete`, plus an ordered-layer evaluator. Nested selectors are validated and preserved in JSON details, and the PostgreSQL policy reader passes details to the matcher. Worker-imported selectors remain incomplete, including inline children, until their evidence and coverage are explicitly established.

## NAT

NAT rulebases retain management order, object references, targeting, native methods and automatic/manual flags. Supported deterministic candidates include manual static host source/destination/combined translations, compatible single-port service translation and explicit Original/no-NAT markers. Host/network/range mappings are not conflated; offset-aware network mapping needs further implementation.

Automatic NAT may enforce separate source and destination rules for one connection. Such rules remain unsupported candidates instead of ordinary first-match translations. Hide/dynamic NAT requires allocation evidence. The normalized stage is `checkpoint_management_nat_stage_unverified`: packet stage and gateway settings are not established from this export, and the trace engine refuses to apply it. Native rules remain available for further translation and review.

## Validation and next work

Synthetic native-style JSON and CLI tests cover domain/UID isolation, targets, pagination, nested objects, negation, ordered/inline control flow, cleanup behavior, unsupported conditions, manual NAT and automatic/hide NAT uncertainty. Supported-condition tests explicitly enable completeness only for isolated fixtures; exported submissions remain partial. No live Management API run, policy installation check or database round trip has been verified.

Next work is representative management exports, implied/global-policy and installed-package evidence, complete automatic/manual NAT ordering and packet stages, and supported management-proxied gateway operational evidence for routing/interfaces, clusters/VSX and sessions. Management policy alone cannot establish those states. Do not promote this adapter to production-ready based on unit tests.

## References

- [Check Point Management API](https://sc1.checkpoint.com/documents/latest/APIs/)
- [Ordered and inline layer enforcement](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Ordered-Layers-and-Inline-Layers.htm)
- [Automatic and manual NAT behavior](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_SecurityManagement_AdminGuide/Topics-SECMG/Configuring-NAT-Policy.htm)
