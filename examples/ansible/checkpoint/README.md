# Check Point management-plane adapter

Use the Security Management Server Management API as the central source. Smart-1 Cloud and on-premises Management/Smart-1 deployments can expose it; SmartConsole is a client, not the endpoint. Supply the deployment's exact HTTPS `web_api` URL and domain. Navis does not log into gateways or receive management credentials.

The collector opens a read-only session, reads the native session domain UID, objects, gateways/clusters, full packages, layer settings/rulebases and NAT rulebases, then logs out in an always block. It never publishes, installs policy or runs scripts on gateways. TLS verification is enabled; credentials/session IDs stay in memory on the collector. Exported policy is sensitive and files use restrictive permissions.

Configure `checkpoint_api_url`, `checkpoint_username`, `checkpoint_password`, stable `checkpoint_management_id`, and optional `checkpoint_domain` through AWX credentials or encrypted Vault variables. Adjust page size/budget for the deployment and verify command support and account permissions against its Management API version.

```text
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

From the repository root with `PYTHONPATH=src` set:

```text
python examples/ansible/checkpoint/normalize.py checkpoint-output --package-uid PACKAGE_UID --gateway-uid GATEWAY_OR_CLUSTER_UID --namespace lab --external-device-id MAPPED_GATEWAY_ASSET --semantics checkpoint-semantics.json > checkpoint-ingestions.json
```

Select native UIDs, not display names. The external device ID must already map to the selected gateway/cluster in Navis. Run separately for each package and gateway; do not combine alternative packages into one effective installed policy. The CLI emits an array of policy and, when collected, NAT requests. Submit each individually through the authenticated `/v1/ingestions` flow. The CLI makes no network requests.

The adapter validates native pagination intervals/totals, domain ownership, package/layer identities and gateway targets. It preserves ordered layers and inline parent gates, native cleanup actions, source/destination negation, nested static address/service groups, IPv4/IPv6 hosts/networks/ranges, TCP/UDP services and supported port comparisons. UIDs distinguish same-name objects. A missing alternative does not become `any` or leave a narrowed selector behind. Unknown VPN/time/content/application/identity/dynamic conditions remain unresolved.

Ordered layers are independent stages: Accept proceeds to the next ordered layer; Drop stops. Inline rules are evaluated only after their parent matches, and inline cleanup does not fall through to the next parent rule. Generic matching and JSON details preserve that structure. The adapter does not invent implicit cleanup behavior when the native layer setting is missing.

NAT output supports deterministic manual static host/service translations and explicit Original/no-NAT markers. Automatic NAT can combine separate source and destination rules, so it remains unresolved rather than being flattened into ordinary first-match NAT. Hide NAT, network-offset mappings, gateway packet stages and allocations remain unverified. The common trace engine refuses the unverified Check Point NAT stage.

Management configuration is not proof of installed policy. Implied/global policy, routing/interfaces, VPN, cluster/VSX state, runtime application inspection and sessions need additional native evidence and development. Every request remains partial and policy/NAT selectors remain incomplete. No live Check Point collection or database integration has been verified. See [adapter scope](../../../docs/CHECKPOINT.md).

References: [Management API](https://sc1.checkpoint.com/documents/latest/APIs/), [ordered and inline layers](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Ordered-Layers-and-Inline-Layers.htm), [NAT policy](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_SecurityManagement_AdminGuide/Topics-SECMG/Configuring-NAT-Policy.htm).
