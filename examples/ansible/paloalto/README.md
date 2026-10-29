# Panorama collection example

Use Panorama as the central entry point when firewalls are managed there. This example sends selected read-only XML API requests through Panorama with a target firewall serial; it does not log in to firewalls from Navis. It is a starting point for collection, not a complete Palo Alto adapter.

Panorama policy is hierarchical. Shared and device-group pre-rules, local rules, post-rules, defaults, inherited and overridden objects, and device/VSYS targeting affect the actual rule order. The selected firewall configuration requests here do not establish that complete effective policy. Collect and reconcile Panorama hierarchy and effective firewall state before marking policy coverage complete. Use operational route, ARP, interface, HA and PBF data from the targeted firewall where supported; this example does not yet collect operational routing or establish the active HA peer.

Supply `panorama_host`, `panorama_api_key`, and `firewall_serials` as a list through AWX credentials or an encrypted Ansible Vault file. The Ansible controller must trust Panorama's TLS certificate. The API key stays on the collector; do not submit it to Navis. The output contains potentially sensitive configuration and is stored with restrictive permissions. Query responses can differ by PAN-OS version, target permissions and management topology. Validate all requested XPath values and returned XML against your environment; a successful HTTP response alone is not proof of complete data.

Run from this directory:

```text
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

Responses are saved as native XML, organized by serial. The metadata is explicitly partial. No automatic device discovery, pagination, redaction, normalization, or Navis ingestion is implemented. Some objects or policy attributes may contain sensitive material: review and redact before any submission. An effective-policy adapter must preserve original/pushed provenance without storing device credentials.

References: [Query a firewall from Panorama](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api), [Device-group policy inheritance](https://docs.paloaltonetworks.com/panorama/getting-started/panorama-overview/centrally-manage-firewall-configuration-and-updates-with-panorama/device-groups), [XML configuration API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api).
