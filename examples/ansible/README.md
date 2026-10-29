# Collector examples

For current implementations and adapter gaps, see [project status](../../docs/STATUS.md). The ACI example now includes a partial collector-side adapter; the general examples below are not a complete inventory of implemented collectors.

These are partial, read-only examples, not production collectors or complete network discovery. Run on an Ansible controller with network access and credentials managed in AWX/Ansible Vault or another external secret store. Navis does not receive device credentials. Verify endpoints, version compatibility, permissions, pagination, certificates and response redaction for your platform. Some outputs may contain sensitive configuration.

`rest_discovery.yml` demonstrates a single GET using an externally supplied URL and bearer token, with TLS verification enabled. Use the documented endpoint examples below as a starting point, then implement platform-specific authentication and pagination. API responses are not the Navis normalized JSON format: do not submit them as `navis/normalized-json/1`. Navis currently has no native vendor adapters and its ingestion API is not configured by default.

| Product | Partial discovery example | Documentation |
| --- | --- | --- |
| VMware NSX | `GET /policy/api/v1/infra/domains/{domain-id}/security-policies` | [NSX security policies](https://developer.broadcom.com/xapis/nsx-vmc-policy/latest/policy/api/v1/infra/domains/domain-id/security-policies/get/) (check your NSX deployment and API version; follow cursors) |
| Cisco ACI | Query APIC class `fvTenant` | [ACI REST API](https://developer.cisco.com/docs/apic-rest-api-configuration-guide/) |
| Cisco Nexus | Use NX-API or Ansible NX-OS commands to obtain routes and interfaces | [Cisco NX-OS Ansible collection](https://docs.ansible.com/projects/ansible/latest/collections/cisco/nxos/) |
| Palo Alto | Use the PAN-OS API to retrieve policies and operational state | [PAN-OS API](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api) |
| F5 BIG-IP | `GET /mgmt/tm/ltm/virtual` | [iControl REST virtual servers](https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_ltm_virtual.html) |
| VMware Avi | Retrieve virtual services from the controller API | [Avi API guide](https://developer.broadcom.com/xapis/vmware-avi-load-balancer/latest/) |
| FortiGate | Use FortiOS REST API through the Fortinet Ansible collection | [FortiOS HTTP API plugin](https://docs.ansible.com/projects/ansible/latest/collections/fortinet/fortios/fortios_httpapi.html) |

Example invocation (provide variables through a protected AWX credential or Vault, not command-line history):

```text
ansible-playbook -i localhost, rest_discovery.yml -e @protected-vars.yml
```

Required variables: `collector_url`, `collector_token`. The token is not printed. The example reports only HTTP status, not the collected payload; a real adapter must sanitize and map the response before sending it to Navis.

`submit_normalized.yml` shows the actual Navis POST with a partial interface fixture. Provide `navis_url`, `navis_token`, `navis_source_namespace`, `navis_external_device_id`, and a timezone-aware ISO timestamp as `navis_collected_at`. See [CONTRACT.md](CONTRACT.md) for the response and current normalization gaps.
