# Check Point collection example

Use the Check Point **Security Management Server Management API** as the central source for management objects and policy. Smart-1 Cloud is a hosted management service exposing this API; an on-premises Smart-1 or Security Management Server can provide it as well. SmartConsole is a client, not the API endpoint. Use the exact `web_api` base URL and domain for your deployment and API version.

This playbook uses read-only Management API commands to collect gateway inventory and policy packages, discover access layers via `show-access-layers`, and collect the discovered layers by UID. It performs bounded pagination, verifies the discovered count, logs out, preserves response pages, and marks coverage partial. It does not publish or install policy. Supply `checkpoint_api_url`, `checkpoint_username`, `checkpoint_password`, and optional `checkpoint_domain` through an AWX credential or encrypted Ansible Vault file. Credentials and session IDs remain with the collector. TLS certificate validation is enabled.

```text
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

Validate command availability, pagination, response `total`, access-layer identifiers, and account permissions against your Management API version. The example intentionally fails rather than asserting completeness if pagination cannot be verified. Policy data can be sensitive; output files have restrictive permissions and require protected retention.

Management policy and gateway state are different evidence. This example does not collect NAT rulebases, all objects and nested groups, inline layers, installed-policy state, gateway routes/interfaces, cluster/VSX context, or effective gateway state. A gateway-specific collector or supported management-proxied operational query is needed for those details; availability depends on the deployment. No Check Point adapter, normalization, or Navis submission is implemented. Raw API results must not be marked complete or treated as effective policy.

References: [Smart-1 Cloud Management API](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Check-Point-SmartCloud-Admin-Guide/Topics-Smart-1-Cloud/Best-Practices.htm), [Check Point Management API reference](https://sc1.checkpoint.com/documents/latest/APIs/).
