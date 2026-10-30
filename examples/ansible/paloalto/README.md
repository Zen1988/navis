# Panorama collection example

Use Panorama as the central entry point when firewalls are managed there. This example sends selected read-only XML API requests through Panorama with a target firewall serial; it does not log in to firewalls from Navis. It is a starting point for collection, not a complete Palo Alto adapter.

Collection now includes Panorama config and native device-group hierarchy, plus targeted running config, pushed config, predefined applications and operational routes. The adapter prefers the firewall's pushed rules/objects; raw Panorama hierarchy can be selected explicitly. Commit/push state, active HA peer and verified installed forwarding remain unestablished. Requests and XML shapes must be checked against the deployment's PAN-OS version and routing engine.

Supply `panorama_host`, `panorama_api_key`, and `firewall_serials` as a list through AWX credentials or an encrypted Ansible Vault file. The Ansible controller must trust Panorama's TLS certificate. The API key stays on the collector; do not submit it to Navis. The output contains potentially sensitive configuration and is stored with restrictive permissions. Query responses can differ by PAN-OS version, target permissions and management topology. Validate all requested XPath values and returned XML against your environment; a successful HTTP response alone is not proof of complete data.

Run from this directory:

```text
ansible-playbook -i localhost, collect.yml -e @protected-vars.yml
```

Responses are saved as native XML, organized by serial. `running-config.xml` is a full `/config` read with `action=show` (running, rather than candidate configuration), preserving shared-object and VSYS ancestry. Protect this file: it can contain unrelated sensitive device settings. The translator only includes selected security-rule XML and translated selectors in its output. The metadata remains explicitly partial. No automatic device discovery, redaction, or Navis submission is implemented.

From the repository root with `PYTHONPATH=src` set, translate one explicitly selected firewall/VSYS:

```text
python examples/ansible/paloalto/normalize.py panorama-output --serial SERIAL --device-entry localhost.localdomain --vsys vsys1 --namespace lab --external-device-id FIREWALL_ASSET_ID --semantics paloalto-semantics.json > paloalto-ingestions.json
```

Use the exact device-entry name in the returned XML and a pre-mapped Navis external device ID. The serial must appear in collection metadata. Run separately for each VSYS. The CLI writes policy, security-zone, NAT, interface and route requests; submit each individually to `/v1/ingestions`. It does not contact Navis or the firewall. Select the corresponding data-type snapshots when building the graph dataset.

Evidence files are discovered automatically: `SERIAL/pushed-config.xml`, `SERIAL/applications.xml`, and `SERIAL/routes.xml`. If pushed config is absent, root-level `panorama-config.xml` and `device-group-hierarchy.xml` are used. Explicit paths can be supplied through `--pushed-config`, `--panorama-config`, `--hierarchy`, `--applications`, and `--routes`. `--panorama-config` selects raw hierarchy instead of pushed data. Hierarchy assembly discovers membership from native serial/VSYS assignments; no hand-authored policy mapping is needed.

Supported translation covers inherited pre/local/post order, explicit targets and zone defaults, static address/service groups, App-ID groups/containers and application-default numeric ports, deterministic host SNAT/DNAT/combined NAT, configured interfaces/static routes and active operational routes. App-ID matching requires explicit application identity; NAT uses original-address/pre-NAT-zone matching followed by original-address/post-NAT-zone security matching. Dynamic PAT, conflicting raw inherited objects, dynamic applications/objects, schedules, advanced routing, HA and sessions retain uncertainty. The worker still marks imported selectors incomplete. See [project status](../../../docs/STATUS.md) and [adapter scope](../../../docs/PALO_ALTO.md). Review sensitive policy output before submission.

References: [Query a firewall from Panorama](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api), [Device-group policy inheritance](https://docs.paloaltonetworks.com/panorama/getting-started/panorama-overview/centrally-manage-firewall-configuration-and-updates-with-panorama/device-groups), [XML configuration API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api).
