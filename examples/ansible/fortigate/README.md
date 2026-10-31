# FortiGate FortiOS REST collection

The Python collector in this directory makes HTTPS GET requests to the FortiOS REST API (`/api/v2/cmdb/...` and `/api/v2/monitor/router/...`) for one VDOM. It does not change configuration, log in with a password or use the CLI.

## Device preparation

1. Create an admin profile with **read** access to System, Network (Router), and Firewall policy/address/service objects. Nothing needs write access.
2. Create a **REST API administrator** (System → Administrators → Create New → REST API Admin) that uses that profile. Limit it to the VDOMs you collect and set **Trusted Hosts** to the collector's address. Copy the generated token into your secret manager.
3. Make sure HTTPS administrative access is enabled on the interface the collector reaches, and note the admin port if it is not 443.

## Run

Supply the token in `FORTIGATE_API_TOKEN` through your protected credential mechanism, not on the command line. TLS verification is mandatory; use `--ca-file` for a private CA or the device's self-signed certificate. Set `PYTHONPATH=src`, and use a protected output directory and a new export filename for each VDOM:

```text
python examples/ansible/fortigate/collect.py --url https://fortigate-management.example --vdom root --device-id fgt-site-a --output protected/fgt-root.json --ca-file fgt-ca.pem
python examples/ansible/fortigate/normalize.py protected/fgt-root.json --namespace lab --external-device-id fgt-site-a-root > protected/fgt-root-submissions.json
```

The collector requests every path in `ENDPOINTS` in `navis_common/fortigate_adapter.py` with `?vdom=<name>`. Required configuration endpoints (interfaces, zones, address/service objects, policy, VIP, static routes) must succeed. Optional endpoints, such as `address6`, `static6`, `central-snat-map` and the routing monitor, are recorded as failures and reported as findings. Redirects are rejected and response sizes are bounded. The export contains sensitive configuration; the adapter redacts password/secret/key fields only in its output.

The normalization result is an array of six partial envelopes. Map the external device ID to a Navis device, approve the normalized adapter digest, and submit each envelope separately to `/v1/ingestions`. Run once per VDOM.

## First live test checklist

- Confirm each endpoint returns `"status": "success"` for your FortiOS version and token profile.
- Compare `monitor/router/ipv4` entries against `get router info routing-table all`. The adapter expects `ip_mask`, `gateway`, `interface`, `type`, `distance` and `vrf`.
- Check the policy order against the GUI sequence and verify interface/zone names in `srcintf`/`dstintf`.
- Keep the export and findings for adapter fixes; do not commit them.

See [supported semantics and remaining work](../../../docs/FORTIGATE.md).
