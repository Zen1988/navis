# F5 BIG-IP iControl REST collection

The Python collector in this directory uses management-plane HTTPS GET requests only. Supply an externally provisioned token for an account restricted to the necessary read permissions in `F5_AUTH_TOKEN`, using your protected credential mechanism. It does not create a login session, change configuration or use a shell endpoint. Tokens are neither CLI arguments nor export fields. TLS verification is mandatory; use `--ca-file` for a private CA.

Set `PYTHONPATH=src`, use a protected output directory and a fresh export filename:

```text
python examples/ansible/f5/collect.py --url https://bigip-management.example --device-id bigip-site-a --output protected/f5-export.json --ca-file trusted-ca.pem
python examples/ansible/f5/normalize.py protected/f5-export.json --partition Common --route-domain 0 --namespace f5-site --external-device-id bigip-common-rd0 > protected/f5-submissions.json
```

Endpoints: `/mgmt/tm/ltm/virtual`, `/ltm/pool`, each pool's `/members`, `/ltm/snatpool`, `/net/route`, `/net/self`, `/net/route-domain` and `/auth/partition` (all under `/mgmt/tm`). Pool endpoints are constructed from validated full paths rather than following arbitrary object links. Pagination is bounded, checks native identities/counts when supplied, rejects redirects and foreign resource paths, and rewrites BIG-IP `https://localhost` pagination links to the explicitly configured management origin. Requests use timeouts and bounded response sizes. Missing permissions or collection errors fail the export. Exports contain sensitive configuration; OS ACLs and secret retention remain the operator's responsibility.

The normalization result is an array of four partial ingestion envelopes. Map the source identity to the intended partition/route-domain device context, approve the normalized adapter digest and submit each envelope separately through the normal authenticated API. No device credentials go to Navis. No live Ansible workflow is provided; the Python commands can be run by your existing collection automation.

See [supported semantics and remaining work](../../../docs/F5.md). Configuration alone does not establish member health, active HA ownership, installed forwarding, actual source translation or end-to-end connectivity.
