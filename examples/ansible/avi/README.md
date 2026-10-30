# Avi Controller collection

Run `collect.yml` on an Ansible controller using a dedicated read-only Avi account. Supply `avi_controller_url` (HTTPS origin), `avi_controller_id` (stable deployment identity), `avi_username`, `avi_password`, `avi_tenant_uuid` and `avi_api_version` through protected Vault/AWX variables. Set `avi_output_dir` to a fresh protected directory for each run. Credentials are never included in metadata. Native configuration exports can contain sensitive data.

```text
ansible-playbook -i localhost, examples/ansible/avi/collect.yml -e @protected-vars.yml
```

Collection uses GET only, TLS verification, no redirects, tenant/version headers, bounded pagination and same-origin resource URL checks. It retrieves virtualservice, vsvip, pool, poolgroup, vrfcontext and networkprofile. Permissions must expose the referenced profiles, including shared profiles, or translation remains incomplete. No Service Engine runtime collection is implemented.

Set `PYTHONPATH=src` and normalize one explicitly selected native VRF UUID:

```text
python examples/ansible/avi/normalize.py avi-output --vrf-uuid vrfcontext-UUID --namespace avi-site --external-device-id tenant-vrf-device --semantics avi-semantics.json > avi-submissions.json
```

The result is an array of four partial envelopes. Submit each separately through the normal authenticated ingestion API after mapping the source identity and approving the adapter digest. Keep tenant/VRF identities distinct. Missing pages or count mismatches fail translation; do not combine exports from separate runs.

See [scope and remaining work](../../../docs/AVI.md). This is a configuration adapter; server health, actual source allocation, installed routing and end-to-end sessions remain unknown.
