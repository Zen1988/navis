# NSX Manager Ansible example

NSX Manager exposes HTTPS APIs for an NSX deployment. This read-only example queries selected Policy API resources: domains, one domain's groups and security policies, and services. It follows cursors and stops on a configured page limit. It does not automatically discover all NSX Manager clusters or domains, expand every policy's rules, resolve effective group membership, or collect topology, routing, NAT and gateway policies. It is not a complete NSX collector.

Supply `nsx_base_url` (for example `https://nsx.example`), `nsx_username`, `nsx_password`, and `nsx_domain` through AWX or an encrypted Vault file. The controller must trust the Manager certificate. Run `ansible-playbook -i localhost, collect.yml -e @protected-vars.yml`. Native JSON pages are saved with restricted permissions; use a fresh output directory for each run. Protect output because it contains policy and inventory information. Credentials are never sent to Navis.

Native NSX data is not yet normalized or submitted to Navis. DFW direction, policy ordering, rules, dynamic group membership and enforcement scope must be interpreted by an NSX adapter before evaluation. Results remain partial. Validate the API paths and pagination against your NSX version and deployment; Global Manager and VMC have different scopes. No live NSX or Ansible test has been run.

References: [NSX API guide](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/api_single_page.html) and [security policy listing](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/method_ListSecurityPoliciesForDomain.html).
