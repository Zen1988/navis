# NSX Manager SaltStack example

This example uses the existing [Salt Extension for VCF](https://github.com/salt-extensions/saltext-vcf) execution modules to collect NSX security policies, their firewall rules, groups and services. The extension targets VCF 9.x; confirm its compatibility with your environment. It is a separate extension, not a claim that every NSX version has built-in Salt support or that VMware maintains this repository.

Install and configure the extension and its NSX connection profile according to its documentation on the collector minion. Install `_modules/navis_nsx.py` in a trusted Salt fileserver and sync it. The wrapper uses extension functions rather than implementing HTTP requests; the extension itself communicates with NSX Manager over HTTPS. Keep credentials in the extension's protected configuration or secret backend.

```text
salt 'collector-minion' navis_nsx.snapshot /secure/nsx-output profile=YOUR_PROFILE
```

Use a fresh, trusted output directory. This example only supports the default domain because the extension group listing does not expose a domain parameter. It refuses responses containing a pagination cursor because these extension functions do not expose cursor continuation. Coverage is partial: effective group membership, topology, routing, NAT and Navis normalization/submission are not included. Raw output may be sensitive. This example has not been tested against a live Salt or NSX installation.
