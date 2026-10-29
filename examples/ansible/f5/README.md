# F5 BIG-IP collection example

A BIG-IP can participate in dynamic routing, including BGP route advertisement for virtual addresses. Its management address is used to collect evidence, but management routes are separate from traffic-plane routes. Collect each relevant BIG-IP/HA peer because active state and runtime routes can differ. BIG-IQ may manage devices centrally, but this example connects to each BIG-IP management endpoint directly.

Install `f5networks.f5_modules` and run `ansible-playbook -i localhost, collect.yml -e @protected-vars.yml`. Supply `f5_host`, `f5_user`, `f5_password` in Vault/AWX; configure trusted TLS. Optionally set `f5_partition` and `f5_output_dir`. Credentials remain with the collector. Outputs are sensitive and stored locally, and should be reviewed before sharing.

The playbook gathers interface, VLAN, self-IP, route-domain, virtual server and pool facts, plus selected static route, advertisement configuration, firewall, address/port list and packet-filter configuration with F5's command module. Command failures are recorded individually, including unavailable modules or insufficient permissions. Output is raw evidence, not yet normalized or submitted to Navis.

AFM policies can apply at global, route-domain, self-IP or virtual-server contexts; staged rules are not enforced. Self-IP port lockdown concerns traffic to the BIG-IP, not automatically forwarded application traffic. The example does not establish effective policy, collect the operational routing table or BGP advertisements, resolve all objects, evaluate virtual server/pool translation, iRules, HA state, or cover every partition. Therefore route and policy coverage remains partial, even when collection succeeds. Check version, licenses, permissions, partitions, command output and live routes before using results in analysis.

Salt has a [BIG-IP module](https://docs.saltproject.io/en/3006/ref/modules/all/salt.modules.bigip.html), but its documented list functions do not provide the complete routing and firewall evidence required here. No custom Salt HTTP collector is included.

References: [F5 device info module](https://clouddocs.f5.com/products/orchestration/ansible/devel/modules/bigip_device_info_module.html), [F5 routing and advertisement example](https://clouddocs.f5.com/training/community/adc/html/class5/module1/lab1.html), [F5 firewall policies](https://clouddocs.f5.com/api/icontrol-soap/Security__FirewallPolicy.html).
