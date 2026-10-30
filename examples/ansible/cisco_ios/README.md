# Cisco IOS / IOS XE collection example

The collector connects to each device in the `ios_devices` inventory group using `network_cli` and read-only commands. Credentials and SSH keys remain on the Ansible/AWX controller, not in Navis. Configure host-key verification and supply connection credentials through AWX or Ansible Vault. Install the collections in `requirements.yml` and the relevant SSH transport dependencies.

```yaml
all:
  children:
    ios_devices:
      hosts:
        router-lab-01:
          ansible_host: 192.0.2.10
```

```text
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory.yml collect.yml
```

The example collects platform/version, interfaces, interface-level IP information, VRFs, routes, IPv4/IPv6 ACL definitions, policy-based routing/route maps, NAT translations/statistics, ARP, MAC and neighbor information where the device supports the commands. `show ip interface` can expose applied IPv4 ACLs; ACL definitions alone do not establish which interfaces and directions use them. PBR can override ordinary route lookup. Dynamic NAT translations are operational session data and are not a substitute for configured NAT rules.

Outputs are written on the controller as one JSON file per inventory identifier. They retain command/output/failure fields without Ansible invocation data. Review unsupported commands, privilege failures, CLI errors and truncation. Selected running-config sections add interfaces/ACL attachments, VRFs, static routes and NAT intent. Common sensitive lines are redacted before export; this is basic redaction, not a complete secret classifier. Review export sensitivity and protect OS ACLs/retention. Use a fresh protected output directory. Coverage remains partial.

The partial adapter now translates supported interfaces/VRFs, routes, attached ACLs and static host NAT candidates. Set `PYTHONPATH=src` from the repository root, then run:

```text
python examples/ansible/cisco_ios/normalize.py ios-output/router-lab-01.json --namespace ios-site --external-device-id router-lab-01 > protected/ios-submissions.json
```

The result is five partial ingestion envelopes. Map the source identity, approve the updated normalized adapter digest and submit each separately through the existing authenticated API/worker workflow. Review findings and unsupported syntax before changing evidence completeness. Devices still require inventory; this does not discover the network or prove policy/forwarding coverage. No live device, Ansible or database/graph integration test has been run. See [scope and remaining work](../../../docs/IOS.md).

References: [Ansible IOS command module](https://docs.ansible.com/projects/ansible/latest/collections/cisco/ios/ios_command_module.html), [Cisco ACL interface application](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/releases/15_2_7_e/configuration_guides/sec/b_1527e_security_c1000_cg/configuring_ipv4_acls.html), [Cisco policy-based routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr3-fwd/pbr/policy-based-routing-configuration-guide/policy-based-routing.html).
