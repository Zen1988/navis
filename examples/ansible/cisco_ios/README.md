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

Outputs are written on the controller as one JSON file per inventory identifier. They retain per-command results, including errors; review unsupported commands, privilege failures, CLI error text and truncation before interpreting the data. Commands and output vary by platform and release. Metadata is deliberately `partial`: VRF route coverage, IPv6 ACL attachment, configured NAT, zone-based firewall/CBAC, object groups, tunnel state, control-plane policing and other feature-specific enforcement are not fully collected. Avoid collecting full running configuration without a credential-redaction strategy.

This is not a complete inventory discovery system, parser, or Navis adapter. It neither submits data to Navis nor proves policy coverage. Devices must be supplied through inventory, and a future adapter must normalize rules, defaults, interface/direction, VRF, route selection and vendor semantics. No live-device or Ansible integration test has been run.

References: [Ansible IOS command module](https://docs.ansible.com/projects/ansible/latest/collections/cisco/ios/ios_command_module.html), [Cisco ACL interface application](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/releases/15_2_7_e/configuration_guides/sec/b_1527e_security_c1000_cg/configuring_ipv4_acls.html), [Cisco policy-based routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr3-fwd/pbr/policy-based-routing-configuration-guide/policy-based-routing.html).
