# Salt agent host evidence collection

Collect read-only routing and firewall evidence locally on Linux and Windows Salt minions. Copy `_modules/navis_host.py` into a trusted Salt fileserver `_modules` directory, then sync and run on an explicitly targeted minion:

```text
salt 'host-id' saltutil.sync_modules
salt 'host-id' navis_host.snapshot --out=json
```

Run the minion with sufficient read privileges. Protect the Salt master, job cache, output and transport: results include sensitive network configuration. Collection does not alter routing or firewall settings. It returns data and per-collector errors, with coverage always `partial`. Missing software, unsupported cmdlets or insufficient permissions are recorded as errors, not interpreted as an empty configuration.

Linux collects interface/address, IPv4/IPv6 routes and routing rules across tables, neighbors, global forwarding flags, firewalld service status and runtime/permanent zone data, iptables IPv4/IPv6 and nftables rules. These can overlap; determine the active backend and effective hook/chain ordering before normalizing. Per-interface forwarding, network namespaces, VRFs, bridges, dynamic routing advertisements, firewalld policy objects, connection tracking and other controls are not fully collected.

Windows collects adapters, addresses, IP interfaces including forwarding state, routing and neighbors, firewall profiles, ActiveStore rules and associated filters, plus Salt firewall module results. Forwarding support and firewall behavior depend on Windows configuration and roles. Results do not fully account for Windows Filtering Platform callouts, IPsec, all compartments, application identity, third-party firewalls or other controls. Verify your Windows version supports the included cmdlets and options.

If firewalld or a Windows Firewall profile is disabled, report that observation, not an unconditional allow. Linux may still use iptables, nftables or another filter; Windows may use another firewall or filtering driver. A disabled built-in firewall does not establish that a third-party firewall exists or that no filter applies.

Output is native, not a Navis ingestion envelope. Normalization, device identity mapping, coverage assertions and submission are not implemented. A successful collection is not proof of effective end-to-end access. Do not mark missing or unsupported evidence as allow.

References: [Salt iptables](https://docs.saltproject.io/en/3006/ref/modules/all/salt.modules.iptables.html), [Salt firewalld](https://docs.saltproject.io/en/master/ref/modules/all/salt.modules.firewalld.html), [Windows firewall rules and filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2022-ps), [Windows networking cmdlets](https://learn.microsoft.com/en-us/powershell/module/nettcpip/?view=win10-ps).
