"""Read-only host network evidence collector, executed on a Salt minion."""

_LINUX_COMMANDS = {
    "addresses": "ip -j address show",
    "links": "ip -j -details link show",
    "routes_ipv4": "ip -j -4 route show table all",
    "routes_ipv6": "ip -j -6 route show table all",
    "rules_ipv4": "ip -j -4 rule show",
    "rules_ipv6": "ip -j -6 rule show",
    "neighbors": "ip -j neighbor show",
    "forward_ipv4": "sysctl net.ipv4.ip_forward",
    "forward_ipv6": "sysctl net.ipv6.conf.all.forwarding",
    "nftables": "nft -j list ruleset",
}
_WINDOWS_COMMANDS = {
    "interfaces": "Get-NetAdapter | Select-Object * | ConvertTo-Json -Depth 6",
    "addresses": "Get-NetIPAddress | Select-Object * | ConvertTo-Json -Depth 6",
    "ip_interfaces": "Get-NetIPInterface -IncludeAllCompartments | Select-Object * | ConvertTo-Json -Depth 6",
    "routes": "Get-NetRoute -IncludeAllCompartments | Select-Object * | ConvertTo-Json -Depth 6",
    "neighbors": "Get-NetNeighbor -IncludeAllCompartments | Select-Object * | ConvertTo-Json -Depth 6",
    "firewall_profiles": "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object * | ConvertTo-Json -Depth 6",
    "firewall_rules_and_filters": "Get-NetFirewallRule -PolicyStore ActiveStore | ForEach-Object { $r = $_; [pscustomobject]@{rule = $r; address = @($r | Get-NetFirewallAddressFilter); port = @($r | Get-NetFirewallPortFilter); application = @($r | Get-NetFirewallApplicationFilter); service = @($r | Get-NetFirewallServiceFilter); interface = @($r | Get-NetFirewallInterfaceFilter); interface_type = @($r | Get-NetFirewallInterfaceTypeFilter); security = @($r | Get-NetFirewallSecurityFilter)} } | ConvertTo-Json -Depth 8",
}


def snapshot():
    """Return partial native evidence and per-collector errors; no configuration changes."""
    import json
    import datetime

    os_family = __grains__.get("kernel")
    if os_family not in ("Linux", "Windows"):
        raise ValueError("Only Linux and Windows minions are supported")
    result = {"minion_id": __grains__.get("id"), "kernel": os_family,
              "os": __grains__.get("os"), "osrelease": __grains__.get("osrelease"),
              "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "coverage": "partial", "data": {}, "errors": {}}

    def call(name, function, *args, **kwargs):
        if function not in __salt__:
            result["errors"][name] = "Salt function unavailable: " + function
            return
        try:
            value = __salt__[function](*args, **kwargs)
            result["data"][name] = value
        except Exception as exc:
            result["errors"][name] = str(exc)

    call("salt_interfaces", "network.interfaces")
    if os_family == "Linux":
        for family in ("ipv4", "ipv6"):
            call("iptables_" + family, "iptables.get_rules", family=family)
        call("firewalld_service_running", "service.status", "firewalld")
        call("firewalld_runtime_zones", "firewalld.list_zones", permanent=False)
        call("firewalld_permanent_zones", "firewalld.list_zones", permanent=True)
        commands, shell = _LINUX_COMMANDS, None
    else:
        call("windows_firewall_rules", "firewall.get_rule", "all")
        call("windows_firewall_config", "firewall.get_config")
        commands, shell = _WINDOWS_COMMANDS, "powershell"

    for name, command in commands.items():
        try:
            kwargs = {"python_shell": False} if shell is None else {"shell": shell, "python_shell": True}
            response = __salt__["cmd.run_all"](command, **kwargs)
            if response.get("retcode") != 0:
                result["errors"][name] = response.get("stderr") or "command failed"
                continue
            output = response.get("stdout", "")
            if name.startswith("forward_"):
                result["data"][name] = output
            else:
                result["data"][name] = json.loads(output) if output.strip() else []
        except Exception as exc:
            result["errors"][name] = str(exc)
    return result
