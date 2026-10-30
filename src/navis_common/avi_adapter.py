"""Avi Controller configuration -> scoped routing and LB translation evidence."""
from copy import deepcopy
from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit


def reference(value, kind, origin):
    if not isinstance(value, str):
        raise ValueError("native Avi reference required: " + kind)
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or parsed.netloc.lower() != urlsplit(origin).netloc.lower() or parsed.username or parsed.password:
            raise ValueError("foreign or insecure Avi Controller reference")
    if parsed.query:
        raise ValueError("Avi name/query references are not stable UUID identities")
    match = re.fullmatch(r"/api/" + re.escape(kind) + r"/([A-Za-z0-9_-]+)", parsed.path)
    if not match:
        raise ValueError("unexpected Avi reference type/path: " + kind)
    return match[1]


def list_objects(pages, kind, origin):
    if not isinstance(pages, list) or not pages:
        raise ValueError("native Avi list pages required: " + kind)
    result, expected, next_paths = {}, None, set()
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get("results"), list):
            raise ValueError("invalid Avi list response: " + kind)
        count = page.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0 or expected is not None and expected != count:
            raise ValueError("missing or inconsistent Avi list count")
        expected = count
        next_url = page.get("next")
        if bool(next_url) != (index < len(pages) - 1):
            raise ValueError("truncated or extra Avi pages")
        if next_url:
            parsed = urlsplit(next_url)
            if parsed.netloc and (parsed.scheme != "https" or parsed.netloc.lower() != urlsplit(origin).netloc.lower()) or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("foreign/insecure Avi pagination URL")
            if parsed.path.rstrip("/") != "/api/" + kind or next_url in next_paths:
                raise ValueError("unexpected/repeated Avi pagination URL")
            next_paths.add(next_url)
        for obj in page["results"]:
            if not isinstance(obj, dict) or not isinstance(obj.get("uuid"), str) or not obj["uuid"] or obj["uuid"] in result:
                raise ValueError("missing/duplicate native Avi UUID")
            if obj.get("url") and reference(obj["url"], kind, origin) != obj["uuid"]:
                raise ValueError("Avi URL/UUID identity mismatch")
            result[obj["uuid"]] = obj
    if len(result) != expected:
        raise ValueError("Avi count disagrees with collected objects")
    return result


def _ip(value):
    if not isinstance(value, dict):
        raise ValueError("native Avi IP object required")
    address = ip_address(value.get("addr"))
    if value.get("type") != ("V4" if address.version == 4 else "V6"):
        raise ValueError("Avi IP address/type mismatch")
    return str(address)


def _port(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ValueError("invalid Avi transport port")
    return value


def translate_controller(metadata, collection, *, vrf_uuid):
    required = ("controller_id", "controller_url", "tenant_uuid", "collected_at", "api_version")
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(k), str) or not metadata[k].strip() for k in required):
        raise ValueError("Controller identity/URL, tenant UUID, API version and collection time required")
    origin = metadata["controller_url"]
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("Controller URL must be a plain HTTPS origin")
    if not isinstance(collection, dict):
        raise ValueError("native Avi collection required")
    resources = {kind: list_objects(collection.get(kind), kind, origin) for kind in
                 ("virtualservice", "vsvip", "pool", "poolgroup", "vrfcontext", "networkprofile")}
    tenant = metadata["tenant_uuid"]
    def lookup(ref, kind, *, same_tenant=True):
        key = reference(ref, kind, origin)
        if key not in resources[kind]:
            raise ValueError("referenced Avi object not collected: " + kind + "/" + key)
        obj = resources[kind][key]
        if same_tenant and reference(obj.get("tenant_ref"), "tenant", origin) != tenant:
            raise ValueError("cross-tenant Avi reference")
        return obj
    if vrf_uuid not in resources["vrfcontext"]:
        raise ValueError("selected VRF UUID not collected")
    vrf = resources["vrfcontext"][vrf_uuid]
    if reference(vrf.get("tenant_ref"), "tenant", origin) != tenant:
        raise ValueError("VRF tenant association not established")
    cloud = reference(vrf.get("cloud_ref"), "cloud", origin)
    def context(obj, vrf_field):
        if reference(obj.get(vrf_field), "vrfcontext", origin) != vrf_uuid or reference(obj.get("cloud_ref"), "cloud", origin) != cloud:
            raise ValueError("Avi tenant/cloud/VRF context mismatch")
    routes, route_candidates, findings = [], [], []
    used = {kind: {} for kind in resources}
    used["vrfcontext"][vrf_uuid] = deepcopy(vrf)
    seen = set()
    for route in vrf.get("static_routes", []):
        native_id = route.get("route_id")
        if not isinstance(native_id, str) or not native_id or native_id in seen:
            raise ValueError("missing/duplicate native Avi static route ID")
        seen.add(native_id)
        candidate = {"native_id": native_id, "native": deepcopy(route), "unresolved": []}
        try:
            prefix = route["prefix"]
            address = _ip(prefix["ip_addr"])
            mask = prefix["mask"]
            if not isinstance(mask, int) or isinstance(mask, bool):
                raise ValueError("invalid route prefix mask")
            destination = str(ip_network(address + "/" + str(mask), strict=False))
            hop = _ip(route.get("next_hop"))
            if ip_address(hop).version != ip_network(destination).version:
                raise ValueError("route and next-hop address families differ")
            record = {"vrf": vrf_uuid, "destination": destination, "next_hop": hop, "interface": None,
                "route_type": "forward", "details": {"origin": "avi_vrf_static", "native_id": native_id,
                    "configured_interface_name": route.get("if_name"), "evidence": "configured_unverified", "native_route": deepcopy(route)}}
            routes.append(record)
            candidate["normalized"] = record
        except (ValueError, KeyError, TypeError) as error:
            candidate["unresolved"].append(str(error))
            findings.append({"route": native_id, "reason": str(error)})
        route_candidates.append(candidate)

    def pool_candidates(pool):
        context(pool, "vrf_ref")
        used["pool"][pool["uuid"]] = deepcopy(pool)
        servers, unresolved = [], []
        if pool.get("enabled") is False:
            return [], ["pool administratively disabled"]
        if pool.get("domain_name") or pool.get("external_autoscale_groups") or pool.get("autoscale_policy_ref"):
            unresolved.append("dynamic pool membership requires runtime evidence")
        for server in pool.get("servers", []):
            if len(servers) >= 10000:
                unresolved.append("backend expansion limit exceeded")
                break
            if server.get("enabled") is False:
                continue
            try:
                if server.get("resolve_server_by_dns"):
                    raise ValueError("DNS-resolved backend requires runtime address evidence")
                address = _ip(server.get("ip"))
                preserve = pool.get("use_service_port", False)
                if not isinstance(preserve, bool):
                    raise ValueError("invalid use_service_port setting")
                port = None if preserve else _port(server.get("port", pool.get("default_server_port", 80)))
                servers.append({"pool_uuid": pool["uuid"], "address": address, "port": port,
                    "port_mode": "preserve_listener" if preserve else "fixed", "ratio": server.get("ratio"),
                    "backend_tls": "listener" if preserve and pool.get("use_service_ssl_mode") else bool(pool.get("ssl_profile_ref")),
                    "health": "unknown", "native_server": deepcopy(server)})
            except (ValueError, TypeError, KeyError) as error:
                unresolved.append(str(error))
        if not servers:
            unresolved.append("no usable configured backend candidates")
        return servers, unresolved

    virtual_services, interfaces, nat = [], [], []
    for vs in resources["virtualservice"].values():
        if reference(vs.get("tenant_ref"), "tenant", origin) != tenant:
            continue
        if reference(vs.get("vrf_context_ref"), "vrfcontext", origin) != vrf_uuid:
            continue
        context(vs, "vrf_context_ref")
        used["virtualservice"][vs["uuid"]] = deepcopy(vs)
        unresolved = []
        try:
            if vs.get("vsvip_ref"):
                vsvip = lookup(vs["vsvip_ref"], "vsvip")
                context(vsvip, "vrf_context_ref")
                used["vsvip"][vsvip["uuid"]] = deepcopy(vsvip)
                native_vips = vsvip.get("vip", [])
            else:
                native_vips = vs.get("vip", [])
            addresses = set()
            for vip in native_vips:
                if vip.get("enabled") is False:
                    continue
                for field in ("ip_address", "ip6_address"):
                    if vip.get(field):
                        addresses.add(_ip(vip[field]))
                if vip.get("auto_allocate_ip") and not vip.get("ip_address"):
                    unresolved.append("VIP allocation not established")
                if vip.get("floating_ip") or vip.get("floating_ip6"):
                    unresolved.append("cloud floating-IP translation requires provider evidence")
            if not addresses:
                unresolved.append("VIP addresses not collected")
        except (ValueError, KeyError, TypeError) as error:
            addresses = set()
            unresolved.append(str(error))
        listeners = []
        for service in vs.get("services", []):
            try:
                first, last = _port(service.get("port")), _port(service.get("port_range_end", service.get("port")))
                if first > last:
                    raise ValueError("reversed listener port range")
                profile = lookup(service.get("override_network_profile_ref") or vs.get("network_profile_ref"), "networkprofile", same_tenant=False)
                used["networkprofile"][profile["uuid"]] = deepcopy(profile)
                union = profile.get("profile", {})
                kind = union.get("type")
                protocols = {"PROTOCOL_TYPE_TCP_PROXY": "tcp", "PROTOCOL_TYPE_TCP_FAST_PATH": "tcp",
                             "PROTOCOL_TYPE_UDP_FAST_PATH": "udp", "PROTOCOL_TYPE_UDP_PROXY": "udp"}
                protocol = protocols.get(kind)
                if protocol is None:
                    raise ValueError("unsupported/missing network-profile transport")
                if union.get("tcp_fast_path_profile", {}).get("dsr_profile"):
                    unresolved.append("direct-server-return mode requires routing/encapsulation evidence")
                listeners.append({"protocol": protocol, "start": first, "end": last, "tls": service.get("enable_ssl", False),
                                  "network_profile_uuid": profile["uuid"], "proxy_mode": kind})
            except (ValueError, KeyError, TypeError) as error:
                unresolved.append(str(error))
        pool_refs = []
        if vs.get("pool_ref") and vs.get("pool_group_ref"):
            unresolved.append("ambiguous default pool and pool-group references")
        if vs.get("pool_ref"):
            pool_refs.append((vs["pool_ref"], None))
        if vs.get("pool_group_ref"):
            try:
                group = lookup(vs["pool_group_ref"], "poolgroup")
                used["poolgroup"][group["uuid"]] = deepcopy(group)
                for member in group.get("members", []):
                    pool_refs.append((member.get("pool_ref"), {"poolgroup_uuid": group["uuid"], "ratio": member.get("ratio"),
                                                              "priority_label": member.get("priority_label")}))
            except ValueError as error:
                unresolved.append(str(error))
        if any(vs.get(k) for k in ("http_policies", "l4_policies", "vs_datascripts", "service_pool_select", "vh_parent_vs_ref")) or vs.get("type", "VS_TYPE_NORMAL") != "VS_TYPE_NORMAL":
            unresolved.append("conditional L7/L4/DataScript/virtual-host pool selection requires evaluation")
        source_mode = {"mode": "service_engine_address", "addresses": [], "allocation": "unknown"}
        try:
            snat = [_ip(ip) for field in ("snat_ip", "snat_ip6_addresses") for ip in vs.get(field, [])]
            if vs.get("use_vip_as_snat") and snat:
                raise ValueError("conflicting VIP and configured SNAT modes")
            if vs.get("use_vip_as_snat"):
                source_mode = {"mode": "vip", "addresses": sorted(addresses), "allocation": "connection_dependent"}
            elif snat:
                source_mode = {"mode": "configured_snat_pool", "addresses": snat, "allocation": "connection_dependent"}
            if vs.get("preserve_client_ip"):
                source_mode = {"mode": "preserve_client", "addresses": [], "allocation": "not_applicable"}
                unresolved.append("client-IP preservation routing mode requires additional native validation")
        except (ValueError, TypeError) as error:
            unresolved.append(str(error))
            source_mode = {"mode": "unknown", "addresses": [], "allocation": "unknown"}
        backends = []
        for ref, group_member in pool_refs:
            try:
                pool = lookup(ref, "pool")
                servers, errors = pool_candidates(pool)
                if len(backends) + len(servers) > 10000:
                    raise ValueError("backend expansion limit exceeded")
                backends.extend({**server, "pool_group_member": group_member,
                    "algorithm": pool.get("lb_algorithm"), "persistence_ref": pool.get("application_persistence_profile_ref")} for server in servers)
                unresolved.extend(errors)
            except (ValueError, KeyError, TypeError) as error:
                unresolved.append(str(error))
        if not backends:
            unresolved.append("backend/pool association not established")
        if not listeners:
            unresolved.append("listener service not established")
        enabled = vs.get("enabled", True) and vs.get("traffic_enabled", True)
        record = {"uuid": vs["uuid"], "name": vs.get("name"), "vrf_uuid": vrf_uuid, "cloud_uuid": cloud,
            "tenant_uuid": tenant, "enabled": enabled is True, "vip_addresses": sorted(addresses), "listeners": listeners,
            "backends": backends, "source_translation": source_mode, "selection": "runtime_unknown",
            "conditions_complete": not unresolved, "unresolved": unresolved, "native_virtualservice": deepcopy(vs)}
        virtual_services.append(record)
        for address in sorted(addresses):
            interfaces.append({"name": (vs.get("name") or vs["uuid"]) + ":" + address, "native_id": vs["uuid"] + ":vip:" + address,
                "kind": "virtual", "vrf": vrf_uuid, "addresses": [address], "config": {"origin": "avi_configured_vip",
                "virtualservice_uuid": vs["uuid"], "enabled": enabled is True, "placement": "unknown"}})
        for index, listener in enumerate(listeners):
            selectors = [{"role": "source", "kind": "any", "value": None, "negated": False}]
            selectors.extend({"role": "destination", "kind": "address", "value": address, "negated": False} for address in sorted(addresses))
            selectors.append({"role": "service", "kind": "service", "value": {"protocol": listener["protocol"],
                "destination_port_start": listener["start"], "destination_port_end": listener["end"]}, "negated": False})
            nat.append({"enforcement_point": "avi:" + metadata["controller_id"] + ":" + tenant + ":" + vrf_uuid,
                "rule_set": "avi-virtual-services", "processing_stage": "load_balancer_frontend_backend_connections",
                "rule_id": vs["uuid"] + ":listener:" + str(index), "position": len(nat) + 1, "enabled": enabled is True,
                "translation_kind": "load_balance", "translation": {"backends": deepcopy(backends), "source_translation": source_mode},
                "selectors": selectors, "details": {"origin": "avi_load_balancer", "virtualservice_uuid": vs["uuid"],
                    "selectors_complete": False, "selection": "runtime_unknown", "unresolved": unresolved}})
        findings.extend({"virtualservice": vs["uuid"], "reason": reason} for reason in unresolved)
    return {"controller_id": metadata["controller_id"], "tenant_uuid": tenant, "cloud_uuid": cloud, "vrf_uuid": vrf_uuid,
        "virtual_services": virtual_services, "routes": routes, "route_candidates": route_candidates,
        "interfaces": interfaces, "nat": nat, "findings": findings, "coverage": "partial",
        "inventory": {kind: list(objects.values()) for kind, objects in used.items()},
        "limitations": ["configured VRF routes are not installed Service Engine forwarding entries",
            "VIP placement/advertisement, health, server selection, persistence and SNAT allocation require runtime evidence",
            "full proxy connections are not assumed to be ordinary deterministic destination NAT",
            "L7/DataScript/SNI/policy routing, cloud floating IP, DSR and return paths remain unverified"]}


def normalized_submissions(metadata, collection, namespace, external_device_id, *, vrf_uuid):
    if any(not isinstance(v, str) or not v.strip() for v in (namespace, external_device_id)):
        raise ValueError("namespace and mapped Avi VRF/device identity required")
    semantics = translate_controller(metadata, collection, vrf_uuid=vrf_uuid)
    base = {"source": {"namespace": namespace, "external_device_id": external_device_id},
        "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
        "collected_at": metadata["collected_at"], "completeness": "partial"}
    requests = [{**base, "data_type": kind, "payload": {"entries": semantics[key]}}
                for kind, key in (("route", "routes"), ("interface", "interfaces"), ("nat", "nat"))]
    requests.append({**base, "data_type": "topology", "payload": {"kind": "avi_load_balancer_evidence", "version": 1,
        "semantics": semantics, "inventory": semantics["inventory"]}})
    return requests
