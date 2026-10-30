"""BIG-IP iControl REST configuration evidence, scoped by partition/route domain."""
from copy import deepcopy
from ipaddress import ip_address, ip_network


def address(value, default_domain=0):
    if not isinstance(value, str):
        raise ValueError('native BIG-IP address required')
    host, separator, domain = value.rpartition('%')
    if not separator:
        host, domain = value, default_domain
    if not str(domain).isdigit():
        raise ValueError('invalid route domain')
    return str(ip_address(host)), int(domain)


def endpoint(value, default_domain=0):
    value = value.rsplit('/', 1)[-1]
    # BIG-IP IPv6 service addresses use a dot before the service port.
    host, separator, port = value.rpartition('.' if value.count(':') > 1 else ':')
    if not separator or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise ValueError('unsupported BIG-IP service endpoint')
    ip, domain = address(host, default_domain)
    return ip, domain, int(port)


def objects(pages):
    if not isinstance(pages, list) or not pages:
        raise ValueError('native REST pages required')
    result = {}
    total = None
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get('items', []), list):
            raise ValueError('invalid REST collection')
        if bool(page.get('nextLink')) != (index < len(pages)-1):
            raise ValueError('truncated or extra REST pages')
        if 'totalItems' in page:
            count = page['totalItems']
            if type(count) is not int or count < 0 or total is not None and total != count:
                raise ValueError('inconsistent REST count')
            total = count
        for item in page.get('items', []):
            path = item.get('fullPath') if isinstance(item, dict) else None
            if not isinstance(path, str) or not path.startswith('/') or path in result:
                raise ValueError('missing or duplicate fullPath')
            result[path] = item
    if total is not None and total != len(result):
        raise ValueError('REST count mismatch')
    return result


def translate_management(metadata, collection, *, partition, route_domain):
    if any(not isinstance(metadata.get(k), str) or not metadata[k].strip() for k in ('device_id', 'collected_at')):
        raise ValueError('stable device identity and collection time required')
    if not isinstance(partition, str) or not partition or '/' in partition or type(route_domain) is not int or route_domain < 0:
        raise ValueError('explicit partition and numeric route domain required')
    inventory = {kind: objects(collection.get(kind)) for kind in ('virtual', 'pool', 'route', 'self', 'snatpool', 'route-domain', 'partition')}
    domains = [o for o in inventory['route-domain'].values() if o.get('partition') == partition and o.get('id') == route_domain]
    if len(domains) != 1:
        raise ValueError('selected partition/route-domain association not collected')
    partitions = [o for o in inventory['partition'].values() if o.get('name') == partition]
    if len(partitions) != 1 or type(partitions[0].get('defaultRouteDomain')) is not int:
        raise ValueError('partition default route domain not collected')
    default = partitions[0]['defaultRouteDomain']
    vrf = 'f5:' + partition + ':' + str(route_domain)
    def scoped(obj):
        return obj.get('partition') == partition and obj.get('fullPath', '').startswith('/' + partition + '/')
    routes, interfaces, services, nat, findings = [], [], [], [], []
    for path, obj in inventory['route'].items():
        if not scoped(obj):
            continue
        try:
            network = obj['network']
            if network in ('default', 'default-inet6'):
                network = '0.0.0.0/0' if network == 'default' else '::/0'
            host, mask = network.rsplit('/', 1)
            host, domain = address(host, default)
            if domain != route_domain:
                continue
            prefix = str(ip_network(host + '/' + mask, strict=False))
            gateway, gateway_domain = address(obj.get('gw'), default)
            if gateway_domain != domain or ip_address(gateway).version != ip_network(prefix).version or obj.get('pool') or obj.get('blackhole') == 'enabled':
                raise ValueError('unsupported gateway pool/discard/domain route')
            routes.append(dict(vrf=vrf, destination=prefix, next_hop=gateway, interface=None, route_type='forward',
                details=dict(origin='f5_configured_route', native_id=path, evidence='configured_unverified', native=deepcopy(obj))))
        except (ValueError, TypeError, KeyError) as error:
            findings.append(dict(object=path, reason=str(error)))
    for path, obj in inventory['self'].items():
        if not scoped(obj):
            continue
        try:
            host, mask = obj['address'].rsplit('/', 1)
            host, domain = address(host, default)
            if domain != route_domain:
                continue
            ip_network(host + '/' + mask, strict=False)
            interfaces.append(dict(name=path, native_id=path, kind='virtual', vrf=vrf, addresses=[host + '/' + mask],
                config=dict(origin='f5_self_ip', vlan=obj.get('vlan'), traffic_group=obj.get('trafficGroup'), placement='unknown')))
        except (ValueError, TypeError, KeyError) as error:
            findings.append(dict(object=path, reason=str(error)))
    members = collection.get('members', {})
    for path, obj in inventory['virtual'].items():
        if not scoped(obj):
            continue
        unresolved, backends = [], []
        try:
            vip, domain, port = endpoint(obj['destination'], default)
            if domain != route_domain:
                continue
        except (ValueError, TypeError, KeyError) as error:
            findings.append(dict(object=path, reason=str(error)))
            continue
        protocol = obj.get('ipProtocol')
        if protocol not in ('tcp', 'udp') or not port:
            unresolved.append('wildcard or unsupported listener transport/port')
        if obj.get('mask') not in ('255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'):
            unresolved.append('non-host or missing virtual address mask')
        if any(obj.get(k) for k in ('rules', 'policiesReference', 'fwEnforcedPolicy', 'securityLogProfiles', 'vlansEnabled', 'ipForward', 'l2Forward', 'reject', 'internal', 'nat64')):
            unresolved.append('conditional policy/iRule/firewall/forwarding/scope requires native evaluation')
        unresolved.append('virtual precedence, source/VLAN restrictions, profiles and runtime selection unverified')
        pool_path = obj.get('pool')
        pool = inventory['pool'].get(pool_path)
        if pool is None or not scoped(pool):
            unresolved.append('default pool not collected')
        else:
            try:
                for member_path, member in objects(members.get(pool_path)).items():
                    if member.get('session') == 'user-disabled' or member.get('state') == 'user-down':
                        continue
                    backend, backend_domain = address(member.get('address'), default)
                    member_name = member_path.rsplit('/', 1)[-1]
                    port_text = member_name.rsplit('.' if member_name.count(':') > 1 else ':', 1)[-1]
                    if not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
                        raise ValueError('invalid pool member port')
                    member_port = int(port_text)
                    if backend_domain != route_domain or not member_port:
                        unresolved.append('cross-domain or wildcard backend unresolved')
                        continue
                    if obj.get('translateAddress', 'enabled') != 'enabled':
                        unresolved.append('address translation disabled; transparent/nPath routing unverified')
                        continue
                    backends.append(dict(pool_uuid=pool_path, address=backend, port=member_port,
                        port_mode='preserve_listener' if obj.get('translatePort') == 'disabled' else 'fixed',
                        backend_tls='unknown', health='unknown', ratio=member.get('ratio'),
                        algorithm=pool.get('loadBalancingMode'), priority_group=member.get('priorityGroup'), native_member=deepcopy(member)))
                    if len(backends) >= 10000:
                        unresolved.append('backend candidate budget reached')
                        break
            except (ValueError, TypeError, KeyError) as error:
                unresolved.append(str(error))
        source = obj.get('sourceAddressTranslation', {})
        mode = source.get('type', 'unknown')
        snat_addresses = []
        if mode == 'snat':
            snatpool = inventory['snatpool'].get(source.get('pool'))
            if snatpool and snatpool.get('partition') == partition:
                for value in snatpool.get('members', []):
                    try:
                        ip, rd = address(value.rsplit('/', 1)[-1], default)
                        if rd == route_domain:
                            snat_addresses.append(ip)
                    except (ValueError, TypeError):
                        unresolved.append('SNAT member requires translation object resolution')
            else:
                unresolved.append('SNAT pool not collected')
        source_mode = dict(mode=mode, addresses=snat_addresses, allocation='unknown', source_port_mode=obj.get('sourcePort'))
        enabled = obj.get('disabled') is not True
        listeners = [dict(protocol=protocol, start=port, end=port)] if protocol in ('tcp', 'udp') and port else []
        service = dict(uuid=path, name=obj.get('name'), vrf_uuid=vrf, tenant_uuid=partition, enabled=enabled,
            vip_addresses=[vip], listeners=listeners, backends=backends, source_translation=source_mode,
            conditions_complete=False, unresolved=unresolved, native_virtual=deepcopy(obj))
        if pool is not None and scoped(pool):
            service['native_pool'] = deepcopy(pool)
        services.append(service)
        interfaces.append(dict(name=path, native_id=path, kind='virtual', vrf=vrf, addresses=[vip],
            config=dict(origin='f5_virtual_address', enabled=enabled, placement='unknown')))
        for listener in listeners:
            nat.append(dict(enforcement_point=metadata['device_id'] + ':' + vrf, rule_set='f5-virtuals', rule_id=path,
                position=len(nat)+1, enabled=enabled, processing_stage='load_balancer_frontend_backend_connections',
                translation_kind='load_balance', translation=dict(backends=backends, source_translation=source_mode),
                selectors=[dict(role='source', kind='any', value=None, negated=False), dict(role='destination', kind='address', value=vip, negated=False),
                    dict(role='service', kind='service', value=dict(protocol=protocol, destination_port_start=port, destination_port_end=port), negated=False)],
                details=dict(origin='f5_ltm', selectors_complete=False, unresolved=unresolved)))
        findings.extend(dict(object=path, reason=reason) for reason in unresolved)
    return dict(device_id=metadata['device_id'], partition=partition, route_domain=route_domain, vrf=vrf,
        virtual_services=services, routes=routes, interfaces=interfaces, nat=nat, findings=findings, coverage='partial')


def normalized_submissions(metadata, collection, namespace, external_device_id, *, partition, route_domain):
    if any(not isinstance(v, str) or not v.strip() for v in (namespace, external_device_id)):
        raise ValueError('mapped source identity required')
    semantics = translate_management(metadata, collection, partition=partition, route_domain=route_domain)
    base = dict(source=dict(namespace=namespace, external_device_id=external_device_id),
        adapter=dict(name='navis', input_format='normalized-json', format_version='1'), collected_at=metadata['collected_at'], completeness='partial')
    requests = [{**base, 'data_type': kind, 'payload': dict(entries=semantics[key])} for kind, key in (('route','routes'), ('interface','interfaces'), ('nat','nat'))]
    requests.append({**base, 'data_type':'topology', 'payload':dict(kind='f5_load_balancer_evidence', version=1, semantics=semantics)})
    return requests
