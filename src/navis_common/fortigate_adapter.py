"""Translate one FortiOS VDOM REST export into partial Navis submissions.

Interfaces, zones, ordered firewall policies, deterministic VIP candidates,
static routes and active routing-monitor entries are translated. Unsupported
match conditions remain unknown; nothing missing becomes an allow or deny.
"""
from ipaddress import ip_address, ip_interface, ip_network, summarize_address_range
import re

# Paths below /api/v2/. Interfaces are global objects filtered by their vdom.
ENDPOINTS = (
    'cmdb/system/settings', 'cmdb/system/interface', 'cmdb/system/zone',
    'cmdb/firewall/address', 'cmdb/firewall/addrgrp', 'cmdb/firewall/address6', 'cmdb/firewall/addrgrp6',
    'cmdb/firewall.service/custom', 'cmdb/firewall.service/group',
    'cmdb/firewall/policy', 'cmdb/firewall/vip', 'cmdb/firewall/vipgrp', 'cmdb/firewall/ippool',
    'cmdb/firewall/central-snat-map', 'cmdb/router/static', 'cmdb/router/static6',
    'monitor/router/ipv4', 'monitor/router/ipv6')
REQUIRED = ('cmdb/system/interface', 'cmdb/system/zone', 'cmdb/firewall/address', 'cmdb/firewall/addrgrp',
            'cmdb/firewall.service/custom', 'cmdb/firewall.service/group', 'cmdb/firewall/policy',
            'cmdb/firewall/vip', 'cmdb/router/static')
SENSITIVE = re.compile(r'passw|secret|psk|private-key|key-string|token|community', re.I)
VIP_STAGE = 'fortigate_vip_destination_nat_before_policy_unverified'
POLICY_SNAT_STAGE = 'fortigate_policy_source_nat_after_policy_unverified'


def redact(value):
    if isinstance(value, dict):
        return {k: '<navis-redacted>' if SENSITIVE.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def _names(values):
    if values is None:
        return []
    if not isinstance(values, list) or any(not isinstance(v, dict) or not isinstance(v.get('name'), str) or not v['name'] for v in values):
        raise ValueError('invalid native name list')
    return [v['name'] for v in values]


def _selector(role, kind='any', value=None, negated=False):
    return dict(role=role, kind=kind, value=value, negated=negated)


def responses(export):
    """Return per-endpoint results lists and collection findings."""
    if not isinstance(export, dict) or any(not isinstance(export.get(k), str) or not export[k].strip() for k in ('device_id', 'collected_at', 'vdom')):
        raise ValueError('device identity, collection time and VDOM required')
    raw = export.get('responses')
    if not isinstance(raw, dict):
        raise ValueError('responses object required')
    results, findings = {}, []
    for path in ENDPOINTS:
        body = raw.get(path)
        if body is None:
            if path in REQUIRED:
                raise ValueError('required endpoint unavailable: ' + path)
            findings.append(dict(endpoint=path, reason='endpoint not collected'))
            continue
        if not isinstance(body, dict) or body.get('status') != 'success' or 'results' not in body:
            if path in REQUIRED:
                raise ValueError('required endpoint failed: ' + path)
            findings.append(dict(endpoint=path, reason='endpoint failed or unsupported'))
            continue
        if path.startswith('cmdb/') and path != 'cmdb/system/interface' and body.get('vdom') not in (None, export['vdom']):
            raise ValueError('response VDOM mismatch: ' + path)
        value = body['results']
        results[path] = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
    return results, findings


def _index(entries, key='name'):
    result = {}
    for entry in entries:
        name = entry.get(key) if isinstance(entry, dict) else None
        if name is None or name in result:
            raise ValueError('missing or duplicate native object identity')
        result[name] = entry
    return result


def _v4_subnet(text):
    fields = (text or '').split()
    if len(fields) != 2:
        raise ValueError('invalid IPv4 subnet')
    return ip_network(fields[0] + '/' + fields[1], strict=False)


def _range(start, end):
    return [str(n) for n in summarize_address_range(ip_address(start), ip_address(end))]


class Objects:
    """Resolve VDOM address, VIP and service objects to normalized values."""

    def __init__(self, results):
        self.addresses = {4: _index(results.get('cmdb/firewall/address', [])), 6: _index(results.get('cmdb/firewall/address6', []))}
        self.groups = {4: _index(results.get('cmdb/firewall/addrgrp', [])), 6: _index(results.get('cmdb/firewall/addrgrp6', []))}
        self.vips = _index(results.get('cmdb/firewall/vip', []))
        self.vip_groups = _index(results.get('cmdb/firewall/vipgrp', []))
        self.services = _index(results.get('cmdb/firewall.service/custom', []))
        self.service_groups = _index(results.get('cmdb/firewall.service/group', []))

    def address(self, name, family, chain=()):
        if len(chain) >= 64 or name in chain:
            raise ValueError('cyclic or deep address group: ' + name)
        if name in self.groups[family]:
            group = self.groups[family][name]
            if group.get('exclude') == 'enable' or group.get('type') not in (None, 'default', 'folder'):
                raise ValueError('address group exclusion/type unsupported: ' + name)
            members = _names(group.get('member'))
            if not members:
                raise ValueError('empty address group: ' + name)
            return [p for m in members for p in self.address(m, family, (*chain, name))]
        if family == 4 and (name in self.vips or name in self.vip_groups):
            # Policy matching uses the VIP's external (original) destination.
            return [self.vip(name)['extip']]
        node = self.addresses[family].get(name)
        if node is None:
            raise ValueError('unresolved address object: ' + name)
        kind = node.get('type', 'ipmask' if family == 4 else 'ipprefix')
        if family == 4 and kind == 'ipmask':
            return [str(_v4_subnet(node.get('subnet')))]
        if family == 6 and kind == 'ipprefix':
            return [str(ip_network(node.get('ip6'), strict=False))]
        if kind == 'iprange':
            return _range(node.get('start-ip'), node.get('end-ip'))
        raise ValueError('unsupported address type (' + str(kind) + '): ' + name)

    def vip(self, name):
        if name in self.vip_groups:
            raise ValueError('VIP group policy destination requires member expansion: ' + name)
        node = self.vips[name]
        if node.get('type', 'static-nat') != 'static-nat':
            raise ValueError('unsupported VIP type: ' + name)
        ext = (node.get('extip') or '').split('-')
        if len(ext) != 1:
            raise ValueError('VIP external range unsupported: ' + name)
        return dict(extip=str(ip_network(ext[0].strip() + '/32')))

    def service(self, name, chain=()):
        if len(chain) >= 64 or name in chain:
            raise ValueError('cyclic or deep service group: ' + name)
        if name in self.service_groups:
            members = _names(self.service_groups[name].get('member'))
            if not members:
                raise ValueError('empty service group: ' + name)
            return [s for m in members for s in self.service(m, (*chain, name))]
        node = self.services.get(name)
        if node is None:
            raise ValueError('unresolved service: ' + name)
        protocol = node.get('protocol', 'TCP/UDP/SCTP')
        if protocol == 'IP' and int(node.get('protocol-number', 0)) == 0:
            return [None]
        if protocol != 'TCP/UDP/SCTP':
            raise ValueError('service protocol unsupported (' + str(protocol) + '): ' + name)
        if node.get('iprange') not in (None, '', '0.0.0.0') or node.get('fqdn'):
            raise ValueError('service address restriction unsupported: ' + name)
        if node.get('sctp-portrange'):
            raise ValueError('SCTP service unsupported: ' + name)
        values = []
        for proto in ('tcp', 'udp'):
            for token in (node.get(proto + '-portrange') or '').split():
                values.append(dict(protocol=proto, **_portrange(token)))
        if not values:
            raise ValueError('service has no TCP/UDP ports: ' + name)
        return values


def _bounds(text):
    parts = text.split('-')
    if len(parts) not in (1, 2) or any(not p.isdigit() for p in parts):
        raise ValueError('unsupported port expression: ' + text)
    start, end = int(parts[0]), int(parts[-1])
    if not 0 <= start <= end <= 65535:
        raise ValueError('invalid port range: ' + text)
    return start, end


def _portrange(token):
    """FortiOS syntax is destination[-high][:source[-high]]."""
    destination, _, source = token.partition(':')
    start, end = _bounds(destination)
    source_start, source_end = _bounds(source) if source else (0, 65535)
    return dict(destination_port_start=start, destination_port_end=end, source_port_start=source_start, source_port_end=source_end)


def _address_selectors(rule, role, objects):
    """Combine IPv4/IPv6 lists without letting one family match the other."""
    key = 'srcaddr' if role == 'source' else 'dstaddr'
    selectors = []
    for family, field in ((4, key), (6, key + '6')):
        names = _names(rule.get(field))
        if not names:
            continue
        negated = rule.get(field + '-negate', rule.get(key + '-negate') if family == 4 else 'disable') == 'enable'
        prefixes = []
        for name in names:
            if name == 'all' and name not in objects.addresses[family] and name not in objects.groups[family]:
                prefixes.append('0.0.0.0/0' if family == 4 else '::/0')
            else:
                prefixes.extend(objects.address(name, family))
            if len(prefixes) > 10000:
                raise ValueError('selector expansion limit exceeded')
        if negated:
            # The family universe stays positive so the other family cannot match.
            selectors.append(_selector(role, 'address', '0.0.0.0/0' if family == 4 else '::/0'))
        selectors.extend(_selector(role, 'address', p, negated) for p in prefixes)
    if not selectors:
        raise ValueError('no ' + role + ' address for either IP family')
    return selectors


SUPPORTED_POLICY_FIELDS = {
    'policyid', 'q_origin_key', 'name', 'uuid', 'status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'srcaddr6', 'dstaddr6',
    'srcaddr-negate', 'dstaddr-negate', 'srcaddr6-negate', 'dstaddr6-negate', 'service', 'service-negate', 'action',
    'schedule', 'nat', 'ippool', 'poolname', 'poolname6', 'comments', 'logtraffic', 'logtraffic-start'}
UNSUPPORTED_WHEN_SET = ('internet-service', 'internet-service-src', 'internet-service6', 'internet-service6-src')
UNSUPPORTED_LISTS = ('users', 'groups', 'fsso-groups', 'application', 'app-category', 'app-group', 'url-category',
                     'internet-service-name', 'internet-service-src-name', 'src-vendor-mac', 'ztna-ems-tag', 'ztna-geo-tag')


def translate_policies(rules, point, vdom, objects, zones):
    known = {z['zone'] for z in zones}
    entries, nat, findings = [], [], []
    for index, rule in enumerate(rules):
        rule_id = str(rule.get('policyid'))
        unresolved, selectors = [], []
        for field, role in (('srcintf', 'source_zone'), ('dstintf', 'destination_zone')):
            try:
                names = _names(rule.get(field))
                if not names:
                    raise ValueError('missing ' + field)
                if 'any' in names:
                    if len(names) != 1:
                        raise ValueError('ambiguous any in ' + field)
                    selectors.append(_selector(role))
                    continue
                missing = [n for n in names if n not in known]
                if missing:
                    raise ValueError(field + ' references SD-WAN zone, other VDOM or uncollected interface: ' + ', '.join(missing))
                selectors.extend(_selector(role, 'zone', n) for n in names)
            except ValueError as error:
                unresolved.append(str(error))
        for role in ('source', 'destination'):
            try:
                selectors.extend(_address_selectors(rule, role, objects))
            except (ValueError, TypeError, KeyError) as error:
                # Drop the whole role: a partial alternative list could skip this rule.
                unresolved.append(role + ': ' + str(error))
        try:
            negated = rule.get('service-negate') == 'enable'
            values = [v for name in _names(rule.get('service')) for v in objects.service(name)]
            if not values:
                raise ValueError('missing service')
            if None in values:
                if len(values) != 1 or negated:
                    raise ValueError('ALL service combined or negated')
                selectors.append(_selector('service'))
            else:
                selectors.extend(_selector('service', 'service', v, negated) for v in values)
        except (ValueError, TypeError) as error:
            unresolved.append('service: ' + str(error))
        if rule.get('schedule', 'always') != 'always':
            unresolved.append('schedule requires evaluation')
        for field in UNSUPPORTED_WHEN_SET:
            if rule.get(field) == 'enable':
                unresolved.append('unsupported condition: ' + field)
        for field in UNSUPPORTED_LISTS:
            if rule.get(field):
                unresolved.append('unsupported condition: ' + field)
        action = {'accept': 'allow', 'deny': 'deny'}.get(rule.get('action'), 'unknown')
        if action == 'unknown':
            unresolved.append('unsupported or missing action: ' + str(rule.get('action')))
        if rule.get('status', 'enable') not in ('enable', 'disable'):
            unresolved.append('invalid status')
        native = redact({k: v for k, v in rule.items() if k != 'q_origin_key'})
        entries.append(dict(enforcement_point=point, rule_set='firewall-policy:' + vdom, default_action='deny',
            rule_id=rule_id, position=index + 1, action=action, enabled=rule.get('status', 'enable') != 'disable',
            selectors=selectors, details=dict(origin='fortigate_firewall_policy', vdom=vdom, native_name=rule.get('name'),
                native_uuid=rule.get('uuid'), native_action=rule.get('action'), statefulness='stateful', selectors_complete=False,
                zone_relation='universal', translated_conditions_complete=not unresolved,
                order_semantics='sequence_first_match_then_implicit_deny', vip_destinations=[
                    n for n in _names(rule.get('dstaddr') or []) if n in objects.vips or n in objects.vip_groups],
                unresolved=unresolved, native=native)))
        findings.extend(dict(policy=rule_id, reason=r) for r in unresolved)
        if rule.get('nat') == 'enable' and action == 'allow':
            pools = _names(rule.get('poolname')) if rule.get('ippool') == 'enable' else []
            nat.append(dict(enforcement_point=point, rule_set='policy-snat:' + vdom, processing_stage=POLICY_SNAT_STAGE,
                rule_id=rule_id, position=len(nat) + 1, enabled=entries[-1]['enabled'], translation_kind='unsupported',
                translation={}, selectors=[], details=dict(origin='fortigate_policy_snat', policy_id=rule_id, pools=pools,
                    egress_interface_address=not pools, selectors_complete=False,
                    unresolved='runtime source NAT allocation required (' + ('IP pool' if pools else 'egress interface address') + ')')))
    return entries, nat, findings


def translate_vips(vips, point, vdom):
    """Static single-host VIPs are deterministic destination NAT candidates."""
    nat, findings = [], []
    for name, vip in vips.items():
        unresolved, selectors, translation = [], [], {}
        try:
            if vip.get('type', 'static-nat') != 'static-nat':
                raise ValueError('unsupported VIP type: ' + str(vip.get('type')))
            ext = (vip.get('extip') or '').split('-')
            mapped = [m.get('range', '') for m in vip.get('mappedip') or [] if isinstance(m, dict)]
            if len(ext) != 1 or len(mapped) != 1 or '-' in mapped[0]:
                raise ValueError('only single external and mapped hosts are deterministic')
            translation['address'] = str(ip_address(mapped[0].strip()))
            selectors.append(_selector('destination', 'address', str(ip_network(ext[0].strip() + '/32'))))
            sources = [f['range'] for f in vip.get('src-filter') or []]
            if sources:
                selectors.extend(_selector('source', 'address', str(ip_network(s, strict=False))) for s in sources)
            else:
                selectors.append(_selector('source'))
            if vip.get('portforward') == 'enable':
                protocol = vip.get('protocol', 'tcp')
                if protocol not in ('tcp', 'udp'):
                    raise ValueError('port forward protocol unsupported: ' + protocol)
                start, end = _bounds(str(vip.get('extport')))
                mapped_start, mapped_end = _bounds(str(vip.get('mappedport')))
                if start != end or mapped_start != mapped_end:
                    raise ValueError('port range forwarding requires per-port expansion')
                translation['port'] = mapped_start
                selectors.append(_selector('service', 'service', dict(protocol=protocol, destination_port_start=start, destination_port_end=end)))
            else:
                selectors.append(_selector('service'))
            if vip.get('service'):
                raise ValueError('VIP service filter unsupported')
        except (ValueError, TypeError, AttributeError) as error:
            unresolved.append(str(error))
            translation, selectors = {}, []
        nat.append(dict(enforcement_point=point, rule_set='vip:' + vdom, processing_stage=VIP_STAGE, rule_id=name,
            position=len(nat) + 1, enabled=vip.get('status', 'enable') != 'disable',
            translation_kind='destination' if translation else 'unsupported', translation=translation, selectors=selectors,
            details=dict(origin='fortigate_vip', native_name=name, native_uuid=vip.get('uuid'), ingress_interface=vip.get('extintf'),
                arp_reply=vip.get('arp-reply'), selectors_complete=False, policy_address_basis='original_vip_external',
                unresolved=unresolved, reverse='static-nat VIP reverse source mapping unverified', native=redact(vip))))
        findings.extend(dict(vip=name, reason=r) for r in unresolved)
    return nat, findings


def translate_interfaces(entries, vdom):
    interfaces, findings = [], []
    for item in entries:
        if item.get('vdom') != vdom:
            if item.get('vdom') is None:
                findings.append(dict(interface=item.get('name'), reason='interface VDOM missing'))
            continue
        unresolved, addresses = [], []
        try:
            if item.get('mode', 'static') != 'static':
                unresolved.append('dynamic address mode unresolved: ' + str(item.get('mode')))
            elif item.get('ip') not in (None, '', '0.0.0.0 0.0.0.0'):
                addresses.append(str(ip_interface(item['ip'].split()[0] + '/' + item['ip'].split()[1])))
            if item.get('secondary-IP') == 'enable':
                for secondary in item.get('secondaryip') or []:
                    fields = secondary.get('ip', '').split()
                    addresses.append(str(ip_interface(fields[0] + '/' + fields[1])))
            ipv6 = item.get('ipv6') or {}
            if ipv6.get('ip6-mode', 'static') == 'static':
                if ipv6.get('ip6-address') not in (None, '', '::/0'):
                    addresses.append(str(ip_interface(ipv6['ip6-address'])))
                for extra in ipv6.get('ip6-extra-addr') or []:
                    addresses.append(str(ip_interface(extra['prefix'])))
            else:
                unresolved.append('dynamic IPv6 address mode unresolved')
        except (ValueError, IndexError, KeyError, AttributeError) as error:
            unresolved.append('address: ' + str(error))
        kind = item.get('type', 'physical')
        vlan = item.get('vlanid')
        interfaces.append(dict(name=item['name'], native_id=item['name'], kind='physical' if kind == 'physical' else 'virtual',
            parent=item.get('interface') or None, vrf=str(item.get('vrf', 0)),
            operational_state=None, vlans=[vlan] if isinstance(vlan, int) and 1 <= vlan <= 4094 else [],
            addresses=addresses, config=dict(origin='fortigate_configured_interface', native_type=kind,
                admin_status=item.get('status'), role=item.get('role'), unresolved=unresolved)))
        findings.extend(dict(interface=item['name'], reason=r) for r in unresolved)
    for interface in interfaces:
        if interface['parent'] is None:
            del interface['parent']
        if interface['operational_state'] is None:
            del interface['operational_state']
    return interfaces, findings


def translate_zones(entries, interfaces, point):
    """Zones plus one pseudo-zone per unzoned interface, matching policy references."""
    zones, members = [], set()
    names = {i['name'] for i in interfaces}
    findings = []
    for zone in entries:
        listed = _names(zone.get('interface'))
        missing = [n for n in listed if n not in names]
        if missing:
            findings.append(dict(zone=zone.get('name'), reason='member interfaces not collected in VDOM: ' + ', '.join(missing)))
        members.update(listed)
        zones.append(dict(enforcement_point=point, zone=zone['name'], interfaces=[n for n in listed if n in names]))
    zones.extend(dict(enforcement_point=point, zone=n, interfaces=[n]) for n in sorted(names - members))
    return zones, findings


def intrazone_rules(entries, point, vdom):
    """Zone intrazone=allow bypasses policy; precedence stays an explicit barrier."""
    return [dict(enforcement_point=point, rule_set='firewall-policy:' + vdom, default_action='deny',
        rule_id='intrazone:' + zone['name'], position=0, action='unknown', enabled=True,
        selectors=[_selector('source_zone', 'zone', zone['name']), _selector('destination_zone', 'zone', zone['name']),
                   _selector('source'), _selector('destination'), _selector('service')],
        details=dict(origin='fortigate_zone_intrazone', vdom=vdom, zone_relation='intrazone', selectors_complete=False,
            unresolved=['intrazone allow precedence relative to firewall policies unverified']))
        for zone in entries if zone.get('intrazone') == 'allow']


def _route_context(item, interfaces):
    if 'vrf' in item:
        return str(item['vrf'])
    device = item.get('device')
    contexts = {i['name']: i['vrf'] for i in interfaces}
    if device in contexts:
        return contexts[device]
    if set(contexts.values()) <= {'0'}:
        return '0'
    raise ValueError('route VRF unresolved')


def static_routes(entries, family, interfaces):
    routes, candidates = [], []
    names = {i['name'] for i in interfaces}
    for item in entries:
        candidate = dict(seq_num=item.get('seq-num'), family=family, native=redact(item), unresolved=[])
        try:
            if item.get('status', 'enable') != 'enable':
                raise ValueError('disabled static route')
            for field in ('dstaddr', 'internet-service', 'internet-service-custom'):
                if item.get(field) not in (None, '', 0):
                    raise ValueError('named/ISDB destination unsupported: ' + field)
            if item.get('sdwan') == 'enable' or item.get('virtual-wan-link') == 'enable' or item.get('sdwan-zone'):
                raise ValueError('SD-WAN route requires SD-WAN rule evidence')
            if item.get('dynamic-gateway') == 'enable':
                raise ValueError('dynamic gateway unresolved')
            prefix = _v4_subnet(item.get('dst', '0.0.0.0 0.0.0.0')) if family == 4 else ip_network(item.get('dst', '::/0'), strict=False)
            vrf = _route_context(item, interfaces)
            details = dict(origin='fortigate_configured_static', seq_num=item.get('seq-num'), administrative_distance=item.get('distance', 10),
                priority=item.get('priority'), weight=item.get('weight'), evidence='configured_unverified')
            if item.get('blackhole') == 'enable':
                route = dict(vrf=vrf, destination=str(prefix), next_hop=None, interface=None, route_type='discard', details=details)
            else:
                device = item.get('device')
                if device not in names:
                    raise ValueError('egress device not collected in VDOM: ' + str(device))
                gateway = ip_address(item.get('gateway') or ('0.0.0.0' if family == 4 else '::'))
                if gateway.version != family:
                    raise ValueError('gateway family mismatch')
                route = dict(vrf=vrf, destination=str(prefix), next_hop=None if gateway.is_unspecified else str(gateway),
                    interface=device, route_type='forward', details=details)
            candidate['normalized'] = route
            routes.append(route)
        except (ValueError, TypeError) as error:
            candidate['unresolved'].append(str(error))
        candidates.append(candidate)
    return routes, candidates


def active_routes(entries, family, interfaces):
    """Routing-monitor entries; field names must be validated per FortiOS release."""
    routes, evidence = [], []
    names = {i['name'] for i in interfaces}
    for item in entries:
        candidate = dict(native=item)
        try:
            prefix = ip_network(item['ip_mask'], strict=False)
            if prefix.version != family:
                raise ValueError('route family mismatch')
            interface = item.get('interface')
            gateway = ip_address(item.get('gateway') or ('0.0.0.0' if family == 4 else '::'))
            details = dict(origin='fortigate_routing_monitor', native_type=item.get('type'), administrative_distance=item.get('distance'),
                metric=item.get('metric'), priority=item.get('priority'), evidence='rib_unverified_fib')
            vrf = str(item.get('vrf', 0))
            if interface in ('Null', 'blackhole'):
                route = dict(vrf=vrf, destination=str(prefix), next_hop=None, interface=None, route_type='discard', details=details)
            else:
                if interface not in names:
                    raise ValueError('route interface not collected in VDOM: ' + str(interface))
                connected = item.get('type') == 'connect'
                route = dict(vrf=vrf, destination=str(prefix), next_hop=None if gateway.is_unspecified else str(gateway),
                    interface=interface, route_type='connected' if connected else 'forward', details=details)
                if connected:
                    route['next_hop'] = None
            candidate['normalized'] = route
            routes.append(route)
        except (ValueError, TypeError, KeyError) as error:
            candidate['reason'] = str(error)
        evidence.append(candidate)
    return routes, evidence


def translate_export(export):
    results, findings = responses(export)
    vdom = export['vdom']
    point = 'fortigate:' + (export.get('serial') or export['device_id']) + ':' + vdom
    settings = (results.get('cmdb/system/settings') or [{}])[0]
    if settings.get('opmode', 'nat') != 'nat':
        findings.append(dict(setting='opmode', reason='transparent mode forwarding is not translated'))
    if settings.get('ngfw-mode', 'profile-based') != 'profile-based':
        findings.append(dict(setting='ngfw-mode', reason='policy-based NGFW security policies are not collected'))
    central = settings.get('central-nat') == 'enable'
    if central:
        findings.append(dict(setting='central-nat', reason='central SNAT map is not translated; policy NAT flags are ignored'))
    interfaces, interface_findings = translate_interfaces(results['cmdb/system/interface'], vdom)
    zones, zone_findings = translate_zones(results['cmdb/system/zone'], interfaces, point)
    objects = Objects(results)
    policies, policy_nat, policy_findings = translate_policies(results['cmdb/firewall/policy'], point, vdom, objects, zones)
    derived = intrazone_rules(results['cmdb/system/zone'], point, vdom)
    for index, rule in enumerate(derived + policies):
        rule['position'] = index + 1
    vip_nat, vip_findings = translate_vips(objects.vips, point, vdom)
    routes = []
    route_candidates = []
    for family, path in ((4, 'cmdb/router/static'), (6, 'cmdb/router/static6')):
        values, candidates = static_routes(results.get(path, []), family, interfaces)
        routes.extend(values)
        route_candidates.extend(candidates)
    rib, rib_evidence = [], []
    for family, path in ((4, 'monitor/router/ipv4'), (6, 'monitor/router/ipv6')):
        if path in results:
            values, evidence = active_routes(results[path], family, interfaces)
            rib.extend(values)
            rib_evidence.extend(evidence)
    if 'monitor/router/ipv4' in results:
        # Never fill gaps in an active table with configured candidates.
        seen, routes = set(), []
        for route in rib:
            key = (route['vrf'], route['destination'], route['next_hop'], route['interface'], route['route_type'])
            if key not in seen:
                routes.append(route)
                seen.add(key)
    for item in results.get('cmdb/firewall/central-snat-map', []) if central else []:
        findings.append(dict(central_snat=item.get('policyid'), reason='central SNAT rule retained as evidence only'))
    findings.extend(interface_findings + zone_findings + policy_findings + vip_findings)
    findings.extend(dict(static_route=c['seq_num'], reason=r) for c in route_candidates for r in c['unresolved'])
    return dict(device_id=export['device_id'], serial=export.get('serial'), vdom=vdom, collected_at=export['collected_at'],
        firmware=export.get('version'), interfaces=interfaces, zones=zones, policies=derived + policies,
        nat=vip_nat + ([] if central else policy_nat), routes=routes, route_candidates=route_candidates,
        rib_evidence=rib_evidence, ip_pools=redact(results.get('cmdb/firewall/ippool', [])), findings=findings,
        coverage='partial', limitations=[
            'configuration does not establish installed forwarding, HA ownership or effective policy',
            'ISDB, identity, application, schedule, FQDN, geography and dynamic objects remain unknown',
            'VIP and policy SNAT stages are not evaluated by the trace engine; IP pool allocation and sessions are runtime state',
            'SD-WAN rules, policy routes, central NAT, transparent mode and multi-VDOM links are not translated'])


def normalized_submissions(export, namespace, external_device_id):
    if any(not isinstance(v, str) or not v.strip() for v in (namespace, external_device_id)):
        raise ValueError('mapped source identity required')
    semantics = translate_export(export)
    base = dict(source=dict(namespace=namespace, external_device_id=external_device_id),
        adapter=dict(name='navis', input_format='normalized-json', format_version='1'),
        collected_at=export['collected_at'], completeness='partial')
    requests = [{**base, 'data_type': kind, 'payload': dict(entries=semantics[key])} for kind, key in
                (('interface', 'interfaces'), ('security_zone', 'zones'), ('route', 'routes'), ('policy', 'policies'), ('nat', 'nat'))]
    requests.append({**base, 'data_type': 'topology', 'payload': dict(kind='fortigate_vdom_evidence', version=1,
        semantics={k: v for k, v in semantics.items() if k not in ('interfaces', 'zones', 'routes', 'policies', 'nat')})})
    return requests

