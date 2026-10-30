"""Narrow IOS/IOS XE CLI evidence translation; unsupported syntax stays explicit."""
from ipaddress import ip_address, ip_interface, ip_network, IPv4Address
import re

CONFIG_COMMANDS = {
    'interfaces': 'show running-config | section ^interface',
    'acls': 'show running-config | section ^ip access-list|^ipv6 access-list|^access-list',
    'routes': 'show running-config | include ^ip route|^ipv6 route',
    'nat': 'show running-config | include ^ip nat',
    'vrfs': 'show running-config | section ^vrf definition|^ip vrf',
}


def redact(text):
    return '\n'.join(' ! navis-redacted-sensitive-line' if re.search(r'\b(password|secret|community|key-string|pre-shared-key|authentication-key)\b', line, re.I) else line for line in text.splitlines())


def command_outputs(export):
    if not isinstance(export, dict) or any(not isinstance(export.get(k), str) or not export[k].strip() for k in ('device_id', 'collected_at')):
        raise ValueError('device identity and collection time required')
    outputs, failures = {}, []
    for result in export.get('results', []):
        command = result.get('command', result.get('item'))
        if not isinstance(command, str) or command in outputs:
            raise ValueError('missing or duplicate command identity')
        stdout = result.get('stdout', [])
        text = stdout if isinstance(stdout, str) else stdout[0] if isinstance(stdout, list) and len(stdout) == 1 and isinstance(stdout[0], str) else None
        if result.get('failed') or text is None or re.search(r'(?im)^\s*%\s*(Invalid|Error|Incomplete|Ambiguous|Authorization|Unrecognized|Access|Command|Unknown|No such)|--More--|\x08', text):
            failures.append(dict(command=command, reason='failed, unsupported or truncated command'))
            continue
        outputs[command] = redact(text)
    for command in CONFIG_COMMANDS.values():
        if command not in outputs:
            failures.append(dict(command=command, reason='required configuration section unavailable'))
    return outputs, failures


def selector(role, kind='any', value=None):
    return dict(role=role, kind=kind, value=value, negated=False)


def acl_address(tokens, family):
    value = tokens.pop(0)
    if value in ('any', 'any4', 'any6'):
        if value == 'any4' and family != 4 or value == 'any6' and family != 6:
            raise ValueError('ACL address family mismatch')
        return None
    if value == 'host':
        ip = ip_address(tokens.pop(0))
        if ip.version != family:
            raise ValueError('ACL address family mismatch')
        return str(ip_network(str(ip) + ('/32' if family == 4 else '/128')))
    if family == 6:
        network = ip_network(value, strict=False)
    else:
        wildcard = int(IPv4Address(tokens.pop(0)))
        # Inverse masks must be contiguous. Never widen a discontiguous wildcard.
        if wildcard & (wildcard + 1):
            raise ValueError('discontiguous ACL wildcard requires exact bit matching')
        mask = 32 - wildcard.bit_length()
        network = ip_network(value + '/' + str(mask), strict=False)
    if network.version != family:
        raise ValueError('ACL address family mismatch')
    return str(network)


def ports(tokens):
    if not tokens or tokens[0] not in ('eq', 'range', 'lt', 'gt', 'neq'):
        return 0, 65535
    operator = tokens.pop(0)
    first = tokens.pop(0)
    if not first.isdigit() or not 0 <= int(first) <= 65535:
        raise ValueError('named or invalid ACL port unsupported')
    first = int(first)
    if operator == 'eq':
        return first, first
    if operator == 'range':
        last = tokens.pop(0)
        if not last.isdigit() or not first <= int(last) <= 65535:
            raise ValueError('invalid ACL port range')
        return first, int(last)
    if operator == 'lt' and first > 0:
        return 0, first-1
    if operator == 'gt' and first < 65535:
        return first+1, 65535
    raise ValueError('unsupported ACL port operator')


def ace(line, family, standard=False):
    tokens = line.split()
    sequence = int(tokens.pop(0)) if tokens and tokens[0].isdigit() else None
    if tokens and tokens[0] == 'remark':
        return None
    result = dict(sequence=sequence, native=line, action='unknown', selectors=[], parsed=False)
    try:
        action = tokens.pop(0)
        if action not in ('permit', 'deny'):
            raise ValueError('unsupported ACL entry')
        protocol = 'ip' if standard else tokens.pop(0)
        src = acl_address(tokens, family)
        source_ports = ports(tokens) if protocol in ('tcp', 'udp') else (0, 65535)
        dst = None if standard else acl_address(tokens, family)
        dest_ports = ports(tokens) if protocol in ('tcp', 'udp') else (0, 65535)
        service = None
        if protocol in ('tcp', 'udp'):
            service = dict(protocol=protocol, source_port_start=source_ports[0], source_port_end=source_ports[1],
                destination_port_start=dest_ports[0], destination_port_end=dest_ports[1])
            if tokens and tokens[0] == 'established' and protocol == 'tcp':
                tokens.pop(0)
                service['tcp_flags_any'] = ['ack', 'rst']
        elif protocol not in (('ip',) if family == 4 else ('ipv6',)):
            raise ValueError('protocol/ICMP/object-group ACL semantics unsupported')
        if tokens and tokens[0] in ('log', 'log-input'):
            tokens.pop(0)
        if tokens:
            raise ValueError('additional ACL conditions unsupported')
        result.update(action='allow' if action == 'permit' else 'deny', parsed=True,
            selectors=[selector('source', 'address', src) if src else selector('source'),
                       selector('destination', 'address', dst) if dst else selector('destination'),
                       selector('service', 'service', service) if service else selector('service')])
    except (ValueError, IndexError, TypeError) as error:
        result['reason'] = str(error)
    return result


def parse_acls(text):
    definitions, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        header = re.fullmatch(r'ip access-list (standard|extended) (\S+)|ipv6 access-list (\S+)', line)
        if header:
            family, name, standard = (6, header[3], False) if header[3] else (4, header[2], header[1] == 'standard')
            current = (family, name)
            if current in definitions:
                raise ValueError('duplicate ACL definition')
            definitions[current] = dict(standard=standard, entries=[])
            continue
        numbered = re.fullmatch(r'access-list (\d+) (.+)', line)
        if numbered:
            number = int(numbered[1])
            standard = 1 <= number <= 99 or 1300 <= number <= 1999
            if not standard and not (100 <= number <= 199 or 2000 <= number <= 2699):
                current = None
                continue
            key = (4, numbered[1])
            definitions.setdefault(key, dict(standard=standard, entries=[]))['entries'].append(ace(numbered[2], 4, standard))
            current = None
        elif current and line and line != '!':
            definitions[current]['entries'].append(ace(line, current[0], definitions[current]['standard']))
        elif not line or line == '!':
            current = None
    for definition in definitions.values():
        definition['entries'] = [entry for entry in definition['entries'] if entry is not None]
        sequences = [e['sequence'] for e in definition['entries'] if e['sequence'] is not None]
        if len(sequences) != len(set(sequences)):
            raise ValueError('duplicate ACL sequence')
        if sequences and len(sequences) == len(definition['entries']):
            definition['entries'].sort(key=lambda e: e['sequence'])
    return definitions


def parse_interfaces(text):
    blocks, current = {}, None
    for raw in text.splitlines():
        if raw.startswith('interface '):
            name = raw.split(None, 1)[1].strip()
            if name in blocks:
                raise ValueError('duplicate interface identity')
            current = blocks[name] = dict(name=name, native_id=name, kind='virtual' if name.startswith(('Loopback','Vlan','Tunnel','Port-channel')) else 'physical',
                vrf='default', addresses=[], config=dict(origin='ios_configured_interface', shutdown=False, native_lines=[], unresolved=[]))
        elif current and raw.startswith(' '):
            line = raw.strip()
            current['config']['native_lines'].append(line)
            try:
                if line.startswith(('vrf forwarding ', 'ip vrf forwarding ')):
                    current['vrf'] = line.split()[-1]
                elif line == 'shutdown':
                    current['config']['shutdown'] = True
                elif line.startswith('ip address '):
                    fields = line.split()[2:]
                    if len(fields) not in (2,3) or len(fields) == 3 and fields[2] != 'secondary':
                        raise ValueError('dynamic/negotiated/unsupported IPv4 address')
                    current['addresses'].append(str(ip_interface(fields[0] + '/' + fields[1])))
                elif line.startswith('ipv6 address '):
                    fields = line.split()[2:]
                    if len(fields) != 1 or '/' not in fields[0]:
                        raise ValueError('EUI64/link-local/dynamic IPv6 address unresolved')
                    current['addresses'].append(str(ip_interface(fields[0])))
                elif re.search(r'\b(policy route-map|inspect|zone-member|service-policy|switchport|ip unnumbered)\b', line):
                    current['config']['unresolved'].append('feature requires additional forwarding/enforcement evidence: ' + line)
            except (ValueError, IndexError) as error:
                current['config']['unresolved'].append(str(error))
        else:
            current = None
    return list(blocks.values())


def static_routes(text):
    routes, candidates = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        candidate = dict(native=line, unresolved=[])
        try:
            tokens = line.split()
            family = 4 if tokens[:2] == ['ip','route'] else 6 if tokens[:2] == ['ipv6','route'] else None
            if family is None:
                raise ValueError('unsupported static route command')
            tokens = tokens[2:]
            vrf = tokens[1] if tokens[0] == 'vrf' else 'default'
            if tokens[0] == 'vrf':
                tokens = tokens[2:]
            prefix = ip_network(tokens.pop(0) + ('/' + tokens.pop(0) if family == 4 else ''), strict=False)
            if prefix.version != family:
                raise ValueError('static route family mismatch')
            interface, hop = None, None
            if tokens[0] == 'Null0':
                interface = tokens.pop(0)
            else:
                try:
                    hop = str(ip_address(tokens[0]))
                    tokens.pop(0)
                except ValueError:
                    interface = tokens.pop(0)
                    if not re.fullmatch(r'[A-Za-z][A-Za-z-]*\d[\w/.:-]*', interface):
                        raise ValueError('unknown static route egress syntax')
                    if tokens:
                        try:
                            hop = str(ip_address(tokens[0]))
                            tokens.pop(0)
                        except ValueError:
                            pass
            distance = int(tokens.pop(0)) if tokens and tokens[0].isdigit() else 1
            if not 1 <= distance <= 255 or tokens:
                raise ValueError('tracked/tagged/global/conditional static route unresolved')
            if hop and ip_address(hop).version != family:
                raise ValueError('next-hop family mismatch')
            route = dict(vrf=vrf, destination=str(prefix), next_hop=hop, interface=interface, route_type='forward',
                details=dict(origin='ios_configured_static', native=line, administrative_distance=distance, evidence='configured_unverified'))
            if interface == 'Null0':
                route.update(interface=None, next_hop=None, route_type='discard')
            candidate['normalized'] = route
            routes.append(route)
        except (ValueError, IndexError, TypeError) as error:
            candidate['unresolved'].append(str(error))
        candidates.append(candidate)
    return routes, candidates


def rib_routes(text, interfaces, family=4, default_vrf='default'):
    """Explicit CIDR route display subset; do not infer classful subnet masks."""
    routes, evidence, current, vrf = [], [], None, default_vrf
    names = {i['name'] for i in interfaces}
    contexts = {i['name']: i['vrf'] for i in interfaces}
    aliases = {'Gi':'GigabitEthernet', 'Te':'TenGigabitEthernet', 'Fa':'FastEthernet',
               'Eth':'Ethernet', 'Et':'Ethernet', 'Lo':'Loopback', 'Vl':'Vlan', 'Tu':'Tunnel', 'Po':'Port-channel'}
    def interface_name(value):
        if value == 'Null0' or value in names:
            return value
        for short, full in aliases.items():
            if re.fullmatch(re.escape(short) + r'\d[\d/.:]*', value) and full + value[len(short):] in names:
                return full + value[len(short):]
        return None
    for raw in text.splitlines():
        line = raw.strip()
        context = re.fullmatch(r'(?:Routing Table:|IPv6 Routing Table -)\s*(\S+).*', line)
        if context:
            vrf, current = context[1], None
            continue
        match = re.match(r'^([A-Za-z0-9*+% ]+?)\s+([0-9a-fA-F:.]+/\d+)\s*(.*)$', line)
        if match:
            try:
                prefix = ip_network(match[2], strict=False)
                if prefix.version != family:
                    raise ValueError('RIB address family mismatch')
                current = dict(destination=str(prefix), code=match[1].strip(), vrf=vrf)
                tail = match[3]
            except ValueError:
                current = None
                evidence.append(dict(native=raw, reason='invalid RIB prefix'))
                continue
        elif current and (line.startswith('[') or line.startswith('via ')):
            tail = line
        else:
            if re.search(r'\b(?:via|directly connected)\b', line):
                evidence.append(dict(native=raw, reason='unsupported RIB display or missing explicit prefix'))
            if line and not line.startswith('['):
                current = None
            continue
        if not tail:
            continue
        candidate = dict(native=raw, **current)
        try:
            if current['code'].startswith('L'):
                raise ValueError('local receive route retained without forwarding interpretation')
            distance = re.search(r'\[(\d+)/(\d+)\]', tail)
            fields = [v.strip() for v in tail.split(',')]
            iface = interface_name(fields[-1])
            if re.search(r'[()%]', tail):
                raise ValueError('scoped/cross-VRF RIB next hop requires native resolution')
            if iface is None and re.fullmatch(r'[A-Za-z][A-Za-z-]*\d[\w/.:-]*', fields[-1]):
                raise ValueError('explicit RIB interface not collected')
            if iface in contexts and contexts[iface] != vrf:
                raise ValueError('RIB interface belongs to another VRF')
            direct = 'is directly connected' in tail or family == 6 and current['code'] == 'C'
            hop_match = re.search(r'\bvia\s+([0-9a-fA-F:.]+)', tail)
            hop = str(ip_address(hop_match[1])) if hop_match else None
            if hop and ip_address(hop).version != family:
                raise ValueError('RIB next-hop family mismatch')
            if direct:
                hop = None
            if iface != 'Null0' and (direct and iface is None or not direct and hop is None):
                raise ValueError('unsupported RIB next-hop/interface')
            route_type = 'connected' if direct else 'forward'
            if iface == 'Null0':
                route_type, iface, hop = 'discard', None, None
            route = dict(vrf=vrf, destination=current['destination'], next_hop=hop, interface=iface, route_type=route_type,
                details=dict(origin='ios_active_rib', code=current['code'], native=raw, evidence='rib_unverified_fib',
                    administrative_distance=int(distance[1]) if distance else None, metric=int(distance[2]) if distance else None))
            routes.append(route)
            candidate['normalized'] = route
        except (ValueError, TypeError) as error:
            candidate['reason'] = str(error)
        evidence.append(candidate)
    return routes, evidence


def translate_export(export):
    outputs, findings = command_outputs(export)
    interfaces = parse_interfaces(outputs.get(CONFIG_COMMANDS['interfaces'], ''))
    definitions = parse_acls(outputs.get(CONFIG_COMMANDS['acls'], ''))
    routes, route_candidates = static_routes(outputs.get(CONFIG_COMMANDS['routes'], ''))
    rib, rib_candidates, rib_collected = [], [], False
    for command, output in outputs.items():
        command_match = re.fullmatch(r'show (ip|ipv6) route(?: vrf (\S+))?', command)
        if command_match:
            rib_collected = True
            selected_vrf = command_match[2] or 'default'
            # Multi-VRF commands need native table headers for every block.
            if selected_vrf in ('*', 'all') and not re.search(r'Routing Table:|IPv6 Routing Table -', output):
                findings.append(dict(command=command, reason='VRF table headers unavailable'))
                continue
            values, evidence = rib_routes(output, interfaces, 4 if command_match[1] == 'ip' else 6,
                'default' if selected_vrf in ('*','all') else selected_vrf)
            rib.extend(values)
            rib_candidates.extend(evidence)
    if rib_collected:
        # Never combine configured fallback routes with a partial active RIB.
        seen = set()
        routes = []
        for route in rib:
            key = (route['vrf'], route['destination'], route['next_hop'], route['interface'], route['route_type'])
            if key not in seen:
                routes.append(route)
                seen.add(key)
    policies = []
    for interface in interfaces:
        for line in interface['config']['native_lines']:
            attached = re.fullmatch(r'ip access-group (\S+) (in|out)|ipv6 traffic-filter (\S+) (in|out)', line)
            if not attached:
                continue
            family, name, direction = (6, attached[3], attached[4]) if attached[3] else (4, attached[1], attached[2])
            definition = definitions.get((family,name))
            entries = definition['entries'] if definition else [dict(action='unknown', selectors=[], native='missing ACL definition', parsed=False)]
            for index, entry in enumerate(entries):
                policies.append(dict(enforcement_point=export['device_id'] + ':' + interface['name'],
                    rule_set='ipv' + str(family) + ':' + direction + ':' + name, default_action='deny', rule_id=str(entry.get('sequence') or index+1),
                    position=index+1, action=entry['action'], enabled=True, selectors=entry['selectors'],
                    details=dict(origin='ios_interface_acl', native_ace=entry['native'], native_acl=name,
                        selectors_complete=False, syntax_parsed=entry['parsed'], stateless=True,
                        interface_condition=dict(native_id=interface['native_id'], direction=direction, ip_version=family),
                        vrf=interface['vrf'], unresolved=entry.get('reason'))))
    nat = []
    for index, line in enumerate(outputs.get(CONFIG_COMMANDS['nat'], '').splitlines()):
        if not line.strip():
            continue
        record = dict(enforcement_point=export['device_id'], rule_set='ios-nat', rule_id=str(index+1), position=index+1,
            enabled=True, processing_stage='ios_inside_outside_unverified', translation_kind='unknown', translation={}, selectors=[],
            details=dict(origin='ios_nat', native=line, selectors_complete=False))
        match = re.fullmatch(r'ip nat inside source static (\S+) (\S+)(?: extendable)?', line)
        try:
            if not match:
                raise ValueError('dynamic/PAT/port/VRF/route-map NAT requires additional stage and session modeling')
            local, global_ip = str(ip_address(match[1])), str(ip_address(match[2]))
            if ip_address(local).version != 4 or ip_address(global_ip).version != 4:
                raise ValueError('only explicit IPv4 static host mapping supported')
            record.update(translation_kind='source', translation=dict(address=global_ip),
                selectors=[selector('source','address',local), selector('destination'), selector('service')])
            record['details'].update(inside_local=local, inside_global=global_ip, reverse_destination_candidate=local,
                unresolved='inside/outside association, VRF, NAT order and reverse session unverified')
        except ValueError as error:
            record['details']['unresolved'] = str(error)
        nat.append(record)
    return dict(device_id=export['device_id'], interfaces=interfaces, routes=routes, route_candidates=route_candidates,
        policies=policies, nat=nat, rib_candidates=rib_candidates, acl_definitions=[dict(family=k[0], name=k[1], **v) for k,v in definitions.items()],
        findings=findings, coverage='partial', native_outputs=outputs,
        limitations=['configuration does not establish installed forwarding or effective policy',
            'PBR/ZBF/CBAC/CoPP/L2 enforcement, dynamic objects, NAT stages and runtime state remain unverified'])


def normalized_submissions(export, namespace, external_device_id):
    if any(not isinstance(value, str) or not value.strip() for value in (namespace,external_device_id)):
        raise ValueError('mapped source identity required')
    semantics = translate_export(export)
    base = dict(source=dict(namespace=namespace, external_device_id=external_device_id),
        adapter=dict(name='navis',input_format='normalized-json',format_version='1'),collected_at=export['collected_at'],completeness='partial')
    requests = [{**base,'data_type':kind,'payload':dict(entries=semantics[key])} for kind,key in
                (('interface','interfaces'),('route','routes'),('policy','policies'),('nat','nat'))]
    requests.append({**base,'data_type':'topology','payload':dict(kind='ios_device_evidence',version=1,semantics=semantics)})
    return requests
