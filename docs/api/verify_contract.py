"""Validate integration examples; --write refreshes request files and OpenAPI.

Run from the repository root with the project and httpx installed:
  python docs/api/verify_contract.py --write
No database, network connection or application startup is used.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from navis_api.main import app
from navis_api.ingestion import Ingestion
from navis_api.trace import TraceRequest
from navis_api.normalized_adapter import normalize
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.auth import Principal


ROOT = Path(__file__).resolve().parent
BUILD = '20000000-0000-4000-8000-000000000001'
SESSION = '40000000-0000-4000-8000-000000000001'
RECEIPT = '10000000-0000-4000-8000-000000000001'


def examples():
    selectors = [dict(role='source', kind='address', value='192.0.2.0/24', negated=False),
                 dict(role='destination', kind='address', value='198.51.100.5/32', negated=False),
                 dict(role='service',kind='service',value=dict(protocol='tcp',destination_port_start=443,destination_port_end=443),negated=False)]
    entries = dict(
        interface=[dict(name='GigabitEthernet0/0', native_id='GigabitEthernet0/0', kind='physical', vrf='BLUE',
            addresses=['192.0.2.1/24'], operational_state='up', config=dict(evidence='collected'))],
        route=[dict(vrf='BLUE',destination='203.0.113.0/24',next_hop='192.0.2.254',interface='GigabitEthernet0/0',route_type='forward',details=dict(evidence='configured_unverified'))],
        neighbor=[dict(interface='GigabitEthernet0/0',vrf='BLUE',ip='192.0.2.254',mac='00:11:22:33:44:55',state='reachable')],
        mac=[dict(interface='GigabitEthernet0/0',mac='0011.2233.4455',vlan=100)],
        security_zone=[dict(enforcement_point='firewall-a:vsys1',zone='trust',interfaces=['ethernet1/1'])],
        policy=[dict(enforcement_point='firewall-a:vsys1',rule_set='security',default_action='unknown',rule_id='allow-web',position=10,
            action='allow',enabled=True,selectors=selectors,details=dict(statefulness='unknown',selectors_complete=False))],
        nat=[dict(enforcement_point='firewall-a:vsys1',rule_set='nat',processing_stage='before_route_after_policy',rule_id='dnat-web',position=10,
            enabled=True,translation_kind='destination',translation=dict(address='198.51.100.5',port=443),
            selectors=[dict(role='source',kind='any',value=None,negated=False),dict(role='destination',kind='address',value='203.0.113.5/32',negated=False),
                dict(role='service',kind='service',value=dict(protocol='tcp',destination_port_start=8443,destination_port_end=8443),negated=False)],
            details=dict(selectors_complete=False))])
    result = {}
    for kind, values in entries.items():
        result['ingestion-' + kind.replace('_','-') + '.json'] = dict(
            source=dict(namespace='collector-site-a',external_device_id='router-a' if kind in ('interface','route','neighbor','mac') else 'firewall-a'),
            adapter=dict(name='navis',input_format='normalized-json',format_version='1'),data_type=kind,
            collected_at='2026-10-30T04:00:00Z',completeness='partial',payload=dict(entries=values))
    result['trace.json'] = dict(graph_build_id=BUILD,caller_session_id='myproject-20261030-7b1c4d',source='192.0.2.10;192.0.2.11',
        destination='198.51.100.5',protocol='tcp',source_port=51000,destination_port=443)
    return result


def unresolved_trace(trace_request):
    """Actual trace implementation with an empty synthetic database view."""
    connection, cursor = MagicMock(), MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchone.side_effect = [('docs-consumer',), ('20000000-0000-4000-8000-000000000002','completed','navis_docs',{}), None]
    cursor.fetchall.return_value = []
    request = TraceRequest.model_validate(trace_request)
    principal = Principal(subject='docs',issuer='docs',scopes=frozenset({'analysis:run'}))
    with patch('navis_api.trace_postgres.evidence_manifest',return_value={}):
        return PostgresTraceProcessor(lambda:connection).trace(request,request.flows(),principal)


def http_boundary_checks(envelope, trace_request, trace_result):
    """Exercise actual HTTP handlers with fake storage; no live integration claim."""
    scopes = {'inventory:write','graph:read','analysis:run','analysis:read','application:read'}
    class Verifier:
        def verify(self, token):
            if token == 'documentation-test':
                return Principal(subject='docs', issuer='docs', scopes=frozenset(scopes))
            return None
    class Ingest:
        def submit(self, submission, principal):
            return dict(ingestion_id=RECEIPT,status='pending_identity')
    class Trace:
        def trace(self, request, flows, principal):
            return deepcopy(trace_result)
    class Sessions:
        def save(self, *args):
            return SESSION
        def recommendations(self, principal, caller_id):
            return dict(code='RECOMMENDATIONS_UNAVAILABLE',caller_session_id=caller_id,trace_session_id=SESSION,
                recommendations=[dict(status='unavailable',result=None)])
    names = ('token_verifier','ingestion_processor','trace_processor','trace_sessions','graph_reader')
    original = {name:getattr(app.state,name) for name in names}
    try:
        app.state.token_verifier = Verifier()
        app.state.ingestion_processor = Ingest()
        app.state.trace_processor = Trace()
        app.state.trace_sessions = Sessions()
        app.state.graph_reader = lambda build, principal: dict(build_id=str(build),dataset_id=BUILD,status='completed',nodes=[],connections=[],projection_status='device_identity_only')
        # No context manager: intentionally do not run environment-driven startup.
        client = TestClient(app)
        headers = {'Authorization':'Bearer documentation-test'}
        assert client.get('/health/live').json() == {'status':'ok'}
        assert client.post('/v1/ingestions',json=envelope).status_code == 401
        response = client.post('/v1/ingestions',headers=headers,json=envelope)
        assert response.status_code == 202 and response.json() == dict(ingestion_id=RECEIPT,status='pending_identity')
        assert client.get('/v1/graph-builds/'+BUILD+'/graph',headers=headers).json()['projection_status'] == 'device_identity_only'
        assert client.get('/v1/graph-builds/invalid/graph',headers=headers).status_code == 422
        response = client.post('/v1/traces',headers=headers,json=trace_request)
        assert response.status_code == 200 and response.json()['code'] == 'TRACE_RESULT_READY'
        assert len(response.json()['results']) == 2
        assert client.get('/v1/trace-sessions/docs-session/recommendations',headers=headers).json()['code'] == 'RECOMMENDATIONS_UNAVAILABLE'
        invalid = dict(trace_request, source='192.0.2.0/24')
        assert client.post('/v1/traces',headers=headers,json=invalid).status_code == 422
        assert client.post('/v1/traces',headers=headers,json=dict(trace_request,extra=True)).status_code == 422
        scopes.remove('inventory:write')
        assert client.post('/v1/ingestions',headers=headers,json=envelope).status_code == 403
        client.close()
    finally:
        for name,value in original.items():
            setattr(app.state,name,value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args = parser.parse_args()
    values = examples()
    for name, value in values.items():
        if name.startswith('ingestion-'):
            model = Ingestion.model_validate(value)
            normalize(model.data_type,model.payload)
        else:
            assert len(TraceRequest.model_validate(value).flows()) == 2
    schema = app.openapi()
    assert len(schema['paths']) == 7
    trace_result = unresolved_trace(values['trace.json'])
    responses = {
        'ingestion-accepted.json': dict(ingestion_id=RECEIPT,status='pending_identity'),
        'trace-unresolved.json':dict(code='TRACE_RESULT_READY',caller_session_id=values['trace.json']['caller_session_id'],trace_session_id=SESSION,**trace_result),
        'recommendations-unavailable.json':dict(code='RECOMMENDATIONS_UNAVAILABLE',caller_session_id=values['trace.json']['caller_session_id'],trace_session_id=SESSION,recommendations=[dict(status='unavailable',result=None)])}
    artifacts = {ROOT/'openapi.json':schema, **{ROOT/'examples'/name:value for name,value in values.items()},
        **{ROOT/'responses'/name:value for name,value in responses.items()}}
    for path,value in artifacts.items():
        if args.write:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
        else:
            assert json.loads(path.read_text(encoding='utf-8')) == value, 'stale artifact: ' + str(path)
    http_boundary_checks(values['ingestion-interface.json'],values['trace.json'],trace_result)
    print('Validated 8 requests, 3 response fixtures, 7 API paths, OpenAPI and mocked HTTP/trace checks.')


if __name__ == '__main__':
    main()
