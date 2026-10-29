"""Exercise the restricted NAT stage with existing AGE fixture data."""
import json
import os
from types import SimpleNamespace
from uuid import UUID
import psycopg
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.auth import Principal
from navis_common.trace import expand_flows

dsn = os.environ["NAVIS_AGE_TEST_DSN"]
build_id = UUID(os.environ["NAVIS_TEST_BUILD_ID"])
processor = PostgresTraceProcessor(lambda: psycopg.connect(dsn))
request = SimpleNamespace(graph_build_id=build_id)
principal = Principal("local-test", frozenset({"analysis:run"}), "navis-local")
for port in (443, 22):
    result = processor.trace(request, expand_flows("192.0.2.1", "198.51.100.10", "tcp", port), principal)
    hops = result["results"][0]["hops"]
    assert len(hops) >= 2, hops
    firewall = hops[1]
    if port == 443:
        assert firewall["packet_before"]["destination"] == "198.51.100.10", firewall
        assert firewall["packet_after"]["destination"] == "10.10.1.10", firewall
        assert firewall["nat_evidence"][0]["rule_id"] == "dnat-web", firewall
        assert firewall["route"]["prefix"] == "10.10.1.0/24", firewall
    else:
        assert firewall["packet_after"]["destination"] == "198.51.100.10", firewall
        assert firewall["nat_evidence"][0]["status"] == "unchanged", firewall
        assert firewall["route"]["prefix"] == "198.51.100.0/24", firewall
    print(json.dumps({"port": port, "firewall": firewall}, indent=2))
print("NAT and route selection checks passed; end-to-end reachability remains unverified")
