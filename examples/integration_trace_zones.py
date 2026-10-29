"""Run against the AGE test DB after loading the three-device zone fixture."""
import json
import os
from types import SimpleNamespace
from uuid import UUID

import psycopg
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.auth import Principal
from navis_common.trace import expand_flows

dsn = os.environ["NAVIS_AGE_TEST_DSN"]
processor = PostgresTraceProcessor(lambda: psycopg.connect(dsn))
request = SimpleNamespace(graph_build_id=UUID(os.environ["NAVIS_TEST_BUILD_ID"]))
principal = Principal("local-test", frozenset({"analysis:run"}), "navis-local")
for port, expected in ((443, "allow"), (22, "deny")):
    result = processor.trace(request, expand_flows("192.0.2.1", "198.51.100.10", "tcp", port), principal)
    hops = result["results"][0]["hops"]
    assert len(hops) == (3 if port == 443 else 2), f"Unexpected hop count for port {port}: {hops}"
    firewall = hops[1]
    evaluation = firewall["policy_evaluations"][0]
    assert (evaluation["decision"], evaluation["source_zone"], evaluation["destination_zone"]) == (expected, "APP", "DB"), evaluation
    if port == 22:
        recommendation = firewall["recommendations"][0]
        assert (recommendation["source_zone"], recommendation["destination_zone"]) == ("APP", "DB"), recommendation
    print(json.dumps({"port": port, "firewall": firewall}, indent=2))
print("Zone integration checks passed")
