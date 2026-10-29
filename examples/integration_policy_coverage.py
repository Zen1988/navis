"""Verify normalized policy applicability on the test dataset."""
import os
from types import SimpleNamespace
from uuid import UUID
import psycopg
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.auth import Principal
from navis_common.trace import expand_flows

dsn = os.environ["NAVIS_AGE_TEST_DSN"]
request = SimpleNamespace(graph_build_id=UUID(os.environ["NAVIS_TEST_BUILD_ID"]))
principal = Principal("local-test", frozenset({"analysis:run"}), "navis-local")
result = PostgresTraceProcessor(lambda: psycopg.connect(dsn)).trace(
    request, expand_flows("192.0.2.1", "198.51.100.10", "tcp", 443), principal)["results"][0]
assert result["coverage"]["relational_evidence_unchanged"], result["coverage"]
assert result["coverage"]["policy"]["complete"], result["coverage"]
assert [hop["policy_direction_applicability"]["ingress"] for hop in result["hops"]] == ["not_applicable", "enforced", "not_applicable"]
assert result["status"] == "unknown", "forwarding evidence is not yet verified"
print("Normalized policy applicability and coverage checks passed; overall verdict remains unknown")
