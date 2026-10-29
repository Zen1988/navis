"""Check build evidence and detect a rolled-back test mutation."""
import os
from uuid import UUID
import psycopg
from navis_api.build_evidence import evidence_manifest

dsn = os.environ["NAVIS_AGE_TEST_DSN"]
build_id = UUID(os.environ["NAVIS_TEST_BUILD_ID"])
with psycopg.connect(dsn) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT dataset_id,evidence_manifest FROM navis.graph_build WHERE id=%s", (build_id,))
        dataset_id, stored = cur.fetchone()
        assert stored and stored == evidence_manifest(cur, dataset_id), "build evidence does not match"
        cur.execute("UPDATE navis.policy_rule SET name='temporary-manifest-test' WHERE id='10000000-0000-4000-8000-000000000095'")
        assert stored != evidence_manifest(cur, dataset_id), "mutation was not detected"
        conn.rollback()
print("Build evidence change detection passed; mutation rolled back")
