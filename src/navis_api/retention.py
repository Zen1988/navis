"""Operator maintenance: archive inactive historical bundles, then purge audit.

Normal request paths never read audit implicitly. Run without --apply to preview.
Each archived bundle is copied and removed in one transaction; retained foreign
keys and current graph/trace dependencies stop a bundle from moving.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
from uuid import uuid4


class ProtectedData(ValueError):
    pass


PROTECTED = {"source_system", "device", "device_identity_mapping", "api_consumer", "consumer_data_scope",
             "adapter_artifact", "instance_identity", "nauth_client", "nauth_access_token",
             "topology_definition", "topology_version", "trace_session", "topology_link_endpoint",
             "analysis_result", "analysis_dataset_snapshot", "analysis_step", "analysis_finding", "recommendation",
             "graph_build", "device_snapshot"}

DEPENDENTS = {'trace_recommendation_draft', 'topology_build', 'graph_build_snapshot', 'graph_dataset_snapshot',
              'graph_config', 'adapter_verification', 'ingestion_submission', 'raw_payload', 'snapshot_coverage',
              'normalization_run', 'interface', 'interface_address', 'interface_segment', 'routing_context',
              'route', 'route_next_hop', 'route_protocol_attributes', 'neighbor_entry', 'mac_entry',
              'enforcement_point', 'security_zone', 'security_zone_member', 'address_object', 'address_group_member',
              'service_object', 'service_group_member', 'policy_rule_set', 'policy_rule', 'policy_selector',
              'policy_schedule', 'policy_applicability', 'nat_rule_set', 'nat_rule', 'nat_selector',
              'nat_translation', 'nat_session_evidence'}


def dependency_order(edges, root):
    order, visiting, done = [], set(), set()
    def visit(node):
        if node in visiting:
            raise ProtectedData("cyclic dependencies require explicit maintenance")
        if node in done:
            return
        visiting.add(node)
        for child in edges.get(node, []):
            visit(child)
        visiting.remove(node)
        done.add(node)
        order.append(node)
    visit(root)
    return order


class Retention:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    @staticmethod
    def candidates(cur, namespace, limit):
        # Current heads and graph/snapshot dependencies remain live regardless
        # of age. Freshness uses updated_at, never the original graph build date.
        cur.execute("SELECT archive_after_days,audit_retention_years FROM navis.retention_policy WHERE singleton")
        days, years = cur.fetchone()
        cur.execute("SELECT id FROM navis.source_system WHERE namespace=%s", (namespace,))
        source = cur.fetchone()
        if source is None:
            raise LookupError("namespace not found")
        source = source[0]
        queries = {
            "trace_session": """SELECT s.id,s.updated_at,s.consumer_id FROM navis.trace_session s
                WHERE s.expires_at<=now() AND s.updated_at<now()-%s*interval '1 day'
                AND EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs JOIN navis.device_snapshot snap ON snap.id=bs.snapshot_id
                    JOIN navis.import_batch b ON b.id=snap.import_batch_id WHERE bs.graph_build_id=s.graph_build_id AND b.source_system_id=%s)
                ORDER BY s.updated_at LIMIT %s""",
            "topology_version": """SELECT v.id,v.updated_at,d.consumer_id FROM navis.topology_version v
                JOIN navis.topology_definition d ON d.id=v.topology_id WHERE d.source_system_id=%s
                AND v.id<>d.latest_version_id AND v.updated_at<now()-%s*interval '1 day'
                AND NOT EXISTS (SELECT 1 FROM navis.trace_session s WHERE s.graph_build_id=v.build_id AND s.expires_at>now())
                ORDER BY v.updated_at LIMIT %s""",
            "ingestion_submission": """SELECT i.id,i.updated_at,NULL::uuid FROM navis.ingestion_submission i
                WHERE i.source_system_id=%s AND i.updated_at<now()-%s*interval '1 day' AND i.status IN ('processed','raw_only')
                AND i.snapshot_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs WHERE bs.snapshot_id=i.snapshot_id)
                AND NOT EXISTS (SELECT 1 FROM navis.graph_dataset_snapshot ds WHERE ds.snapshot_id=i.snapshot_id)
                AND NOT EXISTS (SELECT 1 FROM navis.topology_version v, jsonb_array_elements(COALESCE(v.latest_evidence->'snapshots','[]')) e WHERE e->>'snapshot_id'=i.snapshot_id::text)
                ORDER BY i.updated_at LIMIT %s""",
            "graph_build": """SELECT b.id,b.completed_at,NULL::uuid FROM navis.graph_build b
                JOIN navis.topology_build t ON t.build_id=b.id WHERE t.source_system_id=%s
                AND b.completed_at<now()-%s*interval '1 day'
                AND NOT EXISTS (SELECT 1 FROM navis.topology_version v WHERE v.build_id=b.id)
                AND NOT EXISTS (SELECT 1 FROM navis.topology_definition d WHERE d.latest_build_id=b.id)
                AND NOT EXISTS (SELECT 1 FROM navis.trace_session s WHERE s.graph_build_id=b.id)
                ORDER BY b.completed_at LIMIT %s""",
            "graph_dataset": """SELECT d.id,d.created_at,NULL::uuid FROM navis.graph_dataset d
                WHERE d.created_at<now()-%s*interval '1 day' AND NOT EXISTS (SELECT 1 FROM navis.graph_build b WHERE b.dataset_id=d.id)
                AND EXISTS (SELECT 1 FROM navis.graph_dataset_snapshot ds JOIN navis.device_snapshot s ON s.id=ds.snapshot_id
                    JOIN navis.import_batch b ON b.id=s.import_batch_id WHERE ds.dataset_id=d.id AND b.source_system_id=%s)
                ORDER BY d.created_at LIMIT %s""",
            "device_snapshot": """SELECT s.id,s.received_at,NULL::uuid FROM navis.device_snapshot s
                JOIN navis.import_batch b ON b.id=s.import_batch_id WHERE b.source_system_id=%s AND s.received_at<now()-%s*interval '1 day'
                AND NOT EXISTS (SELECT 1 FROM navis.graph_build_snapshot bs WHERE bs.snapshot_id=s.id)
                AND NOT EXISTS (SELECT 1 FROM navis.graph_dataset_snapshot ds WHERE ds.snapshot_id=s.id)
                AND NOT EXISTS (SELECT 1 FROM navis.analysis_dataset_snapshot ds WHERE ds.snapshot_id=s.id)
                AND NOT EXISTS (SELECT 1 FROM navis.topology_version v, jsonb_array_elements(COALESCE(v.latest_evidence->'snapshots','[]')) e WHERE e->>'snapshot_id'=s.id::text)
                AND NOT EXISTS (SELECT 1 FROM navis.snapshot_coverage c WHERE c.snapshot_id=s.id AND NOT EXISTS (
                    SELECT 1 FROM navis.device_snapshot newer JOIN navis.import_batch nb ON nb.id=newer.import_batch_id
                    JOIN navis.snapshot_coverage nc ON nc.snapshot_id=newer.id AND nc.data_type=c.data_type
                    WHERE nb.source_system_id=b.source_system_id AND newer.device_id=s.device_id AND
                    (newer.collected_at,newer.received_at,newer.id)>(s.collected_at,s.received_at,s.id)))
                ORDER BY s.received_at LIMIT %s""",
            "import_batch": """SELECT b.id,b.received_at,NULL::uuid FROM navis.import_batch b
                WHERE b.source_system_id=%s AND b.received_at<now()-%s*interval '1 day'
                AND NOT EXISTS (SELECT 1 FROM navis.device_snapshot s WHERE s.import_batch_id=b.id)
                ORDER BY b.received_at LIMIT %s""",
            "audit_event": """SELECT e.id,e.occurred_at,e.api_consumer_id FROM navis.audit_event e
                WHERE EXISTS (SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=e.api_consumer_id AND ds.source_system_id=%s)
                AND e.occurred_at<now()-%s*interval '1 day'
                AND (SELECT count(DISTINCT ds.source_system_id) FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=e.api_consumer_id)=1
                ORDER BY e.occurred_at LIMIT %s""",
        }
        items = []
        for table, query in queries.items():
            params = (days, source, limit) if table in ("trace_session", "graph_dataset") else (source, days, limit)
            cur.execute(query, params)
            items.extend({"table": table, "id": str(row[0]), "updated_at": row[1], "consumer_id": row[2]} for row in cur.fetchall())
        return source, days, years, items

    @staticmethod
    def archive_bundle(cur, table, key, source, consumer, updated_at, years, days=90):
        from psycopg import sql
        from psycopg.types.json import Jsonb
        cur.execute("SELECT now()")
        server_now = cur.fetchone()[0]
        if table == 'graph_build':
            cur.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s,2))", ('graph:'+str(key),))
            if not cur.fetchone()[0]:
                raise ProtectedData("graph is currently being traced")
        cur.execute("""SELECT t.relname,array_agg(a.attname ORDER BY k.ordinality)
            FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum,ordinality)
            JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum
            WHERE n.nspname='navis' AND c.contype='p' GROUP BY t.relname""")
        keys = dict(cur.fetchall())
        cur.execute("""SELECT parent.relname,child.relname,
            array_agg(pa.attname ORDER BY k.ordinality),array_agg(ca.attname ORDER BY k.ordinality)
            FROM pg_constraint c JOIN pg_class parent ON parent.oid=c.confrelid
            JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace n ON n.oid=child.relnamespace
            CROSS JOIN LATERAL unnest(c.confkey,c.conkey) WITH ORDINALITY k(p,c,ordinality)
            JOIN pg_attribute pa ON pa.attrelid=parent.oid AND pa.attnum=k.p
            JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=k.c
            WHERE n.nspname='navis' AND c.contype='f' GROUP BY c.oid,parent.relname,child.relname""")
        foreign = cur.fetchall()
        rows, edges = {}, {}

        def collect(name, columns, values, root=False):
            if not root and name in PROTECTED:
                raise ProtectedData("retained dependency: " + name)
            if not root and name not in DEPENDENTS:
                raise ProtectedData("dependency has no archive policy: " + name)
            if name == 'graph_build_snapshot' and table != 'graph_build' or name == 'graph_dataset_snapshot' and table != 'graph_dataset':
                raise ProtectedData("retained graph selection: " + name)
            where = sql.SQL(' AND ').join(sql.SQL('{}=%s').format(sql.Identifier(col)) for col in columns)
            cur.execute(sql.SQL('SELECT row_to_json(t) FROM navis.{} t WHERE {} FOR UPDATE').format(sql.Identifier(name), where), values)
            found = [r[0] for r in cur.fetchall()]
            result = []
            for row in found:
                if name == 'ingestion_submission' and row.get('status') not in ('processed', 'raw_only'):
                    raise ProtectedData("pending ingestion still needs processing")
                if name == 'nat_session_evidence' and (not row.get('expires_at') or datetime.fromisoformat(row['expires_at']) > server_now):
                    raise ProtectedData("NAT session evidence has not expired")
                if not root:
                    cutoff = server_now-timedelta(days=days)
                    for clock in ('updated_at', 'received_at', 'created_at', 'checked_at', 'occurred_at', 'observed_at'):
                        if row.get(clock) and datetime.fromisoformat(row[clock]) > cutoff:
                            raise ProtectedData("recent dependent record: " + name)
                if name not in keys:
                    raise ProtectedData("table has no primary key: " + name)
                identity = (name, json.dumps({col: row[col] for col in keys[name]}, sort_keys=True))
                result.append(identity)
                if identity in rows:
                    continue
                rows[identity] = row
                edges[identity] = []
                for parent, child, pcols, ccols in foreign:
                    if parent == name:
                        vals = [row[col] for col in pcols]
                        if all(v is not None for v in vals):
                            # Only protect when there actually is a referencing row.
                            condition = sql.SQL(' AND ').join(sql.SQL('{}=%s').format(sql.Identifier(col)) for col in ccols)
                            cur.execute(sql.SQL('SELECT 1 FROM navis.{} WHERE {} LIMIT 1').format(sql.Identifier(child), condition), vals)
                            if cur.fetchone():
                                edges[identity].extend(collect(child, ccols, vals))
            return result

        roots = collect(table, ['id'], [key], root=True)
        if not roots:
            return 0
        root = roots[0]
        context = {}
        if table == "topology_version":
            version = rows[root]
            cur.execute("SELECT projection FROM navis.topology_build WHERE build_id=%s", (version['build_id'],))
            graph = cur.fetchone()
            if graph is None:
                raise ProtectedData("historical graph projection is unavailable")
            context = {"projection": graph[0], "topology_id": version['topology_id']}
        for identity in dependency_order(edges, root):
            name, encoded_key = identity
            row, row_key = rows[identity], json.loads(encoded_key)
            row_updated = next((row[field] for field in ('updated_at', 'received_at', 'created_at', 'checked_at', 'occurred_at', 'observed_at') if row.get(field)), updated_at)
            row_consumer = row.get('consumer_id') or row.get('submitted_consumer_id') or row.get('api_consumer_id') or consumer
            cur.execute("""INSERT INTO navis.audit_record(id,source_table,record_key,source_system_id,consumer_id,row_data,context,source_updated_at,purge_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now()+%s*interval '1 year')""",
                        (uuid4(), name, Jsonb(row_key), source, row_consumer, Jsonb(row), Jsonb(context if identity == root else {}), row_updated, years))
            where = sql.SQL(' AND ').join(sql.SQL('{}=%s').format(sql.Identifier(col)) for col in row_key)
            cur.execute(sql.SQL('DELETE FROM navis.{} WHERE {}').format(sql.Identifier(name), where), list(row_key.values()))
        if table == "graph_build":
            graph_name = rows[root].get('graph_name')
            if graph_name:
                if not re.fullmatch(r'navis_[0-9a-f]{32}', graph_name):
                    raise ProtectedData("unexpected AGE graph name")
                cur.execute("LOAD 'age'")
                cur.execute("SELECT ag_catalog.drop_graph(%s,true)", (graph_name,))
        return len(rows)

    def run(self, namespace, *, apply=False, limit=100):
        result = {"namespace": namespace, "dry_run": not apply, "archived_rows": 0, "protected": []}
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", ('retention:'+namespace,))
            source, days, years, candidates = self.candidates(cur, namespace, limit)
            result.update(archive_after_days=days, audit_retention_years=years, candidates=candidates)
            if apply:
                # Take the same namespace lock as ingestion/build publication.
                cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (str(source),))
                source, days, years, candidates = self.candidates(cur, namespace, limit)
                result['candidates'] = candidates
                for item in candidates:
                    try:
                        with conn.transaction():
                            result['archived_rows'] += self.archive_bundle(cur, item['table'], item['id'], source, item['consumer_id'], item['updated_at'], years, days)
                    except ProtectedData as exc:
                        result['protected'].append({"table": item['table'], "id": item['id'], "reason": str(exc)})
                cur.execute("DELETE FROM navis.audit_record WHERE source_system_id=%s AND purge_at<=now()", (source,))
                result['purged_audit_rows'] = cur.rowcount
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace')
    parser.add_argument('--purge-only', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--limit', type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error('--limit must be 1..1000')
    if not args.namespace and not args.purge_only:
        parser.error('--namespace is required unless --purge-only is selected')
    import psycopg
    if args.purge_only:
        with psycopg.connect(os.environ['NAVIS_DATABASE_URL']) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM navis.audit_record WHERE purge_at<=now()")
            result = {"dry_run": not args.apply, "expired_audit_rows": cur.fetchone()[0]}
            if args.apply:
                cur.execute("DELETE FROM navis.audit_record WHERE purge_at<=now()")
                result['purged_audit_rows'] = cur.rowcount
        print(json.dumps(result, indent=2))
        return
    result = Retention(lambda: psycopg.connect(os.environ['NAVIS_DATABASE_URL'])).run(args.namespace, apply=args.apply, limit=args.limit)
    print(json.dumps(result, default=str, indent=2))


if __name__ == '__main__':
    main()
