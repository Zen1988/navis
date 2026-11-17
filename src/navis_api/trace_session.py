"""Persist and retrieve caller-owned trace sessions and recommendation drafts."""
from datetime import timedelta
from uuid import uuid4


class PostgresTraceSessions:
    def __init__(self, connection_factory, *, lifetime=timedelta(hours=24)):
        if lifetime <= timedelta(0):
            raise ValueError("lifetime must be positive")
        self.connection_factory = connection_factory
        self.lifetime = lifetime

    @staticmethod
    def _consumer(cur, principal):
        if not principal.issuer:
            raise PermissionError("issuer required")
        cur.execute("SELECT id FROM navis.api_consumer WHERE issuer=%s AND subject_or_client_id=%s AND status='active'", (principal.issuer, principal.subject))
        row = cur.fetchone()
        if row is None:
            raise PermissionError("consumer not authorized")
        return row[0]

    def save(self, principal, caller_session_id, graph_build_id, request, result):
        from psycopg.types.json import Jsonb
        session_id = uuid4()
        with self.connection_factory() as conn:
            with conn.cursor() as cur:
                consumer = self._consumer(cur, principal)
                cur.execute("""INSERT INTO navis.trace_session
                    (id,consumer_id,caller_session_id,graph_build_id,request,result,expires_at)
                    VALUES (%s,%s,%s,%s,%s,%s,now()+%s)""", (session_id, consumer, caller_session_id, graph_build_id, Jsonb(request), Jsonb(result), self.lifetime))
                drafts = [draft for flow in result.get("results", []) for hop in flow.get("hops", []) for draft in hop.get("recommendations", [])]
                if drafts:
                    for draft in drafts:
                        cur.execute("INSERT INTO navis.trace_recommendation_draft(id,trace_session_id,status,recommendation) VALUES (%s,%s,'ready',%s)", (uuid4(), session_id, Jsonb(draft)))
                else:
                    cur.execute("INSERT INTO navis.trace_recommendation_draft(id,trace_session_id,status) VALUES (%s,%s,'unavailable')", (uuid4(), session_id))
        return session_id

    def get(self, principal, caller_session_id):
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self._consumer(cur, principal)
            cur.execute("""SELECT id,graph_build_id,request,result,updated_at,expires_at FROM navis.trace_session
                WHERE consumer_id=%s AND caller_session_id=%s AND expires_at>now()""", (consumer, caller_session_id))
            row = cur.fetchone()
            if row is None:
                raise LookupError("session not found or expired")
            from navis_common.lifecycle import lifecycle
            return {"trace_session_id": str(row[0]), "caller_session_id": caller_session_id,
                    "graph_build_id": str(row[1]), "request": row[2], "result": row[3],
                    "updated_at": row[4], "expires_at": row[5],
                    "lifecycle": lifecycle(row[4], active=True, expires_at=row[5])}

    def list(self, principal, *, active_only=True, include_audit=False, limit=50):
        from navis_common.lifecycle import lifecycle
        with self.connection_factory() as conn, conn.cursor() as cur:
            consumer = self._consumer(cur, principal)
            cur.execute("""SELECT id,caller_session_id,graph_build_id,created_at,updated_at,expires_at
                FROM navis.trace_session WHERE consumer_id=%s AND (NOT %s OR expires_at>now())
                ORDER BY updated_at DESC,id LIMIT %s""", (consumer, active_only, limit))
            sessions = [{"trace_session_id": str(i), "caller_session_id": caller,
                "graph_build_id": str(build), "created_at": created, "updated_at": updated, "expires_at": expires,
                "lifecycle": lifecycle(updated, active=True, expires_at=expires)}
                for i,caller,build,created,updated,expires in cur.fetchall()]
            if include_audit and not active_only:
                cur.execute("""SELECT row_data,archived_at FROM navis.audit_record
                    WHERE source_table='trace_session' AND consumer_id=%s
                    ORDER BY source_updated_at DESC LIMIT %s""", (consumer, limit))
                for row, archived in cur.fetchall():
                    sessions.append({"trace_session_id": row['id'], "caller_session_id": row['caller_session_id'],
                        "graph_build_id": row['graph_build_id'], "created_at": row['created_at'], "updated_at": row['updated_at'],
                        "expires_at": row['expires_at'], "lifecycle": lifecycle(row['updated_at'], active=False, expires_at=row['expires_at'], archived_at=archived)})
            from navis_common.lifecycle import as_datetime
            sessions.sort(key=lambda s: (as_datetime(s['updated_at']), s['trace_session_id']), reverse=True)
            return {"sessions": sessions[:limit]}

    def recommendations(self, principal, caller_session_id):
        with self.connection_factory() as conn:
            with conn.cursor() as cur:
                consumer = self._consumer(cur, principal)
                cur.execute("""SELECT s.id,d.status,d.recommendation FROM navis.trace_session s
                    JOIN navis.trace_recommendation_draft d ON d.trace_session_id=s.id
                    WHERE s.consumer_id=%s AND s.caller_session_id=%s AND s.expires_at>now()
                    ORDER BY d.created_at,d.id""", (consumer, caller_session_id))
                rows = cur.fetchall()
                if not rows:
                    raise LookupError("session not found or expired")
                code = "RECOMMENDATION_PENDING" if any(row[1] == "pending" for row in rows) else ("RECOMMENDATIONS_AVAILABLE" if any(row[1] == "ready" for row in rows) else "RECOMMENDATIONS_UNAVAILABLE")
                return {"code": code, "caller_session_id": caller_session_id, "trace_session_id": str(rows[0][0]), "recommendations": [{"status": row[1], "result": row[2]} for row in rows]}
