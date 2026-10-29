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
                cur.execute("INSERT INTO navis.trace_recommendation_draft(id,trace_session_id,status) VALUES (%s,%s,'pending')", (uuid4(), session_id))
        return session_id

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
                return {"code": "RECOMMENDATION_PENDING" if any(row[1] == "pending" for row in rows) else "RECOMMENDATIONS_AVAILABLE", "caller_session_id": caller_session_id, "trace_session_id": str(rows[0][0]), "recommendations": [{"status": row[1], "result": row[2]} for row in rows]}
