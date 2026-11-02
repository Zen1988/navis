"""Local provisioning and NAuth client credentials with opaque tokens."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
from uuid import UUID, uuid4
from navis_common.auth import Principal

SCOPES = frozenset({"application:read", "inventory:write", "graph:read", "analysis:run", "analysis:read"})
TOKEN_TTL = 300


def digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class NAuthError(Exception):
    def __init__(self, error):
        self.error = error
        super().__init__(error)


class Registration:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def initialize(self):
        """Explicit installation step; competing initializers share one ID."""
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO navis.instance_identity (id) VALUES (%s) ON CONFLICT (singleton) DO NOTHING", (uuid4(),))
            cur.execute("SELECT id FROM navis.instance_identity WHERE singleton")
            return str(cur.fetchone()[0])

    def issue(self, consumer_id, scopes):
        if not scopes or not set(scopes) <= SCOPES:
            raise ValueError("Choose supported scopes")
        secret = secrets.token_urlsafe(32)
        client_id = uuid4()
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM navis.instance_identity WHERE singleton")
            row = cur.fetchone()
            if row is None:
                raise ValueError("Initialize this instance locally first")
            instance_id = row[0]
            cur.execute("SELECT id FROM navis.api_consumer WHERE id = %s AND status = 'active'", (consumer_id,))
            if cur.fetchone() is None:
                raise ValueError("An active, operator-approved api_consumer is required")
            cur.execute("""INSERT INTO navis.nauth_client
                (id, instance_id, consumer_id, secret_digest, scopes)
                VALUES (%s, %s, %s, %s, %s)""",
                (client_id, instance_id, consumer_id, digest(secret), sorted(set(scopes))))
        return {"instance_id": str(instance_id), "client_id": str(client_id),
                "client_secret": secret, "scope": " ".join(sorted(set(scopes)))}

    def token(self, client_id, secret, scope=None):
        try:
            client_id = UUID(client_id)
        except (ValueError, TypeError, AttributeError):
            raise NAuthError("invalid_client") from None
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("""SELECT k.secret_digest, k.scopes FROM navis.nauth_client k
                JOIN navis.api_consumer c ON c.id = k.consumer_id
                JOIN navis.instance_identity i ON i.id = k.instance_id
                WHERE k.id = %s AND k.revoked_at IS NULL AND c.status = 'active'
                FOR UPDATE OF k""", (client_id,))
            row = cur.fetchone()
            matches = hmac.compare_digest(digest(secret), row[0] if row else "0" * 64)
            if row is None or not matches:
                raise NAuthError("invalid_client")
            allowed = set(row[1])
            requested = allowed if scope is None else set(scope.split())
            if not requested or not requested <= allowed:
                raise NAuthError("invalid_scope")
            token = "navis-at-" + secrets.token_urlsafe(32)
            cur.execute("""INSERT INTO navis.nauth_access_token
                (id, client_id, secret_digest, scopes, expires_at)
                VALUES (%s, %s, %s, %s, now() + %s * interval '1 second')""",
                (uuid4(), client_id, digest(token), sorted(requested), TOKEN_TTL))
        return {"access_token": token, "token_type": "Bearer", "expires_in": TOKEN_TTL,
                "scope": " ".join(sorted(requested))}

    def verify(self, token):
        if not token.startswith("navis-at-") or len(token) > 256:
            return None
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("""SELECT c.issuer, c.subject_or_client_id, t.scopes, k.scopes
                FROM navis.nauth_access_token t
                JOIN navis.nauth_client k ON k.id = t.client_id
                JOIN navis.instance_identity i ON i.id = k.instance_id
                JOIN navis.api_consumer c ON c.id = k.consumer_id
                WHERE t.secret_digest = %s AND t.expires_at > now()
                  AND k.revoked_at IS NULL AND c.status = 'active'""", (digest(token),))
            row = cur.fetchone()
        return None if row is None else Principal(issuer=row[0], subject=row[1], scopes=frozenset(row[2]) & frozenset(row[3]))

    def revoke(self, client_id):
        with self.connection_factory() as conn, conn.cursor() as cur:
            cur.execute("UPDATE navis.nauth_client SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (client_id,))
            return cur.rowcount > 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    issue = commands.add_parser("issue")
    issue.add_argument("--consumer-id", type=UUID, required=True)
    issue.add_argument("--scope", action="append", required=True, choices=sorted(SCOPES))
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--client-id", type=UUID, required=True)
    args = parser.parse_args()
    import psycopg
    service = Registration(lambda: psycopg.connect(os.environ["NAVIS_DATABASE_URL"]))
    if args.command == "init":
        result = {"instance_id": service.initialize()}
    elif args.command == "issue":
        result = service.issue(args.consumer_id, args.scope)
    else:
        result = {"revoked": service.revoke(args.client_id)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
