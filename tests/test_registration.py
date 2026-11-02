import asyncio
import os
import unittest
from contextlib import nullcontext
from uuid import uuid4
from unittest.mock import patch
import httpx
from navis_api.main import app, configure_test_services
from navis_api.registration import NAuthError, Registration


class NAuthApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.previous = app.state.registration
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def asyncTearDown(self):
        app.state.registration = self.previous
        await self.client.aclose()

    async def test_disabled_and_invalid_requests(self):
        app.state.registration = None
        response = await self.client.post("/nauth/token")
        self.assertEqual(response.status_code, 503)
        app.state.registration = object()
        response = await self.client.post("/nauth/token", data={"grant_type": "client_credentials"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "invalid_client"})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("Basic", response.headers["www-authenticate"])
        auth = (str(uuid4()), "secret")
        for body, expected in [
            ("grant_type=password", "unsupported_grant_type"),
            ("grant_type=client_credentials&grant_type=password", "invalid_request"),
            ("grant_type=client_credentials&client_secret=x", "invalid_request"),
            ("scope=graph:read", "invalid_request"),
        ]:
            response = await self.client.post("/nauth/token", content=body, auth=auth,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["error"], expected)

    async def test_token_and_scope_errors(self):
        class Service:
            def token(self, client_id, secret, scope):
                if secret != "correct":
                    raise NAuthError("invalid_client")
                if scope != "graph:read":
                    raise NAuthError("invalid_scope")
                return {"access_token": "opaque", "token_type": "Bearer", "expires_in": 300, "scope": scope}
        app.state.registration = Service()
        for secret, scope, expected in [("wrong", "graph:read", 401), ("correct", "inventory:write", 400), ("correct", "graph:read", 200)]:
            response = await asyncio.wait_for(self.client.post("/nauth/token", auth=(str(uuid4()), secret),
                data={"grant_type": "client_credentials", "scope": scope}), timeout=10)
            self.assertEqual(response.status_code, expected)
            self.assertEqual(response.headers["cache-control"], "no-store")
            if expected == 200:
                self.assertNotIn("refresh_token", response.json())

    async def test_no_registration_http_operations(self):
        paths = {route.path for route in app.routes}
        self.assertNotIn("/v1/enrollments/redeem", paths)
        self.assertNotIn("/v1/registrations", paths)
        self.assertNotIn("/nauth/register", paths)

    async def test_startup_rejects_unsafe_auth_configuration(self):
        for env in [
            {"NAVIS_AUTH_MODE": "unknown"},
            {"NAVIS_AUTH_MODE": "nauth"},
            {"NAVIS_AUTH_MODE": "nauth", "NAVIS_DATABASE_URL": "unused", "NAVIS_LOCAL_TOKEN": "x" * 32},
        ]:
            with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
                configure_test_services()


@unittest.skipUnless(os.environ.get("NAVIS_TEST_DATABASE_URL"), "Requires a migrated test PostgreSQL database")
class RegistrationDatabaseTests(unittest.TestCase):
    def test_lifecycle_and_boundaries(self):
        import psycopg
        with psycopg.connect(os.environ["NAVIS_TEST_DATABASE_URL"]) as conn:
            with conn.transaction(force_rollback=True):
                service = Registration(lambda: nullcontext(conn))
                instance = service.initialize()
                self.assertEqual(instance, service.initialize())
                consumer = uuid4()
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO navis.api_consumer
                        (id, issuer, subject_or_client_id, name, status)
                        VALUES (%s, 'test-registration', %s, 'test', 'active')""", (consumer, str(consumer)))
                client = service.issue(consumer, ["graph:read", "analysis:run"])
                client_id, secret = client["client_id"], client["client_secret"]
                for candidate, scope in [("wrong", None), (secret, "inventory:write")]:
                    with self.assertRaises(NAuthError):
                        service.token(client_id, candidate, scope)
                result = service.token(client_id, secret, "graph:read")
                token = result["access_token"]
                self.assertIsNone(service.verify(secret))
                principal = service.verify(token)
                self.assertEqual(principal.subject, str(consumer))
                self.assertEqual(principal.scopes, frozenset({"graph:read"}))
                with conn.cursor() as cur:
                    cur.execute("UPDATE navis.nauth_access_token SET expires_at = now() - interval '1 second' WHERE client_id = %s", (client_id,))
                self.assertIsNone(service.verify(token))
                token = service.token(client_id, secret)["access_token"]
                self.assertTrue(service.revoke(client_id))
                self.assertIsNone(service.verify(token))
                with self.assertRaises(NAuthError):
                    service.token(client_id, secret)


if __name__ == "__main__":
    unittest.main()
