# Local container and Kubernetes test setup

This setup is for an isolated test environment. The local token is a static bearer credential, not OAuth, does not rotate automatically, and has no per-token expiry or revocation. Use TLS or mTLS at a trusted ingress, restrict database access, and use external identity for production. Device credentials stay outside Navis. Never commit credentials or put them in shell history.

1. Install PostgreSQL and apply all SQL files in `migrations/` in numeric order with `psql -v ON_ERROR_STOP=1 -f <file>` (currently 001 through 015). Apply each migration once; there is not yet a migration tracking service. Use an AGE-compatible PostgreSQL with Apache AGE installed for graph work; enable the AGE extension separately with an appropriately privileged administrator. The API can stage data without AGE. The user has run migrations and selected AGE tests in an isolated environment; upgrades and broader integration remain unverified.
2. Provision a test source and consumer using UUIDs you choose. These statements are examples; apply them to your test database and replace the UUIDs:

```sql
INSERT INTO navis.source_system(id, namespace, kind, name)
VALUES ('00000000-0000-4000-8000-000000000001', 'lab', 'collector', 'Lab');
INSERT INTO navis.api_consumer(id, issuer, subject_or_client_id, name, status, identity_source_system_id)
VALUES ('00000000-0000-4000-8000-000000000002', 'navis-local', 'local-test', 'Local test', 'active', '00000000-0000-4000-8000-000000000001');
INSERT INTO navis.consumer_data_scope(id, api_consumer_id, source_system_id, permissions)
VALUES ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001', '["inventory:write", "graph:read", "analysis:run", "analysis:read"]'::jsonb);
```

3. Generate a high-entropy random token of at least 32 characters, store it in a secret manager, and configure `NAVIS_LOCAL_TOKEN`, `NAVIS_DATABASE_URL`, `NAVIS_LOCAL_ISSUER=navis-local`, `NAVIS_LOCAL_SUBJECT=local-test`, and `NAVIS_LOCAL_SCOPES="inventory:write graph:read analysis:run analysis:read"`. The caller uses this bearer token. Absence of a token leaves authentication deny-all. The database consumer issuer and subject must match the environment configuration; source access is separately checked in PostgreSQL.
4. Build the image from the repository root: `docker build -t navis:local .`. Make the image available to your local Kubernetes cluster. Create a Kubernetes secret named `navis-test` with keys `database-url` and `token`, using your secret manager or a secure local method. Apply `deploy/kubernetes/navis.yaml`. Port-forward the service to port 8000 and open `http://localhost:8000/`. Configure database networking and TLS for your environment.
5. To stage example data, use `examples/ansible/submit_normalized.yml` or the JSON fixtures. A successful response is `pending_identity`. Worker invocation, device mappings, approved adapter digest, dataset selection and graph building are separate manual steps. The web console and API do not yet deliver complete traces or firewall recommendations.

The `navis:local` image is a build target; it is not published by this repository. Readiness checks only test authentication configuration and database schema connectivity. They do not certify that ingestion processing, graph building or analysis are complete.
