# NAuth integration onboarding

Use this guide to connect a backend service such as Tessera to Navis. NAuth
(Navis Authentication) is built into Navis; no external identity provider is
required. Registration and client-secret generation are local operator tasks.
The caller uses the token API after the operator provisions its access.

## 1. Agree on the integration

The caller team supplies its application name, required operations, source
namespaces and response identity requirements. The Navis operator approves
access and provides:

| Item | Purpose | Secret? |
| --- | --- | --- |
| HTTPS base URL | Navis origin, for example `https://navis.example.net` | No |
| Instance ID | Stable identity of this Navis installation, shared across pods | No |
| Client ID | Identifies the provisioned application credential | No |
| Client secret | Authenticates the application at `/nauth/token` | Yes |
| Approved scopes | Operations the client can request | No |
| Source permissions | Sources the consumer can read or submit | No |

The instance ID is an installation reference; it is not sent to the token API.
The client ID is distinct from the internal consumer UUID. Multiple client IDs
can map to one consumer, for example during secret rotation. Pod runtime IDs
are internal diagnostics and are not caller credentials.

## 2. Operator: prepare the installation

Apply migrations `001` through `017` in numeric order, once per database.
Install Navis and configure `NAVIS_DATABASE_URL` through your secret manager.
Run locally in that Python environment:

```powershell
python -m navis_api.registration init
```

Keep the returned instance ID for the installation record. Repeating `init`
returns the same identity. All pods for this installation must use the same
database. See [deployment prerequisites](../deploy/README.md) and
[NAuth security setup](SECURITY.md) for TLS and database-role requirements.

## 3. Operator: register the consumer and source permissions

There is no registration HTTP endpoint. Use approved local database access.
This example registers Tessera for one source. Replace the sample UUIDs,
namespace and instance marker with deployment values; run it once. If the
source already exists, reuse its UUID instead of inserting another source.

```sql
BEGIN;
INSERT INTO navis.source_system (id, namespace, kind, name)
VALUES ('00000000-0000-4000-8000-000000000001',
        'tessera-site-a', 'collector', 'Tessera site A');

INSERT INTO navis.api_consumer
    (id, issuer, subject_or_client_id, name, status,
     identity_source_system_id, identity_object_class)
VALUES ('00000000-0000-4000-8000-000000000002',
        'navis:<instance-uuid>', 'tessera', 'Tessera', 'active',
        '00000000-0000-4000-8000-000000000001', 'device');

INSERT INTO navis.consumer_data_scope
    (id, api_consumer_id, source_system_id, permissions)
VALUES ('00000000-0000-4000-8000-000000000003',
        '00000000-0000-4000-8000-000000000002',
        '00000000-0000-4000-8000-000000000001',
        '["inventory:write", "graph:read", "analysis:run", "analysis:read"]'::jsonb);
COMMIT;
```

Issuer and subject are operator-controlled principal values, not external
provider settings. NAuth resolves them from the consumer record. The caller
cannot override them at token exchange. Choose stable values per consumer.
Response identity source/class and device mappings are separate from login;
see [external device identity](INTEGRATION_API.md#external-device-identity-and-registered-clients).

Grant only needed permissions. Add source-permission rows for other approved
sources. Graph reads and traces require access to every source in the selected
build, including sources collected by other systems.

## 4. Operator: issue client credentials and enable NAuth

```powershell
python -m navis_api.registration issue --consumer-id 00000000-0000-4000-8000-000000000002 --scope inventory:write --scope graph:read --scope analysis:run --scope analysis:read
```

The JSON output contains `instance_id`, `client_id`, `client_secret` and
`scope`. Deliver the secret privately to the caller's secret manager. Navis
stores its hash and cannot return the plaintext secret later. Do not retain
command output in build logs or tickets.

Configure every API pod with `NAVIS_AUTH_MODE=nauth` and the shared
`NAVIS_DATABASE_URL`, remove `NAVIS_LOCAL_TOKEN`, and start/restart the pods.
Initialization must already be complete. The sample Kubernetes manifest uses
legacy static-token mode until the operator makes these changes.

| Scope | API operation | Further requirement |
| --- | --- | --- |
| `inventory:write` | `POST /v1/ingestions` | Source permission; later processing is an operator handoff |
| `graph:read` | `GET /v1/graph-builds/{build_id}/graph` | Completed build and access to all selected sources |
| `analysis:run` | `POST /v1/traces` | Completed build and access to all selected sources |
| `analysis:read` | `GET /v1/trace-sessions/{caller_session_id}/recommendations` | Consumer owns an unexpired session |
| `application:read` | `GET /v1/applications` | Storage is not implemented; currently returns 503 |

API scopes and database source permissions are both required; issuing a scope
does not create source access.

## 5. Caller: request an access token

```http
POST /nauth/token
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=client_credentials&scope=graph:read%20analysis:run
```

Use HTTP Basic, with the client ID and secret URL form encoded separately
before joining with `:` and Base64 encoding. Generated UUIDs and URL-safe
secrets need no escaping. Send credentials only in the Authorization header;
JSON requests and credentials in the form body are unsupported. `scope` is an
optional, space-separated, nonempty subset of approved scopes. Omit it to
request all approved scopes. The form body must be at most 4096 bytes.

Successful response: HTTP 200 with `Cache-Control: no-store` and `Pragma: no-cache`.

```json
{
  "access_token": "<opaque-secret-token>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "analysis:run graph:read"
}
```

Treat the access token as opaque. Cache it in memory and obtain a new token
before expiry, for example 30 seconds early. No refresh token is issued.
Future API calls send the access token, not the client secret:

```http
GET /v1/graph-builds/<completed-build-uuid>/graph
Authorization: Bearer <access_token>
Accept: application/json
```

This Python example uses only the standard library. Inject the environment
values from a secret manager; do not hardcode credentials. `NAVIS_BUILD_ID`
must identify a real completed build provided by the operator.

```python
import base64
import json
import os
from urllib.parse import quote_plus, urlencode
from urllib.request import Request, urlopen

base = os.environ["NAVIS_BASE_URL"].rstrip("/")
client_id = quote_plus(os.environ["NAVIS_CLIENT_ID"], safe="")
secret = quote_plus(os.environ["NAVIS_CLIENT_SECRET"], safe="")
basic = base64.b64encode(f"{client_id}:{secret}".encode("ascii")).decode("ascii")
request = Request(
    base + "/nauth/token",
    data=urlencode({"grant_type": "client_credentials", "scope": "graph:read"}).encode("ascii"),
    headers={"Authorization": "Basic " + basic,
             "Content-Type": "application/x-www-form-urlencoded",
             "Accept": "application/json"},
)
with urlopen(request, timeout=30) as response:
    token = json.load(response)["access_token"]

request = Request(
    base + "/v1/graph-builds/" + os.environ["NAVIS_BUILD_ID"] + "/graph",
    headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
)
with urlopen(request, timeout=30) as response:
    graph = json.load(response)
# Use graph in your application; never print credentials or token responses.
```

## 6. Handle failures and credential changes

Token errors use `{"error":"<code>"}`; protected API errors normally use
`{"detail":"<message>"}`. Do not assume they share a response schema.

| Token HTTP status | Error | Caller action |
| --- | --- | --- |
| 400 | `invalid_request` | Fix content type, required fields, duplicate fields or body size |
| 400 | `unsupported_grant_type` | Send `grant_type=client_credentials` |
| 400 | `invalid_scope` | Request a valid subset; ask the operator for approval if needed |
| 401 | `invalid_client` | Check Basic credentials; ask the operator about revocation or consumer status |
| 503 | `temporarily_unavailable` | Check NAuth configuration/database health with the operator; retry transient failures with bounded backoff |

A protected API 401 can indicate expiry or revocation. Obtain a new token and
retry at most once if the operation is safe to repeat. A 403 requires review
of scopes, source access or session ownership; repeatedly renewing the token
will not fix it. Do not automatically replay ingestion or trace POST requests
after ambiguous network failures: these APIs have no idempotency-key contract.

Rotate credentials by issuing a new client for the same consumer, updating
the caller, verifying its access, then revoking the old client locally:

```powershell
python -m navis_api.registration revoke --client-id <old-client-uuid>
```

Revocation invalidates the client's existing tokens on subsequent checks across
pods. Already authorized requests can finish. A lost or stolen client secret
requires replacement and revocation; client secrets do not expire automatically.

## 7. Complete the data integration

Successful authentication does not prepare inventory or graph builds. Agree
with the operator on device mappings, worker execution, adapter approval,
dataset selection, completed build IDs and supported evidence limitations.
Continue with the [integration lifecycle and payload reference](INTEGRATION_API.md).
Health readiness alone does not prove the data pipeline is ready.
