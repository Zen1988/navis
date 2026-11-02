# NAuth: Navis Authentication

For the operator-to-caller setup sequence and runnable integration example, see
[NAuth integration onboarding](ONBOARDING_API.md).

Navis supports confidential service callers such as Tessera using a `client_id`,
private `client_secret`, and operator-approved scopes. A client ID or instance ID
alone grants no access. Each client exchanges its credentials for a short-lived
opaque bearer access token using the NAuth client credentials grant.

## Local provisioning

Apply migrations through 017. Configure `NAVIS_DATABASE_URL` through a secret
manager and run these commands in the installed Navis Python environment:

```powershell
python -m navis_api.registration init
python -m navis_api.registration issue --consumer-id <consumer-uuid> --scope graph:read --scope analysis:run
```

First provision the active `navis.api_consumer` and source permissions locally as
shown in the [deployment guide](../deploy/README.md). `issue` prints the client
ID, secret, instance ID and scopes. Protect this output: do not capture it in CI
logs, tickets or shell transcripts. There is no public registration or credential
issuance API. The CLI requires privileged local database access.

Initialization is explicit, idempotent and safe for competing installers. The
stable instance UUID lives in PostgreSQL and is shared by every replica using
that database. Each API process separately generates a runtime UUID at startup.
Pods never initialize the installation themselves. Back up the database to retain
instance identity and clients. A restored database represents the same installation;
independent clones must be provisioned as separate installations.

Set `NAVIS_AUTH_MODE=nauth` and the shared database URL on every pod. Remove
`NAVIS_LOCAL_TOKEN`: mixing it with NAuth mode fails startup. An uninitialized
installation or missing schema also fails startup. The sample Kubernetes manifest
still selects legacy static-token test mode; replace its `NAVIS_LOCAL_TOKEN`
entry with `NAVIS_AUTH_MODE=nauth` to use NAuth mode. Unknown auth modes fail
startup. With no auth mode set, legacy local mode remains the default.

## Token exchange

Over HTTPS, authenticate with HTTP Basic (`client_id:client_secret`) and submit:

```http
POST /nauth/token
Authorization: Basic <base64-encoded-client-credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=graph:read
```

Basic username and password use URL form encoding before Base64 encoding.
Generated UUIDs and URL-safe secrets need no special escaping. Client credentials
in the request body are deliberately unsupported. Omitted scope selects the
client's approved scopes; requested scopes must be a nonempty subset.

```json
{"access_token":"<opaque-secret>","token_type":"Bearer","expires_in":300,"scope":"graph:read"}
```

Token responses prevent caching. No refresh token is issued. Subsequent API calls
use `Authorization: Bearer <access_token>` and do not include the client secret.
At expiry the caller obtains another access token. Existing source and dataset
permissions remain separate from API scopes. Both secrets and access tokens have
256 bits of random entropy and are stored only as SHA-256 digests.

Every request checks the shared database for expiry, client revocation and active
consumer status. Revocation and scope reductions affect subsequent checks across
pods; already authorized requests can finish. Revoke locally:

```powershell
python -m navis_api.registration revoke --client-id <client-uuid>
```

Rotate by issuing another client for the same consumer, updating the caller, then
revoking the old client. Client secrets have no automatic expiry in this increment.
Periodically delete expired `navis.nauth_access_token` rows using an operator job;
no cleanup scheduler is supplied yet.

## Trust boundary and limitations

Stealing only Tessera's identity cannot authenticate. Stealing its client secret
allows impersonation until revocation; stealing an access token allows use until
expiry or client revocation. NAuth client credentials do not themselves prevent
credential theft. Private-key client authentication or certificate-bound access
tokens using mTLS can strengthen that boundary in a later increment.

Deploy behind TLS, restrict direct pod access, and rate-limit `/nauth/token` at
trusted ingress. Do not log request bodies, Authorization headers, or token
responses. Use separate operator and runtime database roles: runtime should not
have permission to initialize instances, provision clients or change approvals.
The token endpoint supports service client credentials. Interactive login, discovery, signed
JWTs, mTLS binding, audit trails, automatic secret expiry and ingress policy
configuration are not implemented here. Hiding setup details is not a security
boundary.

Design references: [RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4)
and [RFC 9700 section 2.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5).

Validation: `python -m unittest discover -s tests`. Set
`NAVIS_TEST_DATABASE_URL` to a migrated test PostgreSQL database for lifecycle,
expiry, scope and revocation integration checks; test writes roll back.
