# Navis API documentation

Start with [NAuth integration onboarding](ONBOARDING_API.md) for the steps an
operator and caller must complete before making authenticated API requests.

Navis also provides a built-in NAuth client-credentials issuer, with local
client provisioning, shared instance identity and five-minute access tokens.
See [NAuth: Navis Authentication](SECURITY.md); no external identity provider is required.

The current consumer reference is the [API integration guide](INTEGRATION_API.md). It covers every implemented endpoint, authorization, ingestion and normalization contracts, graph/trace responses, recommendations, error handling, retries and client examples.

Companion artifacts:

- [Generated OpenAPI snapshot](api/openapi.json)
- [Complete request examples](api/examples/)
- [Contract verification script and instructions](api/README.md)
- [Implementation status and remaining work](STATUS.md)

The guide supersedes the earlier API foundation notes. Ingestion acceptance is staging, normalization/build preparation remains a separate operational step, and candidate evidence must not be treated as confirmed end-to-end connectivity. See the guide for exact implemented behavior and deployment prerequisites.

External device identities use source namespace, object class and opaque ID. Registered consumer identity and source authorization are separate. See the [external identity contract](INTEGRATION_API.md#external-device-identity-and-registered-clients) for CMDB examples, caller configuration and migration 016.
