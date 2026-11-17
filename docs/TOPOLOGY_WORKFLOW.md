# Incremental topology and on-demand traces

Apply migration `018_topology_workflow.sql` along with earlier migrations before
starting the updated API. PostgreSQL with Apache AGE, registered device identity
mappings and an approved normalized adapter are still required.

## Incremental ingestion

`POST /v1/ingestions` returns its normal 202 receipt. The API then attempts a
background namespace refresh: process pending submissions, select the latest
snapshot by collection time for each device and data type in that namespace,
and build a new immutable graph. Uploads do not have to arrive together. An
older collection arriving late does not replace a newer collection. Missing
data types remain missing; partial data retains its coverage status.

The snapshot selection and graph build are now performed by the API, without
manual dataset SQL. Each build has a fresh dataset; later refreshes do not
rewrite earlier selections. Refreshes are serialized per namespace using a
PostgreSQL advisory lock. The graph records the actual snapshot timestamps;
this is a latest-known view, not a claim of simultaneous collection.

Inspect `GET /v1/ingestions/{ingestion_id}` with `inventory:write` to see whether
normalization reached `processed` or `raw_only`. Invalid mappings or unapproved
adapters remain staged. Refresh responses include `pending_submissions` with
processing failures. Background failures are logged. Background execution is
best effort, not a durable job queue: after a process interruption, the next
ingestion or explicit topology/trace request retries pending work. A processed
receipt status does not by itself guarantee that graph publication succeeded.

## Build and inspect the default namespace topology

With `analysis:run` and database permission for the namespace:

```http
POST /v1/topologies
Content-Type: application/json
Authorization: Bearer <token>

{"namespace":"lab"}
```

The response includes `graph_build_id`, `dataset_id`, nodes, connections,
snapshot timestamps and coverage. The default view includes every selected
device, including disconnected devices. It attempts connections from declared
links and next-hop IP matches. A matched address is candidate evidence, not a
verified physical link or an allow verdict. Reused addresses are reported as
ambiguous in the projection. AGE traversal only uses unique matches within the
same source and matching native routing context; unresolved cross-context
transitions are not inferred. Inferred traversal keeps forwarding coverage
incomplete. Route/policy/return-path evidence still controls trace conclusions.

With `graph:read` and database source permission:

```http
GET /v1/graph-builds?namespace=lab&limit=50
GET /v1/topologies/<graph_build_id>
GET /v1/graph-builds/<graph_build_id>/graph
```

The list includes accessible legacy builds, but the new topology projection
endpoint requires an API-created topology build. The legacy graph endpoint
retains its identity-only fallback for older operator-built graphs. List limits
are 1–200; cursor pagination is not implemented.

## Named application topology

```http
POST /v1/topologies
Content-Type: application/json
Authorization: Bearer <token>

{"namespace":"lab","name":"checkout","ips":["192.0.2.10","198.51.100.5"]}
```

This freezes the full namespace evidence for tracing and presents an IP-selected
view with transit devices on candidate paths. Named builds belong to their
creating consumer and are versioned by build ID; the name is a label, not a
mutable unique identifier. Views currently use shortest undirected candidate
paths for visualization, not protocol/port-aware path selection. The trace
response supplies the evaluated directional paths and findings. Missing and
ambiguous IP ownership is explicit in `endpoint_candidates`; selecting an IP
does not invent a host or prove delivery to it.

## Trace without a pre-created graph or session ID

```http
POST /v1/traces
Content-Type: application/json
Authorization: Bearer <token>

{
  "namespace":"lab",
  "source":"192.0.2.10",
  "destination":"198.51.100.5",
  "protocol":"tcp",
  "destination_port":443
}
```

`graph_build_id` and `caller_session_id` are optional. Without a build ID, the
API refreshes and freezes the namespace evidence before tracing. Without a
caller session ID, it generates a UUID. Both IDs are returned with the analysis.
Namespace may be omitted when the consumer has exactly one source authorized
for analysis; otherwise the API returns 409 and requires a namespace. Supplying
an existing build ID retains that build and does not refresh its evidence.

With `analysis:read`, session ownership and current database `analysis:run`
source permission:

```http
GET /v1/trace-sessions/<caller_session_id>/graph
```

This returns the saved trace request/result and the IP-selected candidate graph
from its frozen build. Sessions retain the existing expiry (24 hours by default).
This graph retrieval route requires an API-created topology build. Existing
recommendation retrieval is unchanged.

The trace engine still has documented vendor, forwarding and policy limitations.
Endpoint resolution currently requires exact selected interface host addresses;
an arbitrary workload inside a subnet can remain unresolved. These changes
automate evidence selection and graph orchestration, not missing device or
vendor semantics. Unknown and incomplete results must remain visible.
