# Incremental topology and on-demand traces

Apply migrations through `021_ingestion_progress.sql` before
starting the updated API. PostgreSQL with Apache AGE, registered device identity
mappings and an approved normalized adapter are still required.

## Incremental ingestion

`POST /v1/ingestions` returns its normal 202 receipt. The API then attempts a
background namespace refresh: process pending submissions, select the latest
snapshot by collection time for each device and data type in that namespace,
and compare network content before saving a graph version. Unchanged content reuses the existing graph and advances `updated_at`. Uploads do not have to arrive together. An
older collection arriving late does not replace a newer collection. Missing
data types remain missing; partial data retains its coverage status.

The snapshot selection and graph build are now performed by the API, without
manual dataset SQL. Each changed build has a fresh dataset; an unchanged refresh discards its provisional selection. Later refreshes do not rewrite earlier build selections. Refreshes are serialized per namespace using a
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
GET /v1/topologies?namespace=lab
GET /v1/topologies/by-name/default?namespace=lab
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

{"namespace":"lab","name":"application 1","members":["appserver1","appserver2","appserver3","dbserver1","dbserver2","dbserver3"]}
```

Names are the main way to select topologies; UUIDs identify reproducible internal
builds and versions. `default` is reserved for all selected inventory within the
namespace. Application names are stable, case-sensitive, trimmed identifiers
unique per consumer and namespace. Names can contain spaces; slashes and control characters are not accepted. Posting the same name updates its member list;
posting only an existing name refreshes its saved members.

Members match collected device display names, time-valid external IDs within the
namespace, or literal IPs. Navis does not perform DNS lookups or invent hosts from
names. Missing/duplicate names are explicit in `member_resolution`. The older
`ips` field is still supported for named views, and can be combined with members
up to 1,000 unique selectors. Selecting members without a name is refused because
`default` always represents all inventory.

Named views include selected servers plus candidate transit connections. Every
namespace refresh rechecks saved application views; each name keeps its member
list. A named view can reuse a namespace build internally, but has its own version
ID and frozen membership. Candidate view paths are for visualization, not a
protocol/port-aware reachability verdict. Unresolved endpoints and network gaps
stay visible.

```http
GET /v1/topologies/by-name/application%201?namespace=lab
POST /v1/topologies/by-name/application%201/refresh?namespace=lab
GET /v1/topologies/by-name/application%201/versions?namespace=lab
GET /v1/topologies/by-name/application%201?namespace=lab&version_id=<old-version-uuid>
GET /v1/topologies/by-name/application%201/compare?namespace=lab&from_version=<old-version-uuid>
```

A name lookup returns the latest live version unless `version_id` is supplied.
History returns `version_id`, `graph_build_id`, `built_at`, `updated_at`,
`check_count`, membership and lifecycle labels. Comparison reports changed tables
and member additions/removals; omit `to_version` to compare against latest.
Unchanged content keeps its IDs and `built_at` while advancing `updated_at`.
See [data lifecycle and retention](DATA_LIFECYCLE.md) for deduplication and explicit
audit history access; see [upgrading](UPGRADING.md) before deploying schema changes.

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

`graph_build_id` and `caller_session_id` are optional. Use `topology_name` (for example `application 1`) to select a saved application, or omit it to use `default`. Without an explicit build/version, the API refreshes and compares content before tracing. Without a
caller session ID, it generates a UUID. Both IDs are returned with the analysis.
Namespace may be omitted when the consumer has exactly one source authorized
for analysis; otherwise the API returns 409 and requires a namespace. Supplying
an existing build ID retains that build and does not refresh its evidence. Alternatively, supply `topology_name` plus `topology_version_id` to trace a specific retained live version. Do not combine a name with `graph_build_id`. The response saves the resolved topology name/version and dates alongside the session; archived versions are inspection-only until restored to live storage.

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

## Unmanaged nodes and visibility gaps

Traces continue through available managed route evidence even when the remote
destination is absent from inventory. For example, a home router's default route
may lead to a next-hop IP for which Navis has no device data. The response shows:

```text
Home router -> [Unmanaged / missing network] -> [Unmanaged / unresolved destination]
               visibility ends here             requested server IP
```

Each flow includes a `visibility_graph` containing `nodes` and `connections`.
A placeholder has `type: "unmanaged"`, `placeholder: true`, `device_id: null`,
`management_status: "unknown"`, a `role` and a `reason`. Known next-hop IPs are
retained when available. `unknown_hop_count: null` means Navis cannot tell whether
the gap contains one device, two devices or an entire external network. The
placeholder is not a newly registered device or proof of its administrative
ownership. A missing inventory record and an intentionally unmanaged network
cannot be distinguished from the available evidence alone.

Edges into a gap use `kind: "visibility_gap"`; edges toward the untraced
destination use `kind: "untraced_remainder"`. Both have `status: "unknown"`.
They do not establish a real link or successful forwarding across the gap. The
response adds `UNMANAGED_PATH_SEGMENT` and `ENDPOINT_VISIBILITY_MISSING` findings
as applicable. Verdicts and coverage retain their evidence-based meanings; an
unknown segment cannot make a trace allowed. A policy denial or discard route
does not create a fictitious missing transit device.

Default topology projections also show placeholders for next-hop addresses
absent from the selected inventory. Named IP views retain adjacent visibility
boundaries and display unresolved requested endpoints. Session graph retrieval
includes the saved per-flow visibility nodes and unknown edges, including gaps
between two managed endpoints. Tracing stops at the gap; the remaining known
endpoint is displayed without claiming that its policy or path was evaluated.
Visibility fields require no separate migration; the current API requires migrations through 021 for names, versions and lifecycle storage. Existing frozen builds/session results
remain unchanged; new traces/builds populate the additional visibility fields.

### Evidence on both managed sides

A discovered device has `evidence_status: "verified"`, the display label
`Verified evidence (inventory)`, and `verification_scope: "inventory_presence"`.
This confirms its presence in the selected Navis inventory; it does not promote
partial configuration, candidate links, policy decisions or connectivity to
verified. Collection times, coverage and trace assessments retain their own
meaning. An unmanaged placeholder has `evidence_status: "unverified"` and no
verification scope.

For example, a discovered home router and a discovered AWS server both retain
their verified inventory evidence even when the internet between them is an
unverified gap. The AWS server is not converted into an unmanaged placeholder.
In a trace visibility graph, `trace_status: "visited"` identifies an evaluated
managed hop; `trace_status: "not_traced"` identifies a known endpoint beyond the
gap whose path has not been evaluated. Navis does not jump across the gap or
claim that the AWS-side policy was evaluated merely because it has AWS inventory.
