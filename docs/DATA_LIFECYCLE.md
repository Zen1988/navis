# Active data, graph versions and audit storage

The live store serves normal application work. Audit is historical storage, not
an implicit fallback on every normal query. Apply migrations 019 and 020 for
named version tracking, lifecycle timestamps and the shared `navis.audit_record`
archive. `audit_event` remains the operational event log; old eligible events
can themselves be archived into `audit_record`.

## Record labels

Lifecycle metadata separates three questions:

| Field | Meaning |
| --- | --- |
| `is_active`, `usage_status` | Current use: active, historical, or an expired trace session |
| `freshness_status` | `recent` or `old`, measured against the 90-day `updated_at` threshold |
| `storage_status` | `live` operational tables or `audit` archive |
| `archive_eligible` | Old, inactive and not known to be protected; maintenance rechecks actual dependencies |
| `protected` | A retained dependency prevents moving the row |
| `purge_at`, `purge_eligible` | One calendar year after archival, for audit data |

An active record can have old evidence. A recent but expired trace is inactive
but does not reach the archival age immediately. Reading a historical record
does not change its timestamps or make it current.

## Graph dates and duplicate prevention

- `built_at`: when that graph version was first saved; unchanged for its lifetime.
- `updated_at`: the latest completed content recheck of the current version.
- `check_count`: one on creation, incremented on each successful recheck.
- `latest_evidence.snapshots[].collected_at`: actual source collection times.

`updated_at` means rechecked, not necessarily newly collected or complete. Pending
ingestion failures remain visible. Retention uses `updated_at`, not `built_at`:
an unchanged six-month-old graph rechecked today is still current. Initially
`built_at` and `updated_at` are equal.

Network content fingerprints ignore generated import/snapshot/row IDs and
delivery/collection envelope timestamps. They retain device identity, addresses,
routes, policy/NAT/coverage values, raw evidence, current declared links,
identity aliases and builder implementation changes. Stored fingerprints contain
compact per-row hashes, not another full copy of configurations. Policy and raw
payload array order is preserved; uncertain differences conservatively create a
version. Unknown/cyclic foreign references also cause conservative differences.

Identical evidence keeps its existing graph/build/version IDs, removes the
provisional dataset selection and advances `updated_at`. Changed content gets a
new version. Original build snapshot IDs remain frozen; the newest equivalent
collection receipts are recorded separately in `latest_evidence`. Named views
include their connected network context, including possible alternate paths;
changes to a disconnected unrelated device do not by themselves change that
application's version. Device and interface native identity keep declared links
stable across re-collection.

## Retention policy

The initial `navis.retention_policy` is **90 days live for eligible inactive
history, then one calendar year in audit after archival**. This is not one year
from original collection. The archive row retains the original table/key,
source/consumer, complete row JSON, source update time, archive/purge dates and
any context required for historical topology rendering/comparison.

Age alone never deletes current configuration. Maintenance protects current
named/default heads, latest device/data-type snapshots, pending ingestions,
unexpired trace sessions, retained graph/dataset references and unresolved
dependencies. Active source/consumer/device/identity/security configuration
stays live. A retained historical graph can pin old snapshots beyond 90 days
until the graph itself is archived. Thus 90 days is an eligibility threshold,
not a guarantee that every live row older than 90 days is moved.

The maintenance runner handles expired trace sessions and their drafts, old
non-head topology versions, unreferenced graph builds/datasets, superseded
unreferenced snapshots and their dependent typed/raw rows, processed ingestion
receipts, orphaned import batches, and unambiguous single-source usage events.
The shared audit format accepts rows from any table, but unknown active
relationships and dependency cycles are protected rather than guessed away.
Legacy analysis rows and multi-source usage attribution need explicit policies
before automated movement. There is no blanket deletion of every old table row.

Copying rows to audit and deleting the live dependency bundle happen in one
transaction. Dependency order removes children first. Current references and
trace leases prevent graph removal during analysis/session persistence. Archived
graph versions include a frozen projection and content fingerprints, so history
and comparison can work without running AGE against cold data. Raw archived
rows are for operator/audit access; normal inventory/tracing queries stay live.

## Run maintenance

Use a privileged maintenance connection, not an exposed HTTP delete operation:

```text
python -m navis_api.retention --namespace lab
python -m navis_api.retention --namespace lab --apply --limit 100
```

The first command previews candidates and performs no archive/delete writes.
The second archives eligible bundles and purges expired audit rows for that
namespace. The limit is per root category (1–1000); dependent rows can be more
numerous. Several bounded runs may be needed: graph versions, their now-orphaned
builds, datasets and snapshots become eligible in dependency order. Dependency
checks are repeated under the namespace lock on application. Protected bundles
are reported. Foreign-key or database failures roll back affected transactions.

In a container:

```bash
docker run --rm --env-file .env.maintenance --entrypoint python \
  navis:0.1.0 -m navis_api.retention --namespace lab
```

After validating the preview and backup/restore procedure, schedule the `--apply`
command with your host scheduler or a Kubernetes CronJob for each namespace.
Use `python -m navis_api.retention --purge-only` to preview globally expired audit
rows, and add `--apply` for the maintenance purge. This also covers audit left
behind by retired namespaces; it never deletes live operational rows.
The API does not start a hidden retention scheduler. No live archive or purge
has been run by the repository tests. Audit data contains network configuration:
apply database encryption/access controls and backup protection to it too.

## Explicit history access

Normal requests return current live data. History is explicit:

```http
GET /v1/topologies/by-name/application%201/versions?namespace=lab
GET /v1/topologies/by-name/application%201/versions?namespace=lab&include_audit=true
GET /v1/topologies/by-name/application%201?namespace=lab&version_id=<version-uuid>
GET /v1/topologies/by-name/application%201/compare?namespace=lab&from_version=<old-uuid>
GET /v1/trace-sessions
GET /v1/trace-sessions?active_only=false&include_audit=true
```

Named history and comparison are scoped to the requesting consumer and source;
the public `default` name is scoped to its namespace. Trace listing is always
consumer-owned. Archived versions can be inspected/compared until purge but
cannot be re-traced directly: restore them to live storage before analysis.
Expired trace sessions cannot be used as active recommendation/session-graph
requests. Old versions from before content fingerprinting can be rendered but
cannot provide a reliable content comparison baseline; refresh after upgrading
to establish the new baseline.
