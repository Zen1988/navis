# Know whether ingestion succeeded

HTTP 202 means **the envelope was accepted and stored**. It does not mean the
adapter validated the payload, resolved the device, normalized every item, built
the graph, or verified connectivity. Apply migration 021 for item counts,
collection progress and persisted worker failure diagnostics.

## Identify each collection and declare expected totals

Use a unique URL-safe `collection_run_id` for each Ansible/collector run. Send it
on every envelope in the run. The following fields are optional additions to the
normal ingestion envelope:

```json
{
  "collection_run_id": "ansible-site-a-20261117-001",
  "expected_submissions": 1000,
  "expected_items": 1000
}
```

Include them alongside `source`, `adapter`, `data_type`, `collected_at`,
`completeness` and `payload`. A submission is **one envelope**. An item is one
element in `payload.entries`; it is not the number of SQL rows produced. For
example, 1,000 envelopes with one entry each differ from one envelope with 1,000
entries. Opaque raw evidence without an entries array has an unknown item count.
An intentionally empty typed collection can declare `expected_items: 0`.

Expected totals refer to the whole collection, not the current envelope. They
may be provided on the first envelope or repeated consistently on every one.
Without expected totals, Navis cannot tell whether the caller stopped uploading
early. Do not reuse a run ID for daily uploads. The caller/namespace filter used
to poll progress must match the collection whose totals were declared.

## Poll one submission

```http
GET /v1/ingestions/<ingestion_id>
Authorization: Bearer <token-with-inventory:write>
```

The response includes adapter name/format/version, external device ID, data type,
source collection time, input/processed item counts, device/snapshot IDs, attempt
count, last attempt time, `processing_error`, validation/quality fields and lifecycle
labels. Source permissions are checked. Main states:

| State | Meaning | Action |
| --- | --- | --- |
| `pending` | Stored; normalization has not committed | Poll with bounded backoff |
| `processed` | Approved adapter and unique valid identity; typed normalization committed | Inspect counts, coverage and topology |
| `raw_only` | Identity/adapter approved; evidence stored without typed normalization | Do not treat it as normalized routes/policies |
| `failed` | A processing attempt rolled back; diagnostic persisted | Fix the reported input/identity/approval problem and refresh/retry |

`status` retains the existing database state; `processing_state` distinguishes a
failed attempt from an untouched pending receipt. Successful retry clears the
error. `processing_error.normalization_committed: false` confirms the failed
attempt committed no typed records. A database outage can also prevent writing
diagnostics; inspect service health/logs when polling fails.

Each envelope is atomic. If one bad entry causes a 1,000-entry envelope to fail,
Navis reports zero committed items for that envelope, not 900 partially processed
items. Split work along complete device/data-type envelopes; arbitrary chunks
for the same device/type are separate snapshots and are not merged automatically.

## Poll the collection

```http
GET /v1/ingestions/collections/ansible-site-a-20261117-001?namespace=lab&limit=50&offset=0
Authorization: Bearer <token-with-inventory:write>
```

This endpoint is scoped to the authenticated consumer, its source permissions
and optional namespace. It aggregates counts in PostgreSQL and pages submission
details; it does not load every payload into the API. Summary example:

```json
{
  "processing_status": "processing_pending",
  "expected_submissions": 1000,
  "expected_items": 1000,
  "counts": {
    "received_submissions": 1000,
    "processed_submissions": 900,
    "pending_submissions": 100,
    "failed_submissions": 0,
    "raw_only_submissions": 0,
    "input_items": 1000,
    "processed_items": 900
  },
  "upload_complete": true,
  "processing_complete": false,
  "normalization_success": false
}
```

Responses also group outcomes by data type and list per-submission details,
including failed receipts and their messages. Use `next_offset` for the next
page (limit 1–200). The principal must have `inventory:write`; another caller's
run with the same label is not included. Collections without new owner metadata
from before migration 021 are not guessed into a caller's history.

If only 900 of the expected 1,000 envelopes arrived, the status is
`awaiting_uploads`, even when those 900 all processed. Failed attempts,
inconsistent expected totals or excess/duplicate receipts produce
`needs_attention`. With no declared total, `complete_for_received_data` only
means the received work finished; upload completion remains unknown.

## What “good” means

`normalization_success: true` means expected received counts match and all those
items were normalized transactionally. It does **not** mean policy coverage is
complete or the network path works. The response preserves source-declared
partial/unknown coverage warnings, raw-only limitations and
`quality.network_connectivity_verified: false`. Completeness declarations are
not independently verified installed forwarding or policy evidence.

Finally inspect the name-based topology response and its `latest_evidence` and
`pending_submissions`, then run a trace and inspect its verdict/coverage. A
processed snapshot can be superseded by a newer collection; processing progress
is not a guarantee that every historical receipt is in the current graph.

See [the Ansible submission/polling example](../examples/ansible/submit_normalized.yml),
[topology workflow](TOPOLOGY_WORKFLOW.md), [lifecycle](DATA_LIFECYCLE.md), and
[upgrade toolkit](UPGRADING.md). Normal progress reads live records; old receipt
history moves to audit only through the separate retention job.

Legacy terminal counts are backfilled from the stored entries array where possible. Attempt counts on pre-021 receipts are a migration baseline, not a reconstruction of earlier retries. New failures and retries are tracked by the updated worker.
