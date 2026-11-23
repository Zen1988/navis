# Update the application and database

The application image now includes a database upgrade toolkit and PostgreSQL
backup clients. The same toolkit runs from a checkout, Docker, Podman or a
Kubernetes maintenance Job. It does not contain a PostgreSQL server or Apache
AGE. Keep the database server and AGE extension compatible with your deployment.

This release needs migrations **001–021**. New functionality includes named
topologies, version reuse/history/comparison, visibility gaps and lifecycle/audit
storage, plus ingestion progress/error diagnostics in 021. Apply the database migrations before starting the new API. API startup
fails clearly when the version/audit tables are missing.

## Upgrade sequence

1. Save the running application image tag/digest and database/AGE versions.
2. Build the new image under a new tag; keep the previous image available.
3. Stop API writers, ingestion workers and retention jobs for the upgrade window.
4. Verify [maintenance ownership and backup grants](DATABASE_ROLES.md), then run
   the read-only migration plan. Adopt a known legacy baseline if required.
5. Run `apply`. The toolkit requires a backup directory, creates a custom-format
   `pg_dump`, checks that `pg_restore` can read it, and then applies pending SQL.
6. Restart the API with the new image. Validate health, authentication and a
   controlled ingestion/topology/trace example before reopening normal traffic.
7. Preview retention separately; enable an operator-scheduled retention job only
   after reviewing its plan in your environment.

No commands below are run automatically when the API image starts. Schema
administration uses a maintenance database role; the long-running API should
use its runtime role. Protect environment files and backups as sensitive data.

## Container toolkit

For rootless Podman on Linux, use the complete
[Podman build/upgrade sequence](PODMAN.md), including SELinux backup mounts,
UID mapping and container replacement. The Docker/Compose examples below are
for Docker; replacing the word `docker` does not turn Compose into Podman.

Use the tagged v0.1.1 checkout (git fetch origin --tags, then git switch --detach v0.1.1). From that repository root, on Linux with Docker:

```bash
docker build --pull --build-arg NAVIS_VERSION=0.1.1 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" -t navis:0.1.1 .
mkdir -p backups
docker compose stop navis

docker run --rm --env-file .env.maintenance --entrypoint python \
  navis:0.1.1 -m navis_api.migrate plan
```

`.env.maintenance` supplies `NAVIS_DATABASE_URL` for the maintenance role. The
container must be able to reach the database; its `localhost` is not the host.
Mount certificates/service files too when your connection requires them. The
dump client uses libpq `PG*` environment variables, keeping passwords out of
process arguments. Unsupported connection options stop the backup before any
migration is applied. Use a backup client at least as new as the server;
`pg_dump` refuses unsupported server/client combinations.

### First upgrade of an existing installation without a ledger

Earlier releases applied SQL files manually. The toolkit deliberately does not
guess the last applied migration from a table name. If your deployment has
applied 001–017, adopt **17**; if it has also applied 018, adopt **18**. Use the
actual verified baseline, not whichever number appears in this example.

```bash
docker run --rm --user "$(id -u):$(id -g)" --env-file .env.maintenance \
  --mount type=bind,src="$PWD/backups",dst=/backups --entrypoint python \
  navis:0.1.1 -m navis_api.migrate adopt --through 17 --backup-dir /backups
```

`adopt` checks expected tables/views/added columns and records the selected SQL
checksums; it does not re-execute the old SQL. These object checks do not prove
that every historical constraint/data correction was applied. The operator
must establish the baseline from the previous deployment record. Adoption also
creates and validates a backup before changing the ledger.

On a fresh database, skip `adopt` and use `apply` directly. If the ledger already
exists, `adopt` refuses to overwrite it.

### Apply pending migrations

```bash
docker run --rm --user "$(id -u):$(id -g)" --env-file .env.maintenance \
  --mount type=bind,src="$PWD/backups",dst=/backups --entrypoint python \
  navis:0.1.1 -m navis_api.migrate apply --backup-dir /backups

docker run --rm --env-file .env.maintenance --entrypoint python \
  navis:0.1.1 -m navis_api.migrate plan
```

The image's default user is UID 10001. The examples above run one-off maintenance
as your host UID so a Linux backup bind mount is writable without granting the
API extra permissions. For rootless Podman, configure the appropriate user
namespace mapping (for example `--userns=keep-id`). On Windows/PowerShell, omit
the Linux `--user` flag and bind a directory writable by the container:

```powershell
New-Item -ItemType Directory -Force backups | Out-Null
docker run --rm --env-file .env.maintenance `
  --mount "type=bind,src=$((Resolve-Path backups).Path),dst=/backups" `
  --entrypoint python navis:0.1.1 `
  -m navis_api.migrate apply --backup-dir /backups
if ($LASTEXITCODE -ne 0) { throw 'Database upgrade failed; keep the API stopped' }
```

Each migration and its ledger entry commit atomically. A session advisory lock
serializes upgrade tools. Re-running `apply` skips matching applied versions;
changed checksums, a ledger gap or a newer database stop the upgrade. This is
not a distributed application maintenance lock: stop application writers first.

For Compose, after a successful upgrade:

```bash
docker tag navis:0.1.1 navis:local
docker compose up -d --no-build --force-recreate navis
docker compose logs --tail=100 navis
```

## Upgrade on Kubernetes with CloudNativePG

Use the [database role setup](DATABASE_ROLES.md#cloudnativepg-host-scripts) to
prepare the maintenance login and environment file. The database URL should use
the CloudNativePG read-write Service, such as `navis-postgres-rw.navis:5432`.
The maintenance pod connects through cluster DNS, so a host port-forward is
unnecessary. Use the same namespace for all commands below.

Push the image to a registry your nodes can pull from, or preload it on every
eligible node. For a containerd cluster using node-local images, build the new
tag with [Podman](PODMAN.md), then save and import that exact tag. Run the import
on each eligible node against the containerd instance used by kubelet:

```bash
podman save --format docker-archive -o navis-0.1.1.tar localhost/navis:0.1.1
sudo ctr -n k8s.io images import navis-0.1.1.tar
sudo ctr -n k8s.io images ls | grep -F 'localhost/navis:0.1.1'
```

Run the launcher with the image reference you actually published or preloaded:

```bash
export NAVIS_K8S_NAMESPACE=navis
image=localhost/navis:0.1.1
bash deploy/kubernetes/start-maintenance.sh "$image" .env.maintenance
```

The launcher runs `plan`. If the pod is waiting, check its Events with
`kubectl describe pod navis-maintenance -n "$NAVIS_K8S_NAMESPACE"`.
`InvalidImageName` means the reference is malformed. `ImagePullBackOff` means
the node could not pull the image. Check the exact tag in the node's image
store when using a local import. If `navis_api.migrate` is missing after an
image update, check the running image and run the module's `--help` before
retrying. A Ready condition can briefly describe the previous container.

Save the deployed replica count and stop the API and other writers before
making database changes:

```bash
replicas=$(kubectl get deployment/navis -n "$NAVIS_K8S_NAMESPACE" \
  -o jsonpath='{.spec.replicas}')
kubectl scale deployment/navis -n "$NAVIS_K8S_NAMESPACE" --replicas=0
kubectl rollout status deployment/navis -n "$NAVIS_K8S_NAMESPACE" --timeout=120s

migrate() {
  kubectl exec -n "$NAVIS_K8S_NAMESPACE" navis-maintenance -c maintenance -- \
    python -m navis_api.migrate "$@"
}
migrate plan
```

Wait for API pods and other writers to stop. For a legacy database with a
confirmed 001–017 baseline and `baseline_required: true`, run
`migrate adopt --through 17 --backup-dir /backups` and check `migrate plan`
again. Select the actual baseline if yours differs. For a fresh database or a
database with a ledger, start from its plan. Run
`migrate apply --backup-dir /backups` when migrations are pending. If `pg_dump`
reports `ag_catalog` permission errors, use the [AGE grant script](DATABASE_ROLES.md)
with the maintenance login, then retry after checking the plan.

After the final plan shows `pending: []`, update the API image and restore the
replica count. The sample manifest uses `navis` as the container name:

```bash
kubectl set image deployment/navis -n "$NAVIS_K8S_NAMESPACE" navis="$image" &&
kubectl scale deployment/navis -n "$NAVIS_K8S_NAMESPACE" --replicas="$replicas" &&
kubectl rollout status deployment/navis -n "$NAVIS_K8S_NAMESPACE" --timeout=120s
```

Check readiness and make an authenticated request before resuming ingestion.
Keep the backup PVC for rollback. When maintenance is finished, you can delete
the temporary pod to stop serving the maintenance credentials inside it.

## Checkout toolkit

With the project installed in a virtual environment, PostgreSQL client tools on
`PATH`, and `NAVIS_DATABASE_URL` configured securely:

```text
python -m navis_api.migrate plan
python -m navis_api.migrate adopt --through 17 --backup-dir backups
python -m navis_api.migrate apply --backup-dir backups
```

The `adopt` line is only for a verified legacy baseline. Do not rerun old SQL
manually after adopting the ledger. Do not edit files already recorded as
applied; add the next numbered migration for future changes.

## Validate the deployment

Check `/health/live` and `/health/ready`, then use an approved source/mapping. See [ingestion progress](INGESTION_PROGRESS.md) to poll counts, expected totals and processing errors:

- Submit two identical normalized collections at different collection times.
  Confirm that ingestion receipts differ but the graph/version IDs and
  `built_at` stay the same; `updated_at` and `check_count` advance.
- Change a route/interface in a test collection. Confirm a new topology version
  appears under the same name and `/compare` reports changed tables.
- Retrieve `default`, create a named server-member topology, trace without a
  UUID, and retrieve its session graph. Inspect unknown visibility gaps.
- Preview retention. Confirm current graph versions, latest device data and
  unexpired sessions are protected, and normal queries do not read audit rows.

Unit/HTTP contract tests cover the code paths with fake storage; they do not
replace this live PostgreSQL/AGE and backup-restore validation.

## Roll back

Keep the old image and backup until validation is complete. There are no
automatic down migrations. For a database rollback, stop writers, restore the
pre-upgrade dump into a separate database with matching PostgreSQL/AGE support,
verify it, and point the previous application image at that restored database.
Keep the original database until recovery is confirmed. A readable dump listing
is not a tested restore; rehearse `pg_restore --exit-on-error` into a disposable
database as part of release validation. Restoring a backup loses writes made
after that backup, which is why the upgrade window stops writers.

Container builds, live migrations, restore rehearsals and maintenance must be
validated in your environment before production rollout.
