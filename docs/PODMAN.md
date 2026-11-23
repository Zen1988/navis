# Build and upgrade with Podman

This guide matches a rootless Linux checkout at `/home/zen/navis`, such as the
Podman 5.8.2 session in the build transcript. Run these commands as the same user
who owns the existing images/containers. Rootless `podman` and `sudo podman` use
different container/image stores; do not switch between them during an upgrade.
No Docker Compose installation is required.

## 1. Update the existing checkout and build

Your checkout already has `.git` and `Dockerfile` directly in `/home/zen/navis`.
Keep that layout; there is no need to clone again or move files out of a nested
directory.

```bash
cd /home/zen/navis
git status --short
git fetch origin --tags
git switch --detach v0.1.1
git log -1 --oneline
podman --version

NAVIS_RELEASE_IMAGE=localhost/navis:0.1.1
podman build --pull=always --build-arg NAVIS_VERSION=0.1.1 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" -t "$NAVIS_RELEASE_IMAGE" .
podman image inspect "$NAVIS_RELEASE_IMAGE" --format '{{.Id}}'
```

If Git reports tracked local changes, review them before switching releases; do not discard
them or replace environment files. The checkout is pinned to the published release tag rather than a changing main branch. For the next release, fetch tags again and select its new version. The final build command above is the same
style as your `podman build --pull=always -t localhost/navis:local .`, but keeps
the new release under a separate tag from the running image.

The older build transcript used commit `439072d`, whose image had no PostgreSQL
backup client. Rebuild from the updated checkout. Verify the new toolkit before
stopping the application:

```bash
podman run --rm --entrypoint pg_dump "$NAVIS_RELEASE_IMAGE" --version
podman run --rm --entrypoint python "$NAVIS_RELEASE_IMAGE" -m navis_api.migrate --help
```

Wait for a successful build and inspect command. A log ending during wheel
downloads does not establish that the image finished building.

## 2. Prepare secrets and the backup folder

Keep the existing `.env` for the application. It must contain the real database
address, authentication configuration and scopes, matching the registered
consumer/source. Do not replace it with placeholder values during an upgrade.

Create `.env.maintenance` if it does not exist and edit it with your editor:

```bash
umask 077
touch .env.maintenance
chmod 600 .env.maintenance
vi .env.maintenance
```

Provision this login and its AGE backup grants using the
[database role setup](DATABASE_ROLES.md) before running `adopt` or `apply`.

Its required entry is a maintenance-role connection string:

```text
NAVIS_DATABASE_URL=postgresql://MAINTENANCE_USER:ENCODED_PASSWORD@DATABASE_HOST:5432/navis
```

Use the actual database hostname reachable from containers and URL-encode
special characters in credentials. The application image contains no database
server. A database in a different container requires the appropriate shared
Podman network; add the same `--network` to the maintenance and application
commands. For a host service, use a reachable host address and verify PostgreSQL
listen/access rules. `localhost` inside the default container network refers to
that container. Mount any required TLS/service files separately.

```bash
mkdir -p backups
chmod 700 backups
```

The commands below use `--userns=keep-id --user "$(id -u):$(id -g)"` so one-off
maintenance writes backups as the host user. `:Z` labels this dedicated backup
folder for the container on SELinux hosts. Do not relabel your entire home
directory. See the official [Podman run options](https://docs.podman.io/en/stable/markdown/podman-run.1.html).

## 3. Stop writers and inspect the database plan

Stop other workers and retention jobs using this database too. For an existing
rootless container named `navis`, preserve it for rollback instead of removing it:

```bash
if podman container exists navis; then
  podman stop --time 60 navis
  NAVIS_PREVIOUS_CONTAINER="navis-before-$(date -u +%Y%m%dT%H%M%SZ)"
  podman rename navis "$NAVIS_PREVIOUS_CONTAINER"
fi

podman run --rm --env-file .env.maintenance --entrypoint python \
  "$NAVIS_RELEASE_IMAGE" -m navis_api.migrate plan
```

If Navis actually runs in Kubernetes, stop/scale those writers instead; a host
named `k8s` alone does not mean this Podman container is the deployed API. Local
Podman images are not automatically deployed to Kubernetes nodes. See the
[Kubernetes setup](SETUP.md#4-kubernetes-on-red-hat-or-other-linux-hosts).

### Only for a verified legacy database without a ledger

The old transcript lists migration files 001–017. That does not prove those
migrations were applied to the database. If you have confirmed that the actual
database has applied 001–017 and the plan reports `baseline_required: true`, run:

```bash
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --env-file .env.maintenance -v "$PWD/backups:/backups:Z" --entrypoint python \
  "$NAVIS_RELEASE_IMAGE" -m navis_api.migrate adopt --through 17 --backup-dir /backups
```

Use the actual known baseline (for example 18 if that was already applied).
Skip adoption on a fresh database or when a ledger already exists. The toolkit
checks expected objects and creates a checked backup before recording a legacy
baseline. Do not guess a baseline or rerun all SQL files blindly.

## 4. Back up and apply pending database changes

```bash
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --env-file .env.maintenance -v "$PWD/backups:/backups:Z" --entrypoint python \
  "$NAVIS_RELEASE_IMAGE" -m navis_api.migrate apply --backup-dir /backups
```

Continue only if that command succeeds. It creates and checks a custom-format
backup before applying pending migrations through **021**, with a checksum
ledger. Check the plan again:

```bash
podman run --rm --env-file .env.maintenance --entrypoint python \
  "$NAVIS_RELEASE_IMAGE" -m navis_api.migrate plan
```

`pending` should be empty and `baseline_required` false. A missing `pg_dump`
means the old image was used. A backup write failure needs host-user mapping,
folder permissions or SELinux labeling fixed before retrying. A failed migration
leaves the API stopped; inspect the error and ledger before retrying.

## 5. Start the updated application

After successful migrations, use the runtime `.env`, not the maintenance-role
file:

```bash
podman run -d --name navis --env-file .env \
  -p 127.0.0.1:8000:8000 \
  --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges \
  "$NAVIS_RELEASE_IMAGE"

podman ps --filter name=navis
podman logs --tail 100 navis
curl --fail http://127.0.0.1:8000/health/live
curl --fail http://127.0.0.1:8000/health/ready
```

The console is at `http://127.0.0.1:8000/` and API docs at `/docs`. Keep loopback
binding for local testing; arrange your existing ingress/TLS separately for
remote access. Health does not prove successful normalization or complete traces:
run the checks in [upgrading](UPGRADING.md#validate-the-deployment) and poll
[ingestion processing outcomes](INGESTION_PROGRESS.md).

## Maintenance and rollback

Preview retention using the same image:

```bash
podman run --rm --env-file .env.maintenance --entrypoint python \
  "$NAVIS_RELEASE_IMAGE" -m navis_api.retention --namespace lab
```

Replace `lab` with the actual namespace. Archival/purge is an explicit maintenance
operation; see [data lifecycle](DATA_LIFECYCLE.md) before enabling `--apply` or
scheduling it.

Keep the previous image, preserved container and backups until validation is
complete. There are no automatic down migrations. A database rollback restores
the pre-upgrade dump to a separate compatible PostgreSQL/AGE database before
pointing the old application at it; merely restarting an old image does not
undo schema changes. See the [rollback procedure](UPGRADING.md#roll-back).

These commands are documented for your Linux/Podman workflow; this workspace has
not executed them against your host or database.
