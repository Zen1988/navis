# Navis setup

Run commands from the repository root. The same OCI image works with Docker,
Podman and Kubernetes; there is no separate Kubernetes image.

## Platform

The Dockerfile uses Ubuntu 26.04 LTS (Resolute Raccoon) and its distribution
Python in a virtual environment. The explicit version prevents an unexpected
Ubuntu release change during rebuilds. Ubuntu userspace can run on a Red Hat
Linux host, but shares the host kernel. Use an Ubuntu VM if you require a separate
kernel security boundary. Keep host SELinux enforcement enabled.

Install a container runtime on the **Red Hat host** using section 0 below.
The Ubuntu container does not need its own Docker/Podman installation.
Kubernetes also needs `kubectl`, a cluster and a reachable registry.
Build for the node architecture, such as linux/amd64 or linux/arm64.
The build requires access to Ubuntu repositories and PyPI. Dependency versions
currently use ranges, so builds are not fully reproducible. Scan release images,
record their digests and rebuild for security updates.

## 0. Install the container tools on Red Hat

Choose one runtime. These commands run on the host, before building the image.
No Ubuntu VM, Kubernetes cluster or GPU container toolkit is required for Navis.
Check the host release first:

```bash
cat /etc/redhat-release
```

### Podman on RHEL 9/10

Use a registered host with its standard Red Hat repositories enabled. Install
the container tool suite and PostgreSQL client:

```bash
sudo dnf install -y container-tools postgresql
podman --version
podman info
podman run --rm docker.io/library/ubuntu:26.04 cat /etc/os-release
psql --version
```

Run Podman as your normal user. It is daemonless, so no Docker service or
`podman machine` is needed on this Linux host. If rootless startup reports missing
subordinate IDs, ask the host administrator to configure `/etc/subuid` and
`/etc/subgid` for your account. RHEL 8 has different container module-stream
instructions; follow the documentation for that release.

See [Red Hat container documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index).
Use the explicit Podman build/run commands below; Docker Compose is not included
in this path.

### Docker Engine with Compose (alternative)

On a host selected for Docker, review the official installation prerequisites
and conflicting packages first. Do not remove an existing Podman installation
that other workloads depend on.

```bash
sudo dnf install -y dnf-plugins-core postgresql
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
sudo docker compose version
```

Verify the package signing key against the
[official Docker RHEL instructions](https://docs.docker.com/engine/install/rhel/).
Use `sudo docker` for subsequent Docker commands unless your administrator has
configured user access. Docker group membership grants root-level host access.

## Host preparation complete

Continue with PostgreSQL below, then build the Ubuntu application image.

## 1. Prepare PostgreSQL

Create a dedicated database. Apply all SQL files in `migrations/` in filename
order, once per database. Set `NAVIS_DATABASE_URL` securely first. In PowerShell:

```powershell
Get-ChildItem migrations/*.sql | Sort-Object Name | ForEach-Object {
    psql --dbname=$env:NAVIS_DATABASE_URL -v ON_ERROR_STOP=1 -f $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "Migration failed: $($_.Name)" }
}
```

On Linux with Bash:

```bash
for migration in migrations/*.sql; do
  psql --dbname="$NAVIS_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$migration" || exit 1
done
```

There is no migration ledger: do not rerun this loop on an existing installation.
Back up before upgrades and apply only unapplied migrations. Migration 016 needs
permission to install `btree_gist` and rejects overlapping historical mappings.
PostgreSQL without Apache AGE supports API staging; graph operations require a
compatible PostgreSQL/AGE installation and separately enabled AGE extension.
The application image contains neither a database server nor AGE.

Provision a source, consumer and data scopes with the SQL in the
[deployment guide](../deploy/README.md). Source authorization requires these rows
even if readiness succeeds.

## 2. Build the Ubuntu image

```bash
docker build --pull -t navis:local .
docker run --rm --entrypoint cat navis:local /etc/os-release
```

On Red Hat with Podman:

```bash
podman build --pull=always -t navis:local .
podman run --rm --entrypoint cat navis:local /etc/os-release
```

The image runs as UID 10001 on port 8000 and includes the API, web console,
registration CLI and migrations. It does not automatically start workers.

## 3. Run a local lab

Copy `.env.example` to `.env`. Replace the database URL and token. Generate a
random token using `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
Protect the file with local filesystem permissions. Use a database hostname
reachable from the container: `localhost` means the container itself.
URL-encode special characters in database credentials.

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 navis
curl --fail http://localhost:8000/health/live
curl --fail http://localhost:8000/health/ready
```

Open http://localhost:8000/ for the console and `/docs` for the API reference.
Compose binds only to loopback. For Podman without Compose:

```bash
podman run -d --name navis --env-file .env -p 127.0.0.1:8000:8000 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges navis:local
```

Stop Compose with `docker compose down`. The external database is managed
separately. A 503 readiness response means authentication or database/schema
configuration is unavailable. A 401 means missing/invalid credentials; a 403
means missing scopes or source/dataset approval. Avoid publishing secret logs.
Readiness does not certify completed ingestion, graph building or analysis.

## 4. Kubernetes on Red Hat or other Linux hosts

Push the same image to your registry with an immutable release tag:

```bash
docker tag navis:local registry.example.com/team/navis:0.1.0-ubuntu26.04
docker push registry.example.com/team/navis:0.1.0-ubuntu26.04
```

Create a protected local `navis-secret.env` containing `database-url=...` and
`token=...` lines. The database address must be reachable from pods. Then:

```bash
kubectl create secret generic navis-test --from-env-file=navis-secret.env
kubectl apply -f deploy/kubernetes/navis.yaml
kubectl set image deployment/navis navis=registry.example.com/team/navis:0.1.0-ubuntu26.04
kubectl rollout status deployment/navis
kubectl port-forward service/navis 8000:8000
```

Remove the local secret file after provisioning. Configure pull credentials for
private registries. Record the release digest and use
`registry.example.com/team/navis@sha256:<digest>` for reproducible deployments.
The sample uses static-token lab authentication. Configure TLS and NAuth before
exposing the service outside the lab. OpenShift admission policies may require
an approved UID/security-context adjustment; this sample is not certified on
OpenShift.

## 5. NAuth and processing

Follow [security setup](SECURITY.md) and [onboarding](ONBOARDING_API.md) for
service callers. Initialize the migrated database, provision clients, then set
`NAVIS_AUTH_MODE=nauth` and remove `NAVIS_LOCAL_TOKEN`. Run the operator CLI from
the image with a protected environment file containing operator database access:

```bash
docker run --rm --env-file .env.operator navis:local python -m navis_api.registration init
```

Use separate privileged operator and runtime database credentials. All replicas
must share the initialized database. Never capture client secrets in CI logs.
Collectors, identity mappings, workers, dataset approval and graph building remain
separate operations. See [integration](INTEGRATION_API.md), [graph setup](GRAPH.md)
and [project status](STATUS.md) for supported behavior and limitations.
