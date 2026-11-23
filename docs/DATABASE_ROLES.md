# Database roles for Navis

Create a dedicated maintenance login before the first install. Use it for schema
migrations and the backup that `adopt` and `apply` take before making changes.
Use a separate runtime login for the API. Configure the maintenance URL only in
the maintenance environment file or Kubernetes Secret.

## CloudNativePG host scripts

Run from the repository on your Kubernetes host with Bash, `kubectl` and
Python 3. The database and AGE extension must already be installed.

```bash
# First install into a database with no navis schema or maintenance login
bash deploy/kubernetes/setup-maintenance.sh fresh navis_maintenance

# Existing database: supply the existing migration-capable login instead
bash deploy/kubernetes/setup-maintenance.sh existing navis_maintenance .env.maintenance.new
```

Choose the command that matches the database. Fresh setup prompts to set the
password and asks you to re-enter it to write the environment file. Existing
setup checks the login's ownership access before applying the backup grants.
If fresh setup is interrupted after the schema is created, finish setting the
login password through `psql` and resume with `existing`. The script refuses to
overwrite an existing environment file. Override the namespace, cluster,
database, or database DNS host with `NAVIS_K8S_NAMESPACE`, `NAVIS_PG_CLUSTER`,
`NAVIS_PG_DATABASE`, or `NAVIS_PG_HOST` respectively.

Start the maintenance pod and run the read-only plan:

```bash
bash deploy/kubernetes/start-maintenance.sh localhost/navis:0.1.1 .env.maintenance
```

Use a registry image the cluster can pull, or preload the local image on eligible
nodes as described in the [Podman guide](PODMAN.md). Pass the environment file
you just created. The launcher creates a Secret, backup PVC and pod if missing,
then waits for readiness. It preserves existing resources and uses the existing
Secret if present. To change credentials, update that Secret through your normal
secret management process and recreate the maintenance pod during an idle window.
Set `NAVIS_BACKUP_SIZE` to size a new PVC for your backups. Use the plan output to
choose `adopt` or `apply` using the [upgrade guide](UPGRADING.md).

## Fresh database

Connect as a database administrator to the dedicated Navis database. Install
Apache AGE using your database deployment procedure, then run these commands in
`psql`. Set the login password through the prompt or provision it through your
database operator if it manages roles declaratively.

```sql
CREATE ROLE navis_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
\password navis_maintenance
GRANT CONNECT, CREATE ON DATABASE navis TO navis_maintenance;
CREATE SCHEMA navis AUTHORIZATION navis_maintenance;
```

The database `CREATE` privilege lets the maintenance login install trusted
extensions such as `btree_gist`. Owning the `navis`
schema and running the first migrations as this role gives it ownership of the
application tables and views created by those migrations.

Run the [backup grant SQL](../deploy/grant_maintenance_backup.sql) as a database
administrator. From a shell with an authenticated `psql` admin connection to the
Navis database, use:

```bash
psql -X -d navis -v maintenance_role=navis_maintenance \
  -f deploy/grant_maintenance_backup.sql
```

The script grants schema access and read access to tables and sequences in
`ag_catalog` and all currently registered AGE graph schemas in that database.
Run it again before upgrades if graphs were created by another role after the
last grant. If the dedicated database also contains other schemas owned by
another role, provision backup access to those objects too. The toolkit invokes
a full database dump.

Set `NAVIS_DATABASE_URL` in `.env.maintenance` or the maintenance pod's Secret to
use `navis_maintenance`. Then follow the [upgrade toolkit](UPGRADING.md) to run
`plan` and `apply`. Provision your deployment's runtime grants separately,
including access to the tables and AGE operations used by the API.

## Existing database

Check who owns the schema and tables before choosing a maintenance login:

```sql
SELECT nspname, pg_get_userbyid(nspowner) AS owner
FROM pg_namespace WHERE nspname = 'navis';

SELECT tableowner AS owner, count(*) AS tables
FROM pg_tables WHERE schemaname = 'navis' GROUP BY tableowner;
```

Use the existing schema owner for migrations if it can be used as a maintenance
login. To switch to a dedicated login, have the DBA arrange ownership or
membership with inherited privileges in the existing owner roles so the new
login can alter existing objects. Changing the schema owner alone leaves existing
tables and views under their original owners. Check runtime access to newly
created tables before bringing the API back up.

Run the backup grant script with the chosen maintenance login. In CloudNativePG
you can stream the SQL to the primary using the existing local administrator
connection, with no database port-forward:

```bash
primary=$(kubectl get cluster navis-postgres -n navis \
  -o jsonpath='{.status.currentPrimary}')
kubectl exec -i -n navis "$primary" -c postgres -- \
  psql -X -U postgres -d navis -v maintenance_role=navis_maintenance \
  < deploy/grant_maintenance_backup.sql
```

The bootstrap and backup grants are separate from numbered migrations because
the database and login have to exist, and the backup runs before migration SQL.
If `pg_dump` reports a missing read grant, it stops the upgrade before the ledger
transaction. The dump from that failed attempt is incomplete.
