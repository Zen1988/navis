#!/usr/bin/env bash
set -euo pipefail
set +x

if [[ $# -lt 2 || $# -gt 3 || ! ${1:-} =~ ^(fresh|existing)$ ]]; then
  echo "Usage: bash $0 fresh|existing MAINTENANCE_ROLE [ENV_FILE]" >&2
  exit 2
fi

mode=$1
maintenance_role=$2
env_file=${3:-.env.maintenance}
namespace=${NAVIS_K8S_NAMESPACE:-navis}
cluster=${NAVIS_PG_CLUSTER:-navis-postgres}
database=${NAVIS_PG_DATABASE:-navis}
db_host=${NAVIS_PG_HOST:-$cluster-rw.$namespace}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ ! $maintenance_role =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
  echo 'Use a lowercase PostgreSQL maintenance role name.' >&2
  exit 2
fi
if [[ -e $env_file || -L $env_file ]]; then
  echo "Destination already exists: $env_file. Choose a new path." >&2
  exit 2
fi

primary=$(kubectl get cluster "$cluster" -n "$namespace" -o jsonpath='{.status.currentPrimary}')
if [[ -z $primary ]]; then
  echo "CloudNativePG cluster $cluster has no current primary." >&2
  exit 1
fi

admin_psql() {
  kubectl exec -i -n "$namespace" "$primary" -c postgres -- \
    psql -X -U postgres -d "$database" -v ON_ERROR_STOP=1 \
    -v maintenance_role="$maintenance_role" -v database="$database" "$@"
}

if [[ $mode == fresh ]]; then
  admin_psql <<'SQL'
BEGIN;
CREATE ROLE :"maintenance_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT, CREATE ON DATABASE :"database" TO :"maintenance_role";
CREATE SCHEMA navis AUTHORIZATION :"maintenance_role";
COMMIT;
SQL
  kubectl exec -it -n "$namespace" "$primary" -c postgres -- \
    psql -X -U postgres -d "$database" -v ON_ERROR_STOP=1 \
    -c "\password $maintenance_role"
fi

admin_psql <<'SQL'
SELECT set_config('navis.maintenance_role', :'maintenance_role', false);
DO $check$
DECLARE
    role_name text := current_setting('navis.maintenance_role');
    role_oid oid;
BEGIN
    SELECT oid INTO role_oid FROM pg_roles WHERE rolname = role_name AND rolcanlogin;
    IF role_oid IS NULL THEN
        RAISE EXCEPTION 'Maintenance login % is missing', role_name;
    END IF;
    IF NOT has_database_privilege(role_oid, current_database(), 'CONNECT') OR NOT EXISTS (
        SELECT FROM pg_namespace n WHERE n.nspname = 'navis'
        AND has_schema_privilege(role_oid, n.oid, 'USAGE')
        AND has_schema_privilege(role_oid, n.oid, 'CREATE')
    ) THEN
        RAISE EXCEPTION 'Maintenance login needs CONNECT and USAGE/CREATE on schema navis';
    END IF;
    IF EXISTS (
        SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'navis' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
        AND NOT pg_has_role(role_oid, c.relowner, 'USAGE')
    ) THEN
        RAISE EXCEPTION 'Maintenance login must own or inherit ownership of existing Navis relations';
    END IF;
END;
$check$;
SQL

admin_psql < "$script_dir/../grant_maintenance_backup.sql"

read -r -s -p "Password for $maintenance_role (used to write $env_file): " db_password
printf '\n'
if [[ -z $db_password ]]; then
  echo 'Enter the existing maintenance login password.' >&2
  exit 1
fi

umask 077
set -o noclobber
printf '%s' "$db_password" | python3 -c '
import sys
from urllib.parse import quote

role, host, database = sys.argv[1:]
password = quote(sys.stdin.read(), safe="")
user = quote(role, safe="")
dbname = quote(database, safe="")
print(f"NAVIS_DATABASE_URL=postgresql://{user}:{password}@{host}:5432/{dbname}")
' "$maintenance_role" "$db_host" "$database" > "$env_file"
unset db_password
printf 'Wrote %s. Run the maintenance pod migration plan to verify the connection.\n' "$env_file"
