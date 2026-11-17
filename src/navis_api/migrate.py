"""Back up, track and apply ordered SQL migrations from the same API image."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2] / "migrations"
if not ROOT.is_dir():
    ROOT = Path.cwd() / "migrations"


def migration_files(root=ROOT):
    result = []
    for path in sorted(root.glob("[0-9][0-9][0-9]_*.sql")):
        body = path.read_text(encoding="utf-8")
        result.append({"version": int(path.name[:3]), "name": path.name,
                       "checksum": hashlib.sha256(body.encode()).hexdigest(), "sql": body})
    versions = [m["version"] for m in result]
    if not versions:
        raise ValueError("No migration SQL files found; run from the repository root or use the application image")
    if versions != list(range(1, len(versions)+1)):
        raise ValueError("migration files must have consecutive versions starting at 001")
    return result


def transaction_body(sql):
    # Repository migrations contain a single top-level BEGIN/COMMIT pair.
    # The runner owns that transaction so schema and ledger commit together.
    sql = re.sub(r"(?im)^BEGIN;\s*", "", sql, count=1)
    return re.sub(r"(?im)^COMMIT;\s*$", "", sql, count=1)


def plan(cur, files):
    cur.execute("SELECT to_regclass('navis.schema_migration'),to_regclass('navis.device')")
    ledger, existing = cur.fetchone()
    if ledger:
        cur.execute("SELECT version,name,checksum FROM navis.schema_migration ORDER BY version")
        applied = {v: (name, checksum) for v, name, checksum in cur.fetchall()}
        if any(v > len(files) for v in applied):
            raise ValueError("database is newer than this image; do not downgrade the schema")
        if sorted(applied) != list(range(1, len(applied)+1)):
            raise ValueError("migration ledger has gaps; repair it before upgrading")
        for item in files:
            if item["version"] in applied and applied[item["version"]] != (item["name"], item["checksum"]):
                raise ValueError("applied migration changed: " + item["name"])
    else:
        applied = {}
    return {"baseline_required": bool(existing and not ledger), "applied": sorted(applied),
            "pending": [m["name"] for m in files if m["version"] not in applied]}


def backup(dsn, directory):
    from psycopg.conninfo import conninfo_to_dict
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("navis-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".dump")
    # Keep passwords out of process arguments and printed command lines.
    env = dict(os.environ)
    mapping = {"dbname": "PGDATABASE", "host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT",
               "user": "PGUSER", "password": "PGPASSWORD", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
               "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "service": "PGSERVICE", "connect_timeout": "PGCONNECT_TIMEOUT"}
    options = conninfo_to_dict(dsn)
    unsupported = set(options)-set(mapping)
    if unsupported:
        raise ValueError("backup client options need an explicit PG environment mapping: " + ", ".join(sorted(unsupported)))
    env.update({mapping[key]: value for key, value in options.items()})
    subprocess.run(["pg_dump", "--format=custom", "--file", str(path)], env=env, check=True)
    subprocess.run(["pg_restore", "--list", str(path)], env=env, check=True, stdout=subprocess.DEVNULL)
    return str(path)


def create_ledger(cur):
    cur.execute("CREATE SCHEMA IF NOT EXISTS navis")
    cur.execute("""CREATE TABLE IF NOT EXISTS navis.schema_migration (
        version integer PRIMARY KEY,name text NOT NULL,checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now(),adopted boolean NOT NULL DEFAULT false)""")


def verify_baseline(cur, files, through):
    """Check objects before recording an operator-declared legacy baseline."""
    if not 1 <= through <= len(files):
        raise ValueError("baseline must be a known migration number")
    for item in files[:through]:
        for name in re.findall(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z_0-9.]*)", item["sql"], re.I):
            relation = name if "." in name else "navis." + name
            cur.execute("SELECT to_regclass(%s)", (relation,))
            if cur.fetchone()[0] is None:
                raise ValueError("baseline object missing: " + relation)
        for table, column in re.findall(r"ALTER\s+TABLE\s+([a-z_][a-z_0-9.]*)\s+ADD\s+COLUMN\s+([a-z_][a-z_0-9]*)", item["sql"], re.I):
            table = table.removeprefix("navis.")
            cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema='navis' AND table_name=%s AND column_name=%s", (table, column))
            if cur.fetchone() is None:
                raise ValueError("baseline column missing: " + table + "." + column)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "apply", "adopt"])
    parser.add_argument("--backup-dir")
    parser.add_argument("--through", type=int)
    args = parser.parse_args()
    if args.command != "plan" and not args.backup_dir:
        parser.error("--backup-dir is required before database changes")
    if args.command == "adopt" and args.through is None:
        parser.error("adopt requires --through with the known last applied migration")
    import psycopg
    dsn = os.environ["NAVIS_DATABASE_URL"]
    files = migration_files()
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(hashtextextended('navis:schema-migrations',0))")
        current = plan(cur, files)
        if args.command == "plan":
            print(json.dumps(current, indent=2))
            return
        if args.command == "apply" and current["baseline_required"]:
            raise ValueError("legacy database has no ledger; adopt its known baseline first")
        if args.command == "adopt":
            if current["applied"]:
                raise ValueError("database already has a migration ledger")
            verify_baseline(cur, files, args.through)
        backup_path = backup(dsn, args.backup_dir)
        with conn.transaction():
            create_ledger(cur)
            if args.command == "adopt":
                for item in files[:args.through]:
                    cur.execute("INSERT INTO navis.schema_migration(version,name,checksum,adopted) VALUES (%s,%s,%s,true)", (item["version"], item["name"], item["checksum"]))
        if args.command == "apply":
            for item in files:
                if item["version"] not in current["applied"]:
                    with conn.transaction():
                        cur.execute(transaction_body(item["sql"]), prepare=False)
                        cur.execute("INSERT INTO navis.schema_migration(version,name,checksum) VALUES (%s,%s,%s)", (item["version"], item["name"], item["checksum"]))
        print(json.dumps({"backup": backup_path, **plan(cur, files)}, indent=2))


if __name__ == "__main__":
    main()
