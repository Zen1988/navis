-- Run as a database administrator in the Navis database after installing AGE.
-- Supply -v maintenance_role=<existing dedicated login> to psql.
\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('navis.maintenance_role', :'maintenance_role', true);

DO $grant$
DECLARE
    role_name text := current_setting('navis.maintenance_role');
    schema_name text;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = role_name AND rolcanlogin) THEN
        RAISE EXCEPTION 'Maintenance login % does not exist', role_name;
    END IF;

    FOR schema_name IN
        SELECT 'ag_catalog'::text
        UNION
        SELECT n.nspname::text FROM ag_catalog.ag_graph g
        JOIN pg_namespace n ON n.oid = g.namespace
    LOOP
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, role_name);
        EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I', schema_name, role_name);
        EXECUTE format('GRANT SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', schema_name, role_name);
    END LOOP;
END;
$grant$;
COMMIT;
