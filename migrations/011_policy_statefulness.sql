BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE policy_rule_set ADD COLUMN statefulness text NOT NULL DEFAULT 'unknown'
 CHECK (statefulness IN ('stateful','stateless','unknown'));
ALTER TABLE policy_rule_set ADD COLUMN session_semantics jsonb;
COMMIT;
