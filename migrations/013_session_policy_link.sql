BEGIN;
SET LOCAL search_path = navis, public;
ALTER TABLE nat_session_evidence ADD COLUMN policy_rule_id uuid REFERENCES policy_rule(id);
COMMIT;
