BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE nat_session_evidence (
 id uuid PRIMARY KEY,
 snapshot_id uuid NOT NULL REFERENCES device_snapshot(id),
 nat_rule_id uuid NOT NULL REFERENCES nat_rule(id),
 original_packet jsonb NOT NULL,
 translated_packet jsonb NOT NULL,
 observed_at timestamptz NOT NULL,
 expires_at timestamptz,
 source_system_id uuid NOT NULL REFERENCES source_system(id),
 details jsonb,
 CHECK(expires_at IS NULL OR expires_at > observed_at)
);
CREATE INDEX nat_session_rule_idx ON nat_session_evidence(snapshot_id,nat_rule_id,observed_at);
COMMIT;
