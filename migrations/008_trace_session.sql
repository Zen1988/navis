BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE trace_session (
 id uuid PRIMARY KEY,
 consumer_id uuid NOT NULL REFERENCES api_consumer(id),
 caller_session_id text NOT NULL,
 graph_build_id uuid NOT NULL REFERENCES graph_build(id),
 request jsonb NOT NULL,
 result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 UNIQUE(consumer_id, caller_session_id),
 CHECK(expires_at > created_at)
);
CREATE TABLE trace_recommendation_draft (
 id uuid PRIMARY KEY,
 trace_session_id uuid NOT NULL REFERENCES trace_session(id),
 status text NOT NULL CHECK(status IN ('pending','ready','unavailable')),
 recommendation jsonb,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX trace_session_expiry_idx ON trace_session(expires_at);
COMMIT;
