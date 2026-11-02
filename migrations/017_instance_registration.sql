BEGIN;
CREATE TABLE navis.instance_identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 id uuid NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE navis.nauth_client (
 id uuid PRIMARY KEY,
 instance_id uuid NOT NULL REFERENCES navis.instance_identity(id),
 consumer_id uuid NOT NULL REFERENCES navis.api_consumer(id),
 secret_digest text NOT NULL,
 scopes text[] NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz
);
CREATE TABLE navis.nauth_access_token (
 id uuid PRIMARY KEY,
 client_id uuid NOT NULL REFERENCES navis.nauth_client(id),
 secret_digest text NOT NULL UNIQUE,
 scopes text[] NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE INDEX nauth_token_expiry ON navis.nauth_access_token(expires_at);
COMMIT;
