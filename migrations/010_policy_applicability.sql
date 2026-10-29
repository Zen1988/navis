BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE policy_applicability (
 id uuid PRIMARY KEY,
 snapshot_id uuid NOT NULL REFERENCES device_snapshot(id),
 routing_context_id uuid,
 interface_id uuid,
 direction text NOT NULL CHECK(direction IN ('ingress','egress','both','device')),
 mechanism text NOT NULL,
 state text NOT NULL CHECK(state IN ('enforced','not_applicable','unknown')),
 evidence jsonb NOT NULL,
 FOREIGN KEY(routing_context_id,snapshot_id) REFERENCES routing_context(id,snapshot_id),
 FOREIGN KEY(interface_id,snapshot_id) REFERENCES interface(id,snapshot_id)
);
CREATE INDEX policy_applicability_snapshot_idx ON policy_applicability(snapshot_id);
COMMIT;
