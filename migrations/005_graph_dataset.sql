BEGIN;
SET LOCAL search_path = navis, public;
CREATE TABLE graph_dataset (
 id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE graph_dataset_snapshot (
 dataset_id uuid NOT NULL REFERENCES graph_dataset(id),
 device_id uuid NOT NULL REFERENCES device(id),
 data_type text NOT NULL,
 snapshot_id uuid NOT NULL,
 PRIMARY KEY(dataset_id,device_id,data_type),
 FOREIGN KEY(snapshot_id,device_id) REFERENCES device_snapshot(id,device_id)
);
-- A dataset chooses one snapshot per device and data type. The graph builder
-- must verify coverage, native interface identity and temporal compatibility.
ALTER TABLE graph_build ADD COLUMN dataset_id uuid REFERENCES graph_dataset(id);
COMMIT;
