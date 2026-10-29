-- Initial Navis schema. Graph projections are created separately by the AGE builder.
BEGIN;
CREATE SCHEMA IF NOT EXISTS navis;
SET LOCAL search_path = navis, public;

CREATE TABLE source_system (
 id uuid PRIMARY KEY, namespace text NOT NULL UNIQUE, kind text NOT NULL, name text NOT NULL
);
CREATE TABLE device (
 id uuid PRIMARY KEY, vendor text NOT NULL, platform text NOT NULL, model text,
 display_name text, first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL,
 CHECK (last_seen_at >= first_seen_at)
);
CREATE TABLE device_identity_mapping (
 id uuid PRIMARY KEY, device_id uuid NOT NULL REFERENCES device(id),
 source_system_id uuid NOT NULL REFERENCES source_system(id), external_id text NOT NULL,
 provenance text NOT NULL, valid_from timestamptz NOT NULL, valid_until timestamptz,
 CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE UNIQUE INDEX device_identity_active ON device_identity_mapping(source_system_id, external_id) WHERE valid_until IS NULL;
CREATE TABLE import_batch (
 id uuid PRIMARY KEY, source_system_id uuid NOT NULL REFERENCES source_system(id), external_id text,
 received_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL,
 UNIQUE (source_system_id, external_id)
);
CREATE TABLE device_snapshot (
 id uuid PRIMARY KEY, device_id uuid NOT NULL REFERENCES device(id), import_batch_id uuid NOT NULL REFERENCES import_batch(id),
 collected_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), firmware_version text,
 platform_version text, source_snapshot_id text, UNIQUE(id, device_id)
);
CREATE TABLE snapshot_coverage (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), data_type text NOT NULL,
 coverage text NOT NULL CHECK (coverage IN ('complete','partial','unknown')), scope jsonb, details jsonb
);
CREATE TABLE raw_payload (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), data_type text NOT NULL,
 format text NOT NULL, format_version text, payload jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE normalization_run (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), adapter_name text NOT NULL,
 adapter_version text NOT NULL, started_at timestamptz NOT NULL, status text NOT NULL, details jsonb,
 UNIQUE(id, snapshot_id)
);
CREATE TABLE routing_context (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), normalization_run_id uuid,
 native_id text NOT NULL, name text, details jsonb, UNIQUE(id,snapshot_id),
 FOREIGN KEY (normalization_run_id,snapshot_id) REFERENCES normalization_run(id,snapshot_id)
);
CREATE TABLE network_segment (
 id uuid PRIMARY KEY, source_system_id uuid REFERENCES source_system(id), external_id text, name text, details jsonb,
 UNIQUE(source_system_id,external_id)
);
CREATE TABLE interface (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), normalization_run_id uuid,
 native_id text NOT NULL, name text NOT NULL, kind text NOT NULL, parent_interface_id uuid,
 routing_context_id uuid, operational_state text, details jsonb, UNIQUE(id,snapshot_id),
 FOREIGN KEY (normalization_run_id,snapshot_id) REFERENCES normalization_run(id,snapshot_id),
 FOREIGN KEY (parent_interface_id,snapshot_id) REFERENCES interface(id,snapshot_id),
 FOREIGN KEY (routing_context_id,snapshot_id) REFERENCES routing_context(id,snapshot_id)
);
CREATE TABLE interface_address (
 id uuid PRIMARY KEY, interface_id uuid NOT NULL REFERENCES interface(id), address inet NOT NULL, purpose text, details jsonb
);
CREATE TABLE interface_segment (
 id uuid PRIMARY KEY, interface_id uuid NOT NULL REFERENCES interface(id), network_segment_id uuid NOT NULL REFERENCES network_segment(id),
 vlan_id integer CHECK(vlan_id BETWEEN 1 AND 4094), details jsonb
);
CREATE TABLE route (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), normalization_run_id uuid,
 routing_context_id uuid NOT NULL, destination cidr NOT NULL, route_type text NOT NULL, protocol text,
 preference bigint CHECK(preference >= 0), metric bigint CHECK(metric >= 0), native_id text, details jsonb,
 UNIQUE(id,snapshot_id), FOREIGN KEY (routing_context_id,snapshot_id) REFERENCES routing_context(id,snapshot_id),
 FOREIGN KEY (normalization_run_id,snapshot_id) REFERENCES normalization_run(id,snapshot_id)
);
CREATE INDEX route_context_idx ON route(snapshot_id,routing_context_id);
CREATE INDEX route_prefix_idx ON route USING gist(destination inet_ops);
CREATE TABLE route_next_hop (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, route_id uuid NOT NULL, next_hop_address inet,
 interface_id uuid, next_hop_context_id uuid, weight integer CHECK(weight > 0), details jsonb,
 FOREIGN KEY (route_id,snapshot_id) REFERENCES route(id,snapshot_id),
 FOREIGN KEY (interface_id,snapshot_id) REFERENCES interface(id,snapshot_id),
 FOREIGN KEY (next_hop_context_id,snapshot_id) REFERENCES routing_context(id,snapshot_id)
);
CREATE TABLE neighbor_entry (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, routing_context_id uuid NOT NULL, interface_id uuid NOT NULL,
 ip_address inet NOT NULL, mac_address macaddr, state text, observed_at timestamptz, details jsonb,
 FOREIGN KEY(routing_context_id,snapshot_id) REFERENCES routing_context(id,snapshot_id),
 FOREIGN KEY(interface_id,snapshot_id) REFERENCES interface(id,snapshot_id)
);
CREATE INDEX neighbor_lookup_idx ON neighbor_entry(snapshot_id,routing_context_id,ip_address);
CREATE TABLE mac_entry (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, interface_id uuid NOT NULL, mac_address macaddr NOT NULL,
 network_segment_id uuid REFERENCES network_segment(id), vlan_id integer CHECK(vlan_id BETWEEN 1 AND 4094),
 entry_type text, observed_at timestamptz, details jsonb,
 FOREIGN KEY(interface_id,snapshot_id) REFERENCES interface(id,snapshot_id)
);
CREATE INDEX mac_lookup_idx ON mac_entry(snapshot_id,network_segment_id,vlan_id,mac_address);
CREATE TABLE topology_link (
 id uuid PRIMARY KEY, origin text NOT NULL, source_system_id uuid REFERENCES source_system(id),
 observed_at timestamptz, valid_from timestamptz, valid_until timestamptz, details jsonb,
 CHECK(valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);
CREATE TABLE topology_link_endpoint (
 link_id uuid NOT NULL REFERENCES topology_link(id), endpoint_number smallint NOT NULL CHECK(endpoint_number IN (1,2)),
 interface_id uuid REFERENCES interface(id), network_segment_id uuid REFERENCES network_segment(id),
 PRIMARY KEY(link_id,endpoint_number), CHECK(num_nonnulls(interface_id,network_segment_id)=1)
);
CREATE TABLE routing_protocol_instance (
 id uuid PRIMARY KEY, routing_context_id uuid NOT NULL REFERENCES routing_context(id), protocol text NOT NULL,
 local_asn bigint CHECK(local_asn BETWEEN 0 AND 4294967295), router_id inet, details jsonb
);
CREATE TABLE routing_peer (
 id uuid PRIMARY KEY, routing_protocol_instance_id uuid NOT NULL REFERENCES routing_protocol_instance(id),
 peer_address inet NOT NULL, remote_asn bigint CHECK(remote_asn BETWEEN 0 AND 4294967295), state text, details jsonb
);
CREATE TABLE route_protocol_attributes (route_id uuid PRIMARY KEY REFERENCES route(id), attributes jsonb NOT NULL);

CREATE TABLE network_zone (id uuid PRIMARY KEY, name text NOT NULL, source_system_id uuid REFERENCES source_system(id), external_id text, details jsonb);
CREATE TABLE network_zone_membership (
 id uuid PRIMARY KEY, network_zone_id uuid NOT NULL REFERENCES network_zone(id), device_id uuid REFERENCES device(id),
 network_segment_id uuid REFERENCES network_segment(id), valid_from timestamptz NOT NULL, valid_until timestamptz,
 CHECK(num_nonnulls(device_id,network_segment_id)=1), CHECK(valid_until IS NULL OR valid_until > valid_from)
);
CREATE TABLE enforcement_point (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), native_id text NOT NULL, kind text NOT NULL, details jsonb,
 UNIQUE(id,snapshot_id)
);
CREATE TABLE security_zone (
 id uuid PRIMARY KEY, enforcement_point_id uuid NOT NULL REFERENCES enforcement_point(id), native_id text NOT NULL, name text, details jsonb,
 UNIQUE(enforcement_point_id,native_id)
);
CREATE TABLE security_zone_member (security_zone_id uuid NOT NULL REFERENCES security_zone(id), interface_id uuid NOT NULL REFERENCES interface(id), details jsonb, PRIMARY KEY(security_zone_id,interface_id));
CREATE TABLE address_object (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), native_id text, kind text NOT NULL,
 host inet, prefix cidr, range_start inet, range_end inet, details jsonb,
 CHECK(range_start IS NULL OR range_end IS NULL OR (family(range_start)=family(range_end) AND range_start <= range_end))
);
CREATE TABLE address_group_member (
 group_id uuid NOT NULL REFERENCES address_object(id), member_id uuid NOT NULL REFERENCES address_object(id),
 is_exclusion boolean NOT NULL DEFAULT false, PRIMARY KEY(group_id,member_id), CHECK(group_id <> member_id)
);
CREATE TABLE service_object (
 id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), native_id text, protocol text,
 source_port_start integer, source_port_end integer, destination_port_start integer, destination_port_end integer, details jsonb,
 CHECK(source_port_start BETWEEN 0 AND 65535), CHECK(source_port_end BETWEEN 0 AND 65535),
 CHECK(destination_port_start BETWEEN 0 AND 65535), CHECK(destination_port_end BETWEEN 0 AND 65535),
 CHECK(source_port_start <= source_port_end), CHECK(destination_port_start <= destination_port_end)
);
CREATE TABLE service_group_member (group_id uuid NOT NULL REFERENCES service_object(id), member_id uuid NOT NULL REFERENCES service_object(id), PRIMARY KEY(group_id,member_id), CHECK(group_id <> member_id));
CREATE TABLE policy_rule_set (
 id uuid PRIMARY KEY, enforcement_point_id uuid NOT NULL REFERENCES enforcement_point(id), native_id text NOT NULL,
 evaluation_order text NOT NULL, default_action text NOT NULL CHECK(default_action IN ('allow','deny','unknown')), details jsonb
);
CREATE TABLE policy_rule (
 id uuid PRIMARY KEY, rule_set_id uuid NOT NULL REFERENCES policy_rule_set(id), native_rule_id text NOT NULL,
 name text, position integer NOT NULL, action text NOT NULL, direction text, enabled boolean NOT NULL, details jsonb,
 UNIQUE(rule_set_id,native_rule_id), UNIQUE(rule_set_id,position)
);
CREATE TABLE policy_selector (
 id uuid PRIMARY KEY, policy_rule_id uuid NOT NULL REFERENCES policy_rule(id), role text NOT NULL,
 address_object_id uuid REFERENCES address_object(id), service_object_id uuid REFERENCES service_object(id),
 security_zone_id uuid REFERENCES security_zone(id), interface_id uuid REFERENCES interface(id), negated boolean NOT NULL DEFAULT false,
 CHECK(num_nonnulls(address_object_id,service_object_id,security_zone_id,interface_id)=1)
);
CREATE TABLE policy_schedule (
 id uuid PRIMARY KEY, policy_rule_id uuid NOT NULL REFERENCES policy_rule(id), kind text NOT NULL,
 valid_from timestamptz, valid_until timestamptz, timezone text, recurrence jsonb, details jsonb,
 CHECK(valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);
CREATE TABLE nat_rule_set (
 id uuid PRIMARY KEY, enforcement_point_id uuid NOT NULL REFERENCES enforcement_point(id), native_id text NOT NULL,
 processing_stage text NOT NULL, evaluation_order text NOT NULL, details jsonb
);
CREATE TABLE nat_rule (
 id uuid PRIMARY KEY, nat_rule_set_id uuid NOT NULL REFERENCES nat_rule_set(id), native_rule_id text NOT NULL,
 position integer NOT NULL, enabled boolean NOT NULL, details jsonb, UNIQUE(nat_rule_set_id,native_rule_id), UNIQUE(nat_rule_set_id,position)
);
CREATE TABLE nat_selector (
 id uuid PRIMARY KEY, nat_rule_id uuid NOT NULL REFERENCES nat_rule(id), role text NOT NULL,
 address_object_id uuid REFERENCES address_object(id), service_object_id uuid REFERENCES service_object(id),
 security_zone_id uuid REFERENCES security_zone(id), interface_id uuid REFERENCES interface(id), negated boolean NOT NULL DEFAULT false,
 CHECK(num_nonnulls(address_object_id,service_object_id,security_zone_id,interface_id)=1)
);
CREATE TABLE nat_translation (id uuid PRIMARY KEY, nat_rule_id uuid NOT NULL REFERENCES nat_rule(id), kind text NOT NULL, specification jsonb NOT NULL, details jsonb);

CREATE TABLE application (id uuid PRIMARY KEY, name text NOT NULL, source_system_id uuid REFERENCES source_system(id), external_id text, details jsonb);
CREATE TABLE application_member (
 id uuid PRIMARY KEY, application_id uuid NOT NULL REFERENCES application(id), device_id uuid NOT NULL REFERENCES device(id),
 valid_from timestamptz NOT NULL, valid_until timestamptz, CHECK(valid_until IS NULL OR valid_until > valid_from)
);
CREATE TABLE application_flow (
 id uuid PRIMARY KEY, application_id uuid NOT NULL REFERENCES application(id), source_selector jsonb NOT NULL,
 destination_selector jsonb NOT NULL, protocol text NOT NULL, destination_port_start integer, destination_port_end integer,
 valid_from timestamptz, valid_until timestamptz, details jsonb,
 CHECK(destination_port_start BETWEEN 0 AND 65535), CHECK(destination_port_end BETWEEN 0 AND 65535),
 CHECK(destination_port_start <= destination_port_end), CHECK(valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);
CREATE TABLE graph_build (id uuid PRIMARY KEY, started_at timestamptz NOT NULL, completed_at timestamptz, status text NOT NULL, builder_version text NOT NULL);
CREATE TABLE graph_build_snapshot (graph_build_id uuid NOT NULL REFERENCES graph_build(id), snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), PRIMARY KEY(graph_build_id,snapshot_id));
CREATE TABLE analysis_request (id uuid PRIMARY KEY, application_flow_id uuid REFERENCES application_flow(id), source jsonb NOT NULL, destination jsonb NOT NULL, protocol text NOT NULL, ports jsonb, requested_at timestamptz NOT NULL DEFAULT now(), parameters jsonb);
CREATE TABLE analysis_dataset_snapshot (analysis_request_id uuid NOT NULL REFERENCES analysis_request(id), snapshot_id uuid NOT NULL REFERENCES device_snapshot(id), PRIMARY KEY(analysis_request_id,snapshot_id));
CREATE TABLE analysis_result (id uuid PRIMARY KEY, analysis_request_id uuid NOT NULL REFERENCES analysis_request(id), graph_build_id uuid REFERENCES graph_build(id), status text NOT NULL, completed_at timestamptz, engine_version text NOT NULL, details jsonb);
CREATE TABLE analysis_step (
 id uuid PRIMARY KEY, analysis_result_id uuid NOT NULL REFERENCES analysis_result(id), parent_step_id uuid REFERENCES analysis_step(id),
 sequence integer NOT NULL, device_id uuid REFERENCES device(id), route_id uuid REFERENCES route(id), nat_rule_id uuid REFERENCES nat_rule(id),
 policy_rule_id uuid REFERENCES policy_rule(id), packet_before jsonb, packet_after jsonb, decision text, explanation text
);
CREATE TABLE analysis_finding (id uuid PRIMARY KEY, analysis_result_id uuid NOT NULL REFERENCES analysis_result(id), policy_rule_id uuid REFERENCES policy_rule(id), kind text NOT NULL, coverage jsonb, confidence text, explanation text NOT NULL, details jsonb);
CREATE TABLE recommendation (id uuid PRIMARY KEY, analysis_result_id uuid NOT NULL REFERENCES analysis_result(id), enforcement_point_id uuid REFERENCES enforcement_point(id), policy_rule_id uuid REFERENCES policy_rule(id), recommendation jsonb NOT NULL, reason text NOT NULL, uncertainty text);
CREATE TABLE api_consumer (id uuid PRIMARY KEY, issuer text NOT NULL, subject_or_client_id text NOT NULL, name text NOT NULL, status text NOT NULL, UNIQUE(issuer,subject_or_client_id));
CREATE TABLE consumer_data_scope (id uuid PRIMARY KEY, api_consumer_id uuid NOT NULL REFERENCES api_consumer(id), source_system_id uuid REFERENCES source_system(id), permissions jsonb NOT NULL);
CREATE TABLE audit_event (id uuid PRIMARY KEY, api_consumer_id uuid REFERENCES api_consumer(id), occurred_at timestamptz NOT NULL DEFAULT now(), operation text NOT NULL, resource_type text, resource_id uuid, outcome text NOT NULL, details jsonb);
CREATE TABLE adapter_artifact (
 id uuid PRIMARY KEY, product text NOT NULL, version text NOT NULL, artifact_name text NOT NULL,
 digest_algorithm text NOT NULL CHECK(digest_algorithm = 'sha256'), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 status text NOT NULL CHECK(status IN ('approved','revoked')), approved_at timestamptz NOT NULL, approved_by text NOT NULL,
 revoked_at timestamptz, details jsonb, UNIQUE(product,version,artifact_name,digest_algorithm,digest),
 CHECK((status='revoked') = (revoked_at IS NOT NULL))
);
CREATE TABLE adapter_verification (id uuid PRIMARY KEY, adapter_artifact_id uuid REFERENCES adapter_artifact(id), checked_at timestamptz NOT NULL DEFAULT now(), observed_digest bytea, result text NOT NULL, reason text, import_batch_id uuid REFERENCES import_batch(id));
COMMIT;
