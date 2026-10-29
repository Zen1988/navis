BEGIN;
SET LOCAL search_path = navis, public;

-- Unverified ACI candidates are evidence, not effective policy rules.
CREATE VIEW aci_policy_candidate AS
SELECT e.raw_payload_id, e.snapshot_id, e.device_id, e.fabric_id,
       candidate->>'contract' AS contract_dn,
       candidate->>'subject' AS subject_dn,
       candidate->>'consumer_epg' AS consumer_epg_dn,
       candidate->>'provider_epg' AS provider_epg_dn,
       candidate->>'filter_entry' AS filter_entry_dn,
       candidate->>'candidate_action' AS candidate_action,
       candidate->>'native_direction' AS native_direction,
       candidate->>'protocol' AS protocol,
       candidate->>'status' AS status,
       candidate AS evidence
FROM aci_fabric_evidence e
CROSS JOIN LATERAL jsonb_array_elements(
  CASE WHEN jsonb_typeof(e.semantics->'policy_candidates') = 'array'
       THEN e.semantics->'policy_candidates' ELSE '[]'::jsonb END) AS candidate;

COMMIT;
