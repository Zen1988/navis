-- Apply to the isolated three-device fixture before rebuilding its graph.
UPDATE navis.interface SET routing_context_id='10000000-0000-4000-8000-000000000032'
WHERE id='10000000-0000-4000-8000-000000000043';
