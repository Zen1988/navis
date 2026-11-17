"""Caller-visible ingestion progress, separate from network verification."""


def details(row):
    result = dict(row)
    status = row['status']
    terminal = status in ('processed', 'raw_only')
    result['processing_state'] = status if terminal else 'failed' if row.get('processing_error') else 'pending'
    result['validation'] = {'envelope': 'passed', 'adapter': 'approved' if terminal else 'pending_or_failed',
        'identity': 'resolved' if row.get('snapshot_id') else 'pending_or_failed',
        'normalization': 'passed' if status == 'processed' else 'not_supported_raw_only' if status == 'raw_only' else 'pending_or_failed'}
    warnings = []
    if row.get('completeness') != 'complete':
        warnings.append('Source declares partial or unknown collection coverage.')
    if status == 'raw_only':
        warnings.append('Stored as raw evidence; typed normalization was not performed.')
    result['quality'] = {'warnings': warnings, 'network_connectivity_verified': False}
    if 'adapter_name' in row:
        result['adapter'] = {key: row.get(column) for key, column in
                             (('name','adapter_name'),('input_format','input_format'),('format_version','format_version'))}
    for key in ('ingestion_id', 'snapshot_id', 'device_id'):
        if result.get(key) is not None:
            result[key] = str(result[key])
    return result


def summarize(groups):
    totals = dict(received_submissions=0, processed_submissions=0, raw_only_submissions=0,
                  failed_submissions=0, pending_submissions=0, input_items=0, processed_items=0,
                  failed_items=0, pending_items=0, raw_only_items=0, unknown_item_count_submissions=0,
                  incomplete_coverage_submissions=0)
    expected_submissions, expected_items, types = set(), set(), {}
    for group in groups:
        count = int(group['submissions'])
        input_items = int(group.get('input_items') or 0)
        status = group['status']
        state = status if status in ('processed', 'raw_only') else 'failed' if group['has_error'] else 'pending'
        prefix = 'processed' if state == 'processed' else 'raw_only' if state == 'raw_only' else state
        totals['received_submissions'] += count
        totals[prefix+'_submissions'] += count
        totals['input_items'] += input_items
        totals['processed_items'] += int(group.get('processed_items') or 0)
        if prefix != 'processed':
            totals[prefix+'_items'] += input_items
        totals['unknown_item_count_submissions'] += int(group.get('unknown_items') or 0)
        if group['completeness'] != 'complete':
            totals['incomplete_coverage_submissions'] += count
        bucket = types.setdefault(group['data_type'], {})
        bucket[prefix] = bucket.get(prefix, 0)+count
        for key, target in (('submissions', expected_submissions), ('items', expected_items)):
            for bound in ('min', 'max'):
                value = group.get('expected_'+key+'_'+bound)
                if value is not None:
                    target.add(int(value))
    expected = next(iter(expected_submissions)) if len(expected_submissions) == 1 else None
    expected_count = next(iter(expected_items)) if len(expected_items) == 1 else None
    warnings = []
    inconsistent = len(expected_submissions) > 1 or len(expected_items) > 1
    if inconsistent:
        warnings.append('Callers supplied inconsistent expected totals for this collection.')
    if expected is None and expected_count is None:
        warnings.append('No consistent expected submission total; upload completion cannot be confirmed.')
    if totals['unknown_item_count_submissions']:
        warnings.append('Some payloads have no countable entries array; item totals are incomplete.')
    if totals['incomplete_coverage_submissions']:
        warnings.append('Some source submissions declare partial or unknown coverage.')
    if totals['raw_only_submissions']:
        warnings.append('Some evidence was stored raw without typed normalization.')
    received = totals['received_submissions']
    upload_complete = (received == expected if expected is not None else
                       totals['input_items'] == expected_count if expected_count is not None and not totals['unknown_item_count_submissions'] else None)
    processing_complete = received > 0 and not totals['pending_submissions'] and not totals['failed_submissions']
    count_mismatch = bool(expected is not None and received > expected or expected_count is not None and totals['input_items'] > expected_count)
    if processing_complete and upload_complete and expected_count is not None and totals['input_items'] != expected_count:
        count_mismatch = True
    if count_mismatch:
        warnings.append('Received data does not match expected totals; check duplicates or missing items.')
    if inconsistent or count_mismatch or totals['failed_submissions']:
        status = 'needs_attention'
    elif upload_complete is False:
        status = 'awaiting_uploads'
    elif not processing_complete:
        status = 'processing_pending'
    else:
        status = 'complete' if upload_complete else 'complete_for_received_data'
    normalized = (processing_complete and totals['processed_submissions'] == received
                  and totals['processed_items'] == totals['input_items'] and not totals['unknown_item_count_submissions'])
    return {'processing_status': status, 'counts': totals, 'by_data_type': types,
            'expected_submissions': expected, 'expected_items': expected_count, 'upload_complete': upload_complete,
            'processing_complete': processing_complete,
            'normalization_success': bool(normalized and not inconsistent and not count_mismatch) if upload_complete else None,
            'quality': {'warnings': warnings, 'network_connectivity_verified': False}}


FILTER = """i.submitted_consumer_id=%s AND i.collection_run_id=%s
    AND (%s::text IS NULL OR src.namespace=%s)
    AND EXISTS (SELECT 1 FROM navis.consumer_data_scope ds WHERE ds.api_consumer_id=%s
        AND ds.source_system_id=i.source_system_id AND ds.permissions @> '["inventory:write"]'::jsonb)"""


def collection(cur, consumer, run_id, namespace, limit, offset):
    params = (consumer, run_id, namespace, namespace, consumer)
    cur.execute("""SELECT i.status,(i.processing_error IS NOT NULL),i.completeness,i.data_type,count(*),
        sum(i.input_items),sum(i.processed_items),count(*) FILTER(WHERE i.input_items IS NULL),
        min(i.expected_submissions),max(i.expected_submissions),min(i.expected_items),max(i.expected_items)
        FROM navis.ingestion_submission i JOIN navis.source_system src ON src.id=i.source_system_id WHERE """+FILTER+"""
        GROUP BY i.status,(i.processing_error IS NOT NULL),i.completeness,i.data_type""", params)
    keys = ('status','has_error','completeness','data_type','submissions','input_items','processed_items','unknown_items',
            'expected_submissions_min','expected_submissions_max','expected_items_min','expected_items_max')
    groups = [dict(zip(keys, row)) for row in cur.fetchall()]
    if not groups:
        raise LookupError('collection not found in caller scope')
    summary = summarize(groups)
    cur.execute("""SELECT i.id,i.status,src.namespace,i.external_device_id,i.data_type,i.completeness,
        i.input_items,i.processed_items,i.snapshot_id,s.device_id,i.processing_error,i.processing_attempts,
        i.last_attempt_at,i.collected_at,i.updated_at,i.adapter_name,i.input_format,i.format_version FROM navis.ingestion_submission i
        JOIN navis.source_system src ON src.id=i.source_system_id LEFT JOIN navis.device_snapshot s ON s.id=i.snapshot_id
        WHERE """+FILTER+" ORDER BY i.received_at,i.id LIMIT %s OFFSET %s", params+(limit,offset))
    keys = ('ingestion_id','status','namespace','external_device_id','data_type','completeness','input_items','processed_items',
            'snapshot_id','device_id','processing_error','processing_attempts','last_attempt_at','collected_at','updated_at',
            'adapter_name','input_format','format_version')
    rows = [details(dict(zip(keys, row))) for row in cur.fetchall()]
    return {'collection_run_id': run_id, 'namespace': namespace, **summary, 'submissions': rows,
            'limit': limit, 'offset': offset,
            'next_offset': offset+len(rows) if rows and offset+len(rows)<summary['counts']['received_submissions'] else None}
