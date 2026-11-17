import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from navis_api.ingestion import Ingestion, PostgresIngestionProcessor
from navis_api.ingestion_progress import summarize, details
from navis_api.worker import process_submission
from navis_common.auth import Principal


def group(status, submissions, *, expected=1000, input_items=None, error=False, complete='complete', raw_expected=None):
    count = submissions if input_items is None else input_items
    return dict(status=status, submissions=submissions, input_items=count,
                processed_items=count if status == 'processed' else 0, has_error=error,
                completeness=complete, data_type='interface', unknown_items=0,
                expected_submissions_min=expected, expected_submissions_max=expected,
                expected_items_min=raw_expected, expected_items_max=raw_expected)


class ProgressTests(unittest.TestCase):
    def test_1000_received_900_processed_100_pending(self):
        result = summarize([group('processed',900),group('pending_identity',100)])
        self.assertEqual(result['counts']['received_submissions'],1000)
        self.assertEqual(result['counts']['processed_submissions'],900)
        self.assertEqual(result['counts']['pending_submissions'],100)
        self.assertEqual(result['counts']['processed_items'],900)
        self.assertTrue(result['upload_complete'])
        self.assertFalse(result['normalization_success'])

    def test_missing_uploads_are_not_reported_as_complete(self):
        result = summarize([group('processed',900)])
        self.assertEqual(result['processing_status'],'awaiting_uploads')
        self.assertFalse(result['upload_complete'])

    def test_failed_atomic_envelope_reports_zero_of_1000_items_committed(self):
        result = summarize([group('pending_identity',1,input_items=1000,error=True,expected=1)])
        self.assertEqual(result['counts']['failed_items'],1000)
        self.assertEqual(result['counts']['processed_items'],0)
        self.assertEqual(result['processing_status'],'needs_attention')

    def test_normalization_success_is_not_network_verification(self):
        result = summarize([group('processed',1000,complete='partial')])
        self.assertTrue(result['normalization_success'])
        self.assertFalse(result['quality']['network_connectivity_verified'])
        self.assertTrue(result['quality']['warnings'])

    def test_raw_only_is_not_typed_success_and_unknown_totals_stay_unknown(self):
        result = summarize([group('raw_only',1000)])
        self.assertFalse(result['normalization_success'])
        self.assertEqual(result['counts']['raw_only_submissions'],1000)
        result = summarize([group('processed',900,expected=None)])
        self.assertIsNone(result['upload_complete'])
        self.assertIsNone(result['normalization_success'])
        self.assertEqual(result['processing_status'],'complete_for_received_data')

    def test_duplicate_receipts_and_inconsistent_expected_totals_need_attention(self):
        self.assertEqual(summarize([group('processed',1001)])['processing_status'],'needs_attention')
        result = summarize([group('processed',1,expected=100),group('processed',1,expected=101)])
        self.assertEqual(result['processing_status'],'needs_attention')

    def test_caller_can_declare_expected_items_instead_of_envelope_count(self):
        result = summarize([group('processed',1,expected=None,input_items=900,raw_expected=1000)])
        self.assertFalse(result['upload_complete'])
        self.assertEqual(result['processing_status'],'awaiting_uploads')

    def test_details_explain_raw_only_and_preserve_actual_error(self):
        result = details(dict(status='raw_only',snapshot_id=str(uuid4()),completeness='partial'))
        self.assertEqual(result['validation']['normalization'],'not_supported_raw_only')
        error = {'code':'VALIDATION_OR_IDENTITY_FAILED','message':'device identity requires confirmation'}
        result = details(dict(status='pending_identity',processing_error=error))
        self.assertEqual(result['processing_state'],'failed')
        self.assertEqual(result['processing_error'],error)

    def test_receipt_records_consumer_collection_and_item_count(self):
        payload = json.loads(Path('docs/api/examples/ingestion-interface.json').read_text())
        submission = Ingestion(**payload,collection_run_id='run-1',expected_submissions=1,expected_items=1)
        conn,cur = MagicMock(),MagicMock()
        conn.__enter__.return_value=conn
        conn.cursor.return_value.__enter__.return_value=cur
        consumer=uuid4()
        cur.fetchone.return_value=(uuid4(),consumer)
        receipt=PostgresIngestionProcessor(lambda:conn).submit(submission,Principal(issuer='i',subject='s',scopes=frozenset()))
        self.assertEqual(receipt['input_items'],1)
        self.assertEqual(receipt['collection_run_id'],'run-1')
        self.assertIn(consumer,cur.execute.call_args.args[1])

    def test_worker_persists_failure_after_normalization_rollback(self):
        conn,cur = MagicMock(),MagicMock()
        conn.__enter__.return_value=conn
        conn.cursor.return_value.__enter__.return_value=cur
        with patch('navis_api.worker._process_submission',side_effect=ValueError('invalid route')), self.assertRaisesRegex(ValueError,'invalid route'):
            process_submission(lambda:conn,uuid4())
        sql,params=cur.execute.call_args.args
        self.assertIn('processing_error=',sql)
        self.assertFalse(params[0].obj['normalization_committed'])


if __name__ == '__main__':
    unittest.main()
