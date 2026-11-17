import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from unittest.mock import MagicMock

from navis_common.lifecycle import lifecycle
from navis_api.retention import ProtectedData, dependency_order, main as retention_main
from navis_api.migrate import migration_files, plan, transaction_body


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 17, tzinfo=timezone.utc)

    def test_old_build_rechecked_today_is_active_recent(self):
        state = lifecycle(self.now, active=True, now=self.now)
        self.assertTrue(state['is_active'])
        self.assertEqual(state['freshness_status'], 'recent')
        self.assertFalse(state['archive_eligible'])

    def test_inactive_older_than_90_days_is_archive_eligible(self):
        state = lifecycle(self.now-timedelta(days=91), active=False, now=self.now)
        self.assertTrue(state['archive_eligible'])
        self.assertEqual(state['storage_status'], 'live')

    def test_active_or_protected_old_data_cannot_be_archived(self):
        for active, protected in [(True, False), (False, True)]:
            state = lifecycle(self.now-timedelta(days=91), active=active, protected=protected, now=self.now)
            self.assertFalse(state['archive_eligible'])

    def test_expired_trace_is_inactive_before_archival_age(self):
        state = lifecycle(self.now-timedelta(days=2), active=True, expires_at=self.now-timedelta(days=1), now=self.now)
        self.assertFalse(state['is_active'])
        self.assertEqual(state['usage_status'], 'expired')
        self.assertFalse(state['archive_eligible'])

    def test_audit_uses_calendar_year_after_archival(self):
        archived = datetime(2024, 2, 29, tzinfo=timezone.utc)
        state = lifecycle(archived, active=False, archived_at=archived, now=datetime(2025, 2, 28, tzinfo=timezone.utc))
        self.assertEqual(state['storage_status'], 'audit')
        self.assertTrue(state['purge_eligible'])
        self.assertFalse(state['archive_eligible'])


class MaintenanceTests(unittest.TestCase):
    def test_archiving_deletes_children_before_parent_and_refuses_cycles(self):
        self.assertEqual(dependency_order({'snapshot': ['interface'], 'interface': ['address']}, 'snapshot'), ['address', 'interface', 'snapshot'])
        with self.assertRaises(ProtectedData):
            dependency_order({'a': ['b'], 'b': ['a']}, 'a')

    def test_migrations_are_ordered_and_toolkit_owns_transaction(self):
        files = migration_files()
        self.assertEqual(files[-1]['version'], 21)
        for item in files:
            body = transaction_body(item['sql'])
            self.assertNotIn('\nBEGIN;', '\n'+body)
            self.assertFalse(body.rstrip().endswith('COMMIT;'))

    def test_existing_database_requires_explicit_baseline(self):
        cur = Mock()
        cur.fetchone.return_value = (None, 'navis.device')
        self.assertTrue(plan(cur, migration_files())['baseline_required'])

    def test_changed_applied_migration_fails_closed(self):
        cur = Mock()
        cur.fetchone.return_value = ('navis.schema_migration', 'navis.device')
        cur.fetchall.return_value = [(1, '001_initial.sql', 'wrong')]
        with self.assertRaisesRegex(ValueError, 'applied migration changed'):
            plan(cur, migration_files())

    def test_migration_plan_is_read_only(self):
        cur = Mock()
        cur.fetchone.return_value = (None, None)
        result = plan(cur, migration_files())
        self.assertEqual(len(result['pending']), 21)
        self.assertFalse(any('CREATE ' in c.args[0] or 'INSERT ' in c.args[0] for c in cur.execute.call_args_list))

    def test_missing_migration_files_do_not_silently_initialize_an_empty_ledger(self):
        with TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'No migration SQL'):
            migration_files(Path(directory))

    def test_global_audit_preview_does_not_delete(self):
        conn,cur=MagicMock(),MagicMock()
        conn.__enter__.return_value=conn
        conn.cursor.return_value.__enter__.return_value=cur
        cur.fetchone.return_value=(3,)
        with patch('sys.argv',['retention','--purge-only']), patch.dict('os.environ',{'NAVIS_DATABASE_URL':'unused'}), patch('psycopg.connect',return_value=conn), patch('builtins.print'):
            retention_main()
        self.assertFalse(any('DELETE' in call.args[0] for call in cur.execute.call_args_list))

    def test_explicit_global_audit_purge_never_deletes_live_tables(self):
        conn,cur=MagicMock(),MagicMock()
        conn.__enter__.return_value=conn
        conn.cursor.return_value.__enter__.return_value=cur
        cur.fetchone.return_value=(3,)
        cur.rowcount=3
        with patch('sys.argv',['retention','--purge-only','--apply']), patch.dict('os.environ',{'NAVIS_DATABASE_URL':'unused'}), patch('psycopg.connect',return_value=conn), patch('builtins.print'):
            retention_main()
        deletes=[call.args[0] for call in cur.execute.call_args_list if 'DELETE' in call.args[0]]
        self.assertEqual(deletes,['DELETE FROM navis.audit_record WHERE purge_at<=now()'])


if __name__ == '__main__':
    unittest.main()
