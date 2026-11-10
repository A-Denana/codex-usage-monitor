"""Network-free unit tests for the Linux quota reader."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('codex_usage', Path(__file__).resolve().parents[1] / 'codex_usage.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class ParseTests(unittest.TestCase):
    def test_codex_uses_duration_not_position(self):
        data = monitor.parse_codex({'rate_limit': {'primary_window': {
            'limit_window_seconds': 604800, 'used_percent': 80, 'reset_at': 1700000000},
            'secondary_window': {'limit_window_seconds': 18000, 'used_percent': 15, 'reset_at': 1700000001}}})
        self.assertEqual(data['session']['used'], 15)
        self.assertEqual(data['weekly']['used'], 80)

    def test_codex_falls_back_to_position(self):
        data = monitor.parse_codex({'rate_limit': {
            'primary_window': {'used_percent': 30}, 'secondary_window': None}})
        self.assertEqual(data['session']['used'], 30)
        self.assertIsNone(data['weekly'])

    def test_codex_rejects_invalid_percentage(self):
        with self.assertRaises(monitor.MonitorError):
            monitor.parse_codex({'rate_limit': {'primary_window': {'used_percent': 104}}})

    def test_zai_parses_windows_and_reset_ms(self):
        data = monitor.parse_zai({'code': 200, 'success': True, 'data': {'limits': [
            {'type': 'CREDIT_LIMIT', 'unit': 6, 'percentage': 97, 'nextResetTime': 1700000001000},
            {'type': 'CREDIT_LIMIT', 'unit': 3, 'percentage': 25, 'nextResetTime': 1700000000000}]}})
        self.assertEqual(data['session']['reset'], 1700000000)
        self.assertEqual(data['weekly']['used'], 97)

    def test_missing_window_is_not_zero(self):
        data = monitor.parse_zai({'code': 200, 'success': True, 'data': {'limits': [
            {'type': 'CREDIT_LIMIT', 'unit': 6, 'percentage': 97}]}})
        self.assertIsNone(data['session'])

    def test_decrypt_linux_zcode_envelope(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest('cryptography not installed')
        secret = 'zcode-credential-fallback:linux:/home/example:example'
        key = hashlib.sha256(secret.encode()).digest()
        iv = b'123456789012'
        cipher = AESGCM(key).encrypt(iv, b'abc.def', None)
        encode = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
        credential = 'enc:v1:' + '.'.join(map(encode, (iv, cipher[-16:], cipher[:-16])))
        self.assertEqual(monitor.decode_zai(credential, home='/home/example', username='example'), 'abc.def')
        with self.assertRaises(monitor.MonitorError):
            monitor.decode_zai(credential, home='/home/other', username='example')

    def test_zai_linux_labels_select_single_decryptable_entry(self):
        values = {'zai-current': 'enc:v1:invalid',
                  'provider-other': 'enc:v1:other',
                  'zai-api-token': 'enc:v1:valid'}
        def decrypt(value):
            if value == 'enc:v1:valid':
                return 'zai.valid'
            raise monitor.MonitorError('AUTH')
        with (
            patch.object(monitor, 'read_json', return_value=values),
            patch.object(monitor, 'decode_zai', side_effect=decrypt) as probe,
        ):
            self.assertEqual(monitor.zai_credentials(), 'zai.valid')
            self.assertEqual(probe.call_count, 2)  # Non-Z.ai entry never decrypted

    def test_zai_rejects_multiple_decryptable_entries(self):
        values = {'zai-one': 'enc:v1:one', 'zai-two': 'enc:v1:two'}
        with (
            patch.object(monitor, 'read_json', return_value=values),
            patch.object(monitor, 'decode_zai', side_effect=['one.token', 'two.token']),
        ):
            with self.assertRaisesRegex(monitor.MonitorError, '^AUTH$'):
                monitor.zai_credentials()

    def test_zai_never_uses_other_provider_token(self):
        values = {'other:api-key': 'enc:v1:other', 'zai-key': 'enc:v1:invalid'}
        with (
            patch.object(monitor, 'read_json', return_value=values),
            patch.object(monitor, 'decode_zai', side_effect=monitor.MonitorError('AUTH')) as probe,
        ):
            with self.assertRaisesRegex(monitor.MonitorError, '^AUTH$'):
                monitor.zai_credentials()
            self.assertEqual(probe.call_count, 1)

    def test_genmon_sanitizes_error_and_escapes_text(self):
        result = monitor.render_genmon({'codex': {'data': None, 'error': 'AUTH'},
                                        'zai': {'data': None, 'error': 'NET'}})
        self.assertIn('<txt>', result)
        self.assertIn('AUTH', result)
        self.assertNotIn('<script>', result)
        self.assertIn('USED', result)

    def test_cache_reuses_recent_data_and_marks_stale(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'XDG_CACHE_HOME': root}):
            calls = []
            def ok(provider):
                calls.append(provider)
                return {'session': {'used': 25, 'reset': None}, 'weekly': None}
            first = monitor.collect(now=1000, fetcher=ok)
            self.assertEqual(calls, ['codex', 'zai'])
            second = monitor.collect(now=1100, fetcher=lambda name: self.fail('should be cached'))
            self.assertEqual(second['codex']['data'], first['codex']['data'])
            def fail(name):
                raise monitor.MonitorError('NET')
            third = monitor.collect(now=1400, fetcher=fail)
            self.assertEqual(third['codex']['data'], first['codex']['data'])
            self.assertEqual(third['codex']['error'], 'NET')
            self.assertEqual(third['codex']['updated_at'], 1000)
            self.assertEqual((Path(root) / 'codex-usage-monitor' / 'quota.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
