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

    def test_zai_oauth_decrypts_non_api_key_plaintext(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        secret = 'zcode-credential-fallback:linux:/home/example:example'
        key = hashlib.sha256(secret.encode()).digest()
        iv = b'123456789012'
        cipher = AESGCM(key).encrypt(iv, b'opaque-oauth-token', None)
        encode = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
        stored = 'enc:v1:' + '.'.join(map(encode, (iv, cipher[-16:], cipher[:-16])))
        self.assertEqual(
            monitor.decode_zai(stored, home='/home/example', username='example',
                               require_api_key=False),
            'opaque-oauth-token')
        with self.assertRaises(monitor.MonitorError):
            monitor.decode_zai(stored, home='/home/example', username='example')

    def test_zai_oauth_uses_exact_zai_access_token_record(self):
        values = {'oauth:zai:access_token': 'enc:v1:oauth',
                  'oauth:bigmodel:access_token': 'enc:v1:other',
                  'oauth:zai:user_info': 'enc:v1:info'}
        with (
            patch.object(monitor, 'read_json', return_value=values),
            patch.object(monitor, 'decode_zai', return_value='opaque-oauth') as decode,
            patch.object(monitor, 'exchange_zai_oauth', return_value='business-jwt') as exchange,
        ):
            self.assertEqual(monitor.zai_credentials(), 'business-jwt')
            decode.assert_called_once_with('enc:v1:oauth', require_api_key=False)
            exchange.assert_called_once_with('opaque-oauth')

    def test_zai_manual_api_key_preferred_over_oauth(self):
        values = {'account-provider:coding-plan:account:zai-individual:api-key': 'enc:v1:manual',
                  'oauth:zai:access_token': 'enc:v1:oauth'}
        with (
            patch.object(monitor, 'read_json', return_value=values),
            patch.object(monitor, 'decode_zai', return_value='key.secret') as decode,
            patch.object(monitor, 'exchange_zai_oauth') as exchange,
        ):
            self.assertEqual(monitor.zai_credentials(), 'key.secret')
            decode.assert_called_once_with('enc:v1:manual')
            exchange.assert_not_called()

    def test_zai_rejects_ambiguous_manual_accounts(self):
        values = {'account:zai-one:api-key': 'enc:v1:one',
                  'account:zai-two:api-key': 'enc:v1:two'}
        with patch.object(monitor, 'read_json', return_value=values):
            with self.assertRaisesRegex(monitor.MonitorError, '^AUTH$'):
                monitor.zai_credentials()

    def test_zai_does_not_decrypt_other_provider(self):
        with (
            patch.object(monitor, 'read_json', return_value={
                'oauth:bigmodel:access_token': 'enc:v1:other'}),
            patch.object(monitor, 'decode_zai') as decode,
        ):
            with self.assertRaisesRegex(monitor.MonitorError, '^AUTH$'):
                monitor.zai_credentials()
            decode.assert_not_called()

    def test_zai_business_token_exchange_response(self):
        from io import BytesIO
        payload = b'{"code":0,"success":true,"data":{"access_token":"business.jwt.token"}}'
        with patch.object(monitor.request, 'urlopen', return_value=BytesIO(payload)) as urlopen:
            self.assertEqual(monitor.exchange_zai_oauth('oauth-token'), 'business.jwt.token')
            req = urlopen.call_args.args[0]
            self.assertEqual(req.full_url, 'https://api.z.ai/api/auth/z/login')
            self.assertEqual(json.loads(req.data), {'token': 'oauth-token'})
        with patch.object(monitor.request, 'urlopen',
                          return_value=BytesIO(b'{"code":500,"success":false}')):
            with self.assertRaisesRegex(monitor.MonitorError, '^AUTH$'):
                monitor.exchange_zai_oauth('oauth-token')

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
