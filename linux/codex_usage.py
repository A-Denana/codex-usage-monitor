#!/usr/bin/env python3
"""Read-only Codex/Z.ai quota monitor for Linux, with an XFCE GenMon output mode.

Python 3.10+; Z.ai's AES-GCM credential requires the `cryptography` package.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import getpass
import html
import json
import math
import os
from pathlib import Path
import tempfile
import time
from urllib import error, request

CODEX_URL = 'https://chatgpt.com/backend-api/wham/usage'
ZAI_URL = 'https://api.z.ai/api/monitor/usage/quota/limit'
REFRESH_SECONDS = 300
COLORS = {'codex': '#4bd68a', 'zai': '#bd8aff'}
NAMES = {'codex': 'Codex', 'zai': 'Z.ai'}


class MonitorError(Exception):
    """A sanitized error category; never includes HTTP response bodies or tokens."""


def percent(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MonitorError('ERR')
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise MonitorError('ERR')
    return value


def parse_codex(payload):
    limits = payload.get('rate_limit')
    if not isinstance(limits, dict):
        raise MonitorError('ERR')
    windows = [limits.get('primary_window'), limits.get('secondary_window')]
    result = {'session': None, 'weekly': None}
    for index, item in enumerate(windows):
        if not isinstance(item, dict):
            continue
        duration = item.get('limit_window_seconds')
        if isinstance(duration, (int, float)) and not isinstance(duration, bool):
            kind = 'session' if duration <= 86400 else 'weekly'
        else:
            kind = 'session' if index == 0 else 'weekly'
        if result[kind] is not None:
            continue
        reset = item.get('reset_at')
        result[kind] = {'used': percent(item.get('used_percent')),
                        'reset': int(reset) if isinstance(reset, (int, float)) and not isinstance(reset, bool) else None}
    if all(value is None for value in result.values()):
        raise MonitorError('ERR')
    return result


def parse_zai(payload):
    if payload.get('success') is not True or payload.get('code') != 200:
        raise MonitorError('AUTH' if payload.get('code') == 401 else 'ERR')
    limits = (payload.get('data') or {}).get('limits')
    if not isinstance(limits, list):
        raise MonitorError('ERR')
    result = {'session': None, 'weekly': None}
    for item in limits:
        if not isinstance(item, dict) or item.get('type') not in ('CREDIT_LIMIT', 'TOKENS_LIMIT'):
            continue
        kind = {3: 'session', 6: 'weekly'}.get(item.get('unit'))
        if kind is None or result[kind] is not None:
            continue
        reset = item.get('nextResetTime')
        result[kind] = {'used': percent(item.get('percentage')),
                        'reset': int(reset / 1000) if isinstance(reset, (int, float)) and not isinstance(reset, bool) else None}
    if all(value is None for value in result.values()):
        raise MonitorError('ERR')
    return result


def read_json(path):
    try:
        if path.stat().st_size > 262144:
            raise MonitorError('ERR')
        with path.open(encoding='utf-8') as source:
            result = json.load(source)
        if not isinstance(result, dict):
            raise MonitorError('ERR')
        return result
    except (FileNotFoundError, PermissionError):
        raise MonitorError('AUTH') from None
    except (OSError, ValueError, UnicodeError):
        raise MonitorError('ERR') from None


def codex_credentials():
    home = Path(os.environ.get('CODEX_HOME') or Path.home() / '.codex')
    data = read_json(home / 'auth.json').get('tokens')
    if not isinstance(data, dict) or not isinstance(data.get('access_token'), str) or not data['access_token']:
        raise MonitorError('AUTH')
    return data['access_token'], data.get('account_id')


def decode_zai(stored, *, home=None, username=None, secret=None, require_api_key=True):
    if not isinstance(stored, str) or not stored.startswith('enc:v1:'):
        raise MonitorError('AUTH')
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise MonitorError('DEPS') from None
    import hashlib
    components = stored[len('enc:v1:'):].split('.')
    if len(components) != 3:
        raise MonitorError('AUTH')
    try:
        iv, tag, cipher = [base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)) for s in components]
        if len(iv) != 12 or len(tag) != 16:
            raise ValueError('invalid envelope')
        home = str(Path.home()) if home is None else home
        username = getpass.getuser() if username is None else username
        secret = (os.environ.get('ZCODE_CREDENTIAL_SECRET') or f'zcode-credential-fallback:linux:{home}:{username}') if secret is None else secret
        key = hashlib.sha256(secret.encode()).digest()
        plaintext = AESGCM(key).decrypt(iv, cipher + tag, None).decode('utf-8')
        if not plaintext or len(plaintext) > 16384:
            raise ValueError('invalid credential')
        if require_api_key and len(plaintext.split('.')) != 2:
            raise ValueError('invalid API-key format')
        return plaintext
    except (ValueError, UnicodeError, TypeError):
        raise MonitorError('AUTH') from None
    except Exception as exc:
        # Includes cryptography.exceptions.InvalidTag. Never reveal the input or exception.
        raise MonitorError('AUTH') from None


def exchange_zai_oauth(oauth_token):
    """Read-only exchange of ZCode's Z.ai OAuth token for a Z.ai business JWT.

    Never send OAuth material to the quota endpoint as if it were an API key.
    No token or response body is logged, persisted or returned to CLI output.
    """
    if not isinstance(oauth_token, str) or not oauth_token or len(oauth_token) > 16384:
        raise MonitorError('AUTH')
    endpoint = 'https://api.z.ai/api/auth/z/login'
    payload = json.dumps({'token': oauth_token}).encode('utf-8')
    req = request.Request(endpoint, data=payload, method='POST', headers={
        'Content-Type': 'application/json',
        'User-Agent': 'ZCode/unknown',
        'HTTP-Referer': 'https://zcode.z.ai',
    })
    try:
        with request.urlopen(req, timeout=12) as response:
            body = response.read(262145)
            if len(body) > 262144:
                raise MonitorError('ERR')
            answer = json.loads(body)
    except error.HTTPError as exc:
        raise MonitorError('AUTH' if exc.code in (401, 403) else '429' if exc.code == 429 else '5XX' if exc.code >= 500 else 'ERR') from None
    except (error.URLError, TimeoutError, OSError):
        raise MonitorError('NET') from None
    except (ValueError, UnicodeError):
        raise MonitorError('ERR') from None
    if (not isinstance(answer, dict) or answer.get('success') is not True
            or answer.get('code') not in (0, 200)):
        raise MonitorError('AUTH')
    info = answer.get('data')
    token = info.get('access_token') if isinstance(info, dict) else None
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise MonitorError('AUTH')
    return token


def zai_credentials():
    """Select an explicit Z.ai key, or use the documented ZCode OAuth flow.

    Never infer a token's provider from its decrypted shape.
    """
    credentials = read_json(Path.home() / '.zcode' / 'v2' / 'credentials.json')
    manual = [value for name, value in credentials.items()
              if isinstance(name, str) and 'zai' in name.casefold()
              and name.endswith(':api-key') and isinstance(value, str)
              and value.startswith('enc:v1:')]
    if len(manual) > 1:
        raise MonitorError('AUTH')
    if len(manual) == 1:
        return decode_zai(manual[0])
    stored = credentials.get('oauth:zai:access_token')
    if not isinstance(stored, str) or not stored.startswith('enc:v1:'):
        raise MonitorError('AUTH')
    return exchange_zai_oauth(decode_zai(stored, require_api_key=False))


def http_json(url, token, extra_headers=None):
    headers = {'Authorization': f'Bearer {token}', 'User-Agent': 'codex-cli', 'Accept': 'application/json'}
    headers.update(extra_headers or {})
    req = request.Request(url, headers=headers)
    try:
        with request.urlopen(req, timeout=12) as response:
            if int(response.headers.get('Content-Length', 0)) > 262144:
                raise MonitorError('ERR')
            body = response.read(262145)
            if len(body) > 262144:
                raise MonitorError('ERR')
            return json.loads(body)
    except error.HTTPError as exc:
        raise MonitorError('AUTH' if exc.code in (401, 403) else '429' if exc.code == 429 else '5XX' if exc.code >= 500 else 'ERR') from None
    except (error.URLError, TimeoutError, OSError):
        raise MonitorError('NET') from None
    except (ValueError, UnicodeError):
        raise MonitorError('ERR') from None


def fetch(provider):
    if provider == 'codex':
        token, account = codex_credentials()
        headers = {'ChatGPT-Account-Id': account} if isinstance(account, str) and account else None
        return parse_codex(http_json(CODEX_URL, token, headers))
    if provider == 'zai':
        return parse_zai(http_json(ZAI_URL, zai_credentials()))
    raise ValueError('Unknown provider')


def cache_directory():
    directory = Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'codex-usage-monitor'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    return directory


def store_cache(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.quota-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, separators=(',', ':'))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def collect(*, force=False, now=None, fetcher=fetch):
    now = time.time() if now is None else now
    directory = cache_directory()
    lock_fd = os.open(directory / 'quota.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        cache_path = directory / 'quota.json'
        try:
            snapshot = read_json(cache_path)
        except MonitorError:
            snapshot = {}
        for provider in ('codex', 'zai'):
            state = snapshot.get(provider, {})
            if not isinstance(state, dict):
                state = {}
            if not force and now - float(state.get('checked_at', 0)) < REFRESH_SECONDS:
                continue
            try:
                new_data = fetcher(provider)
                snapshot[provider] = {'data': new_data, 'checked_at': now, 'updated_at': now, 'error': None}
            except MonitorError as exc:
                snapshot[provider] = {'data': state.get('data'), 'checked_at': now,
                                      'updated_at': state.get('updated_at'), 'error': str(exc)}
            except Exception:
                snapshot[provider] = {'data': state.get('data'), 'checked_at': now,
                                      'updated_at': state.get('updated_at'), 'error': 'ERR'}
        store_cache(cache_path, snapshot)
        return snapshot
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def clock_time(timestamp):
    return time.strftime('%m-%d %H:%M', time.localtime(timestamp)) if timestamp else '--'


def render_window(item):
    if not isinstance(item, dict):
        return '--'
    value = item.get('used')
    if not isinstance(value, (int, float)):
        return '--'
    filled = max(0, min(5, round(value / 20)))
    return f'{value:.0f}% ' + '━' * filled + '┄' * (5 - filled)


def render_genmon(snapshot):
    rows, tips = [], ['Quota percentages represent USED, not remaining.']
    for provider, initial in (('codex', 'C'), ('zai', 'Z')):
        state = snapshot.get(provider, {})
        data = state.get('data') if isinstance(state, dict) else None
        error_code = state.get('error') if isinstance(state, dict) else 'ERR'
        error_suffix = ' *' if error_code and data else f' {error_code}' if error_code else ''
        session = render_window(data.get('session') if isinstance(data, dict) else None)
        weekly = render_window(data.get('weekly') if isinstance(data, dict) else None)
        row = (f'<span foreground="{COLORS[provider]}" weight="bold">{initial}</span> '
               f'5h {html.escape(session)}  7d {html.escape(weekly)}{html.escape(error_suffix)}')
        rows.append(row)
        tips.append(f'{NAMES[provider]}: ' + ('stale — ' if error_code and data else '') + (error_code or 'OK'))
        if isinstance(data, dict):
            for label, kind in [('5h', 'session'), ('7d', 'weekly')]:
                item = data.get(kind)
                tips.append(f'  {label}: {render_window(item)} | reset: {clock_time(item.get("reset")) if isinstance(item, dict) else "--"}')
        tips.append(f'  Last successful update: {clock_time(state.get("updated_at")) if isinstance(state, dict) else "--"}')
    return '<txt>' + '\n'.join(rows) + '</txt>\n<tool>' + html.escape('\n'.join(tips)) + '</tool>'


def check_credentials():
    path = Path(os.environ.get('CODEX_HOME') or Path.home() / '.codex') / 'auth.json'
    zpath = Path.home() / '.zcode' / 'v2' / 'credentials.json'
    try:
        import cryptography  # noqa: F401
        installed = True
    except ImportError:
        installed = False
    return {'codex_auth_file': path.is_file(), 'zcode_credentials_file': zpath.is_file(),
            'cryptography_installed': installed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--genmon', action='store_true', help='XFCE GenMon output')
    group.add_argument('--json', action='store_true', help='Provider usage (no credentials)')
    group.add_argument('--check', action='store_true', help='Offline dependency and file checks')
    parser.add_argument('--refresh', action='store_true', help='Bypass 5-minute cache (quota query)')
    args = parser.parse_args()
    if args.check:
        print(json.dumps(check_credentials(), indent=2))
        return
    try:
        snapshot = collect(force=args.refresh)
        print(render_genmon(snapshot) if args.genmon else json.dumps(snapshot, indent=2))
    except (OSError, ValueError) as exc:
        if args.genmon:
            print('<txt>Quota unavailable</txt><tool>Local cache error</tool>')
        else:
            print(json.dumps({'error': 'LOCAL'}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
