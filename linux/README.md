# Codex Usage Monitor for Linux (experimental)

This is a **read-only Linux implementation** for **Codex + Z.ai**. It does not replace or modify the Windows Rust application in `src/`. A Python quota reader is desktop-independent; the included XML presentation currently targets **XFCE GenMon**. GNOME Shell and KDE Plasma panel integrations are **not included** yet.

## Requirements

- Linux, Python 3.10+, signed-in Codex CLI and ZCode (on **this Linux user account**)
- `cryptography` Python package for reading ZCode's AES-256-GCM credentials
- XFCE and `xfce4-genmon-plugin` only if using the panel display
- HTTPS access to the quota endpoints; no extra provider subscription or API purchase

## Install (no `sudo` Python packages; no changes to Windows)

Run from repository root **in a Linux terminal**:

```bash
uv venv ~/.local/share/codex-usage-monitor/venv
uv pip install --python ~/.local/share/codex-usage-monitor/venv/bin/python 'cryptography>=43,<47'
~/.local/share/codex-usage-monitor/venv/bin/python linux/codex_usage.py --check
~/.local/share/codex-usage-monitor/venv/bin/python linux/codex_usage.py --json
```

Use your actual checkout path in GenMon's **Command** setting, with quotes around it:

```bash
/home/denana/.local/share/codex-usage-monitor/venv/bin/python '/mnt/d/Denana/Distinct/Python/Data_analysis_Projects/codex-usage-monitor-linux/linux/codex_usage.py' --genmon
```

The example path above uses the separate `codex-usage-monitor-linux` worktree created during setup. Adjust it if you chose a different worktree directory.

Set **Period** to `30` seconds. The program caches quota responses for at least **five minutes** per provider to avoid excess requests. The panel refreshes locally from that cache. Choose GenMon's text display mode; the output uses two colored text rows and five-segment bars. On panels that are too short for two rows, adjust panel height or select a different placement.

The generic CLI also works outside XFCE:

```bash
python3 linux/codex_usage.py --check                # local-only; no network
python3 linux/codex_usage.py --json                 # portable results, no credentials
python3 linux/codex_usage.py --json --refresh       # explicitly bypass cache
python3 -m unittest discover -s linux/tests -v     # offline tests
```

Run `--json` with the venv Python if `cryptography` is not installed system-wide.

## Quota display

- `5h` is the short session window; `7d` is the weekly window. Percentages are **USED**, not remaining.
- `--` means the service didn't return that window; it does **not** mean 0% used.
- `*` means the last request failed and the displayed values are **stale**.
- `AUTH`: missing/expired/undecryptable credentials; `DEPS`: missing `cryptography`; `NET`: network; `429`: rate limited; `5XX`: server error; `ERR`: other failure.
- Hover over the panel to see reset times, update time and error status. To refresh explicitly, run `--json --refresh`; do not put `--refresh` in GenMon's recurring command.

## Credentials and privacy

The monitor reads `$CODEX_HOME/auth.json` (or `~/.codex/auth.json`) and `~/.zcode/v2/credentials.json`, and sends bearer tokens **only to the respective service usage endpoints** over HTTPS. The encrypted ZCode key is derived using Linux's credential fallback (`zcode-credential-fallback:linux:<home>:<username>`) unless the existing `ZCODE_CREDENTIAL_SECRET` environment variable is set. **Do not copy encrypted ZCode credentials from Windows:** sign in directly on Linux. If ZCode used a custom secret during login, that same secret must be available in the GenMon process environment; never paste it into the GenMon command or commit it.

Only quota percentages, reset timestamps, sanitized error categories, and last-update timestamps are cached under `~/.cache/codex-usage-monitor/` (or `$XDG_CACHE_HOME`), with user-only permissions. Tokens are never saved by this monitor. It never refreshes, rewrites, or uploads credential files and does not send telemetry. Python cannot guarantee zeroization of its in-memory strings; do not use this on untrusted shared hosts. HTTP proxies inherited from your Linux environment should also be trusted.

## Linux ZCode credential selection

Some Linux ZCode installations use credential labels different from the Windows `zai-individual-coding-plan:api-key` name. The adapter considers **only** encrypted entries whose label contains `zai` (case-insensitive), accepts exactly one entry decryptable using the current Linux account, and returns `AUTH` if none or multiple can be used. It never searches or sends non-Z.ai provider credentials. If you see `AUTH` after updating, do not paste `credentials.json` or decrypted tokens into issues, chats, or terminal output. Check that ZCode is logged in to Z.ai under the current Linux user.

## Status and limits

**Experimental / not verified against live Z.ai accounts.** Codex was verified against a real Linux login; Z.ai still requires an on-device request after credential selection. Unit tests use offline fixtures, not user credentials. Codex and Z.ai endpoints may change; a failed request is reported without invented values. This is not currently a packaged Linux binary, a GNOME Shell extension, or a Plasma widget.
