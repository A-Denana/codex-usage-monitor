# Windows installer for the Z.ai fork

Choose the per-user Inno Setup installer for a Start Menu shortcut and an entry
in Windows Settings > Installed Apps. The portable EXE remains available.

## Install

1. Download the installer and its SHA256 file from the fork's GitHub Releases.
2. Verify the EXE checksum with PowerShell Get-FileHash and the matching SHA256 file.
3. Quit any running Codex Usage monitor before installation. Setup checks the
   Global\CodexUsage mutex and requests a clean exit.
4. Run the installer as your Windows user, without administrator elevation.
5. Choose optional desktop shortcut and Start with Windows settings.

Default path: %LOCALAPPDATA%\Programs\CodexUsageZai
Startup registry value: CodexUsageZaiPreview in HKCU\Software\Microsoft\Windows\CurrentVersion\Run.

An existing portable copy in the same install directory is adopted on install.
Setup does not affect the upstream Codex Usage folder or its uninstall registration.
Do not point it manually at the upstream install path.

## Uninstall

Remove Codex Usage + Z.ai from Windows Settings > Installed Apps.
The app's settings in %APPDATA%\CodexUsageZaiPreview stay untouched.
The uninstaller removes its startup value only when it points to the installed EXE.
The original Codex Usage settings and ZCode credential store remain untouched.

An EXE kept within the install folder is managed by Setup and removed on uninstall.
Portable users outside the folder are unaffected.

## Security and limitations

Setup is currently unsigned. Windows SmartScreen may show an unknown-publisher warning.
Only use files from the public fork release, and verify their SHA256 checksum.
Credentials are read by the running monitor, not by the installer.
This beta has been tested with one signed-in ZCode account; other ZCode setups
are not yet guaranteed to work.

## Build for maintainers

Inno Setup 6 compiler example:

    ISCC.exe /DMyAppVersion=1.10.0-zai.2 installer\codex-usage-zai.iss

The release CI verifies the Git tag against Cargo.toml and builds Rust with
the committed Cargo.lock. It publishes the installer, portable binary and their
individual SHA256 files. Keep the installer AppId fixed for upgrades.

Validation happens on the installer feature branch before release tagging.
