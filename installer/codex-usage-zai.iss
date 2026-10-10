#ifndef MyAppVersion
  #define MyAppVersion "1.10.0-zai.2"
#endif
#define MyAppName "Codex Usage + Z.ai"
#define MyAppExe "codex-usage.exe"
#define StartupValue "CodexUsageZaiPreview"
#define StartupRegKey "Software\Microsoft\Windows\CurrentVersion\Run"

[Setup]
; Independent app identity, never overrides upstream installed-app entry.
AppId={{B8E9B83E-AFD9-46BE-8B61-3BF8BC83B7E0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=A-Denana
AppPublisherURL=https://github.com/A-Denana/codex-usage-monitor
AppSupportURL=https://github.com/A-Denana/codex-usage-monitor/issues
AppUpdatesURL=https://github.com/A-Denana/codex-usage-monitor/releases
DefaultDirName={localappdata}\Programs\CodexUsageZai
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=10.0
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir=..\dist
OutputBaseFilename=CodexUsageZai-Setup-{#MyAppVersion}
SetupIconFile=..\src\icons\icon.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
LicenseFile=..\LICENSE
AppMutex=Global\CodexUsage
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Optional tasks:"; Flags: unchecked
Name: "autostart"; Description: "Start automatically with Windows"; GroupDescription: "Optional tasks:"; Flags: unchecked

[Files]
Source: "..\target\release\{#MyAppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; Same key as Z.ai portable builds, controlled by the app's Settings menu.
Root: HKCU; Subkey: "{#StartupRegKey}"; ValueType: string; ValueName: "{#StartupValue}"; ValueData: """{app}\{#MyAppExe}"""; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
// Uninstall keeps settings and removes startup only if it targets installed exe.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  StartupCommand: string;
  InstalledExe: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    if RegQueryStringValue(HKCU, '{#StartupRegKey}', '{#StartupValue}', StartupCommand) then
    begin
      StringChangeEx(StartupCommand, '"', '', True);
      InstalledExe := ExpandConstant('{app}\{#MyAppExe}');
      if CompareText(Trim(StartupCommand), InstalledExe) = 0 then
        RegDeleteValue(HKCU, '{#StartupRegKey}', '{#StartupValue}');
    end;
  end;
end;
