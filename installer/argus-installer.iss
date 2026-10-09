; ARGUS Security Intelligence - Universal Inno Setup Script
; Compatible with all Windows laptops (Windows 10/11, x64, ARM64, admin & standard users)

#define MyAppName "ARGUS Security Intelligence"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ARGUS Security Team"
#define MyAppExe "ARGUS.exe"

[Setup]
AppId={{D9A3B51E-7C2F-4A9B-8E1D-3F5A9C0E2B4D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ARGUS
DefaultGroupName=ARGUS Security
DisableProgramGroupPage=yes
SetupIconFile=..\dist\app\argus.ico
UninstallDisplayIcon={app}\{#MyAppExe}
OutputDir=..\dist\installer
OutputBaseFilename=ARGUS-Setup
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern

; Universal Privileges: Allows installation on ANY laptop (standard user or administrator)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline

; Universal Architecture: 64-bit AMD/Intel and ARM64 Windows laptops
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

; CRITICAL: Prevent "Setup was unable to automatically close all applications" error
; Background processes like node.exe and argus-agent.exe do not handle WM_CLOSE message loops.
; We disable Restart Manager prompting and kill running instances cleanly in [Code].
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\app\ARGUS.exe"; DestDir: "{app}"; Flags: ignoreversion restartreplace
Source: "..\dist\app\argus.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion restartreplace recursesubdirs createallsubdirs
Source: "..\dist\app\api-server\*"; DestDir: "{app}\api-server"; Flags: ignoreversion restartreplace recursesubdirs createallsubdirs; Excludes: "*.exe"
Source: "..\dist\app\engine\*"; DestDir: "{app}\engine"; Flags: ignoreversion restartreplace recursesubdirs createallsubdirs

[Dirs]
Name: "{localappdata}\ARGUS"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\argus.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\argus.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /T /IM {#MyAppExe}"; Flags: runhidden; RunOnceId: "KillArgus"
Filename: "taskkill.exe"; Parameters: "/F /T /IM argus-agent.exe"; Flags: runhidden; RunOnceId: "KillAgent"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\ARGUS\logs"
Type: files; Name: "{localappdata}\ARGUS\argus-launcher.log"

[Code]
// Terminate previous running ARGUS instances to release all file locks on any laptop
procedure KillArgusProcesses;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /T /IM ARGUS.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /T /IM argus-agent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function InitializeSetup(): Boolean;
begin
  KillArgusProcesses;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KillArgusProcesses;
  Result := '';
end;
