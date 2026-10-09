; ARGUS Security Intelligence - Inno Setup Script
; Installs the complete native ARGUS desktop application suite:
; - Native Desktop Shell (ARGUS.exe)
; - Embedded Portable Node Runtime (runtime\node.exe)
; - Express API Server & React Dashboard Assets (api-server\)
; - Standalone Python Security Engine (engine\argus-agent.exe)
; - Application Icon & Official Windows Uninstaller

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
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\app\ARGUS.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\argus.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\app\api-server\*"; DestDir: "{app}\api-server"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\app\engine\*"; DestDir: "{app}\engine"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{localappdata}\ARGUS"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\argus.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\argus.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\ARGUS\logs"
Type: files; Name: "{localappdata}\ARGUS\argus-launcher.log"
