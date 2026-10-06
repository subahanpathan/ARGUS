; ARGUS Security Intelligence — Inno Setup Script
; Generates standard Windows installer: ARGUS-Setup.exe

#define MyAppName "ARGUS Security Intelligence"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ARGUS Security Team"
#define MyAppURL "http://localhost:5000"

[Setup]
AppId={{D9A3B51E-7C2F-4A9B-8E1D-3F5A9C0E2B4D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\ARGUS
DefaultGroupName=ARGUS Security
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=ARGUS-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\production\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\scripts\argus-service.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\ARGUS"
Name: "{commonappdata}\ARGUS\logs"
Name: "{commonappdata}\ARGUS\db"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "http://localhost:5000"
Name: "{autodesktop}\{#MyAppName}"; Filename: "http://localhost:5000"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\argus-service.ps1"" install -InstallDir ""{app}"" -DataDir ""{commonappdata}\ARGUS"""; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\argus-service.ps1"" start -InstallDir ""{app}"" -DataDir ""{commonappdata}\ARGUS"""; Flags: runhidden
Filename: "http://localhost:5000"; Description: "Open ARGUS Security Dashboard"; Flags: postinstall shellexec unchecked

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\argus-service.ps1"" uninstall -InstallDir ""{app}"" -DataDir ""{commonappdata}\ARGUS"""; Flags: runhidden
