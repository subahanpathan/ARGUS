; ARGUS Security Intelligence - Inno Setup Script
; Builds ARGUS-Setup.exe from the standalone desktop app (dist\app\ARGUS.exe).

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
SetupIconFile=..\scripts\icon\argus.ico
UninstallDisplayIcon={app}\ARGUS.exe
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
Source: "..\dist\app\ARGUS.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\scripts\icon\argus.ico"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\ARGUS"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\argus.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\argus.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\ARGUS"
