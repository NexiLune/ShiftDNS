[Setup]
AppName=ShiftDNS
AppVersion=1.2.0
AppPublisher=ShiftDNS
DefaultDirName={autopf}\ShiftDNS
DefaultGroupName=ShiftDNS
UninstallDisplayIcon={app}\ShiftDNS.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=.
OutputBaseFilename=ShiftDNS-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes

[Files]
Source: "target\release\ShiftDNS.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\ShiftDNS"; Filename: "{app}\ShiftDNS.exe"

[Run]
Filename: "{app}\ShiftDNS.exe"; Description: "{cm:LaunchProgram,ShiftDNS}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM ShiftDNS.exe"; Flags: runhidden; RunOnceId: "KillShiftDNS"
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""ShiftDNS"" /F"; Flags: runhidden; RunOnceId: "DeleteShiftDNSTask"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\ShiftDNS"
Type: filesandordirs; Name: "{userappdata}\ShiftDNS"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM ShiftDNS.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
  Result := '';
end;
