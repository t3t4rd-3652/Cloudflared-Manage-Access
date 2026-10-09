; Installeur Inno Setup de Cloudflared Manage Access.
; Construit par packaging/build.py, qui fournit AppVersion, SourceDir et OutputDir.
; Installation par utilisateur (aucun droit administrateur), désinstallation propre.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\CloudflaredManageAccess"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{D59636E8-D9FE-495F-92B0-B83E09A8BA54}
AppName=Cloudflared Manage Access
AppVersion={#AppVersion}
AppPublisher=t3t4rd-3652
AppPublisherURL=https://github.com/t3t4rd-3652/Cloudflared-Manage-Access
DefaultDirName={localappdata}\Programs\CloudflaredManageAccess
DefaultGroupName=Cloudflared Manage Access
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=CloudflaredManageAccess-{#AppVersion}-setup
SetupIconFile=cma.ico
UninstallDisplayIcon={app}\CloudflaredManageAccess.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Démarrer avec Windows (réduit dans la zone de notification)"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Cloudflared Manage Access"; Filename: "{app}\CloudflaredManageAccess.exe"
Name: "{userdesktop}\Cloudflared Manage Access"; Filename: "{app}\CloudflaredManageAccess.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CloudflaredManageAccess"; ValueData: """{app}\CloudflaredManageAccess.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart
; Liens cma:// et profils partagés .cma (cma.platform.links fait de même pour les versions portable et Scoop).
Root: HKCU; Subkey: "Software\Classes\cma"; ValueType: string; ValueName: ""; ValueData: "URL:Cloudflared Manage Access"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\cma"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\cma\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: """{app}\CloudflaredManageAccess.exe"",0"
Root: HKCU; Subkey: "Software\Classes\cma\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CloudflaredManageAccess.exe"" ""%1"""
Root: HKCU; Subkey: "Software\Classes\.cma"; ValueType: string; ValueName: ""; ValueData: "CloudflaredManageAccess.Profile"; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\CloudflaredManageAccess.Profile"; ValueType: string; ValueName: ""; ValueData: "Cloudflared Manage Access — profil partagé"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\CloudflaredManageAccess.Profile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: """{app}\CloudflaredManageAccess.exe"",0"
Root: HKCU; Subkey: "Software\Classes\CloudflaredManageAccess.Profile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CloudflaredManageAccess.exe"" ""%1"""

[Run]
Filename: "{app}\CloudflaredManageAccess.exe"; Description: "{cm:LaunchProgram,Cloudflared Manage Access}"; Flags: nowait postinstall skipifsilent
; Mise à jour automatique lancée par CMA (/SILENT /RELAUNCH=1) : relance de l'application.
Filename: "{app}\CloudflaredManageAccess.exe"; Flags: nowait; Check: ShouldRelaunch

[UninstallRun]
Filename: "{app}\cma.exe"; Parameters: "quit"; Flags: runhidden; RunOnceId: "QuitCMA"
; Tâche planifiée « surveillance des tunnels » (Paramètres) : sans effet si elle n'existe pas.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Cloudflared Manage Access\Surveillance des tunnels"" /F"; Flags: runhidden; RunOnceId: "DeleteWatchTask"

[Code]
function ShouldRelaunch: Boolean;
begin
  Result := ExpandConstant('{param:relaunch|0}') = '1';
end;
