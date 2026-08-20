; Compakt Windows installer.
;
; Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
;
; Built with Inno Setup 6. Compile with:
;     iscc build\installer.iss
;
; Expects build\dist\Compakt and build\dist\pakt to exist -- run
; build\build.py first.
;
; NOT SIGNED. An unsigned installer trips Windows SmartScreen with
; "Windows protected your PC", which is a poor first impression for a
; security tool. The deliberate answer, until there is revenue to spend
; on a certificate, is to publish SHA-256 checksums and an Ed25519
; signature alongside every release: the launch audience trusts a
; published key more than a certificate anyone can buy. See the
; PRE-BUILD RISK REVIEW in compakt.txt.

#define AppName        "Compakt"
#define AppVersion     "1.0.0"
#define AppPublisher   "Kasanki Labs"
#define AppAuthor      "Rounak Miskin"
#define AppURL         "https://github.com/Kasanki-Labs/Compakt"
#define AppExe         "Compakt.exe"
#define CliExe         "pakt.exe"

[Setup]
AppId={{7F3C2A61-4E58-4B7A-9C2D-1A5E8D4F0B93}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=Copyright (c) 2026 {#AppAuthor} (Founder: {#AppPublisher})
VersionInfoDescription={#AppName} archiver
VersionInfoVersion={#AppVersion}

DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=.\installer
OutputBaseFilename=Compakt_Setup
SetupIconFile=..\app\assets\compakt.ico
UninstallDisplayIcon={app}\{#AppExe}
WizardStyle=modern

; Per-user by default so no administrator prompt appears. The file
; association and PATH entry are written under HKCU to match, which
; keeps the whole install inside one user's account rather than
; touching the machine.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; \
    GroupDescription: "Shortcuts:"
Name: "associate"; Description: "Open .pakt files with Compakt"; \
    GroupDescription: "File types:"
; Ticked by default: the manual and the landing page both tell people
; the pakt command exists, so an install that silently leaves it off
; PATH makes documented behaviour look broken. Per-user HKCU, and
; CurUninstallStepChanged removes it again on uninstall.
Name: "addtopath"; Description: \
    "Add the pakt command to PATH (for scripting)"; \
    GroupDescription: "Command line:"

[Files]
Source: "dist\Compakt\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\pakt\*"; DestDir: "{app}\cli"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSING.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\LICENSE-SPEC"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\pakt-format-spec.md"; DestDir: "{app}\docs"; \
    Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; \
    Tasks: desktopicon

[Registry]
; --- .pakt association -------------------------------------------------
; Written under HKCU to match the per-user install. A machine-wide
; association would need administrator rights for no real benefit.
Root: HKCU; Subkey: "Software\Classes\.pakt"; \
    ValueType: string; ValueName: ""; ValueData: "Compakt.Archive"; \
    Flags: uninsdeletevalue; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\.pakt"; \
    ValueType: string; ValueName: "Content Type"; \
    ValueData: "application/x-pakt"; \
    Flags: uninsdeletevalue; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\Compakt.Archive"; \
    ValueType: string; ValueName: ""; ValueData: "Compakt Archive"; \
    Flags: uninsdeletekey; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\Compakt.Archive\DefaultIcon"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"; \
    Tasks: associate
Root: HKCU; Subkey: "Software\Classes\Compakt.Archive\shell\open\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: associate

; --- Explorer context menu ---------------------------------------------
; The WinRAR replacement crowd right-clicks; it is how that job has been
; done for thirty years, and a drop zone does not replace it.
Root: HKCU; Subkey: "Software\Classes\*\shell\CompaktPack"; \
    ValueType: string; ValueName: ""; ValueData: "Pack with Compakt"; \
    Flags: uninsdeletekey; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\*\shell\CompaktPack"; \
    ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; \
    Tasks: associate
Root: HKCU; Subkey: "Software\Classes\*\shell\CompaktPack\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\Directory\shell\CompaktPack"; \
    ValueType: string; ValueName: ""; ValueData: "Pack with Compakt"; \
    Flags: uninsdeletekey; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\Directory\shell\CompaktPack\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: associate

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; \
    Flags: nowait postinstall skipifsilent

[Code]
{ Add the CLI folder to the user's PATH, without duplicating it and
  without disturbing anything already there. }
function NeedsPath(Dir: string): Boolean;
var
  Existing: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Existing) then
    Existing := '';
  Result := Pos(';' + Uppercase(Dir) + ';',
                ';' + Uppercase(Existing) + ';') = 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Existing, Dir: string;
begin
  if CurStep <> ssPostInstall then Exit;
  if not WizardIsTaskSelected('addtopath') then Exit;

  Dir := ExpandConstant('{app}\cli');
  if not NeedsPath(Dir) then Exit;

  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Existing) then
    Existing := '';
  if (Existing <> '') and (Existing[Length(Existing)] <> ';') then
    Existing := Existing + ';';
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Existing + Dir);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Existing, Dir: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then Exit;

  Dir := ExpandConstant('{app}\cli');
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Existing) then
    Exit;

  P := Pos(Uppercase(Dir), Uppercase(Existing));
  if P = 0 then Exit;

  Delete(Existing, P, Length(Dir));
  StringChangeEx(Existing, ';;', ';', True);
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Existing);
end;
