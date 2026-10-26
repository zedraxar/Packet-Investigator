#define AppName "Packet Investigator Desktop Preview"
#ifndef AppVersion
  #error AppVersion must be supplied by build.py
#endif
#ifndef BundleDir
  #error BundleDir must be supplied by build.py
#endif
#ifndef InstallerDir
  #error InstallerDir must be supplied by build.py
#endif

[Setup]
AppId={{75800B97-33C7-416D-87D8-BD2BDE0CE64D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Packet Investigator contributors
DefaultDirName={localappdata}\Programs\PacketInvestigatorPreview
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
OutputDir={#InstallerDir}
OutputBaseFilename=PacketInvestigator-{#AppVersion}-desktop-preview-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
AppMutex=Local\PacketInvestigatorDesktopPreview
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\PacketInvestigator.exe
LicenseFile=..\..\LICENSE
InfoBeforeFile=PREVIEW.txt

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Packet Investigator"; Filename: "{app}\PacketInvestigator.exe"
Name: "{autodesktop}\Packet Investigator"; Filename: "{app}\PacketInvestigator.exe"; Tasks: desktopicon
