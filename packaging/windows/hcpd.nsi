; The Windows installer.
;
; NSIS rather than WiX: this installs two files, a shortcut and an uninstaller,
; and WiX would be a build system for that. Per user rather than per machine, so
; it needs no administrator and raises no prompt; a tool that downloads a file
; into your own folder has no business writing to Program Files.
;
; Built by .github/workflows/release.yml. To build it by hand:
;   makensis -DVERSION=2.0.0 packaging/windows/hcpd.nsi

!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef ARCH
  !define ARCH "x86_64"
!endif

!define NAME "Home Connect Profile Downloader"
!define SLUG "hcpd"
!define PUBLISHER "Jonas Bruestel"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${SLUG}"

Name "${NAME}"
OutFile "..\..\dist\${SLUG}-${VERSION}-windows-${ARCH}-setup.exe"
Unicode true

; Per user. RequestExecutionLevel user is what keeps the elevation prompt away.
InstallDir "$LOCALAPPDATA\Programs\${SLUG}"
InstallDirRegKey HKCU "Software\${SLUG}" "InstallDir"
RequestExecutionLevel user

!define MUI_ICON "..\icon\rendered\hcpd.ico"
!define MUI_UNICON "..\icon\rendered\hcpd.ico"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\hcpd.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${NAME}"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

Section "Install"
  SetOutPath "$INSTDIR"

  ; Both, always. The application looks for the helper beside itself, so an
  ; install with only one of them is an install that cannot sign in.
  File "..\..\dist\stage\hcpd.exe"
  File "..\..\dist\stage\hcpd-login.exe"

  CreateShortcut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\hcpd.exe"

  WriteRegStr HKCU "Software\${SLUG}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\hcpd.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\hcpd.exe"
  Delete "$INSTDIR\hcpd-login.exe"
  Delete "$INSTDIR\uninstall.exe"

  ; Left by versions that let WebView2 choose. It puts its profile beside the
  ; executable, so a browser cache sat inside the installation directory, and
  ; the RMDir below removes only an empty one: it failed without a word and the
  ; whole tree stayed behind with nothing pointing at it. Measured, not feared.
  RMDir /r "$INSTDIR\hcpd-login.exe.WebView2"
  RMDir "$INSTDIR"

  ; The profile as it is written now. A cache, so it goes; the settings live
  ; under %APPDATA% and are deliberately kept.
  RMDir /r "$LOCALAPPDATA\hcpd\webview"
  RMDir "$LOCALAPPDATA\hcpd"

  Delete "$SMPROGRAMS\${NAME}.lnk"

  ; The settings file stays. It holds a region and a folder, it is tiny, and
  ; removing it would surprise anyone who reinstalls.
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegKey HKCU "Software\${SLUG}"
SectionEnd
