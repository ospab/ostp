; Registers the Scheduled Task that lets the GUI start the TUN helper elevated
; without a consent prompt.
;
; This belongs in the installer, not in the app. Registering a task that runs
; with elevated rights is itself a privileged operation, so an unprivileged GUI
; can only get one by raising a UAC prompt — which is the very thing we are
; trying to remove. The installer already runs elevated, so here it costs
; nothing: the user consents once, to the install, and never again per connect.
;
; The task carries no usable trigger (a one-shot dated in the past), because it
; exists solely to be started on demand by the app.

!macro OSTP_WRITE_TASK_XML OUTFILE
  ; NSIS is built in Unicode mode here, so FileWrite emits UTF-16LE — which is
  ; what `schtasks /XML` requires. It still needs the byte-order mark itself.
  FileOpen $R1 "${OUTFILE}" w
  FileWriteWord $R1 65279
  FileWrite $R1 '<?xml version="1.0" encoding="UTF-16"?>$\r$\n'
  FileWrite $R1 '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">$\r$\n'
  FileWrite $R1 '  <RegistrationInfo>$\r$\n'
  FileWrite $R1 '    <Description>Starts the OSTP TUN helper elevated so connecting does not prompt for consent every time.</Description>$\r$\n'
  FileWrite $R1 '  </RegistrationInfo>$\r$\n'
  FileWrite $R1 '  <Principals>$\r$\n'
  FileWrite $R1 '    <Principal id="Author">$\r$\n'
  ; S-1-5-32-545 is BUILTIN\Users by SID rather than by name: the name is
  ; localized ("Пользователи" on a Russian Windows) and would not resolve.
  ; Combined with InteractiveToken this makes the task run as whichever user
  ; actually launches it, so a machine-wide install still works for every
  ; account instead of only the one that happened to run the installer.
  FileWrite $R1 '      <GroupId>S-1-5-32-545</GroupId>$\r$\n'
  FileWrite $R1 '      <LogonType>InteractiveToken</LogonType>$\r$\n'
  FileWrite $R1 '      <RunLevel>HighestAvailable</RunLevel>$\r$\n'
  FileWrite $R1 '    </Principal>$\r$\n'
  FileWrite $R1 '  </Principals>$\r$\n'
  FileWrite $R1 '  <Settings>$\r$\n'
  ; Parallel: reconnecting before a previous helper has fully exited must not
  ; be silently dropped as a duplicate instance.
  FileWrite $R1 '    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>$\r$\n'
  ; A VPN is most needed on battery, and a tunnel must not be killed on unplug.
  FileWrite $R1 '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>$\r$\n'
  FileWrite $R1 '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>$\r$\n'
  FileWrite $R1 '    <StartWhenAvailable>false</StartWhenAvailable>$\r$\n'
  FileWrite $R1 '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>$\r$\n'
  ; PT0S disables the execution time limit; the default would tear the tunnel
  ; down after three days.
  FileWrite $R1 '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>$\r$\n'
  FileWrite $R1 '    <Enabled>true</Enabled>$\r$\n'
  FileWrite $R1 '    <Hidden>false</Hidden>$\r$\n'
  FileWrite $R1 '    <AllowHardTerminate>true</AllowHardTerminate>$\r$\n'
  FileWrite $R1 '  </Settings>$\r$\n'
  FileWrite $R1 '  <Actions Context="Author">$\r$\n'
  FileWrite $R1 '    <Exec>$\r$\n'
  FileWrite $R1 '      <Command>$INSTDIR\ostp-tun-helper.exe</Command>$\r$\n'
  ; The port and auth token change per launch and a task stores a fixed command
  ; line, so they travel in this file instead. %LOCALAPPDATA% is deliberately
  ; left unexpanded: Task Scheduler expands it when the task runs, which lands
  ; on the profile of whoever launched it rather than the installing user's.
  FileWrite $R1 '      <Arguments>--args-file "%LOCALAPPDATA%\OSTP\helper-args.json"</Arguments>$\r$\n'
  FileWrite $R1 '    </Exec>$\r$\n'
  FileWrite $R1 '  </Actions>$\r$\n'
  FileWrite $R1 '</Task>$\r$\n'
  FileClose $R1
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Bundled resources land in $INSTDIR\resources, but the helper loads wintun
  ; with a plain LoadLibrary, which searches its own directory — so put a copy
  ; beside the executables.
  DetailPrint "Placing wintun.dll next to the helper..."
  CopyFiles /SILENT "$INSTDIR\resources\wintun.dll" "$INSTDIR\wintun.dll"

  DetailPrint "Registering the OSTP TUN helper task..."
  !insertmacro OSTP_WRITE_TASK_XML "$PLUGINSDIR\ostp-helper-task.xml"

  ; /F overwrites an existing registration, so reinstalling or upgrading to a
  ; different directory repoints the task instead of leaving a stale path — the
  ; app verifies the registered path at runtime and would otherwise have to
  ; re-register it with a prompt.
  nsExec::ExecToLog 'schtasks.exe /Create /TN "OSTP TUN Helper" /XML "$PLUGINSDIR\ostp-helper-task.xml" /F'
  Pop $R0
  Delete "$PLUGINSDIR\ostp-helper-task.xml"

  ${If} $R0 == 0
    DetailPrint "Helper task registered; connecting will not prompt for consent."
  ${Else}
    ; Not fatal. The app keeps a fallback that registers the task itself on
    ; first connect, at the cost of the one prompt this was meant to avoid.
    DetailPrint "Could not register the helper task (schtasks returned $R0)."
    DetailPrint "OSTP will still work, but the first connect will ask for consent."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Leaving the task behind would point at a deleted executable, and the app
  ; treats a mismatched path as grounds to re-register.
  DetailPrint "Removing the OSTP TUN helper task..."
  nsExec::ExecToLog 'schtasks.exe /Delete /TN "OSTP TUN Helper" /F'
  Pop $R0

  ; This copy was made by the install hook, so the uninstaller does not know
  ; about it and would otherwise leave it behind.
  Delete "$INSTDIR\wintun.dll"
!macroend
