; Registers the Scheduled Task that lets the GUI start the TUN helper elevated
; without a consent prompt.
;
; This belongs in the installer, not in the app. Registering a task that runs
; elevated is itself a privileged operation, so an unprivileged GUI could only
; obtain one by raising the very prompt we are trying to remove. The installer
; already runs elevated (installMode is perMachine), so here it costs nothing:
; the user consents once, to the install, and never again per connect.
;
; The task carries no trigger at all — it exists solely to be started on demand.

!macro NSIS_HOOK_POSTINSTALL
  ; Bundled resources land in $INSTDIR\resources, but the helper loads wintun
  ; with a plain LoadLibrary, which searches its own directory — so put a copy
  ; beside the executables. The destination is the directory, not a file path:
  ; CopyFiles takes a target directory, and naming the file made it fail.
  ${If} ${FileExists} "$INSTDIR\resources\wintun.dll"
    DetailPrint "Placing wintun.dll next to the helper..."
    CopyFiles /SILENT "$INSTDIR\resources\wintun.dll" "$INSTDIR"
  ${Else}
    DetailPrint "WARNING: resources\wintun.dll is missing; TUN mode will not start."
  ${EndIf}

  ; Registered through PowerShell's ScheduledTasks module rather than
  ; `schtasks /XML`. Generating the XML from NSIS wrote a UTF-16 byte-order mark
  ; ahead of content whose encoding depended on whether makensis was built in
  ; Unicode mode, and schtasks rejected the result outright:
  ;   "The task XML is malformed. (1,2)::ERROR: incorrect document syntax"
  ; The cmdlets take the same settings as arguments, so no file is written and
  ; there is no encoding to get wrong.
  ;
  ; The command is delimited with backticks, NSIS's third quote character, so
  ; that PowerShell's own single quotes and the shell's double quotes can both
  ; appear literally — inside a single-quoted NSIS string the first PowerShell
  ; quote would have terminated the argument early.
  ;
  ; $$ is an escaped literal dollar for PowerShell's variables; a bare $ would
  ; be read by NSIS as one of its own. The helper argument is assembled with
  ; [char]34 instead of nested quotes so that a username containing a space
  ; still yields a correctly quoted path, without three levels of escaping.
  ;
  ; The principal is the SID S-1-5-32-545 (BUILTIN\Users) rather than the
  ; installing user, so a per-machine install serves every account instead of
  ; only whoever ran the installer. The SID is used because the name is
  ; localized and would not resolve. %LOCALAPPDATA% is likewise left unexpanded
  ; for Task Scheduler to resolve per running user.
  DetailPrint "Registering the OSTP TUN helper task..."
  nsExec::ExecToLog `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$act = New-ScheduledTaskAction -Execute '$INSTDIR\ostp-tun-helper.exe' -Argument ('--args-file ' + [char]34 + '%LOCALAPPDATA%\OSTP\helper-args.json' + [char]34); $$prn = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Highest; $$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel; Register-ScheduledTask -TaskName 'OSTP TUN Helper' -Action $$act -Principal $$prn -Settings $$set -Force | Out-Null"`
  Pop $R0

  ${If} $R0 == 0
    ; Registering the task is not enough to make it usable. The principal above
    ; decides WHO THE TASK RUNS AS; the task's security descriptor decides who
    ; is allowed to START it, and they are not the same thing. A task created by
    ; an elevated installer defaults to a DACL granting execution to
    ; Administrators only, so the unprivileged GUI got
    ;   schtasks /Run -> ERROR: Access is denied
    ; and fell back to prompting on every single connect. Running it by hand
    ; from an elevated console worked, which is what made this look for a while
    ; like the app was at fault.
    ;
    ; Register-ScheduledTask cannot set a descriptor, so this goes through the
    ; Task Scheduler COM object. GA for Administrators and SYSTEM, GR+GX —
    ; read and execute — for BUILTIN\Users (BU), which is what lets a normal
    ; user start it without being elevated.
    DetailPrint "Granting users permission to start the task..."
    nsExec::ExecToLog `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$svc = New-Object -ComObject Schedule.Service; $$svc.Connect(); $$t = $$svc.GetFolder('\').GetTask('OSTP TUN Helper'); $$t.SetSecurityDescriptor('D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;BU)', 0)"`
    Pop $R1
    ${If} $R1 == 0
      DetailPrint "Helper task registered; connecting will not ask for consent."
    ${Else}
      DetailPrint "Task registered but its permissions could not be set (exit $R1)."
      DetailPrint "Every connect will ask for consent."
    ${EndIf}
  ${Else}
    ; Not fatal: the app still works, it just falls back to an elevated launch
    ; that asks for consent on each connect.
    DetailPrint "Could not register the helper task (exit $R0)."
    DetailPrint "OSTP will still work, but every connect will ask for consent."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Leaving the task behind would point it at a deleted executable, and
  ; `schtasks /Run` reports success for merely accepting such a request — the
  ; app would wait on a helper that never starts.
  DetailPrint "Removing the OSTP TUN helper task..."
  nsExec::ExecToLog 'schtasks.exe /Delete /TN "OSTP TUN Helper" /F'
  Pop $R0

  ; Copied by the install hook, so the uninstaller has no record of it.
  Delete "$INSTDIR\wintun.dll"
!macroend
