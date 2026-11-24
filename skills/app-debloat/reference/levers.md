# Neutralization Levers

Pick the least-flagged lever that actually closes the path. Order below is least likely to be flagged by antivirus first. Every lever is journaled with its original state on first touch, and every lever has an undo.

Columns used in each entry: Stops, Survives upgrade, AV risk, Reversible, Pitfalls.

## 1. Config Gate Off

Turn the component off where the app itself decides to load it (component table, feature flag, ini, registry value).

- Stops: the load or spawn at its source, including paths you have not mapped yet.
- Survives upgrade: no. Installers and component managers rewrite config. Must be re-asserted by the `-Install` task.
- AV risk: none.
- Reversible: yes, restore the original value.
- Pitfalls:
  - Settings UI switches are often cosmetic: they hide the entry point while the component still loads. Verify with the module list.
  - Missing values may default to "on": write the off value, do not delete it.
  - Encrypted or checksummed config: rewrite only with material derived at run time from the user's own install; never ship keys or decrypted config.
  - Shared-memory settings are flushed back over the file by any process holding them. Edit the file in a preboot SYSTEM task that runs before logon and deletes itself.
  - Some apps strip the read-only attribute before writing, so read-only alone protects nothing.
  - A "force enable" field may override the plain enable field; clear both.
  - Plain INI and JSON settings files (`Preferences`, `Local State`, vendor ini) use the engine's `ini-set` and `json-set` action types with `onlyWhenNotRunning`, not a hand-written hook; list the file in `core.preserve`. Chromium Secure Preferences carry MACs: a value covered by a MAC is reset or flagged when edited, so prefer `Local State` or an unprotected key.

## 2. Same-Named Placeholder

Delete `x.exe` (or a DLL) and create an empty directory named `x.exe` at the same path. For a component directory, the inverse: delete the directory and create a read-only empty file with its name.

- Stops: process creation and library load from that path; updaters and repairers cannot write the file back because the name is taken.
- Survives upgrade: only for that path. A new version directory brings a fresh copy. Pair with IFEO (lever 6) for executables, and re-assert from the task.
- AV risk: very low.
- Reversible: delete the placeholder, reinstall over the top.
- Pitfalls:
  - Only for files with no static or delay import from any kept binary. For a DLL, confirm it is loaded dynamically (`LoadLibrary` with a checked result) using imports, delay imports and an xref to the failure branch, then confirm at runtime (thread count or module list drops, host keeps running).
  - Stop the owning process by PID first; a loaded DLL cannot be removed.
  - The parent must not be writable to the updater in a way that lets it remove the placeholder; if it is, add lever 3.

## 3. File or Directory ACL Deny

Add a deny ACE for the identity that rewrites the target. `rights: write` (default) denies WriteData, AppendData, WriteEA and WriteAttributes. `rights: write+protect` also denies Delete, DeleteSubdirectoriesAndFiles, ChangePermissions and TakeOwnership, and only on an Administrators-owned target.

- Stops: writes by that identity.
- Survives upgrade: yes for that path, unless the writer runs as SYSTEM or TrustedInstaller and resets the ACL.
- AV risk: low.
- Reversible: `-Uninstall` removes exactly the rights the tool journaled. Do not use `icacls /remove:d`, which drops every deny entry of the SID. Record the full original SDDL first.
- Trade-off: the user can no longer delete or clean that folder; the engine lifts its own entry (journaled as a note) when it must re-create a placeholder inside it.
- Pitfalls:
  - A deny on the file does not stop rename-and-replace: anyone with `FILE_DELETE_CHILD` on the parent directory can delete or rename the file regardless. Deny on the parent, or use a placeholder.
  - A deny for the user does nothing against a SYSTEM service writer. Disable the service (lever 4).
  - Deny ACEs on shared locations can break unrelated software. Keep them on app-owned paths only.

## 4. Service Disable

Set the vendor service start type to Disabled and clear its recovery actions if they restart it.

- Stops: SYSTEM-level silent writes, repair and re-install through that service.
- Survives upgrade: no. Installers reset start type. Re-assert.
- AV risk: low.
- Reversible: restore the recorded start type and recovery actions.
- Pitfalls:
  - Never `sc delete` a vendor service. Disable it.
  - Driver-protected services may refuse reconfiguration; do not fight the driver, mark the app `out-of-process only` for that path.
  - Some services are core (hotkeys, EC, fan, display, input). Check the contract first.
  - Manual is not off. A service set to Manual (demand start) still runs whenever the app, its tasks or a COM activation start it; a snapshot showing `Manual, Stopped` proves nothing. Check updater logs or a Procmon capture of a launch, and use Disabled when the service must not run.
  - COM wakes services too. A COM server registered with an AppID `LocalService` value (often an updater's elevation or "on demand" class) starts that service whenever any process activates the class, and `sc qtriggerinfo` lists start triggers (network, device, ETW). Record which wake each service has; Disabled stops all of them, a firewall rule stops only the traffic.
  - A security suite may veto the change for one service: `ChangeServiceConfig` returns access denied although the service DACL and protection level (`sc qprotection`) allow it. Do not work around it. Record the evidence (error, `sc sdshow`, protection level, `fltmc` minifilters, installed AV), mark the action `knownFailure {reason, ref}` in the manifest so each run logs a WARN with the reason instead of a failure, and fall back to lever 5 for its wake tasks and lever 6 for its exe.
  - Look for System event 7006 within a few seconds of each denied change ("The ScRegSetValueExW call failed for Start with the following error: Access is denied."). It confirms the veto is at the registry level, on the service's `Start` value (a registry filter, typically a security suite), not in the service's permissions. It names no service, so match it by timestamp to the denied `sc.exe config`, and add it as an anchor on the knownFailure's ledger entry (`pipeline-field-notes.md`, P5 Build: Known Failures).
  - Check `sc qfailure` (elevated) for recovery actions that restart it.

## 5. Scheduled Task Disable

Disable (do not delete) vendor tasks that run updaters, telemetry or promotions.

- Stops: timer and logon triggers.
- Survives upgrade: no. Re-assert.
- AV risk: low.
- Reversible: re-enable.
- Pitfalls:
  - Tasks are often recreated under a new name by the updater; match by action path pattern and re-scan each run.
  - Vendor tasks often sit in subfolders (for example `\<Vendor>UpdaterSystem\<Vendor>Updater\`), not in the root. A name pattern alone searches only the root folder; give the action a `taskPath` (folder, matched recursively) plus the name pattern. The dry run prints the searched path and the match count, so "0 matches" is visible as a miss, not a plain SKIP.

## 6. Firewall Rule per Program

Outbound block rule for a specific executable path.

- Stops: network traffic from that process.
- Survives upgrade: no when the path includes a version directory. Regenerate rules each run for the current path.
- AV risk: low.
- Reversible: remove rules by the script's own display-name prefix.
- Pitfalls:
  - No wildcard paths. One rule per resolved executable.
  - Fallback when a service change is denied (security-suite veto, driver protection): an outbound rule for the service exe and for each exe it launches stops its downloads while the service still runs. Pair it with task disable for its wake tasks, and say in `plan.md` that the service itself still starts.
  - Traffic from a DLL belongs to the host process. You cannot block an in-process SDK or an IME DLL loaded into a browser without blocking the browser.
  - Blocking a helper that also downloads wanted content (dictionaries, skins) breaks that content. Make it opt-in.

## 7. Shell Extension Block

Add the extension CLSID under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked`, and unregister it.

- Stops: Explorer loading the extension, even if the app re-registers it.
- Survives upgrade: yes, CLSIDs are usually stable. Verify the CLSID after an upgrade.
- AV risk: low.
- Reversible: delete the value.
- Pitfalls:
  - Check both registry views (64-bit and WOW6432Node) and HKCU against HKLM.
  - Some referencing keys are owned by TrustedInstaller and cannot be removed without taking ownership; do not take ownership of system keys. A dangling reference to a deleted and blocked CLSID is harmless.
  - Restarting Explorer to unload the extension: restart it in a `finally` block.
  - Vendors that offer their own toggle may disable a handler by appending `-` to the CLSID in the handler key. Match handlers with that suffix too, and check which view wins in the merged HKCR (an HKCU value overrides HKLM for that user).

## 8. IFEO by Image Name

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<name.exe>` with `Debugger` set.

- Stops: any process creation with that file name, from any path, by any launcher (CreateProcess, ShellExecute, COM). Survives new version directories.
- Survives upgrade: yes.
- AV risk: medium. Defender (`Behavior:Win32/ifeoDebugger`) and some third-party AV flag or silently delete IFEO debuggers.
- Reversible: delete the key the script created.
- Pitfalls:
  - Only vendor-specific names. Never generic names (`crashrpt.exe`, `update.exe`, `pdfsdk.exe`) or any system, security or accessibility binary.
  - If a `Debugger` value already exists, leave it and warn.
  - Target: a nonexistent path makes creation fail cleanly (used in the Sogou case); a benign signed stub is the alternative when an AV product treats the missing target as suspicious. Pick one per app and record why.
  - Does not stop `LoadLibrary`. DLLs still need placeholders.
  - Re-read after a delay and after reboot to catch silent AV removal.

## 9. Hosts or DNS Block

- Stops: name resolution of vendor-specific hosts, including from in-process SDKs.
- Survives upgrade: yes.
- AV risk: high for Microsoft domains (`HostsFileHijack`), medium otherwise.
- Reversible: remove lines between the script's markers.
- Pitfalls: discouraged for shared vendor domains (one company's CDN or remote config shared by several of its apps). Prefer a router, DNS filter or proxy the owner already runs. Never touch Microsoft domains.

## Last Resort, Not in Public Outputs

Binary patching (`ret` a popup routine), injected bypass DLLs, signature-check bypass values. These pin to one build, break Authenticode (component loaders often verify signatures), carry ban and legal risk, and are excluded from public repos (see `safety.md`). If the gate is in-binary only and no lever above works, record it as a residual in the ledger.

## Choosing Quickly

| Goal | First choice | Add if needed |
|---|---|---|
| Component loaded by the app | Config gate off | Placeholder on its DLL dir |
| Bloat exe spawned by core | Placeholder | IFEO by name |
| Dynamically loaded SDK DLL | Placeholder after import check | none |
| SYSTEM service re-installs | Service disable | Placeholder on its payloads |
| Updater on a timer | Task disable plus placeholder | IFEO by name |
| Shell or preview extension | Unregister plus Blocked | ACL deny on its install dir |
| Network-only helper | Firewall per program | none |
| Service change denied by a security suite | `knownFailure` on the service action | Task disable plus firewall per program |
| Shared-memory settings | Preboot SYSTEM edit | none |
