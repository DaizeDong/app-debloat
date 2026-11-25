# Worked Example: Sogou Pinyin 15.5

Public repo: https://github.com/SanJerry007/sogou-ime-debloat (`SogouDebloat.ps1`, `docs/how-it-works.md`). Analyzed on build 15.5.0.2004; offsets below are for that build only. This summary contains no key material and no decrypted config.

## P0 Prepare

- Category: IME. Loaded as a DLL into every process that takes text input, plus a COM broker for sandboxed apps.
- Roots: resolved from the vendor's HKLM WOW6432Node key (`Version` value) and the version directory that contains `SGTool.exe`; nothing hard-coded.
- Login and ban risk: optional account for dictionary sync only, no ban mechanism observed. Tier `normal`.
- Backend: pefile plus capstone (tier C) was enough; REA or Ghidra was not needed.
- Contract: typing in a Win32 app, a browser and a Store app; user dictionary merge; settings dialog; cloud candidates (optional).

## P1 Inventory

- Resident: `SGTool.exe -daemon` (command server, dictionary merge, settings), `SogouCloud.exe -daemon` (cloud candidates), `SogouImeBroker.exe` (AppContainer broker).
- Service `SogouSvc` (manual start, COM-activated, runs as SYSTEM).
- Shell extension (`biz_shellext`), PDF suite under `%LOCALAPPDATA%`, a preview handler, toast registrations.
- Injection: `SogouTSF.ime` and `SogouPY.ime` in every input host. Their own network calls cannot be separated by per-program firewall rules.

## P2 Launch Chain and Gates

Shape:

```
TSF shell -> IME core (in every host)
  -> in-process component manager reads Components\ComponentConfig.ini
       per bundle: enable != 0, file exists, signature ok -> LoadLibrary
       (AI assistant, stickers, game center, pet, business center)
  -> SGTool -daemon: hourly remote task table -> component manager actions
       (toast ads, PDF install, shell ext re-register, status bar popups)
  -> periodic: updater, component manager, remote-config launcher
```

- The real gate is the global `ComponentConfig.ini`: base64 over AES-256-CBC. Verified on one machine: every bundle with `enable=1` loaded, every bundle with `enable=0` did not. A `forceenable` field also has to be cleared.
- Decoys: registry switches under the user store key and the per-user `env.ini` only hide entry points. Missing values default to on, so they are written as 0, not deleted.
- Key handling (public-safe): the script derives the key at run time. In CBC the second plaintext block equals `D(C2) xor C1` regardless of IV, so each 32-byte window of an installed vendor binary is tried until block 2 decrypts to `[system]`. Re-encryption keeps the original first ciphertext block as the chaining value, so no IV is needed. The key stays in memory.
- Shared memory: running settings live in a named file mapping shared by all hosts and are flushed back over `env.ini` (read-only attribute stripped first). Fix: a one-shot SYSTEM scheduled task edits `env.ini` at boot before logon and deletes itself.
- Server-pushed switches: a Tencent remote-config SDK fetched by the business launcher can enable popups regardless of user settings, which is why verification is by behavior.
- Signature checks exist before spawning helpers and before loading component DLLs, which is one reason no binary was patched.

## P3 Re-Install Paths

1. `SogouSvc`: the only no-UAC writer of the install directory; all repair and upgrade goes through it.
2. Component manager: re-downloads a component whose file is missing while `enable=1`, about every 8 hours, and rewrites the component config on upgrade.
3. Remote config: launcher pulls server tasks, the business helper executes them (re-register shell ext, install PDF, toasts with fresh AUMIDs after the user turned them off).

New versions install into a new version directory, so path-based blocks alone do not survive upgrades.

## P4 Plan and Levers

| Target | Lever |
|---|---|
| AI assistant, stickers, games, pet, business center | Config gate off, component dirs replaced by read-only same-named files |
| Component manager, updater, remote-config launcher, downloader, assistant exes, crash and feedback helpers | Same-named placeholder directories plus IFEO by name (14 vendor-specific names, Debugger to a nonexistent path) |
| `SogouSvc` | Disabled, not deleted |
| Shell extension | Unregistered plus Shell Extensions\Blocked (both CLSIDs) |
| PDF suite | Vendor uninstaller, then user deny-write ACL on its dir |
| Toast ads | Notification registration removed and disabled |
| Status bar and server popups | Business center off, popup DLLs placeholdered |
| Optional: sync helper, network for SGTool | `-NoSync`, `-BlockNet` firewall per program |

Kept as core: IME DLLs, broker, `SGTool.exe` (looked like bloat, carries dictionary merge and settings), `SogouCloud.exe` (cloud candidates), voice and kaomoji tools unless opted out.

Residual: one context-menu reference under a TrustedInstaller-owned key could not be removed; it points to a deleted and blocked CLSID, so it is inert. Telemetry pings inside the IME DLL itself remain (would need DNS-level blocking of vendor-specific hosts or patching; neither done).

## SDK DLL Removal with Evidence

- SGTool dynamically loads a beacon telemetry SDK and a device-ID SDK. Before: 49 threads, 33 with start addresses in the beacon DLL and 4 in the device-ID DLL.
- Neither DLL appears in any vendor binary's import or delay-import table, and SGTool checks the load result and takes a fallback branch.
- After placeholders: SGTool keeps running, thread count drops to about 9.
- Same check for an ad SDK loaded by the cloud-candidate engine: the path is built and `LoadLibrary` is called with a checked result, so a placeholder leaves cloud candidates intact.

## P5 Script

`SogouDebloat.ps1`: dry run default, `-Apply`, `-ShowComponents`, `-Install`, `-Uninstall`, plus opt-in switches. Idempotent: already-done items print SKIP; non-zero exit on any failure. Config rewrite goes to a temp file, is read back and compared, then swapped with `[IO.File]::Replace(..., [NullString]::Value)`.

## P6 Verify

Module lists per host, process list, thread counts, typing in three app types after reboot, settings dialog. Processes holding old component DLLs need a reboot and a second `-Apply` to finish.

## P7 Keep Applied

`-Install` copies the script and chosen options to an admin-only `%ProgramData%` state dir and registers a task at logon and every 6 hours that runs a logged `-Apply` (all SKIP when nothing changed). It finds the new version directory from the registry after upgrades. It never downloads code. `-Uninstall` removes tasks, IFEO keys, firewall rules and the state dir; placeholders are listed in the log for manual removal before a reinstall.

## What the Generic Skill Takes from This Case

- The settings UI is rarely the gate; find the config the loader reads.
- Placeholders plus IFEO cover both the current path and future version directories.
- Thread start addresses are cheap, strong evidence for SDK removal.
- Shared-memory settings need a preboot edit.
- No unified journal and no evidence ledger in the original; the engine adds both.
