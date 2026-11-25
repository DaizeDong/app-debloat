# Profile: Input Method (IME)

Third-party pinyin and other CJK IMEs (Sogou, QQ Pinyin, Baidu, iFlytek and similar). The worked example for this profile is the public Sogou recipe (`sogou-ime-debloat`: `SogouDebloat.ps1`, `docs/how-it-works.md`); its offsets are version specific, the structure generalizes.

## Architecture and Where the Junk Lives

- **The IME Itself Is a DLL Loaded into Every Process That Takes Text Input.** A TSF text service registered as a COM in-proc server (`HKCR\CLSID\{clsid}\InProcServer32`, plus `Wow6432Node` for x86) and as a TSF profile (`HKLM\SOFTWARE\Microsoft\CTF\TIP\{clsid}`). Usually two builds: x64 and x86, either in the install root or in `System32` / `SysWOW64`. `ctfmon.exe` hosts the language bar side.
- **AppContainer Broker.** Sandboxed apps get the IME through a vendor COM broker exe (Sogou: `SogouImeBroker.exe`). Typing in Store apps, Settings and some browsers depends on it.
- **Daemons Around the Core.** Command or tool server (settings UI, dictionary merge), cloud candidate process, account sync, skin and emoji downloaders, toolbox, AI assistant, "pet", game center, news and toast popups, PDF or browser bundles. These are where ads, AI add-ons and popups live.
- **Component Manager.** A loader inside the IME DLL reads a component table and `LoadLibrary`s plug-in bundles; a separate manager exe downloads missing components (Sogou: `ComponentConfig.ini` + `SogouComMgr.exe`).
- **Third-Party SDKs Inside Daemons.** Telemetry and ad SDKs loaded dynamically (Sogou daemons load `beacon_sdk.dll`, `qimei.dll`, `libamssdk.dll`, `shiply.dll`). Thread start addresses and loaded-module lists show them.
- **Telemetry in the IME DLL Itself.** Pingback URLs referenced from the `.ime`. These requests come from the host process (Notepad, a browser), so a per-program firewall rule cannot separate them.

## Launch, Persistence and Re-Install Vectors

- Activation of the IME in any app spawns daemons (not Run keys); killing them just triggers a respawn on the next keystroke.
- Periodic dispatch from the IME or the tool server: updater, component upgrade, remote task table ("everyhourtask"-style lists from the server that name exes to run).
- SYSTEM service started on demand through COM: the only path that writes `Program Files\<Vendor>` without UAC. Repairs, component reinstall and upgrades all go through it.
- Remote config SDK pulled by a launcher exe, executed by a helper; can re-register shell extensions, reinstall a PDF reader, re-enable toasts with a new AUMID after the user turned notifications off.
- Upgrades install into a new version directory, so placeholders in the old directory stop working. IFEO on vendor-unique helper names survives version changes.
- Running a new installer elevated undoes everything; P7 re-apply must detect the version change.

## Gates

| Gate | Typical Form | Notes |
|---|---|---|
| Global component table | ini under the install root, often base64 + AES (Sogou: AES-256-CBC, key is a constant in the vendor binary) | The real load switch. Per-component `enable` plus a bundle-level `forceenable`. Never ship the key; derive it at runtime from the user's own install (known-plaintext on the second CBC block) and keep it in memory only. |
| User settings | `HKCU\Software\<Vendor>*` values, `%USERPROFILE%\AppData\LocalLow\<Vendor>\<id>\*.ini` | Often only hide the UI entry; the component still loads. Missing value can mean "on", so write 0, do not delete. LocalLow because the IME runs inside low-integrity hosts. |
| Shared-memory settings | Named file mapping plus mutexes shared by all host processes | The running IME writes the whole block back to disk on refresh and clears read-only first. Editing the file while any host has the IME loaded gets overwritten. Edit before logon (one-shot boot task) or not at all. |
| Server switches | Remote config SDK, popup and task lists fetched hourly | Verify behavior (process, module, connection), not file state. Test what happens when the fetch fails. |
| Signature checks | Before launching helpers and before `LoadLibrary` of components | Another reason not to patch binaries. Never set a vendor "no check signature" registry relaxation. |

## Core: Do Not Touch

- The `.ime` / TSF DLLs (both bitnesses), their CLSID and TIP registration, and the TSF profile in the user's language list.
- The AppContainer broker exe.
- `ctfmon.exe` and Windows TSF components (never block, never leave stopped).
- The cloud candidate process if the owner uses cloud candidates (decide in the core contract; it may carry an ad SDK that can be placeholdered separately).
- The settings / tool server if the settings UI or dictionary import is part of the contract.
- The user dictionary and its sync process unless the owner opts out (`-NoSync`-style switch).

## Levers

Use (in this order):

1. Component gate off (`enable=0`, `forceenable=0`) in the global table, written back with the original first cipher block kept.
2. Same-name empty directory in place of helper exes and dynamically loaded SDK DLLs; read-only same-name file in place of component folders (unpackers cannot recreate them).
3. IFEO `Debugger` on vendor-unique helper names (updater, component manager, biz launcher, assistant). Skip generic names such as `crashrpt.exe` that other software also uses.
4. `Shell Extensions\Blocked` for the vendor shell extension CLSIDs.
5. One-shot pre-logon task for shared-memory-backed settings files.
6. DNS-level block of vendor-only telemetry hosts, only if the owner wants it; never shared group CDNs.

Avoid:

- Patching the `.ime` or daemons (signature checks, every update undoes it).
- Unregistering the TSF profile or deleting the CLSID (removes the IME).
- Killing `ctfmon.exe` or Explorer without restarting them in `finally`.
- Editing user settings while host processes hold the shared block.
- Firewall rules meant for the IME DLL: they would hit the host app.

## Integrity, Anti-Tamper and Ban Risk

- Ban risk: low. Accounts are optional (dictionary sync). Tier: normal, after the integrity probe.
- Integrity: component certificate checks and helper signature checks exist; placeholders do not trip them because nothing signed is modified.
- Privacy history to mention in the analysis: cloud conversion that uploaded typed text by default (Baidu IME Japan, 2013: https://ja.wikipedia.org/wiki/Baidu_IME).

## Verification Probes

The probe must never type into a window the agent did not create.

1. Start an agent-owned WinForms window with one TextBox, from both `powershell.exe` and `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` so the x64 and x86 IME DLLs are both exercised.
2. In that process, activate the IME layout with `[System.Windows.Forms.InputLanguage]::CurrentInputLanguage` (or `ActivateKeyboardLayout`) and confirm the TIP is active.
3. Before each key batch: `GetForegroundWindow()` equals the form handle, and the form runs at the agent's integrity level. `SendInput` silently drops input across UIPI and still returns success.
4. Send a short pinyin sequence plus space, then read `TextBox.Text` from inside the form (or via UIA). Pass = expected CJK characters present. "Sent N keys" is not a pass.
5. Check the candidate window appears (cloud candidate optional per contract).
6. Open the vendor settings UI if it is in the contract.
7. After reboot: repeat 1 to 6, then list modules in the test process (expect only the core IME DLLs and resources) and list vendor processes and their threads (helper SDK threads gone).
8. Optional AppContainer check (Store app text box) only if the owner accepts the agent focusing that app; otherwise verify the broker process starts on demand.

## Public Projects and Recipes

- Sogou worked example (method public, key derived at runtime): `sogou-ime-debloat` (`docs/how-it-works.md`).
- Lock-not-delete against Sogou self-repair: https://www.v2ex.com/t/678665 and https://github.com/ArabidopsisDev/SogouFucker (ACL deny and an undeletable placeholder in `%TEMP%\sgrepairbackup`).
- Sogou remote config (Shiply) and server-side popup switches: https://www.52pojie.cn/thread-2061389-1-1.html and https://v2ex.com/t/1160687
- QQ Pinyin news popup removed by deleting the property file the popup reads (version 6.5 era, unverified on current builds): https://zhuanlan.zhihu.com/p/121474396
- TSF registration model and IME sandbox behavior: https://learn.microsoft.com/en-us/windows/apps/develop/input/input-method-editor-requirements
- `SendInput` and UIPI: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput
