# app-debloat

Reverse-engineer one adware-ish Windows app, find every way its junk starts and comes back, and ship an idempotent, reversible, self-reapplying debloat script for it.

[![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-orange?style=flat)](https://docs.anthropic.com/en/docs/claude-code)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![No Binary Patching](https://img.shields.io/badge/Binary%20Patching-None-green?style=flat)](skills/app-debloat/reference/safety.md)
[![Auto Re-Apply](https://img.shields.io/badge/App%20Updates-Auto%20Re--Apply-green?style=flat)](skills/app-debloat/reference/pipeline.md)
[![Languages](https://img.shields.io/badge/Languages-EN%20%2F%20CN-blue?style=flat)](#languages)
[![Roadmap](https://img.shields.io/badge/Roadmap-v1.0.0-purple?style=flat)](ROADMAP.md)
[![Release](https://img.shields.io/github/v/release/DaizeDong/app-debloat?style=flat)](https://github.com/DaizeDong/app-debloat/releases)

[English](README.md) | [中文版](README_CN.md)

---

## Design Philosophy

Adware-ish desktop apps (input methods, cloud drives, downloaders, translators, office suites, OEM utilities, branded Chromium browsers) rarely give you a real off switch. Their ads, AI add-ons and telemetry are separate components started by a launcher, gated by a config the settings page does not control, and brought back by an updater, a repair service or a remote-config SDK. They also reach into the rest of the machine: a right-click entry on every file, a This PC icon, an Office add-in, a browser extension, a takeover of the PDF or video defaults, a peer-to-peer engine listening on every interface. Deleting files or flipping UI toggles fails for the same reason every time: it treats the symptom, not the gate and not the way back.

This skill turns the method that worked on Sogou Pinyin into a repeatable pipeline. It inventories everything the app put on the machine, maps who launches each component and what decides whether it runs, lists every re-install path, blocks those with the least invasive lever, proves the result by behavior (processes, modules, connections, a core-function probe, a reboot, a triggered repair), and keeps it applied after updates. The generic steps only find candidates; each app must answer a fixed list of app-specific questions before anything changes, because no two apps hide their gates in the same place.

[Design rationale](PHILOSOPHY.md)

---

## What It Does

For one installed third-party Windows desktop app at a time. You name the app, what must keep working and what should go. The skill produces:

- **An evidence ledger** (`ledger.jsonl`): every claim about the app (a component exists, A launches B, switch S gates B, path P reinstalls B, action Z held) with a status and an anchor (file hash plus RVA, a captured command line, a registry read).
- **A plan** (`plan.md`) in five fixed sections: core preservation, targeted levers, durability, reversibility, feasibility and honesty.
- **One PowerShell script** (`<App>Debloat.ps1`), built from a JSON manifest, with dry run by default, `-Apply`, `-Install` (re-assert at logon and every 6 hours) and `-Uninstall`.
- **A verification record**: counts and probe results before, after apply, after a reboot and after a triggered repair.

Not covered: Windows-wide debloat, malware removal, uninstalling, browser ad blocking, cracking or license bypass, binary patching, recommending other software. Tencent-family clients are limited to out-of-process measures.

## The Pipeline

| Stage | Goal | Main Tools |
|---|---|---|
| P0 Prepare | Install roots, versions and hashes; half-applied updates; elevated facts under one UAC prompt; RE backend; core function contract; risk tier; the updater noted before the first launch | `inventory.ps1`, `elevated_readonly.ps1`, `setup_re_backend.ps1` |
| P1 Inventory | Every file, service, task, registration, process and connection; before and after use; cross-app integrations; network exposure; resource use | `inventory.ps1`, `launch_monitor.ps1`, `strscan.py`, `snapshot_diff.py` |
| P2 Launch Chain and Gates | Who starts each bloat component and what decides whether it runs; toggle tests; the Settings Map | `pe_triage.py`, REA or Ghidra, `frida/*.js`, `stop_app.ps1` |
| P3 Re-Install Paths | Every vector that brings junk back, each with a proof it is closed; vendor writes outside its own folders | Procmon, `new_files_since.py`, service recovery actions |
| P4 Plan | `plan.md`: each action with target, lever, evidence, default or option, original state, undo and check | `reference/plan-template.md`, `reference/levers.md` |
| P5 Build | One idempotent single-file script from a manifest | `DebloatEngine.ps1` `New-AppScript` |
| P6 Verify | Behavior after apply, after reboot, after a triggered repair or update | `launch_monitor.ps1`, `shot_windows.ps1`, `list_modules.ps1`, contract probes |
| P7 Keep Applied | A watch task re-asserts the blocking actions at logon and every 6 hours | the built script's `-Install` |

Every stage writes to the ledger before the next one starts, so a run resumes from the ledger after a context reset. Eight app-specific questions (tier and ban risk, injection, the real gate, settings that fight back, server switches, who writes the install folder, what only looks like bloat, cosmetic switches) must each have an anchored answer or a reasoned "unknown".

## What It Detects

**Inside the App.** Launch chains (process spawns, DLL loads, COM activation, TSF and shell loads) confirmed at run time; config gates, including encrypted component tables and settings kept in shared memory; updaters, repair executables, SYSTEM services woken by COM, scheduled wake tasks in vendor subfolders; dynamically loaded telemetry and ad SDKs; remote-config switches; half-applied self-updates and exe swaps on launch; helpers that start ten or more minutes after launch; credential-like values on command lines (written as `<redacted>`).

**Cross-App Hijacks.** A read-only sweep of every place the app plugs into other software, live or dormant:

- Context menus, including `SystemFileAssociations` and Windows 11 packaged menus.
- Icon overlays, with their rank among the 11 of Explorer's 15 overlay slots that third parties get, and which other vendors' overlays they push out.
- This PC, Desktop and navigation pane namespace entries.
- Office and WPS add-ins (`Addins`, `Resiliency`, `LoadBehavior`), and dormant add-in payloads that ship unregistered.
- Browser extensions (`Extensions\<id>` keys, policies, profile entries written from outside) and native messaging hosts for Chrome, Edge, Chromium, Brave and Firefox.
- Default-app takeover: file types, protocols and the browser, with key write times that separate an installer's choice from the owner's.
- P2P engines and listening ports: listener scope, UDP fan-out, vendor inbound allow rules, UPnP mappings, debugging ports.
- Staged installers: full packages downloaded into the profile or dropped outside the install folders.
- In-app settings: plain ini, json, `Local State` and `Preferences` keys, encrypted or server-side ones, and installer verbs and environment switches, collected into a Settings Map with menu paths and toggle-probe results.

## Levers and Engine Actions

Levers are picked least-flagged and narrowest first: config gate off, same-named placeholder, file or folder deny-write ACL, service disable, scheduled task disable, per-program firewall rule (outbound, or inbound for a listener), shell extension block, IFEO by image name, and hosts only as a discouraged last resort. Registry entry removal and a browser extension policy block answer the cross-app hijacks. No lever patches a binary.

| Group | Engine Action Types |
|---|---|
| Services and Tasks | `service-disable`, `task-disable` (recursive `taskPath` search) |
| Files and Folders | `file-placeholder-dir`, `dir-placeholder-file`, `acl-deny-write` (`write` or `write+protect`, `emptyFirst`) |
| Processes and Network | `ifeo-block`, `firewall-block-program` (`Outbound` or `Inbound`), `hosts-block` (discouraged) |
| Registry and Shell | `reg-set` (including `Binary` StartupApproved flags), `reg-delete-key` (`match`, `matchDefault`), `reg-delete-value`, `shellext-block`, `toast-off` |
| Browser Policy | `browser-ext-block` (`ExtensionInstallBlocklist` for Chrome and Edge, optional `removeExternal`) |
| Settings Files | `ini-set`, `json-set` (both with `onlyWhenNotRunning`), `preboot-file-edit` (a one-shot pre-logon edit for settings held in shared memory) |
| App-Specific | `hook` (named scriptblocks, for example a config codec that derives its key at run time from the owner's install) |

The full field reference is [manifest.md](skills/app-debloat/reference/manifest.md); lever trade-offs and hijack recipes are in [levers.md](skills/app-debloat/reference/levers.md).

## Safety Model

- **Dry Run by Default.** The built script prints the plan and changes nothing; `-Apply` executes exactly the printed plan. One mode per run.
- **Evidence-Gated Actions.** Only `observed` or `anchored` actions are defaults; `inferred` and `hypothesis` actions ship inactive behind named options, and the plan lists them.
- **Journal and Undo.** Every change is journaled before it happens with its original state. `-Uninstall` replays the journal in reverse and restores only what still holds the value the tool wrote; anything else is reported as a conflict and left alone.
- **Watch Task.** `-Install` registers only after a clean apply, then re-asserts blocking actions at logon and every 6 hours. An unknown app version stops re-application until the analysis is redone.
- **Known Failures.** An explained, accepted failure (a security suite vetoing one service change) becomes a manifest `knownFailure {reason, ref}`: logged as a WARN with its reason on every run, so a new failure still shows as one.
- **Guards.** Only resolved install roots and declared folders are touched; drive roots, Windows, Program Files, the Users folder and reparse points are refused; processes are stopped by full path, then PID; vendor services are disabled, never deleted; antivirus is never disabled or excluded.
- **Private Data Stays Private.** Ledgers, snapshots, journals and verification records live in a private companion repo; public outputs carry no extracted keys, decrypted configs or vendor binaries.

## Install

```
/plugin install github:DaizeDong/app-debloat
```

Or clone manually:

```bash
git clone https://github.com/DaizeDong/app-debloat.git ~/.claude/plugins/app-debloat
```

Requirements: Windows 10 or 11, Windows PowerShell 5.1 and Python 3; `pe_triage.py` also needs pefile and capstone (numpy optional): `setup_re_backend.ps1 -Install -Component pymods` or `pip install pefile capstone`. The reverse-engineering backends (REA, Ghidra) are optional:

```powershell
.\skills\app-debloat\scripts\setup_re_backend.ps1                 # doctor, read-only
.\skills\app-debloat\scripts\setup_re_backend.ps1 -Install        # REA + Ghidra 12.1.4 + JDK 21 into %LOCALAPPDATA%
```

## Usage

Ask Claude Code in plain words, for example: "Youdao Translate keeps popping up ads and an AI assistant, find what launches them and block it without breaking translation." Other phrases that trigger it: "this app is full of ads, slim it down", "it keeps coming back after every update", "find its self-repair mechanism", "disable its telemetry and AI assistant but keep it usable", "debloat <app name>".

The skill then snapshots the app read-only, maps launch chains and gates, writes `analysis.md` and `plan.md`, and asks before any change. Once you approve, it builds the script and you run it:

```powershell
.\ExampleDebloat.ps1              # dry run: prints the plan, changes nothing
.\ExampleDebloat.ps1 -Apply       # elevated; executes exactly the printed plan, journals original state
.\ExampleDebloat.ps1 -Install     # elevated; apply, then re-assert at logon and every 6 hours
.\ExampleDebloat.ps1 -Uninstall   # elevated; remove what it registered, replay the journal
```

## Real-World Results

Per-app public repos built with this method:

| App | Version Analyzed | Kind | Repo |
|---|---|---|---|
| Sogou Pinyin | 15.5 | Input method; the original case the method was distilled from | [sogou-ime-debloat](https://github.com/SanJerry007/sogou-ime-debloat) |
| NetEase Youdao Translate | 11.3.24.0 | Translation client (CEF), per-user install | [youdao-translate-debloat](https://github.com/SanJerry007/youdao-translate-debloat) |
| Quark and Quark Netdisk | 7.4.9.1045 | Chromium-fork browser with a cloud drive and SYSTEM updater services | [quark-debloat](https://github.com/SanJerry007/quark-debloat) |
| Baidu Netdisk | 8.2.1.102 | Cloud drive (Electron) with a BitTorrent engine, overlays and a SYSTEM utility service | [baidu-netdisk-debloat](https://github.com/SanJerry007/baidu-netdisk-debloat) |

The listed version is the build that was analyzed. Offsets and paths hold for that build, and a script built with the engine refuses any other version (unless run with `-Force`) until its manifest is rebuilt from a fresh analysis.

## Example Output

`examples/` holds two synthetic apps generated by `tools/make_fixtures.py`: a manifest, optional hooks and the built single-file script for each. The Sogou method is summarized in [case-sogou.md](skills/app-debloat/reference/case-sogou.md).

## Limitations

- Static analysis offsets are valid for one build only; every app upgrade needs the inventory and the gate questions re-checked (the watch task warns when the version fingerprint changes).
- Code that runs inside another process (an IME, a shell extension) cannot be firewalled per program.
- Server-pushed switches can change behavior without any file change; verification is by behavior, not file state.
- Antivirus may flag or silently revert IFEO and hosts changes; the pipeline re-reads them but cannot prevent it.
- Account-bound apps can kick or ban modified clients; in-tree changes need the owner's explicit consent per app.
- Blocking an updater also blocks that vendor's security fixes; the plan states the cost and how to update by hand.

## Languages

English (`README.md`, authoritative) · 中文 (`README_CN.md`)

## Roadmap · License

See [ROADMAP.md](ROADMAP.md) · [LICENSE](LICENSE) (MIT).
