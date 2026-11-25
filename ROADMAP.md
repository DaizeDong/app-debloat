# Roadmap

Current: **v1.0.0**

Release history is recorded in [CHANGELOG.md](CHANGELOG.md).

## v1.0.0 (current)
- Pipeline P0 to P7 with mandatory app-specific checkpoints, an evidence ledger that survives context resets, category profiles (IME, Electron/CEF, Chromium-fork browser, netdisk and downloader, Tencent IM, OEM utility, office suite) and a worked Sogou Pinyin case.
- Cross-app hijack coverage: context menus, icon overlays and their slot rank, This PC and Desktop namespace entries, Office and WPS add-ins, browser extensions and native messaging hosts, default-app takeover, P2P engines and listening ports, staged installers, dormant payloads, and a Settings Map of in-app switches with toggle probes.
- Read-only analysis tools: `inventory.ps1`, `elevated_readonly.ps1` (one UAC prompt), `launch_monitor.ps1` (launch chains, connections, resource sampling), `pe_triage.py` (imports, launch strings, xrefs; optional REA decompilation), `strscan.py` (keyword sets in large binaries and packages), `snapshot_diff.py`, `new_files_since.py`, `list_modules.ps1`, `shot_windows.ps1`, `stop_app.ps1` and frida tracers.
- Manifest-driven engine with 18 action types that builds one single-file script per app with dry run, `-Apply`, `-Install`, `-Uninstall` and a write-ahead journal: exactly one mode per run, unknown versions refused in every mutating mode, real-path and vendor-identity checks on roots and targets, `inferred` and `hypothesis` actions inactive behind named options, undo that restores only what the tool wrote and reports conflicts, per-target `knownFailure`, re-created placeholders, and an uninstall that keeps its journal when anything fails.
- `reference/plan-template.md`: the five required plan sections (core preservation, targeted levers, durability, reversibility, feasibility and honesty).
- RE backend doctor and installer for REA + Ghidra 12.1.4 + JDK 21, with ReVa or pyghidra-mcp and pefile/capstone fallbacks.
- Verification limits: the engine was exercised in live apply, verify and watch-task runs on three real apps and on synthetic trees; there is no sandbox suite for repeatable apply, reboot and repair cycles yet.

## Planned
- Windows Sandbox and Hyper-V checkpoint harness for repeatable apply, reboot and repair cycles.
- Order manifest actions by antivirus-flag risk automatically instead of by manifest order.
- A signed no-op stub as an IFEO target option.
- More category profiles as new apps are processed.
