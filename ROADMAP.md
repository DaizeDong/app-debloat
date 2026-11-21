# Roadmap

Current: **v0.1.4**

Release history is recorded in [CHANGELOG.md](CHANGELOG.md).

## v0.1.4 (current)
- Pipeline P0 to P7 with mandatory app-specific checkpoints, category profiles (IME, Electron/CEF, netdisk and downloader, Tencent IM, OEM utility, office suite) and a worked Sogou Pinyin case.
- Read-only analysis tools: `inventory.ps1`, `pe_triage.py` (imports, launch strings, xrefs; optional REA decompilation), `snapshot_diff.py`, a frida launch tracer.
- Manifest-driven engine that builds one single-file script per app with dry-run, `-Apply`, `-Install`, `-Uninstall` and a write-ahead journal: exactly one mode per run, unknown versions refused in every mutating mode, real-path and vendor-identity checks on roots and targets, `inferred`/`hypothesis` actions inactive behind named options, undo that restores only what the tool wrote and reports conflicts, uninstall that keeps its journal when anything fails.
- `reference/plan-template.md`: the five required plan sections (core preservation, targeted levers, durability, reversibility, feasibility and honesty).
- RE backend doctor and installer for REA + Ghidra 12.1.4 + JDK 21, with ReVa or pyghidra-mcp and pefile/capstone fallbacks.
- Verification limits: engine actions were exercised in dry-run and on synthetic trees; elevated apply and uninstall of the engine on a real app are covered by the per-app runs, not by a sandbox suite.

## Planned
- Windows Sandbox and Hyper-V checkpoint harness for repeatable apply, reboot and repair cycles.
- Order manifest actions by antivirus-flag risk automatically instead of by manifest order.
- A signed no-op stub as an IFEO target option.
- More category profiles as new apps are processed.
