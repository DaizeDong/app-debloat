# Roadmap

Current: **v0.1.0**

Release history is recorded in [CHANGELOG.md](CHANGELOG.md).

## v0.1.0 (current)
- Pipeline P0 to P7 with mandatory app-specific checkpoints, category profiles (IME, Electron/CEF, netdisk and downloader, Tencent IM, OEM utility, office suite) and a worked Sogou Pinyin case.
- Read-only analysis tools: `inventory.ps1`, `pe_triage.py` (imports, launch strings, xrefs; optional REA decompilation), `snapshot_diff.py`, a frida launch tracer.
- Manifest-driven engine that builds one single-file script per app with dry-run, `-Apply`, `-Install`, `-Uninstall` and a journal.
- RE backend doctor and installer for REA + Ghidra 12.1.4 + JDK 21, with ReVa or pyghidra-mcp and pefile/capstone fallbacks.
- Verification limits: engine actions were exercised in dry-run and on synthetic trees; elevated apply and uninstall of the engine on a real app are covered by the per-app runs, not by a sandbox suite.

## Planned
- Windows Sandbox and Hyper-V checkpoint harness for repeatable apply, reboot and repair cycles.
- Order manifest actions by antivirus-flag risk automatically instead of by manifest order.
- A signed no-op stub as an IFEO target option.
- More category profiles as new apps are processed.
