# Changelog

All notable changes to this project are documented here (Keep a Changelog style).

## [1.0.0] - 2026-11-25
### Changed
- First stable release: the P0 to P7 pipeline, the evidence ledger, seven category profiles plus a generic picker, the read-only analysis tools and the manifest engine with 18 action types, exercised in live apply, verify and watch-task runs on Youdao Translate 11.3.24.0, Quark 7.4.9.1045 and Baidu Netdisk 8.2.1.102.
- `shot_windows.ps1` recognizes Chromium's restore-pages bubble by shape as well as by title (English and Chinese), so a fork's untitled bubble is tagged. The shape route (a small untitled `Chrome_WidgetWin_*` window beside a main window of the same process, sized at 96 DPI) runs only with `-AfterForcedStop`, and its matches are reported as possible bubbles and counted apart from title matches, because a small untitled popup has the same shape; the index records `bubble_match`, `owner` and `monitor_dpi`.
- `launch_monitor.ps1 -Launch` starts the exe in `launch-cwd\` next to `-Out`, and the pipeline and safety rules require a private working directory for every manual start of a vendor exe (`Start-Process -WorkingDirectory`, updater triggers, `frida -f`), so vendor debug logs never land in the agent's current directory. The monitor lists the files the app wrote to `launch-cwd\` in a `note` line before `end`, to be summarized in the ledger and deleted before the companion is committed.
- README and README_CN rewritten: what the skill detects (cross-app hijacks included), the levers and engine action types, the safety model and the public Sogou Pinyin case built with it; PHILOSOPHY gains the cross-app reach principle; ROADMAP describes the current scope.
- Reference consistency: overlay slots stated as 11 of Explorer's 15 everywhere, the IFEO target is the engine's nonexistent path (no stub option), built script named `<App>Debloat.ps1` throughout; headings, bold lead-ins and table headers in Title Case.

## [0.1.7] - 2026-11-24
### Changed
- Hijack coverage from three real sweeps: inventory sections browser (native messaging hosts, extensions, policies), office_addins, dormant_payloads, shell_namespace, overlay rank and pushed-out overlays, default_apps, shell_new, consent_store, settings (redacted), devtools, upnp, listen scope, staged installers, Uninstall-name matching; engine types reg-delete-value and browser-ext-block, reg-delete-key matchDefault, reg-set Binary; launch_monitor -Sample/-Attach; strscan.py keyword scanner; pipeline steps for cross-app integration, network exposure and P2P, in-app setting discovery; Settings Map.

## [0.1.6] - 2026-11-23
### Changed
- Durability round on the three live apps: deleted placeholders are re-created from the journal (incl. under the tool's own deny ACE), history lines report held counts, vendor-restored binaries with a new hash are kept as backups, token/cookie redaction in captured command lines, launch_monitor refuses an elevated -Launch, new_files_since.py for staged downloads outside the roots, P7 revert tests, ledger.jsonl as the single store from P0.

## [0.1.5] - 2026-11-23
### Changed
- Round-3 live feedback: non-elevated task searches say SYSTEM tasks are invisible and show the last elevated enumeration (elevated_readonly -Key); per-target knownFailure (registry hive spellings normalized, regdel covered); dry run counts changes known to fail; compact history.log line; sc.exe denials no longer appear as TerminatingError; shot_windows lists minimized windows and never restores them; weaker P6 pass; JSON files written with ConvertTo-Json -Compress or json.dumps, never heredocs.

## [0.1.4] - 2026-11-21
### Changed
- Improvements from the first live apply/verify/install runs: recursive taskPath matching with visible search counts, knownFailure, access-denied diagnostics, -Install registers only after a clean apply, quiet existence lookups, module-check exemptions for isolated security and VM processes plus -IgnoreUninspectable/checkLoadedExempt, unused-option warnings; snapshot_diff case-insensitive paths and --journal/--expect-removed; list_modules.ps1; prior task state in elevated_readonly; docs on security-suite vetoes and no third-party database copies.

## [0.1.3] - 2026-11-21
### Changed
- Improvements from the first live runs: Toolhelp32 module check by full path (32-bit included), ini-set and json-set actions, core.preserve, Options Not Selected in dry runs, root provenance and identity in the header; inventory fixes (autorunsc lookup, -AppFile, runtime-name exclusion, per-root caps, DNS cache, pending updates); snapshot_diff --out/--summary; new shot_windows, launch_monitor, stop_app, elevated_readonly and frida file/stack tracers; pipeline steps for half-applied updates, first-launch self-update and UAC handling; chromium-fork profile and Baidu 8.x notes.

## [0.1.2] - 2026-11-21
### Changed
- Reject malformed version.sources at build time and warn when no version resolves; pe_triage works under python -I by adding the user site-packages.

## [0.1.1] - 2026-11-20
### Changed
- Engine safety fixes from the first G1 review: exclusive modes, version refusal in Auto, real-path checks, evidence-gated actions, conflict-aware undo, failure-preserving uninstall; plan template; numpy dependency and pure-Python fallback in pe_triage.

## [0.1.0] - 2026-11-19
### Added
- Skill entry with the P0 to P7 pipeline and the mandatory app-specific checkpoints.
- Reference docs: pipeline, levers, safety, ledger format, manifest format, RE backends, a Sogou Pinyin worked case and seven category profiles.
- Read-only analysis scripts (`inventory.ps1`, `pe_triage.py`, `snapshot_diff.py`, `frida/trace_launch.js`).
- `DebloatEngine.ps1` with `New-AppScript` and the single-file per-app template.
- `setup_re_backend.ps1` doctor and user-scope installer.
- Synthetic examples generated by `tools/make_fixtures.py`.
