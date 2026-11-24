# Pipeline: P4 to P7

Continues `pipeline.md` (evidence rules and the read-only stages P0 to P3). Same conventions: every stage writes to the private ledger before the next one starts; "unknown" is allowed, blank is not.

## Elevation

Several steps need Administrator: the elevated read-only bundle at P0, `-Apply`, `-Install`, `-Uninstall`, and some P6 checks. A UAC prompt nobody answers times out after about two minutes and reads as "canceled by the user".

1. Ask for elevation only when the owner is present, and batch the elevated work so one prompt covers it (P0: `scripts/elevated_readonly.ps1 -Key <manifest id>`, the id the built script will use; drop `-Key` under a read-only instruction or a write restriction, see `safety.md` §8. P1: the idle capture's `launch_monitor.ps1`, which runs unelevated when the owner is absent. P6: apply plus its checks, the after-apply capture included). An elevated monitor never starts the app: start it from a normal shell (`pipeline.md`, P1).
2. If UAC is declined or times out, retry at most once.
3. Then stop after the dry run. Write the exact elevated command block into `verification.md` (working directory, script path, mode switches, option switches, where its output goes) so the owner can paste it into an elevated terminal, and mark every elevated step `proposed`, not `performed`.

Never work around a declined prompt (no scheduled task as SYSTEM, no other elevation trick).

## P4 Plan

Goal: a reviewed `plan.md` with the five mandatory sections of `reference/plan-template.md`: core preservation, targeted levers, durability, reversibility, feasibility and honesty.

Steps:
1. Label every component: core, ad, AI, telemetry, updater, repair, unknown. Unknown stays untouched.
2. Choose levers from `reference/levers.md`, least-flagged and narrowest first. Prefer disable over delete, block over patch, per-binary over machine-wide.
3. For each action write: target, lever, evidence IDs and copied status, default or named option, original state and ownership, undo with its conflict rule, verify check, and whether `-Install` may re-assert it (only blocking actions).
4. Map every `L-RI` path to a control and a reapply trigger; state version and path drift handling.
5. Get the owner's consent for account-bound apps before anything in-tree is planned.

Checkpoints (each answer a ledger entry with `stage` `P4`, `ledger.md`, Checkpoint Answers):
- What looks like bloat but is core: helpers that carry dictionary sync, hotkeys, fan or EC control, the main window's host, cloud candidate engines. Each "keep" gets a reason; leaving a component alone is a valid outcome.
- Does this app tolerate in-tree changes (P0 tier)? If not, only services, tasks, firewall, IFEO and external config.
- Is any default action `inferred` or `hypothesis`? Move it behind an option. Options the owner chooses to pass at apply are listed as "owner choice" with their evidence status unchanged. Does any sentence promise complete blocking without a `VER` entry? Reword it.
- Does blocking an updater freeze a browser engine or a network-facing component? Then section 5 states the security-update cost.
- Checks are split into proposed and performed.

Exit: `plan.md` passes the template checklist and is approved by the owner where consent is required.
Artifacts: `plan.md` (private).

## P5 Build Script

Goal: one idempotent PowerShell script for the app.

Steps:
1. Write the plan as a manifest (`reference/manifest.md`): actions with targets, levers, evidence IDs, the copied evidence status and reapply flags, not ad hoc code. Paths use the `{root}` token. Settings files use `ini-set` or `json-set`; files that must survive but may be edited by those actions go in `core.preserve`, files nothing may touch in `core.files`. `inferred` and `hypothesis` actions get a `when` option and are off by default. App-specific logic (for example a config codec) goes into a hooks file as clearly named scriptblocks.
2. Build the single-file script: dot-source `scripts/DebloatEngine.ps1`, then `New-AppScript -ManifestPath <manifest.json> -HooksPath <hooks.ps1> -OutFile <App>Debloat.ps1 -EnginePath <path to DebloatEngine.ps1>`. It inlines the engine (path guard, placeholder, IFEO, Blocked, ACL, service, task, firewall, ini and json settings, journal, preboot task, install and uninstall), the manifest and the hooks into `templates/app-debloat.template.ps1`, so users download one file.
3. Modes: dry run by default (prints the plan, changes nothing), `-Apply` (exactly the printed plan, journals original state on first touch), `-Install` (admin-only state dir, logon plus 6-hourly task, applies once), `-Uninstall` (removes what it registered, replays the journal). Exactly one mode switch per run.
4. Save as UTF-8 with BOM, target Windows PowerShell 5.1.
5. Run the dry run as the user. A non-elevated dry run cannot see SYSTEM tasks, so a task search there can read 0 matches for tasks that exist. `elevated_readonly.ps1 -Key <manifest id>` saves its elevated task list to `%ProgramData%\AppDebloat\<id>\elevated-tasks.json`, and the dry run reports that list's match count and date next to the live one; rerun it after the vendor adds or changes tasks. If `-Apply` cannot be elevated, follow the elevation rule above and stop here.

Exit: dry run on the target machine prints the expected plan; a second `-Apply` reports only SKIP (or the elevated command block is handed over).
Artifacts: `<app>-debloat.ps1`.

## P6 Verify

Goal: prove by behavior that bloat is gone and the contract holds.

Steps:
1. Before and after: process tree, loaded modules per host, outbound connections (Sysmon 3 and 22, `scripts/launch_monitor.ps1`, or a live snapshot). The after-apply `launch_monitor.ps1` capture has the same length as the P1 idle capture, at least 20 minutes (`-Seconds 1200`), so before and after compare like for like and a helper that starts ten minutes in still shows. Like P1, run it in the background and wait for it to finish (a foreground agent shell call is cut off at 10 minutes, before that helper starts), and run it elevated (for the process start trace) when the owner is present, without `-Launch`: start the app from a normal shell after the monitor's `start` line (`pipeline.md`, P1). Then run `python -I scripts/new_files_since.py --since <capture start> --out <private dir>\new-files-after.json --summary` to see whether anything dropped an installer or package outside the roots during the capture (`pipeline.md`, P3).
2. Screenshots of the app's own windows with `scripts/shot_windows.ps1 -Root <root> -Out <private dir>` (DPI-aware PrintWindow, no input sent). Never photograph the whole desktop. IME windows (an input method's status bar or candidates, created inside the focused process) are listed as skipped and never captured. A window hidden to the tray is listed with `visible: false`, and `counts.processes_alive` with "process(es) alive with only hidden windows" on the console separates "the app runs hidden" from "no app". A minimized window cannot paint: the index lists it with `minimized: true` and its restored size (none when `restores_maximized: true`), and it is not captured, because restoring the owner's window would be input. Apps may also start minimized because they restore their last window state. When the app's only window is minimized or hidden, pick one:
   - Stronger: open a window yourself through the app's own command line or entry point (the launch command recorded at P1, or a documented switch such as a new-window flag), then run `shot_windows.ps1` again and capture that window. When the agent itself started the running instance in this run, relaunching the entry point to show that instance's window is this pass, single-instance app or not, but only when both hold in the `launch_monitor.ps1` output of that run: its first poll (the `proc_running` lines, written before the start) shows no process of the app other than service processes (lines with a `service` field), and the window's `pid` in the `shot_windows.ps1` index is the PID the agent started (the `launched` line, or the PID `Start-Process -PassThru` returned, shown in a `proc_start` line) or a tracked descendant of it (follow `ppid` through the `proc_start` lines). A `launched` line alone does not show that the running instance is the agent's: a single-instance app hands the agent's launch to the instance the owner already had open and exits, and the line still says `launched`. Otherwise treat the instance as the owner's: when the app is single-instance, relaunching would restore the owner's window, so do not relaunch; take the weaker pass, or ask the owner to open a window.
   - Weaker: record "process up + window present (minimized)" as a `VER` entry anchored on the index line (title, class, restored size or "restores maximized"), and write in `verification.md` that the window's content was not seen. It does not pass a contract probe that needs the window's content.
3. Run every contract probe. Keystroke probes go only into a window the agent created; verify foreground and read back committed text (see `safety.md`).
4. Reboot and repeat. Then trigger the app's own repair or update path once and repeat. For an updater with a wake task, the recipe:
   - Read the wake task from the elevated bundle (`tasks\*.xml` from `scripts/elevated_readonly.ps1`): its `<Command>` and `<Arguments>`. The bundle writes credential-like values as `<redacted>`; if the arguments hold one, the trigger is not a plain wake: ask the owner instead of reconstructing it.
   - Before: the updater's own log (size and last lines), the state and start mode of its services, and a listing of the updater folder.
   - Start `scripts/launch_monitor.ps1 -Root <root>, <updater folder>` in the background (the updater's folder as a root when it lies outside the app's root, so the updater is tracked by its path; add `-WatchNames` for generic names such as `updater.exe`). After its `start` line, start that exe with exactly those arguments as the user, from a normal shell: `$p = Start-Process <exe> -ArgumentList '<arguments>' -PassThru` (once `$p.HasExited`, `$p.ExitCode` is the exit code below). Never from an elevated shell, and never through an elevated monitor's `-Launch` (it refuses): an updater with the admin token can write Program Files or do its SYSTEM work itself, which changes the machine and voids the COM test below. When the monitor runs unelevated, `-Launch <exe> -LaunchArgs '<arguments>'` does the same. Then run `new_files_since.py` for the same window.
   - After: the exit code, how much the updater's log grew and what it says, the service states, and the folder listing again. For a Manual SYSTEM service the engine could not disable (`knownFailure`), this run also shows whether a user process can still wake it through COM (a `service` line in the monitor output, a Running state); if it can, the firewall rule on its exe is the fallback (`levers.md`, Service Disable).
   - Ask the owner before triggering it: an inactive updater version may uninstall itself on wake, which cannot be undone (`profiles/chromium-fork.md`, Updater Versions). Record the trigger and its result as `VER` entries, and a self-uninstall as an `RI` entry.
5. Delayed re-read after a few minutes and after reboot: IFEO, Blocked and ACL changes still present (AV may revert them).
6. Run the script again: it must report SKIP for everything.

When elevation was not available, P6 records only what ran as the user and lists the rest under `Proposed checks` next to the handed-over command block.

Exit: contract passes after reboot, no bloat process or module, no unexpected changes reverted.
Artifacts: `verification.md` (private) with timestamps, counts, screenshots and probe results.

## P7 Keep Applied

Goal: survive upgrades and repairs without repeating destructive work.

Steps:
1. Install only after P6 passes. The scheduled task runs `-Auto` (logged `-Apply`) at logon and every 6 hours, re-asserting blocking actions only.
2. Store a version fingerprint (product version plus hashes of key binaries). On an unknown version or a changed fingerprint, version-bound actions stay inactive unless the owner passed an explicit force choice; the run logs a warning and says P1 to P3 should be re-run.
3. Never auto-update the script from the network; re-run `-Install` for a new release.

Exit: task registered, first automatic run logged clean.
Artifacts: auto log and per-run history line in the state dir; ledger entry with the fingerprint.
