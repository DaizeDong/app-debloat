# Plan Template

`plan.md` is the P4 deliverable: the reviewed decision record that the manifest (P5) is built from. It is DATA and lives in the app's folder in the private companion, next to the ledger it cites. Examples here are synthetic (`ExampleApp` by `AcmeCorp`).

A plan has exactly five mandatory sections, in this order, each with the concrete contents listed below. A section that cannot be filled says "unknown" and why; a missing or empty section means P4 is not done. Every factual sentence cites ledger IDs (`reference/ledger.md`); a sentence without one is an opinion and is labelled as such.

## Rules That Apply to Every Section

- **Status decides activation.** Each action copies the evidence status of the weakest ledger entry it relies on (`observed`, `anchored`, `inferred`, `hypothesis`). Only `observed` and `anchored` actions may be default actions. `inferred` and `hypothesis` actions ship inactive behind a named option (manifest `options[]` plus `when`), with the probe that would promote them. A hypothesis never becomes a default action, however plausible.
- **Owner choice does not change evidence.** When the owner chooses to pass an option at apply (for example a blanket "block all updaters"), the plan lists that action as `owner choice: <Name>` and keeps its evidence status as it was. Owner consent turns an option on; it never promotes `inferred` to `observed`.
- **Owner choices become defaults only after a real test.** An option the owner tried at apply is promoted to a default (manifest `default: true`, plan row changed from `owner choice` to `default`) only after the owner ran the core test it could break (for a drive: a real upload and download; for a translator: a lookup) and the machine rebooted once with it applied. Record both as `VER` entries; until then it stays an option. A promotion does not change the evidence status.
- **Accepted failures are named.** An action that is denied for an explained reason (a security-suite veto, a protected service) carries `knownFailure {reason, ref}` in the manifest; the plan lists it with its fallback actions in section 3 and as a residual in section 5.
- **No unproven promises.** Do not claim a component is "fully blocked", "never returns" or "gone" unless a ledger `VER` entry shows it after the relevant trigger. Without that, write what the action does and what is still unknown.
- **Leaving something untouched is a valid result.** An evidence-backed decision not to act (core dependency, shared component, no safe lever, licensing risk) is recorded as a decision with its IDs, not as a gap.
- **Narrowest control wins.** Prefer an app-owned switch over a per-app block, a per-binary block over a per-folder block, and anything over a machine-wide or shared change.
- **Proposed is not performed.** Every check is labelled `proposed` or `performed`; only `performed` checks carry results, timestamps and `VER` IDs.

## 1. Core Preservation

What must keep working, and therefore what must not be touched.

Must contain:
- **Core workflows** for THIS app, as the user experiences them (not generic): for example "upload a folder and see it in the web client", "type Chinese in a Store app", "sync a dictionary across devices". One line each, with its `L-CORE` ID.
- **Dependencies of each workflow**: the processes, DLLs, services, tasks, network endpoints and settings it needs, with IDs and status. Mark unknown dependencies as unknown.
- **Safe versus unsafe targets**: a table of every candidate component with verdict `target`, `keep` or `unknown`. `unknown` is treated as `keep`. Every `keep` has a one-line reason.
- **Functional checks for later**: for each core workflow, the probe P6 will run (exact steps and pass condition), and which actions could break it.

```
| Component         | Role guess | Verdict | Why                                    | Evidence                |
|-------------------|------------|---------|----------------------------------------|-------------------------|
| PopNews.exe       | ad         | target  | spawned only by UpdHelper -silent      | L-EDGE-003 (observed)   |
| SyncCore.dll      | core       | keep    | carries folder sync (L-CORE-002)       | L-INV-011 (observed)    |
| AiPanel\          | AI         | unknown | main window imports it; impact untested| L-INV-019 (hypothesis)  |
```

## 2. Targeted Levers

What each action changes and why that is the smallest sufficient change.

Must contain an action table, one row per action:

| Field | Content |
|---|---|
| ID | `A-NN`, stable; the manifest action uses the same ID |
| Target | exact resource: full path pattern under a resolved root, service name, task path, value path with view |
| Lever | from `reference/levers.md` |
| Evidence | the ledger IDs it relies on and the copied status (weakest of them) |
| Default or option | `default` (observed or anchored only) or `option: <Name>` (inferred, hypothesis, or user choice) |
| Why narrowest | why a smaller control would not work (for example the gate is server-pushed, so a per-binary block is needed) |
| Shared or OS impact | why it does not touch shared runtimes, other apps, system binaries or machine-wide policy; if it does (hosts file, IFEO by bare name, browser policy), say so and make it an option |
| Licensing | confirm it does not interfere with licensing, login, payment or entitlement checks |

Rules:
- IFEO by bare executable name, hosts entries, firewall rules for shared hosts and policy keys read by other apps are machine-wide by nature. They are options unless the name or key is proven unique to this app.
- Wildcards (task names, AUMIDs, paths) must be justified by an enumeration showing what they match today, and are re-resolved and re-checked at apply time.

## 3. Durability

How each block survives the app's own ways of coming back.

Must contain a matrix with one row per known path from the ledger's `L-RI` entries (updater, repair exe, service recovery, component manager, cloud SDK, installer re-run, Store or Windows Update package, user "repair" button):

| Return path (ID) | Writer and trigger | Control (action IDs) | Reapply trigger | Proof status |
|---|---|---|---|---|
| UpdHelper repair (L-RI-004) | SYSTEM service, missing file | A-04 placeholder + A-05 deny-write | watch task at logon and every 6 h | performed: L-VER-007 |
| Installer re-run (L-RI-006) | user, manual | none; documented | user re-runs `-Install` | proposed |

Must also state:
- **Deferred while running**: every action that is skipped while the app runs (`onlyWhenNotRunning`, or a hook that skips while the app is running), each with its gap stated: the watch task re-asserts it only on a run that happens to find the app closed, so a setting the app rewrites while it runs can stay reverted for that long. Say whether the app keeps running after its window is closed (background or tray mode, observed at P1 with `launch_monitor.ps1` and `shot_windows.ps1`); if it does, the gap lasts until the app is fully exited or the machine restarts, and say how the owner closes it fully.
  Example: `A-11 floating-ball off (hook, skips while running) | app stays in the tray after its window closes (L-INV-021) | re-asserted only at a logon or 6-hourly run that finds it closed | gap: open`
- **Version drift**: the supported version range (only versions actually inspected), what happens on an unknown version (blocking actions stay inactive until P1 to P3 are re-run, or the user passes an explicit force switch), and how the fingerprint change is reported.
- **Path drift**: which targets are resolved by name or registry pointer at run time rather than fixed path, and what the script does when a target disappears or moves (skip with a warning, never widen the match).
- Paths with no control are listed as open, not hidden.

## 4. Reversibility

How every action is undone without damaging anything the user did later.

Must contain, per action:
- **Original state** captured on first touch (value and type, start mode and recovery actions, ACL, task XML, file hash and whether a copy is kept), and **ownership**: how the script recognizes what it created (exact value it wrote, rule name plus program path, task description, deny ACE for one SID).
- **Undo**: the exact restore step, and the conflict rule: undo restores only when the current state still equals what the action wrote; otherwise it reports a conflict and leaves the current state alone.
- **Irreversible parts**: anything the script cannot restore by itself (deleted vendor bytes need a reinstall or the app's repair). These actions are options, never defaults, unless the file is kept as a copy.

Must also contain:
- **Ordered rollback**: the order `-Uninstall` runs (reverse of apply), what happens when one step fails (keep its journal record, continue, exit non-zero), and how to finish a rollback after an interruption.
- **Recovery** when the app is broken after apply: the shortest path back (uninstall mode, then the app's own repair, then reinstall), and which data survives.
- **Later user changes**: how settings the user changed after apply, files added to the state folder, and unrelated rules or tasks with similar names are preserved.

## 5. Feasibility and Honesty

What will actually be done, by whom, and what is still not known.

Must contain:
- **Sequence**: the numbered steps from dry run to verified install, with the command for each and where the owner must act (approval, consent for account-bound apps, reboot, triggering an update).
- **Privileges**: which actions need elevation, which run as the user, which need SYSTEM or TrustedInstaller-owned keys, and what happens to them when the script runs without those rights.
- **Residual risks**: concrete ones for this app (for example "the main window may re-enable the AI panel after a server switch; L-GATE-004 is inferred").
- **Security-update cost** (required whenever an action blocks the updater of a browser engine, an embedded Chromium or another network-facing component): the engine version that is now frozen, that it will miss security fixes, and how the owner updates by hand (re-run the vendor installer, then P1 to P3 and `-Install`).
- **Server-pushed in-window content**: ads, popups and promotions drawn inside the app's own window from a remote config are a documented residual unless the owner opts into network-level blocking (router, DNS filter or proxy rule they run themselves). Name the config source and the probe that shows it.
- **Settings Map** (`reference/ledger.md`, Settings Map): one row per in-app switch that matters to the plan, from its `GATE` entry: key, storage (`plain`, `encrypted`, `server`), default, current value, menu path, engine-reachable, lever. Switches the plan sets show their toggle probe (`VER` ID, or `proposed`). Switches only the owner can flip (encrypted, server-side, or a plain one the owner chose to keep in their hands) are listed as owner actions with the menu path and the value to choose, including those to re-check after each update because an update dialog offers them pre-ticked.

  ```
  | Key                  | Storage   | Default | Current | Menu Path                              | Engine-Reachable | Lever          | Evidence                 |
  |----------------------|-----------|---------|---------|----------------------------------------|------------------|----------------|--------------------------|
  | [Main] ContextMenu   | plain     | 1       | 0       | Settings > General > Right-click menu  | yes              | ini-set A-07   | L-GATE-009, L-VER-004    |
  | clipboardWatch       | encrypted | on      | unknown | Settings > Notifications > Clipboard   | no               | owner action   | L-GATE-010 (anchored)    |
  ```
- **Unresolved areas**: every open `hypothesis` and `unknown` that touches the plan, with the probe that would settle it.
- **Validation split**: two separate lists. `Proposed checks`: what P6 will do. `Validation performed`: what was actually run, when, on which version, with results and `VER` IDs. Do not merge them, and do not describe a proposed check in the past tense.

## Checklist Before Approval

- Five sections present, in order, none blank.
- Every default action is `observed` or `anchored`; every other action sits behind a named option.
- Every owner-choice action is marked as such with its original evidence status; any promoted to default has a core-test and a reboot `VER` entry.
- Every `knownFailure` has a ledger reference and a fallback lever.
- Section 5 states the security-update cost for every blocked updater of a browser engine or network-facing component.
- Every `keep` and every untouched candidate has a reason and IDs.
- Every return path in the ledger appears in the durability matrix.
- Every action deferred while the app runs is listed in section 3 with its gap, and section 3 says whether the app keeps running after its window is closed.
- Section 5 has the Settings Map: every switch the plan sets has its toggle probe, and every switch only the owner can flip is an owner action with its menu path.
- Every action has original state, ownership, undo with a conflict rule, and a place in the rollback order.
- No sentence claims complete blocking without a `VER` entry behind it.
