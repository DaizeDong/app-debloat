# app-debloat, Design Philosophy

The skill exists because adware-ish desktop apps are built to survive the obvious fixes. Each principle below records the problem it answers, the decision, and what it costs.

## P1, Find the Real Gate Before Touching Anything
- **Problem and evidence:** Settings pages and registry toggles often only hide an entry point while the component still loads. In the Sogou Pinyin case the switches users can see changed nothing about loading; the real gate was an encrypted global component table read by the IME core.
- **Decision:** Every bloat component needs an anchored gate (file hash plus RVA, an xref list, or a runtime capture) or an anchored "no gate, block externally" before a plan is written. Verification checks module lists and processes, not file state.
- **Tradeoffs and limits:** Mapping gates costs analysis time and needs a reverse-engineering backend; offsets are valid for one build only.

## P2, Every Way Back Is Part of the Problem
- **Problem and evidence:** Removed components return through updaters, SYSTEM repair services, component managers, remote-config SDKs, Windows Update driver packages and OEM updaters. Community reports for Baidu Netdisk, Quark and Lenovo utilities show deletions undone within days.
- **Decision:** A re-install vector matrix is a required stage; each vector gets a block and a check that proves it is closed. `-Install` re-asserts blocking actions at logon and every 6 hours and warns when the app version changes.
- **Tradeoffs and limits:** Blocking an updater also blocks security fixes from that vendor. A manual reinstall by an administrator still undoes everything until the next automatic run.

## P3, Least Invasive Lever, Reversible by Default
- **Problem and evidence:** Debloat tools that delete or ACL-lock broadly break core features and leave incomplete undo; antivirus flags IFEO and hosts edits as hijacks.
- **Decision:** Levers are ordered least-flagged first (config gate, placeholder, service or task disable, firewall, Blocked, IFEO; hosts discouraged). Disable over delete, never `sc delete`. Every action journals its original state on first touch and `-Uninstall` replays the journal. No binary patching.
- **Tradeoffs and limits:** Some vendor files can only come back through a reinstall; the uninstall report names them.

## P4, App-Specific Analysis Is Mandatory
- **Problem and evidence:** No generic list fits: one app keeps settings in shared memory and flushes them over the file, another injects into every process, another bans modified clients.
- **Decision:** A fixed list of app-specific questions (tier, injection, real gate and its protection, settings that fight back, server switches, who writes the install dir, what only looks like bloat, cosmetic switches) must be answered in the ledger, with an anchor or a reasoned "unknown". Category profiles carry the known patterns.
- **Tradeoffs and limits:** Answers rely on the agent's inspection; profiles from community sources are marked unverified until confirmed on the machine.

## P5, Real Data Stays Private, Vendor Secrets Are Derived
- **Problem and evidence:** Real inventories reveal what the owner runs; vendors have issued takedown notices against repositories that published extracted keys.
- **Decision:** Ledgers, snapshots, journals and verification records live in a private companion repo. Public outputs carry no extracted keys, decrypted configs or patched binaries; anything secret is derived at run time from the user's own install.
- **Tradeoffs and limits:** Runtime derivation adds a scan step and can break when a vendor changes its format; the script then stops with a clear error instead of guessing.

## P6, The App's Reach into Other Software Is Part of the App
- **Problem and evidence:** The worst intrusions often sit outside the app's own folders and windows. Read-only sweeps of three real clients found native messaging hosts for two browsers, Office and WPS add-ins shipped unregistered and switched on by an in-app dialog, overlay identifiers named to push other vendors' sync icons out of Explorer's 11 third-party slots, video defaults re-checked on a timer and torrent and magnet ownership re-taken at every launch, a full installer staged in the profile outside the blocked updater, and a BitTorrent engine listening on all interfaces behind vendor inbound allow rules for every network profile. None of it shows in the app's settings page or its process list.
- **Decision:** A cross-app sweep (context menus, overlays, namespace entries, browser hosts and extensions, Office add-ins, defaults, listeners and P2P, staged installers) and a Settings Map of every in-app switch are required pipeline steps. Each category ends with a finding or a `negative` entry naming where it was searched, and the engine has dedicated actions for them (`reg-delete-value`, `browser-ext-block`, inbound firewall rules, `matchDefault` key deletes).
- **Tradeoffs and limits:** Some hijacks have no safe lever: `UserChoice` defaults are hash-protected and are released for the owner to re-pick, encrypted or server-side switches become owner actions, and a browser policy block shows "Managed by your organization", so it ships as an option.
