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
