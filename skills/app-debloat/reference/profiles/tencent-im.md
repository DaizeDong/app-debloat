# Profile: Tencent IM Clients (QQ, QQNT, TIM, WeChat / Weixin)

The highest-risk profile. Accounts are valuable, the vendor ships file verification and a driver-protected security service, modified clients have been kicked offline or banned, the user agreement forbids removing components or modifying memory, and Tencent has used DMCA section 1201 notices against key-extraction repos. Default tier: **out-of-process only**.

## Hard Rules for This Profile

- Explicit owner consent for this specific app and account before P4, after stating the ban risk in plain words.
- No change inside the install root or the version directories: no rename, no placeholder, no ACL, no resource edit, no DLL drop-in, no patch.
- No injection, no hooking of the running client, no memory edits. frida is only for the agent's own test processes, never the IM process.
- Recipes for this profile live in the private companion repo only. The public skill keeps this generic profile.
- Probes send messages only to the owner's own account (file transfer assistant or "My device"), only with owner consent.

## Architecture and Where the Junk Lives

- **QQNT / TIM NT**: Electron-based. `%ProgramFiles%\Tencent\QQNT\QQ.exe`, versioned app dirs under `versions\<ver>\resources\app`, hot-update state in `versions\config.json` (`curVersion`, `readyVersion`, `readyType`). Junk: news and mini-program panels, game and ad panels, guild/channel modules (`%LOCALAPPDATA%\Tencent\QQGuild` reported), hot-update downloads.
- **Classic QQ (Win32)**: `QQProtect.exe` with the `QPCore` service and the `QQProtectX64.sys` driver under `%CommonProgramFiles(x86)%\Tencent\QQProtect`. The service resists being disabled ("self-protection" per Tencent support quotes). Reports conflict on whether newer Win32 builds still need it (https://www.zhihu.com/question/265963430, unverified).
- **WeChat 4.x (Weixin)**: `%ProgramFiles%\Tencent\Weixin\<ver>\`, user data and update cache under `%APPDATA%\Tencent\xwechat\` (`update\`), updater plugin at `%APPDATA%\Tencent\xwechat\xplugin\plugins\WeixinUpdate\<id>\extracted\WeixinUpdate.exe`; the `<id>` changes over time.
- **Shared Tencent components**: helper services and SDKs shared with other Tencent apps; disabling them can affect other Tencent software on the machine.

## Launch, Persistence and Re-Install Vectors

| Vector | Form | Note |
|---|---|---|
| Hot update (QQNT) | Downloads from `qqpatch.gtimg.cn` style hosts and CDN variants into `versions\`; `readyVersion` in `config.json` means already downloaded, applied at next restart | Blocking hosts does not undo a package that is already staged (https://github.com/fjh1997/cat, post on QQNT/Weixin update blocking, community) |
| Weixin updater plugin | `WeixinUpdate.exe` re-extracted into a new numbered plugin dir | Locking one plugin dir is beaten when a new id appears (https://github.com/afaa1991/BetterWX-UI/issues/49) |
| Weixin update cache | `%APPDATA%\Tencent\xwechat\update` | Outside the install root; a deny-write ACE here is the out-of-process lever the community uses |
| Scheduled tasks | Vendor update tasks (names vary; enumerate) | Disable, never delete |
| QPCore service | Automatic start, reset to automatic when QQ launches, ACL-hardened | Disabling it can stop QQ from starting |
| Installer repair | Running the installer restores everything | P7 must detect version change |

## Gates

- `versions\config.json` (QQNT): describes which version runs; editing it is an install-dir change and is forbidden here.
- In-app settings: auto-update toggle (Weixin "auto upgrade when available"), startup, news and panel toggles. Community reports say Weixin still updates with the toggle off; verify by behavior.
- Server switches: forced minimum versions. An old client may be refused at login regardless of local blocks.
- QQNT file verification: SHA-256 manifest checked at start; LiteLoaderQQNT needs a third-party `dbghelp.dll` drop-in to bypass it (https://liteloaderqqnt.github.io/guide/install.html). For us this is proof that in-root edits are detected.

## Core: Do Not Touch

- Everything in the install root and version dirs, `QQ.exe` / `Weixin.exe` and their children, `QQProtect` while QQ needs it, user data and chat databases.
- Shared Tencent services used by other Tencent apps the owner runs.
- Login, message sync, file transfer, voice/video if in the contract.

## Levers

Use (all out of process):

1. In-app settings: startup off, auto-update off, news and panel toggles off.
2. Disable vendor update scheduled tasks (journal the original state).
3. Outbound firewall rule by program path for updater exes that live outside the install root (Weixin `WeixinUpdate.exe` per plugin id; re-enumerate in P7 because the id changes).
4. Deny-write ACE on update cache dirs outside the install root (Weixin `xwechat\update`), after deleting a staged package with the client fully exited.
5. Disable optional Tencent services that the integrity probe proved are not needed for login (test, do not assume; QPCore is often needed).

Avoid:

- Any file or ACL change inside the install root or `versions\` (file verification, forced logout, ban reports).
- `sc delete QPCore` or deleting the driver (guides that do this end with QQ no longer starting).
- Firewall-blocking `QQ.exe` / `Weixin.exe`.
- hosts entries for `dldir*.qq.com` or other shared Tencent download domains: they also serve other Tencent software and installers.
- Anti-recall or other client patches, DLL drop-ins, sandboxing tricks presented as debloat.

## Integrity, Anti-Tamper and Ban Risk

- Modified QQNT clients were kicked offline or banned: https://github.com/LiteLoaderQQNT/LiteLoaderQQNT/issues/1063
- WeChat patched for anti-recall forced offline the same day: https://github.com/huiyadanli/RevokeMsgPatcher/issues/922
- User agreement forbids removing components and modifying memory: https://rule.tencent.com/rule/46a15f24-e42c-4cb6-a308-2347139b1201
- QQProtect has driver protection: https://github.com/KaneGreen/idontwantqqprotect
- DMCA 1201 notice against WeChat key extraction (1,464 forks disabled): https://github.com/github/dmca/blob/master/2026/07/2026-07-13-wechat.md
- Integrity probe for this profile is out of process only: change one external lever at a time and watch for forced logout, a repair download or a verification error. Never rename files in the install root to probe.

## Verification Probes

All only with owner consent, on the owner's own account:

1. Client starts and stays logged in across restart and reboot.
2. Send a short synthetic text (for example `app-debloat probe <timestamp>`) to the file transfer assistant / "My device"; confirm it appears on the owner's phone or in the history. Never message a third party.
3. Optional: send a small synthetic file to self.
4. Forced update check: no updater process, no new plugin dir, `readyVersion` stays empty (read-only check of `config.json`), version unchanged.
5. 24 hours later: still logged in, no warning messages from the vendor account about "unofficial client".

## Public Projects and Recipes

- QQNT and Weixin 4.x update channels, `config.json` `readyVersion`, `xwechat\update` lock and per-plugin firewall rules: https://github.com/fjh1997/cat/blob/main/content/posts/Windows%E5%BE%AE%E4%BF%A1QQNT%E9%98%BB%E6%AD%A2%E8%87%AA%E5%8A%A8%E6%9B%B4%E6%96%B0%E4%BB%A5%E9%85%8D%E5%90%88RevokeMsgPatcher.md (community; hosts part blocks shared domains, do not copy that part).
- Weixin updater plugin path and lock attempts: https://github.com/afaa1991/BetterWX-UI/issues/49
- QQNT file verification patch (evidence of verification, not a lever): https://github.com/LiteLoaderQQNT/QQNTFileVerifyPatch
- QPCore behavior and failed removal attempts: https://www.zhihu.com/question/30848564, https://blog.csdn.net/Fanzongshen/article/details/117384061 (old QQ versions).
- Tencent ad-blocking case law in China (unfair competition, the Qihoo 360 "QQ Bodyguard" case, CNY 5 million): https://www.wipo.int/wipolex/en/text/578096
