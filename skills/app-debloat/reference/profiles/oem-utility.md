# Profile: OEM hardware utilities

PC-maker control centers: Lenovo Legion Zone / Vantage / Legion Space, ASUS Armoury Crate, MSI Center, Dell SupportAssist, HP Omen Gaming Hub and similar. They mix hardware control that has no Windows equivalent (fan curves, power modes, battery charge limits, keyboard light, hotkeys) with news feeds, store promos, game recommendations, telemetry and their own update engine. This profile needs the real hardware; it is not part of the paired evaluation.

## Architecture and where the junk lives

- **UI app**: often a Store/MSIX package or Electron/WPF front end. Hosts the news, promo and "recommended" content.
- **Hardware bridge**: a service plus a vendor WMI/ACPI driver that talks to the embedded controller (EC). Lenovo: Lenovo Vantage Service, System Interface Foundation (SWC device `ImController`, `Lenovo.Modern.ImController.exe` with plug-ins), Energy Management and "Vantage Gaming Feature Driver". These are core for fan, power mode and battery features on many models.
- **Plug-in or add-in manager**: downloads feature add-ins on demand (Lenovo ImController plug-ins, Vantage add-ins under `%ProgramData%\Lenovo\Vantage\`). Mix of core and junk.
- **Update engine**: system update agent, driver and BIOS updater, often a SYSTEM service plus tasks.
- **Telemetry and marketing**: data collector services, message/notification services, preinstalled trial software offers.

## Launch, persistence and re-install vectors

This category has vectors that no other profile has: the OS and the firmware install the software for the vendor.

| Vector | Form | Proof it is blocked |
|---|---|---|
| Windows Update driver + Software Component (SWC) | A driver INF with a software component child device installs the service and even the UI app (Lenovo ImController returned after a Windows update: https://zhuanlan.zhihu.com/p/838581577) | Device Manager "Software components" shows no new child; service not recreated after a WU cycle |
| WPBT (Windows Platform Binary Table) | Firmware hands Windows a binary at every boot (Lenovo LSE historically, ASUS installer prompt on some boards) | No new file under `System32` from WPBT after boot; vendor installer not launched |
| BIOS option | ASUS "Download and install Armoury Crate app" style setting | Setting off in firmware (owner action) |
| Store auto-update | MSIX UI re-installed or updated by the Store | Package version stable, or app removed by the owner |
| Vendor update service and tasks | System update service, scheduled scans | Tasks disabled, service disabled or manual |
| Plug-in manager | Downloads add-ins on demand | Add-in dir stable over a day |

## Gates

- **UI preferences**: message categories ("App features", "Marketing"), toolbar, news cards, "recommended" sections. Lenovo Vantage: Preference Settings, Messages (https://www.techfinitive.com/explainers/what-is-lenovo-vantage-should-i-uninstall-it/).
- **Add-in manifests and feature flags** under `%ProgramData%\<Vendor>\` (JSON or XML). Remote-config driven on many builds.
- **WU policy**: "Do not include drivers with Windows Updates" stops all driver delivery, not just the vendor's (https://learn.microsoft.com/en-us/windows/deployment/update/waas-wufb-group-policy). Owner decision; usually too broad.
- **Device installation restrictions** by hardware ID can block one SWC device from being installed (approach described at https://ccmexec.com/2025/09/prevent-software-installations-disguised-as-drivers/). Use only for SWC IDs proven to carry junk, never for the hardware bridge.
- **WPBT**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` `DisableWpbtExecution`=1 is undocumented (https://github.com/Jamesits/dropWPBT). Some vendors offer a firmware toggle or a disabler tool. Owner decision, note it, do not apply by default.

## Core: do not touch

Write this list per model in the core contract before P4. Default "do not touch" set:

- EC, ACPI/WMI and hotkey drivers and their services (Lenovo: Energy Management, Vantage Gaming Feature Driver, Hotkeys / Fn utilities, the parts of System Interface Foundation that power mode and battery limit need).
- Any service whose stop changes fan behavior, power mode, charge threshold, keyboard light, display overdrive or the Fn+Q / mode key.
- Firmware and BIOS update components while an update is pending.
- Never touch: firmware settings, EC registers, undervolt or overclock controls. That is hardware risk, not debloat.

Rule from the brief: hardware-control drivers and services go on the "never touch" list (https://bbs.csdn.net/weixin_29895109/article/details/100447847). If a junk feature and a core feature share one service, leave the service and attack the junk at the UI/add-in level.

## Levers

Use:

1. UI preferences: marketing and app-feature messages off, news and recommendations off, toolbar off, startup of the UI off (the service keeps hardware features alive on most models; verify).
2. Disable (not delete) telemetry and marketing services that the probe proves are unrelated to hardware control. Journal start type and recovery actions.
3. Disable vendor scheduled tasks for promos, surveys and "recommended software".
4. Outbound firewall rule by program path for promo or store helper exes only.
5. Device installation restriction by hardware ID for junk SWC devices, only after proving the hardware bridge does not depend on them.
6. IFEO on vendor-unique promo helper names.

Avoid:

- Removing System Interface Foundation / ImController wholesale when hardware features depend on it (LLT notes that removing only some of the three Vantage components disables options: https://github.com/LenovoLegionToolkit-Team/LenovoLegionToolkit).
- Blanket "disable every service named <Vendor>" (breaks hotkeys, charging, docking, cameras).
- Global WU driver block as the default lever.
- WPBT disable as the default lever.
- Killing the bridge service during a fan or power transition.

## Integrity, anti-tamper and ban risk

- No account ban risk; warranty and support risk if the vendor tool is needed for diagnostics. Note it in the analysis.
- Hardware risk is the real one: a wrong lever can leave fans in a quiet mode under load. The probe below must run under load before and after.
- Tier: normal for UI and promo helpers; out-of-process for driver packages (never edit INF or driver files).

## Verification probes

Before any change, record a baseline for each item; repeat after apply, after reboot, and after one Windows Update scan.

1. Power mode switches through every mode via the vendor key or UI, and the mode is reported back (vendor WMI query or UI readout). Record CPU package power or clock under a 60 s synthetic load (for example a single-thread busy loop) per mode; the values must differ like the baseline.
2. Fan response: under the same load, fan RPM (vendor WMI or sensor tool) rises like the baseline. Never set fan curves as part of the probe.
3. Battery charge limit / conservation mode toggles and is read back.
4. Keyboard light and the Fn hotkeys in the contract still work (owner confirms physically when no readback exists).
5. Device Manager: no new "Software components" children and no vendor service recreated after the WU scan.
6. No promo or news window within one hour idle (enumerate top-level windows by PID).

## Public projects and recipes

- Lenovo Legion Toolkit, community replacement for Vantage / Legion Zone / Legion Space with built-in disablers for Vantage, Legion Zone and Hotkeys (GPL-3.0): https://github.com/LenovoLegionToolkit-Team/LenovoLegionToolkit (original repo archived: https://github.com/BartoszCichecki/LenovoLegionToolkit). Note for the owner only: replacing the vendor tool is out of scope for this skill; its disabler list is useful as evidence of which tasks, services, drivers and autoruns each Lenovo app owns.
- Lenovo ImController uninstall tool (official): https://iknow.lenovo.com.cn/app/detail/201735
- ImController returning after Windows Update: https://zhuanlan.zhihu.com/p/838581577
- Lenovo components re-installed via WU SWC and driver INF: https://www.reddit.com/r/LenovoLegion/comments/vg09x6/remove_tobii_virus/ and https://ccmexec.com/2025/09/prevent-software-installations-disguised-as-drivers/
- WPBT background and disable options: https://eclypsium.com/blog/everyone-gets-a-rootkit and https://github.com/Jamesits/dropWPBT
- ASUS Armoury Crate first-boot install and official uninstall tool: https://www.asus.com/support/faq/1041654/
- Commercial Vantage components and paths (`%ProgramFiles(x86)%\Lenovo\VantageService\<ver>`, add-ins in `%ProgramData%\Lenovo\Vantage\`): https://download.lenovo.com/pccbbs/thinkvantage_en/lenovo_commercial_vantage.pdf
- Dell SupportAssist services list (Dell Client Management Service, Data Vault, TechHub): https://www.dell.com/support/kbdoc/en-us/000131491/supportassist-for-pcs-and-tablets-clean-uninstall-and-reinstall
