# app-debloat

逆向分析一个带广告的 Windows 软件，找出它的垃圾组件从哪里启动、又从哪里装回来，产出一个可反复执行、可完整撤销、软件更新后能自动重做的精简脚本。

[![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-orange?style=flat)](https://docs.anthropic.com/en/docs/claude-code)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![No Binary Patching](https://img.shields.io/badge/Binary%20Patching-None-green?style=flat)](skills/app-debloat/reference/safety.md)
[![Auto Re-Apply](https://img.shields.io/badge/App%20Updates-Auto%20Re--Apply-green?style=flat)](skills/app-debloat/reference/pipeline.md)
[![Languages](https://img.shields.io/badge/Languages-EN%20%2F%20CN-blue?style=flat)](#语言)
[![Roadmap](https://img.shields.io/badge/Roadmap-v1.0.0-purple?style=flat)](ROADMAP.md)
[![Release](https://img.shields.io/github/v/release/DaizeDong/app-debloat?style=flat)](https://github.com/DaizeDong/app-debloat/releases)

[English](README.md) | [中文版](README_CN.md)

---

## 设计理念

带广告的桌面软件，比如输入法、网盘、下载器、翻译软件、办公套件、电脑厂商自带工具、套壳 Chromium 浏览器，几乎都不给真正的关闭开关。广告、AI 插件和遥测是一个个独立组件，由启动器拉起，受一份设置界面管不到的配置控制，删掉后又会被更新器、修复服务或远程配置 SDK 装回来。它们还会把手伸到整台电脑上：给每个文件加右键菜单、在“此电脑”里放图标、装 Office 加载项和浏览器扩展、抢走 PDF 或视频的默认打开方式、开一个在所有网卡上监听的 P2P 引擎。删文件、关界面开关之所以总是失败，原因都一样：只处理了表象，没碰到真正的开关，也没堵住回来的路。

这个 skill 把在搜狗输入法上验证过的方法做成一条可重复的流水线：盘点软件在机器上放的一切，搞清楚每个组件由谁拉起、由什么决定运行不运行，列出所有回装路径，用最轻的手段封住它们，用行为来证明结果（进程、模块、网络连接、核心功能测试、重启一次、触发一次修复），软件更新后自动重做。通用步骤只负责找出候选。每个软件在动手之前，都必须回答一组固定的专项问题，因为没有两个软件把开关藏在同一个地方。

[设计说明](PHILOSOPHY.md)

---

## 它做什么

每次处理一个已安装的第三方 Windows 桌面软件。你告诉它软件名、哪些功能必须保留、想去掉什么，它产出：

- **证据账本**（`ledger.jsonl`）：关于这个软件的每一条结论（某个组件存在、A 拉起 B、开关 S 控制 B、路径 P 会把 B 装回来、操作 Z 生效了）都带状态和锚点，锚点可以是文件哈希加 RVA、抓到的命令行或一次注册表读取。
- **处置方案**（`plan.md`），固定五节：核心功能保全、精准手段、持久性、可撤销性、可行性与诚实说明。
- **一个 PowerShell 脚本**（`<App>Debloat.ps1`），由 JSON manifest 生成，默认只演练，支持 `-Apply`、`-Install`（登录时和每 6 小时重新确认一遍）和 `-Uninstall`。
- **验证记录**：执行前、执行后、重启后、触发一次修复后的计数和测试结果。

**不做**：整机 Windows 精简、清除恶意软件、卸载、浏览器广告拦截、破解或绕过授权、修改二进制、推荐别的软件。腾讯系客户端只做进程外处置。

## 流水线

| 阶段 | 目标 | 主要工具 |
|---|---|---|
| P0 准备 | 安装目录、版本和哈希；更新是否只做了一半；一次 UAC 收集提权才能看到的信息；选逆向后端；写核心功能清单；定风险等级；第一次启动前先记下更新器 | `inventory.ps1`、`elevated_readonly.ps1`、`setup_re_backend.ps1` |
| P1 盘点 | 每个文件、服务、计划任务、注册项、进程和连接；使用前后对比；跨软件挂接；网络暴露；资源占用 | `inventory.ps1`、`launch_monitor.ps1`、`strscan.py`、`snapshot_diff.py` |
| P2 启动链与开关 | 每个垃圾组件由谁拉起、由什么决定运行；开关测试；设置地图 | `pe_triage.py`、REA 或 Ghidra、`frida/*.js`、`stop_app.ps1` |
| P3 回装路径 | 每条把垃圾装回来的路，各配一个证明已堵住的检查；厂商在自己目录之外写了什么 | Procmon、`new_files_since.py`、服务故障恢复设置 |
| P4 方案 | `plan.md`：每个操作写清目标、手段、证据、默认或选项、原始状态、撤销方式和检查方法 | `reference/plan-template.md`、`reference/levers.md` |
| P5 生成脚本 | 由 manifest 生成一个幂等的单文件脚本 | `DebloatEngine.ps1` 的 `New-AppScript` |
| P6 验证 | 执行后、重启后、触发一次修复或更新后，看行为 | `launch_monitor.ps1`、`shot_windows.ps1`、`list_modules.ps1`、核心功能测试 |
| P7 保持生效 | 计划任务在登录时和每 6 小时重新确认拦截类操作 | 生成脚本的 `-Install` |

每个阶段都先写进账本再进入下一阶段，所以上下文重置之后可以从账本接着做。八个专项问题（风险等级与封号风险、注入、真正的开关、会被改回去的设置、服务端开关、谁在写安装目录、哪些只是看着像垃圾、哪些开关只是表面功夫）每一个都要有带锚点的答案，或者写明“未知”及原因。

## 能发现什么

**软件内部。** 启动链（创建进程、加载 DLL、COM 激活、TSF 和资源管理器加载），并在运行时确认；配置开关，包括加密的组件表和存在共享内存里的设置；更新器、修复程序、被 COM 唤醒的 SYSTEM 服务、藏在厂商子文件夹里的唤醒任务；运行时动态加载的遥测和广告 SDK；远程配置开关；只做了一半的自更新和启动时替换 exe；启动十分钟以后才出现的辅助进程；命令行里类似凭据的值（写入时替换成 `<redacted>`）。

**跨软件劫持。** 只读地扫一遍软件挂到其他软件上的每一处，不管当前是否生效：

- 右键菜单，包括 `SystemFileAssociations` 和 Windows 11 的打包菜单。
- 图标覆盖（overlay）：资源管理器一共 15 个覆盖位，留给第三方的只有 11 个，会列出排名，以及它把哪些别家的同步图标挤了出去。
- “此电脑”、桌面和导航窗格里的命名空间入口。
- Office 和 WPS 加载项（`Addins`、`Resiliency`、`LoadBehavior`），以及随软件附带、尚未注册的加载项文件。
- 浏览器扩展（`Extensions\<id>` 注册项、策略、从外部写进用户配置的条目），以及 Chrome、Edge、Chromium、Brave、Firefox 的原生消息主机。
- 默认应用被抢：文件类型、协议和默认浏览器，并用注册项写入时间区分是安装程序设的还是机主自己设的。
- P2P 引擎和监听端口：监听范围、UDP 端点数量、厂商的入站放行规则、UPnP 端口映射、调试端口。
- 预下载的安装包：下载到用户目录里的完整安装包，或放在安装目录之外的程序。
- 软件内设置：普通的 ini、json、`Local State`、`Preferences` 键，加密的或服务端的设置，以及安装程序的命令动词和环境变量开关，汇总成一张带菜单路径和开关测试结果的设置地图。

## 处置手段与引擎操作

手段按“最不容易被杀毒软件报、范围最窄”优先：关配置开关、同名占位、文件或目录拒绝写入 ACL、禁用服务、禁用计划任务、按程序的防火墙规则（出站，或针对监听端口的入站）、屏蔽 Shell 扩展、按映像名设置 IFEO，hosts 只作为不推荐的最后手段。删除注册项和浏览器扩展策略专门对付跨软件劫持。没有任何手段会修改二进制。

| 类别 | 引擎操作类型 |
|---|---|
| 服务和计划任务 | `service-disable`、`task-disable`（`taskPath` 递归搜索） |
| 文件和目录 | `file-placeholder-dir`、`dir-placeholder-file`、`acl-deny-write`（`write` 或 `write+protect`，可加 `emptyFirst`） |
| 进程和网络 | `ifeo-block`、`firewall-block-program`（`Outbound` 或 `Inbound`）、`hosts-block`（不推荐） |
| 注册表和资源管理器 | `reg-set`（包括 StartupApproved 的 `Binary` 标志）、`reg-delete-key`（`match`、`matchDefault`）、`reg-delete-value`、`shellext-block`、`toast-off` |
| 浏览器策略 | `browser-ext-block`（Chrome 和 Edge 的 `ExtensionInstallBlocklist`，可选 `removeExternal`） |
| 设置文件 | `ini-set`、`json-set`（都支持 `onlyWhenNotRunning`）、`preboot-file-edit`（给存在共享内存里的设置做一次登录前修改） |
| 软件专属 | `hook`（具名脚本块，比如在运行时从机主自己的安装里推导密钥的配置编解码器） |

完整字段说明见 [manifest.md](skills/app-debloat/reference/manifest.md)；各手段的取舍和劫持处置方法见 [levers.md](skills/app-debloat/reference/levers.md)。

## 安全模型

- **默认只演练。** 生成的脚本只打印计划，什么都不改；`-Apply` 严格执行打印出来的那份计划。每次只能用一种模式。
- **按证据决定是否默认执行。** 只有 `observed` 或 `anchored` 的操作默认执行；`inferred` 和 `hypothesis` 的操作放在具名选项后面，默认不执行，计划里会列出来。
- **日志与撤销。** 每次改动之前先把原始状态写进日志。`-Uninstall` 倒序回放日志，只恢复仍然保持着工具写入值的项；其他情况报告为冲突，原样不动。
- **计划任务。** `-Install` 只在一次干净的执行之后才注册，此后在登录时和每 6 小时重新确认拦截类操作。软件升级到未知版本时，自动重做会停下来，直到重新分析。
- **已知失败。** 原因清楚、已经接受的失败（比如安全软件否决某个服务的修改）记成 manifest 里的 `knownFailure {reason, ref}`：每次运行都以 WARN 带原因记录，新的失败仍然会显示为失败。
- **护栏。** 只动解析出来的安装目录和声明过的目录；拒绝驱动器根目录、Windows、Program Files、Users 目录和重解析点；先按完整路径再按 PID 结束进程；厂商服务只禁用不删除；从不关闭杀毒软件，也不加排除项。
- **私有数据不公开。** 账本、快照、日志和验证记录放在私有伴生仓里；公开产物不含提取出的密钥、解密后的配置或厂商二进制。

## 安装

```
/plugin install github:DaizeDong/app-debloat
```

或手动克隆：

```bash
git clone https://github.com/DaizeDong/app-debloat.git ~/.claude/plugins/app-debloat
```

环境要求：Windows 10 或 11、Windows PowerShell 5.1 和 Python 3。`pe_triage.py` 还需要 pefile 和 capstone（numpy 可选），用 `setup_re_backend.ps1 -Install -Component pymods` 或 `pip install pefile capstone` 安装。逆向后端（REA、Ghidra）是可选的：

```powershell
.\skills\app-debloat\scripts\setup_re_backend.ps1                 # 自检，只读
.\skills\app-debloat\scripts\setup_re_backend.ps1 -Install        # 把 REA、Ghidra 12.1.4、JDK 21 装到 %LOCALAPPDATA%
```

## 用法

直接用大白话告诉 Claude Code，例如：“有道翻译老弹广告和 AI 助手，帮我找出是谁拉起来的，封掉它们，但别影响翻译。”其他能触发它的说法：“这个软件全是广告，帮我精简”、“每次更新又回来了”、“找到它的自我修复机制”、“关掉它的遥测和 AI 助手，但要能正常用”、“精简一下某某软件”。

skill 会先只读地给软件做盘点，画出启动链、找出开关，写出 `analysis.md` 和 `plan.md`，动手之前先问你。你同意后它生成脚本，由你来运行：

```powershell
.\ExampleDebloat.ps1              # 演练：打印计划，什么都不改
.\ExampleDebloat.ps1 -Apply       # 需要管理员；严格执行打印出的计划，记录原始状态
.\ExampleDebloat.ps1 -Install     # 需要管理员；执行后在登录时和每 6 小时重新确认
.\ExampleDebloat.ps1 -Uninstall   # 需要管理员；删除它注册的东西，回放日志恢复原状
```

## 实际成果

用这套方法做出的单软件公开仓：

| 软件 | 分析的版本 | 类型 | 仓库 |
|---|---|---|---|
| 搜狗输入法 | 15.5 | 输入法；这套方法最初就是从它总结出来的 | [sogou-ime-debloat](https://github.com/SanJerry007/sogou-ime-debloat) |
| 网易有道翻译 | 11.3.24.0 | 翻译客户端（CEF），装在用户目录 | [youdao-translate-debloat](https://github.com/SanJerry007/youdao-translate-debloat) |
| 夸克与夸克网盘 | 7.4.9.1045 | Chromium 魔改浏览器，带网盘和 SYSTEM 更新服务 | [quark-debloat](https://github.com/SanJerry007/quark-debloat) |
| 百度网盘 | 8.2.1.102 | 网盘客户端（Electron），带 BT 引擎、图标角标和 SYSTEM 工具服务 | [baidu-netdisk-debloat](https://github.com/SanJerry007/baidu-netdisk-debloat) |

表中的版本就是当时分析的版本。偏移和路径只对这个版本有效；用引擎生成的脚本遇到其他版本会拒绝执行（加 `-Force` 时除外），直到重新分析并重建 manifest。

## 示例输出

`examples/` 里有两个由 `tools/make_fixtures.py` 生成的虚构软件，每个都附带 manifest、可选的钩子和生成好的单文件脚本。搜狗的方法总结在 [case-sogou.md](skills/app-debloat/reference/case-sogou.md)。

## 局限

- 静态分析得到的偏移只对一个版本有效。软件每次升级都要重新盘点、重新回答专项问题；计划任务发现版本指纹变化时会发出警告。
- 运行在别的进程里的代码（输入法、Shell 扩展）没法按程序单独做防火墙规则。
- 服务端下发的开关可以在文件不变的情况下改变行为，所以验证看行为，不看文件状态。
- 杀毒软件可能拦截或悄悄撤销 IFEO 和 hosts 的改动。流程会复查这些改动，但无法阻止。
- 绑定账号的软件可能踢掉甚至封禁被修改的客户端。要改安装目录里的东西，每个软件都要先得到机主的明确同意。
- 封掉更新器也就收不到这个厂商的安全修复；方案里会写明代价，以及怎样手动更新。

## 语言

English（`README.md`，以英文版为准）· 中文（`README_CN.md`）

## 路线图与许可证

见 [ROADMAP.md](ROADMAP.md) · [LICENSE](LICENSE)（MIT）。
