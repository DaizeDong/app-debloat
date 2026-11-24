# app-debloat

逆向分析一个带广告的 Windows 软件，产出一个可反复执行、软件更新后能自动重做的精简脚本。

[![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-orange?style=flat)](https://docs.anthropic.com/en/docs/claude-code)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![No Binary Patching](https://img.shields.io/badge/Binary%20Patching-None-green?style=flat)](skills/app-debloat/reference/safety.md)
[![Auto Re-Apply](https://img.shields.io/badge/App%20Updates-Auto%20Re--Apply-green?style=flat)](skills/app-debloat/reference/pipeline.md)
[![Languages](https://img.shields.io/badge/Languages-EN%20%2F%20CN-blue?style=flat)](#语言)
[![Roadmap](https://img.shields.io/badge/Roadmap-v0.1.5-purple?style=flat)](ROADMAP.md)

[English](README.md) | [中文版](README_CN.md)

---

## 设计理念

带广告的桌面软件，比如输入法、网盘、下载器、翻译软件、办公套件、电脑厂商自带工具，几乎都不给真正的关闭开关。广告、AI 插件和遥测是一个个独立组件，由启动器拉起，受一份设置界面管不到的配置控制，删掉后又会被更新器、修复服务或远程配置 SDK 装回来。删文件、关界面开关之所以总是失败，原因都一样：只处理了表象，没碰到真正的开关，也没堵住回来的路。

这个 skill 把在搜狗输入法上验证过的方法做成一条可重复的流水线：

1. 盘点软件在机器上放的一切；
2. 搞清楚每个组件由谁拉起、由什么决定运行不运行；
3. 列出所有回装路径；
4. 用最轻的手段封住它们；
5. 用行为来证明结果：进程、模块、网络连接、核心功能测试、重启一次、触发一次修复；
6. 软件更新后自动重做。

通用步骤只负责找出候选。每个软件在动手之前，都必须回答一组固定的专项问题，因为没有两个软件把开关藏在同一个地方。

[设计说明](PHILOSOPHY.md)

---

## 用途与范围

每次处理一个已安装的第三方 Windows 桌面软件。

- **输入**：软件名、哪些功能必须保留、想去掉什么。
- **输出**：
  - 证据账本；
  - 处置方案；
  - 一个单文件 PowerShell 脚本，默认只演练，支持 `-Apply`、`-Install`（登录时和每 6 小时自动重做）和 `-Uninstall`。

**不做**：整机 Windows 精简、清除恶意软件、卸载、浏览器广告拦截、破解或绕过授权、修改二进制、推荐别的软件。腾讯系客户端只做进程外处置。

## 安装

```
/plugin install github:DaizeDong/app-debloat
```

或手动克隆：

```bash
git clone https://github.com/DaizeDong/app-debloat.git ~/.claude/plugins/app-debloat
```

逆向后端是可选的，没有它时，内置的 pefile 加 capstone 回退方案始终可用：

```powershell
.\skills\app-debloat\scripts\setup_re_backend.ps1                 # 自检，只读
.\skills\app-debloat\scripts\setup_re_backend.ps1 -Install        # 把 REA、Ghidra 12.1.4、JDK 21 装到 %LOCALAPPDATA%
```

## 快速开始

直接用大白话告诉 Claude Code，例如：“有道翻译老弹广告和 AI 助手，帮我找出是谁拉起来的，封掉它们，但别影响翻译。”skill 会：

1. 只读地给软件做一次盘点（`inventory.ps1`），并选好逆向后端。
2. 画出启动链、找出真正的开关（`pe_triage.py`、REA 或 Ghidra、frida），并找出回装路径。
3. 写出 `analysis.md` 和 `plan.md`，动手之前先问你。
4. 根据 manifest 生成 `<App>Debloat.ps1`，先演练；你同意后再执行 `-Apply` 和 `-Install`。
5. 分别在执行后、重启后、触发一次修复后各验证一遍。

## 怎么触发

比如这些说法：“这个软件全是广告，帮我精简”、“每次更新又回来了”、“找到它的自我修复机制”、“关掉它的遥测和 AI 助手，但要能正常用”、“精简一下某某软件”。

## 示例输出

`examples/` 里有两个由 `tools/make_fixtures.py` 生成的虚构软件，每个都附带 manifest、可选的钩子和生成好的单文件脚本。真实的完整案例是公开仓 [sogou-ime-debloat](https://github.com/SanJerry007/sogou-ime-debloat)，方法总结在 `skills/app-debloat/reference/case-sogou.md`。

## 局限

- 静态分析得到的偏移只对一个版本有效。软件每次升级都要重新盘点、重新回答专项问题；安装的计划任务发现版本指纹变化时会发出警告。
- 运行在别的进程里的代码（输入法、Shell 扩展）没法按程序单独做防火墙规则。
- 服务端下发的开关可以在文件不变的情况下改变行为，所以验证看行为，不看文件状态。
- 杀毒软件可能拦截或悄悄撤销 IFEO 和 hosts 的改动。流程会复查这些改动，但无法阻止。
- 绑定账号的软件可能踢掉甚至封禁被修改的客户端。要改安装目录里的东西，每个软件都要先得到机主的明确同意。
- 真实的分析结果不公开：账本、快照和验证记录放在私有伴生仓里，绝不放进公开仓。

## 语言

English（`README.md`，以英文版为准）· 中文（`README_CN.md`）

## 路线图与许可证

见 [ROADMAP.md](ROADMAP.md) · [LICENSE](LICENSE)（MIT）。
