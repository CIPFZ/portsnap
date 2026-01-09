# portsnap ⚡

[![Build Status](https://img.shields.io/github/actions/workflow/status/YOUR_USERNAME/portsnap/release.yml?style=flat-square)](https://github.com/YOUR_USERNAME/portsnap/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)]()

**portsnap** 是一个超轻量级的跨平台命令行工具，专为快速查询端口占用情况而生。它旨在替代参数冗长的 `netstat` 或 `lsof`，帮助开发者迅速定位问题。

> “一条命令，少想几秒。”

## ✨ 核心特性

- 🚀 **极致轻量**: 基于 Rust 编写，二进制文件仅 ~1MB，启动速度极快。
- 🔍 **简单直观**: 无需记忆复杂参数，输入端口号即可查询 (如 `portsnap 8080 3000`)。
- 🛠 **脚本友好**: 支持 `--json` 格式输出，完美对接 PowerShell、Python 或 CI/CD 流程。
- 🔪 **查杀一体**: 发现端口被占用？使用 `-k` 参数即可安全地交互式终止进程。
- 📦 **零依赖**: 单一二进制文件，开箱即用，无需安装运行时。

## 📥 安装指南

### 方式 1：下载二进制文件 (推荐)
请前往 [Releases 页面](https://github.com/YOUR_USERNAME/portsnap/releases) 下载适用于 Windows、Linux 或 macOS 的最新版本。

### 方式 2：从源码编译
如果你本地已安装 Rust 环境：

```bash
cargo install --path .
```

# 🚀 使用指南

## 1. 查询指定端口
想知道是谁占用了 8080 和 3000 端口？

```bash
portsnap 8080 3000
```

输出示例：

```plaintext
PROTO  LOCAL ADDRESS             PID        PROCESS
TCP    0.0.0.0:8080              12345      node.exe
TCP    0.0.0.0:3000              9876       python
```

---

## 2. 列出所有监听端口
查看本机所有 TCP / UDP 监听状态：

```bash
portsnap -l
```

---

## 3. 查杀进程（交互模式）
发现僵尸进程占用端口？一键清理：

```bash
portsnap 8080 -k
```

交互示例：

```plaintext
PROTO  LOCAL ADDRESS             PID        PROCESS
TCP    0.0.0.0:8080              12345      node.exe

--- Interactive Kill Mode ---
Kill process 'node.exe' (PID 12345)? [y/N]: y
  ✔ Process terminated.
```

---

## 4. JSON 输出（自动化集成）
适合脚本解析的数据格式：

```bash
portsnap -l --json
```

输出示例：

```json
[
  {
    "protocol": "TCP",
    "local_addr": "0.0.0.0",
    "local_port": 8080,
    "pid": 12345,
    "process_name": "node.exe"
  }
]
```

---

🖥 平台支持

| 平台 | 状态 | 说明 |
|------|------|------|
| Windows | ✅ Stable | 完美支持（Win10 / Win11 推荐） |
| Linux | 🚧 Beta | 支持主流发行版（Ubuntu、Arch 等） |
| macOS | 🚧 Beta | 支持 Intel 及 Apple Silicon |

---

🛠 技术栈

- 开发语言：Rust 🦀
- CLI 框架：clap
- 系统信息：sysinfo / netstat2
- 构建优化：Stripped binary（体积优化）

---

🗺 开发计划（Roadmap）

- [x] v0.1：Windows 核心功能、JSON 支持、交互式 Kill
- [ ] v0.2：高级过滤（仅 TCP / UDP）、本地 / 远程过滤
- [ ] v0.3：TUI（终端 UI）模式，支持键盘光标选择查杀

---

📄 许可证

本项目采用 MIT 许可证，详情请参阅 LICENSE 文件。
