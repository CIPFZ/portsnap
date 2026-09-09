# portsnap

portsnap 是一个 Rust 命令行工具，用于查询本地 TCP / UDP 端点、连接状态和所属进程，并按需交互式终止进程。

## 快速使用

```bash
portsnap 8080 3000        # 查询指定本地端口，包括非监听 TCP 状态
portsnap --list           # 列出 TCP 监听端口和 UDP 绑定端点
portsnap 8080 --json      # 输出结构化扫描报告
portsnap 8080 --tcp -4    # 只查 IPv4 TCP 端点
portsnap 8080 --details   # 查看路径、参数、用户、父 PID 和启动时间
portsnap 8080 --kill      # 逐个确认并终止进程；macOS 需要另加 --force
portsnap --help           # 查看完整参数
```

默认查询 TCP、UDP、IPv4 和 IPv6。`--tcp` / `--udp` 选择协议，`-4` / `--ipv4` 与 `-6` / `--ipv6` 选择地址族；每组互斥。过滤可用于指定端口查询、`--list` 和 `--kill`。指定端口与 `--list` 不能同时使用。

## 安装

从 [Releases](https://github.com/CIPFZ/portsnap/releases) 下载对应平台的压缩包，解压后将 `portsnap`（Windows 为 `portsnap.exe`）放到 PATH 中。发布包包含 README 和 MIT 许可证，并另附 SHA-256 校验文件。

| 平台 | 发布目标 | 运行要求 |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-musl` | 静态链接 musl；扫描需要 procfs，终止需要 pidfd 支持（Linux 5.3+） |
| Windows x86_64 | `x86_64-pc-windows-msvc` | 使用系统 API；读取和终止进程受权限限制 |
| macOS Intel | `x86_64-apple-darwin` | 使用系统 `/usr/sbin/lsof` |
| macOS Apple Silicon | `aarch64-apple-darwin` | 使用系统 `/usr/sbin/lsof` |

从源码安装需要 Rust 1.85 或更新版本：

```bash
git clone https://github.com/CIPFZ/portsnap.git
cd portsnap
cargo install --locked --path .
```

## 查看结果

文本表格包含协议、本地地址、远程地址、状态、PID 和进程名称。同一端点存在多个可见所属进程时，逐个显示；IPv6 使用 `[::1]:8080` 形式。UDP 在文本中显示为 `BOUND`。

`--details` 按需补充所属进程的可执行文件路径、参数数组、用户、父 PID 和 UTC 启动时间，可与 `--json` 组合。参数数组保留空参数和空格；字段不可获取时保留其他字段并给出原因。默认不读取或输出这些详情。

权限不足或部分数据无法读取时，工具会保留可见结果并给出诊断。JSON 报告使用 `complete` 和 `warnings` 表达完整性，诊断的 `code` 可供脚本分类；请求的详情不可完整获取也会返回不完整报告。**不完整报告中的空列表不能说明端口空闲**。

扫描反映当前可见的端点，不预留端口，也不能保证后续绑定成功。Linux 只扫描当前网络命名空间；其他平台的数据可见性同样受系统接口和权限约束。

## 终止进程

```bash
portsnap 8080 --kill --timeout 5
portsnap 8080 --kill --force
portsnap 8080 --tcp -4 --details --kill
```

终止对象是整个进程，会影响它持有的其他端口和工作。每个进程分别确认，默认回答为否；确认后还会重新核验端口归属。`--kill` 必须指定端口，不能与 `--list` 或 `--json` 组合。

| 平台 | 默认行为 | `--force` |
| --- | --- | --- |
| Linux | 发送 `SIGTERM`，等待退出 | 发送 `SIGKILL` |
| Windows | 使用 `TerminateProcess` 强制终止 | 与默认行为相同 |
| macOS | 要求显式提供 `--force` | 使用 Mach 任务端口终止，系统可能因权限限制拒绝 |

默认等待每个进程退出 3 秒，可用 `--timeout` 设置为 1–60 秒。超时会返回失败，不自动升级为强制终止。处理已确认目标后，工具按相同的协议、地址族和端口条件再次扫描并显示仍然存在的端点。

## 脚本集成

```bash
portsnap 8080 --json > report.json
```

成功生成报告时，stdout 仅包含一个 JSON 对象，诊断写入 stderr。参数错误或扫描完全失败时不输出报告。报告包含版本号、端点列表、完整性和诊断信息；字段及示例见 [JSON 接口](docs/json.md)。

| 退出码 | 含义 |
| --- | --- |
| 0 | 无操作失败且扫描完整；完整空结果或明确跳过终止也可返回 0 |
| 1 | 操作失败，或确认操作后仍有匹配端点 |
| 2 | 参数错误 |
| 3 | 无其他操作失败，但扫描结果不完整 |

## 文档与开发

- [架构设计](docs/architecture.md)：模块职责、数据模型、平台采集方式及设计取舍。
- [功能设计](docs/features.md)：各项功能解决的问题、执行规则及平台边界。
- [JSON 接口](docs/json.md)：报告字段、空值语义、完整性和退出码。

本地检查命令：

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s scripts -p 'test_*.py'
```

持续集成配置见 [CI 工作流](.github/workflows/ci.yml)，发布目标及打包配置见 [Release 工作流](.github/workflows/release.yml)。项目采用 [MIT 许可证](LICENSE)。
