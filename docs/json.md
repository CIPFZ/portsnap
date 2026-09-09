# JSON 接口

`--json` 返回机器可读的端点扫描报告，可用于脚本、监控采样或其他工具的数据输入。

```bash
portsnap 8080 --json
portsnap --list --json
```

成功生成报告时，stdout 包含一个 JSON 对象。诊断同时写入 stderr。参数错误或扫描完全失败时不输出报告，调用方需要先检查退出码及输出是否存在。`--json` 不能与 `--kill` 组合。

## 报告结构

```json
{
  "schema_version": 1,
  "sockets": [
    {
      "protocol": "TCP",
      "local_addr": "127.0.0.1",
      "local_port": 8080,
      "remote_addr": null,
      "remote_port": null,
      "state": "LISTEN",
      "owners": [
        {
          "pid": 12345,
          "name": "node",
          "identity": {
            "pid": 12345,
            "start_time": 123456
          }
        }
      ],
      "ownership": "complete"
    }
  ],
  "complete": true,
  "warnings": []
}
```

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `schema_version` | 整数 | 当前报告结构版本，为 `1` |
| `sockets` | 数组 | 按查询条件筛选并整理后的端点记录 |
| `complete` | 布尔值 | 在当前平台可见性范围内，是否未发现影响报告完整性的问题 |
| `warnings` | 数组 | 导致报告不完整的诊断信息，每项包含 `source` 和 `message` 字符串 |

脚本应检查支持的 `schema_version`，并允许对象出现额外字段。`source` 和 `message` 用于定位问题，不应通过匹配诊断文本来代替对完整性和退出码的判断。

## 端点记录

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `protocol` | 字符串 | `TCP` 或 `UDP` |
| `local_addr` | 字符串 | 本地 IP 地址，不含端口或方括号 |
| `local_port` | 整数 | 本地端口 |
| `local_scope` | 可选字符串 | 已知的 IPv6 接口名称或索引；没有时省略字段 |
| `remote_addr` | 字符串或 `null` | 已知的远程 IP 地址 |
| `remote_port` | 整数或 `null` | 已知的远程端口 |
| `remote_scope` | 可选字符串 | 已知的远程 IPv6 scope；没有时省略字段 |
| `state` | 字符串或 `null` | TCP 状态；UDP 为 `null` |
| `owners` | 数组 | 该端点的已知所属进程，可能为空 |
| `ownership` | 字符串 | 该记录的归属完整性，见下表 |

TCP 状态包括 `LISTEN`、`ESTABLISHED`、`SYN_SENT`、`SYN_RECEIVED`、`FIN_WAIT1`、`FIN_WAIT2`、`CLOSE_WAIT`、`CLOSING`、`LAST_ACK`、`TIME_WAIT`、`CLOSED`、`DELETE_TCB` 和 `UNKNOWN`。实际出现的状态取决于操作系统及查询模式。

IPv6 的地址和作用域分开表示。例如 `local_addr: "fe80::1"`、`local_scope: "en0"`、`local_port: 8080` 对应文本端点 `[fe80::1%en0]:8080`。Linux procfs 未提供作用域时，该字段省略。

等价的协议、本地/远程端点、作用域和状态会合并为一条记录，并汇总所属进程。因此 `sockets` 表示端点视图，其数量不等于底层 FD 数量。端点按本地端口及其余端点属性稳定排序，owner 按 PID 排序。

### 归属完整性

| `ownership` | 含义 |
| --- | --- |
| `complete` | 归属收集和核验未报告缺失或冲突，按平台可见范围解释 |
| `partial` | 已有归属信息，但可能缺少其他持有者，或部分 PID 无法完整核验 |
| `unavailable` | 无法确定所属进程 |
| `not_applicable` | 该记录没有用户进程归属，例如内核管理的 TCP 状态 |

不能仅根据 `owners: []` 判断端口未被占用。归属不适用的端点可以存在于完整报告中；某一条记录归属完整，也不代表其他协议表或记录同样完整。

## 所属进程与身份

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `pid` | 整数 | 采集到的进程编号 |
| `name` | 字符串或 `null` | 可读取的进程名称 |
| `identity` | 对象或 `null` | 可核验的进程身份；包含 `pid` 和 `start_time` |

进程名称和身份独立于数字 PID 的可见性。即使知道 PID，也可能无法读取或核验其身份；此时 `identity` 为 `null`，记录仍可用于展示，但不能用于工具的终止操作。

`identity.start_time` 是无符号 64 位原生启动标识：Linux 使用启动 tick，Windows 使用创建时间 FILETIME，macOS 使用原生启动时间的微秒值。它没有跨平台统一的时间戳语义，身份比较应同时使用 PID 和该标识，并限定在同一台机器、同一次启动及相同的 PID 命名空间或进程编号环境内。需要准确读取该值的调用方应使用能保留 64 位整数精度的 JSON 解析方式。

Windows 归属以 IP Helper API 报告的 PID 为准，不保证覆盖所有复制句柄；Windows UDP 的远程地址和端口为 `null`，因为该数据源没有提供对端信息。

## 完整性与退出码

只有 `complete: true` 且 `sockets` 为空时，才能解释为“本次完整扫描未观察到匹配端点”。这仍是扫描时刻的观察，不是对后续端口绑定结果的保证。

不完整的空报告仍包含诊断，例如：

```json
{
  "schema_version": 1,
  "sockets": [],
  "complete": false,
  "warnings": [
    {
      "source": "TCP IPv6",
      "message": "socket table could not be read"
    }
  ]
}
```

上述诊断文本仅为示例。部分数据源成功时可以返回这样的报告；全部端点数据源失败时返回操作错误，不以空报告代替失败。

| 退出码 | 含义 |
| --- | --- |
| 0 | 无操作失败且扫描完整；包括完整空结果，以及扫描完整时明确跳过终止 |
| 1 | 扫描失败、终止失败、输入错误、等待超时，或确认操作后仍有匹配端点 |
| 2 | 参数错误 |
| 3 | 无其他操作失败，但所用扫描存在不完整结果 |

对于普通 JSON 查询，完整报告返回 0，部分报告返回 3。终止操作中，操作失败的退出码优先于不完整状态。
