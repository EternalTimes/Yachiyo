# Yachiyo

类似 Mihomo 的跨平台代理内核，首发 macOS。当前已完成 M1–M2（`v0.1` 显式 TCP 代理链路），准备进入 M3（UDP、独立 DNS 与 macOS TUN 选型与实现）。

项目名称、macOS 首发、Rust 单语言实现（ADR-001，2026-11-08）与 `AGPL-3.0-only` 许可证（ADR-002）均已确认；后续阶段方案仍按决策记录推进（macOS TUN 路线 `D05` 仍待实验证据定案）。

## 文档入口

| 文档 | 用途 |
| --- | --- |
| [项目原则](docs/PROJECT.md) | 定位、范围、兼容性及优先级 |
| [架构草案](docs/ARCHITECTURE.md) | 模块边界、数据流、DNS 与 macOS 接入 |
| [配置规范](docs/CONFIG-SCHEMA.md) | 原生 YAML 配置 schema、出站组、热重载与 IPC 诊断命令 |
| [开发规范](CONTRIBUTING.md) | 任务、提交、构建验证命令、测试分层与评审 |
| [AI 工作约定](AGENTS.md) | 代码代理在本项目中的执行规则 |
| [AI 协作流程](docs/AI-WORKFLOW.md) | 订阅资源分工、上下文交接和成本控制 |
| [CI 方案](docs/CI.md) | 检查分层、macOS 验证和权限 |
| [安全与发布基线](docs/RELEASE.md) | 默认行为、故障恢复及发布门槛 |
| [路线图](docs/ROADMAP.md) | 阶段范围、验收条件和任务进度 |
| [决策记录](docs/DECISIONS.md) | 已确认事项、建议和待决策事项 |
| [许可证说明](docs/LICENSING.md) | AGPL 的范围、源码提供与依赖要求 |
| [依赖与许可审计](docs/DEPENDENCIES.md) | Cargo 依赖树与 `AGPL-3.0-only` 兼容性台账 |
| [基准与互通报告](docs/BENCHMARKS.md) | M2 四阶段负载基线、Xray 互通记录与 8h 浸泡入口 |
| [仓库配置](docs/REPOSITORY-SETUP.md) | 自动化、安全设置与分支保护 |

建议从项目原则、路线图和决策记录开始阅读。实现任务必须引用所属里程碑与验收条件。

## 当前状态与下一目标

- **已落地能力（M1–M2 / `v0.1` 显式 TCP 代理）**：
  - 入站：mixed 首字节嗅探端口（默认 `127.0.0.1:18484`）及独立 SOCKS5 / HTTP CONNECT 监听，默认限制 loopback。
  - 规则与策略：版本化原生 YAML 配置（`schema_version: 1`），顺序规则（`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`MATCH`），`Selector` / `UrlTest` / `Fallback` 策略组与主动 HTTP 204 探针。
  - 出站：`DIRECT`、`REJECT`、SOCKS5 TCP（无认证 / RFC 1929）、Trojan TCP（TLS 1.2/1.3、默认严格证书校验、支持 `ca_cert`，已通过与独立 `Xray 26.3.27` 服务端互通测试）。
  - 运维与控制面：`SIGHUP` 原子配置快照热重载（在途连接无损保持）、Unix 域套接字 IPC 实时诊断（`status` / `nodes` / `connections` / `stats` / `ping --json`）。
- **下一阶段（M3 / `v0.2`）**：按“UDP / 独立 DNS 先独立通过，再根据实验证据确定 macOS TUN 路线与异常恢复入口”推进。
- **操作边界状态**：未安装系统守护服务，未修改本机系统代理、DNS 或路由设置。

## 许可证

除另有声明的第三方内容外，Yachiyo 的项目原创代码、配置示例与配套文档采用 GNU Affero General Public License version 3 only，SPDX 标识为 `AGPL-3.0-only`，全文见 [LICENSE](LICENSE)。目标是使受许可证覆盖的衍生版本保持源码开放，包括修改后仅向远程用户提供网络服务的情况。具体义务与边界见[许可证说明](docs/LICENSING.md)。
