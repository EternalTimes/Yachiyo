# Yachiyo

类似 Mihomo 的跨平台代理内核，首发 macOS。当前处于规划阶段，尚无可运行内核。

本目录是 2026-10-31 编写的 v0.1 规划初稿。项目名称、macOS 首发与 AGPL-3.0-only 许可证已确认；GitHub 公开仓库已建立；语言及具体实现方案仍按决策记录推进。文中的版本号是交付目标，不表示功能已经实现。

## 文档入口

| 文档 | 用途 |
| --- | --- |
| [项目原则](docs/PROJECT.md) | 定位、范围、兼容性及优先级 |
| [架构草案](docs/ARCHITECTURE.md) | 模块边界、数据流、DNS 与 macOS 接入 |
| [开发规范](CONTRIBUTING.md) | 任务、提交、测试、依赖和评审 |
| [AI 工作约定](AGENTS.md) | 代码代理在本项目中的执行规则 |
| [AI 协作流程](docs/AI-WORKFLOW.md) | 订阅资源分工、上下文交接和成本控制 |
| [CI 方案](docs/CI.md) | 检查分层、macOS 验证和权限 |
| [安全与发布基线](docs/RELEASE.md) | 默认行为、故障恢复及发布门槛 |
| [路线图](docs/ROADMAP.md) | 阶段范围、验收条件和首批任务 |
| [决策记录](docs/DECISIONS.md) | 已确认事项、建议和待决策事项 |
| [许可证说明](docs/LICENSING.md) | AGPL 的范围、源码提供与依赖要求 |
| [仓库配置](docs/REPOSITORY-SETUP.md) | 自动化、安全设置与分支保护 |

建议从项目原则、路线图和决策记录开始阅读。实现任务必须引用所属里程碑与验收条件。

## 当前目标

先验证 macOS 上的显式代理链路：HTTP CONNECT / SOCKS5 入站 → 规则 → DIRECT / REJECT / SOCKS5 或 Trojan 出站。通过本地可控服务和远端互通测试后，再扩展 UDP、DNS 与 TUN。

首版不以协议数量或完整兼容 Mihomo 配置作为验收标准。具体范围见路线图。

## 状态与授权

当前处于规划阶段，尚无可运行代理内核。GitHub 基础设施已启用；本次设置调整的应用状态见[仓库配置](docs/REPOSITORY-SETUP.md)。没有安装守护服务或修改系统网络设置；公开发布前完成第三方依赖许可审查。

## 许可证

除另有声明的第三方内容外，Yachiyo 的项目原创代码、配置示例与配套文档采用 GNU Affero General Public License version 3 only，SPDX 标识为 `AGPL-3.0-only`，全文见 [LICENSE](LICENSE)。目标是使受许可证覆盖的衍生版本保持源码开放，包括修改后仅向远程用户提供网络服务的情况。具体义务与边界见[许可证说明](docs/LICENSING.md)。
