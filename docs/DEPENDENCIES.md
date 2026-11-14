<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# 第三方依赖与 AGPL-3.0-only 许可证合规审计

决策与依据参考：ADR-001（语言与运行时，见 docs/DECISIONS.md §2）、ADR-002（开源许可证，见 docs/DECISIONS.md §3）、docs/LICENSING.md。  
审计日期：2026-11-14；基准版本：Yachiyo 0.1.0-alpha.0 (feat/m1-direct-slice)。

---

## 1. 审计背景与合规原则

根据 Project Yachiyo 核心规范（`ORIGINAL_REQUEST.md` R4 及 `docs/LICENSING.md` §4），本项目原创代码、配置示例与配套文档严格采用 **GNU Affero General Public License version 3 only**（SPDX 标识：`AGPL-3.0-only`）。

在 Rust Cargo workspace 中引入第三方代码依赖时，必须执行前置与持续的许可证审查，确保：
1. **组合合法性**：第三方依赖的许可证必须与 AGPL-3.0-only 兼容，允许以静态链接或源码内联形式组合到受 AGPL-3.0-only 约束的最终二进制（`yachiyo`）中，且不违反原许可条款。
2. **无专有或不可兼容限制**：严禁引入带有商业排他（如 Commons Clause、Business Source License）、网络服务限制（如 SSPL）或历史不兼容传染许可（如 GPLv2-only、CDDL）的代码。
3. **保留原版权声明与许可文本**：宽松型许可证（如 MIT、Apache-2.0、Unicode-3.0）要求在分发副本或实质性部分时保留原作者版权声明和免责声明。
4. **满足 AGPL-3.0 第 13 条网络交互要求**：修改后的程序若通过计算机网络进行交互，必须向相应远程用户提供获取对应源码的机会。所有被依赖组件必须允许源码以符合 AGPL 对应源码（Corresponding Source）定义的方式向公众提供。

---

## 2. 审计结论总览

经过对根目录 `Cargo.toml`、`Cargo.lock` 以及各个子 crate (`yachiyo-core`, `yachiyo-inbound`, `yachiyo-cli`, `yachiyo-e2e`) 的深度审计：

- **直接生产依赖 (Direct Production Dependencies)**：6 个 (`tokio`, `tracing`, `tracing-subscriber`, `clap`, `thiserror`, `anyhow`)。
- **直接测试依赖 (Direct Test Dependency)**：1 个 (`libc`)。
- **解析锁定的第三方 crate 总数 (Total Third-Party Crates)**：39 个（连同 4 个项目内部 workspace crate，全图共 43 个包）。
- **许可证类型分布**：
  - `MIT OR Apache-2.0`：24 个（包含 `clap`, `thiserror`, `anyhow`, `libc`, `proc-macro2`, `syn`, `quote` 等）
  - `MIT`：10 个（包含 `tokio`, `tracing`, `tracing-subscriber`, `bytes`, `mio`, `sharded-slab` 等）
  - `Unlicense OR MIT`：2 个（`aho-corasick`, `memchr`）
  - `Apache-2.0 OR MIT`：1 个（`pin-project-lite`）
  - `(MIT OR Apache-2.0) AND Unicode-3.0`：1 个 (`unicode-ident`)
  - `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`：1 个 (`wasi`)
- **合规评定**：**100% 审计通过**。所有 39 个第三方依赖均完全基于宽松自由软件许可证（Permissive Free Software Licenses）。所有依赖均具有 MIT 或同等宽松分支，不存在任何阻碍静态编译进 AGPL-3.0-only 可执行程序的冲突条款。

---

## 3. 工作区直接依赖逐项审查详表

| 依赖名称 | 声明版本约束 | 锁定版本 (Lockfile) | SPDX 许可证 | 引入模块及启用特性 | 项目内核心用途 | AGPL-3.0-only 兼容性与依据 |
|---|---|---|---|---|---|---|
| **tokio** | `^1.43` | `1.54.1` | `MIT` | `yachiyo-core` (`net`, `io-util`, `time`, `sync`, `rt`)<br>`yachiyo-inbound` (`net`, `io-util`, `time`, `sync`)<br>`yachiyo-cli` (`rt-multi-thread`, `net`, `io-util`, `time`, `sync`, `signal`, `macros`)<br>`yachiyo-e2e` (`rt-multi-thread`, `net`, `io-util`, `time`, `sync`, `process`, `macros`) | 异步运行时内核、TCP 套接字与系统 DNS 解析、毫秒级定时器（握手/连接/空闲超时）、并发控制与退出信号监听 | **完全兼容**。MIT 是自由软件基金会 (FSF) 认可的完全兼容宽松许可证。静态链接至 AGPL 二进制时，整作遵从 AGPL-3.0-only，并依 MIT 要求保留原版权声明与免责声明。 |
| **tracing** | `^0.1` | `0.1.44` | `MIT` | `yachiyo-core` (`std`)<br>`yachiyo-inbound` (`std`)<br>`yachiyo-cli` (`std`)<br>`yachiyo-e2e` (`std`) | 结构化诊断与事件埋点。严格执行“零载荷记录”策略，仅记录目标主机与端口，严禁输出任何应用层数据载荷 | **完全兼容**。MIT 许可，与 AGPLv3 链接无权利冲突。 |
| **tracing-subscriber** | `^0.3` | `0.3.23` | `MIT` | `yachiyo-cli` (`fmt`, `env-filter`, `ansi`)<br>`yachiyo-e2e` (`fmt`, `env-filter`) | 订阅器分发与终端格式化。负责将日志输出到标准输出/标准错误，支持通过 `RUST_LOG` 或 `--log-level` 过滤 | **完全兼容**。MIT 许可，与 AGPLv3 链接无权利冲突。 |
| **clap** | `^4.5` | `4.6.7` | `MIT OR Apache-2.0` | `yachiyo-cli` (`derive`, `std`, `help`, `usage`) | 命令行参数解析与使用说明生成。支持 `--mixed`, `--socks`, `--http`, `--allow-lan` 等标志并提供严格格式校验 | **完全兼容**。双重许可任选其一。MIT 与 Apache-2.0 均获 FSF 明确确认为与 GNU GPLv3 / AGPLv3 兼容的宽松许可。 |
| **thiserror** | `^2.0` | `2.0.21` | `MIT OR Apache-2.0` | `yachiyo-core` (default)<br>`yachiyo-inbound` (default)<br>`yachiyo-cli` (default) | 库级别强类型错误定义与 `Display` / `Error` 特征派生，构建标准且清晰的错误链体系 | **完全兼容**。双重许可。过程宏生成代码与库本身均符合 AGPL 衍生作品要求。 |
| **anyhow** | `^1.0` | `1.0.104` | `MIT OR Apache-2.0` | `yachiyo-cli` (`std`) | CLI 顶层动态错误传播与上下文附加（ADR-001 规划之用） | **完全兼容**。双重许可，完全兼容 AGPL-3.0-only。 |
| **libc** | `^0.2` | `0.2.191` | `MIT OR Apache-2.0` | `yachiyo-e2e` (default, 测试专用) | 端到端集成测试中向被测进程发送 Unix 原生信号（`SIGINT`/`SIGTERM`）以验证 5 秒优雅排空 | **完全兼容**。标准底层 FFI 绑定，双重许可，完全兼容。 |

---

## 4. AGPL-3.0-only 许可证组合与法律分析

### 4.1 宽松许可与强 Copyleft 许可证的组合机制
- **MIT 许可证**：允许任何人在无限制条件下使用、复制、修改、合并、发布、分发、再许可和/或销售软件副本，仅要求保留版权声明与免责声明。当 MIT 许可的代码被编译并静态链接进由 AGPL-3.0-only 约束的项目中时，**组合生成的最终作品整体必须遵循 AGPL-3.0-only**，这不违反 MIT 许可证的任何条款。
- **Apache-2.0 许可证**：包含专利授权与保护条款。自由软件基金会 (FSF) 在其官方许可证兼容性列表中明确说明：
  > *"Apache License 2.0 is compatible with GPLv3 and AGPLv3. The patents termination condition in Apache 2.0 is permitted by section 7 of the GPLv3 / AGPLv3."*  
  历史上 Apache-2.0 与 GPLv2 存在不兼容争议，但对于 **GNU AGPLv3 / GPLv3**，官方已完全解决兼容性问题。发布包含 Apache-2.0 代码的 AGPL 二进制时，只需保留原始版权声明和 NOTICE 文件。
- **双重许可 (Dual-licensing)**：Rust 社区通用约定为 `MIT OR Apache-2.0`，使用者有权选择依其一或两者共同遵守。在 Project Yachiyo 中，采用该双重许可的依赖无论依据 MIT 还是 Apache-2.0，均毫无争议地完全兼容 AGPL-3.0-only。

### 4.2 AGPL 第 13 条（远程网络交互）合规性
AGPL-3.0 第 13 条规定，若受覆盖程序被修改并允许通过计算机网络与远程用户交互，维护者必须向远程用户提供获取对应源码（Corresponding Source）的途径。  
- 本项目所引入的所有 39 个第三方依赖均为开源且许可宽松，没有任何依赖包含“禁止公开源码”、“禁止网络分发源码”或“仅限专有二进制使用”的限制。
- 因此，当 Project Yachiyo 按照 AGPL-3.0-only 向网络用户提供完整源码包时（包含依 `Cargo.lock` 固定版本的完整依赖源码与构建材料），所有上游依赖的授权条款均被完全满足。

---

## 5. 间接传递依赖完整审计清单 (39 项)

以下为 `Cargo.lock` 中所有第三方 crate 的详尽审查记录：

| # | Crate 名称 | 锁定版本 | SPDX 标识 | 依赖引入链 (Parent Callers) | 功能作用 | 兼容性判定 |
|---|---|---|---|---|---|---|
| 1 | `aho-corasick` | 1.1.5 | `Unlicense OR MIT` | `regex-automata` | 高性能多模匹配算法 | 兼容 (MIT 分支) |
| 2 | `anstyle` | 1.0.14 | `MIT OR Apache-2.0` | `clap_builder` | 跨平台终端 ANSI 样式 | 兼容 |
| 3 | `anyhow` | 1.0.104 | `MIT OR Apache-2.0` | `yachiyo-cli` | 动态错误报告与上下文管理 | 兼容 |
| 4 | `bytes` | 1.12.1 | `MIT` | `tokio` | 高效字节缓冲区管理 | 兼容 |
| 5 | `cfg-if` | 1.0.5 | `MIT OR Apache-2.0` | `thread_local` | 条件编译分支宏 | 兼容 |
| 6 | `clap` | 4.6.7 | `MIT OR Apache-2.0` | `yachiyo-cli` | 命令行参数解析门面 | 兼容 |
| 7 | `clap_builder` | 4.6.7 | `MIT OR Apache-2.0` | `clap` | CLI 参数解析构建器实现 | 兼容 |
| 8 | `clap_derive` | 4.6.7 | `MIT OR Apache-2.0` | `clap` | `Parser` 宏派生实现 | 兼容 (编译期过程宏) |
| 9 | `clap_lex` | 1.1.1 | `MIT OR Apache-2.0` | `clap_builder` | 命令行参数词法解析器 | 兼容 |
| 10 | `errno` | 0.3.14 | `MIT OR Apache-2.0` | `signal-hook-registry` | 跨平台系统错误号包装 | 兼容 |
| 11 | `heck` | 0.5.0 | `MIT OR Apache-2.0` | `clap_derive` | 标识符命名风格大小写转换 | 兼容 (编译期) |
| 12 | `lazy_static` | 1.5.1 | `MIT OR Apache-2.0` | `sharded-slab` | 惰性全局静态变量定义宏 | 兼容 |
| 13 | `libc` | 0.2.191 | `MIT OR Apache-2.0` | `errno`, `mio`, `signal-hook-registry`, `socket2`, `tokio`, `yachiyo-e2e` | 操作系统原生 C 库系统调用绑定 | 兼容 |
| 14 | `matchers` | 0.2.0 | `MIT` | `tracing-subscriber` | 正则日志目标过滤器匹配器 | 兼容 |
| 15 | `memchr` | 2.8.3 | `Unlicense OR MIT` | `aho-corasick`, `regex-automata` | SIMD 加速单/多字节快速搜索 | 兼容 (MIT 分支) |
| 16 | `mio` | 1.2.4 | `MIT` | `tokio` | 底层非阻塞事件驱动 I/O (kqueue/epoll) | 兼容 |
| 17 | `nu-ansi-term` | 0.50.3 | `MIT` | `tracing-subscriber` | 日志终端彩色输出支持 | 兼容 |
| 18 | `once_cell` | 1.21.4 | `MIT OR Apache-2.0` | `tracing-core`, `tracing-subscriber` | 单次赋值单元与并发静态初始化 | 兼容 |
| 19 | `pin-project-lite`| 0.2.17 | `Apache-2.0 OR MIT` | `tokio`, `tracing` | 轻量级异步 Pin 投影宏 | 兼容 |
| 20 | `proc-macro2` | 1.0.107 | `MIT OR Apache-2.0` | `clap_derive`, `quote`, `syn`, `thiserror-impl`, `tokio-macros` | 编译期 Token 抽象 | 兼容 (编译期) |
| 21 | `quote` | 1.0.47 | `MIT OR Apache-2.0` | `clap_derive`, `syn`, `thiserror-impl`, `tokio-macros` | 宏展开代码准引用代码生成 | 兼容 (编译期) |
| 22 | `regex-automata` | 0.4.18 | `MIT OR Apache-2.0` | `matchers`, `tracing-subscriber` | 确定性有穷状态机正则引擎 | 兼容 |
| 23 | `regex-syntax` | 0.8.11 | `MIT OR Apache-2.0` | `regex-automata` | 正则表达式语法分析器 | 兼容 |
| 24 | `sharded-slab` | 0.1.7 | `MIT` | `tracing-subscriber` | 高性能无锁分片 Slab 内存分配器 | 兼容 |
| 25 | `signal-hook-registry` | 1.4.8 | `MIT OR Apache-2.0` | `tokio` | Unix 系统信号处理器安全注册中心 | 兼容 |
| 26 | `socket2` | 0.6.5 | `MIT OR Apache-2.0` | `tokio` | 高级网络套接字底层配置工具 | 兼容 |
| 27 | `syn` | 3.0.10 | `MIT OR Apache-2.0` | `clap_derive`, `thiserror-impl`, `tokio-macros` | Rust 语法树解析与抽象 | 兼容 (编译期) |
| 28 | `thiserror` | 2.0.21 | `MIT OR Apache-2.0` | `yachiyo-cli`, `yachiyo-core`, `yachiyo-inbound` | 错误派生库接口门面 | 兼容 |
| 29 | `thiserror-impl`| 2.0.21 | `MIT OR Apache-2.0` | `thiserror` | `thiserror` 过程宏底层实现 | 兼容 (编译期) |
| 30 | `thread_local` | 1.1.10 | `MIT OR Apache-2.0` | `tracing-subscriber` | 单对象线程局部存储 | 兼容 |
| 31 | `tokio` | 1.54.1 | `MIT` | `yachiyo-cli`, `yachiyo-core`, `yachiyo-e2e`, `yachiyo-inbound` | 异步网络运行时与多线程调度 | 兼容 |
| 32 | `tokio-macros` | 2.7.2 | `MIT` | `tokio` | `#[tokio::main]` 过程宏属性 | 兼容 (编译期) |
| 33 | `tracing` | 0.1.44 | `MIT` | `tracing-subscriber`, `yachiyo-cli`, `yachiyo-core`, `yachiyo-e2e`, `yachiyo-inbound` | 应用程序跟踪与日志门面 | 兼容 |
| 34 | `tracing-core` | 0.1.36 | `MIT` | `tracing`, `tracing-subscriber` | 跟踪核心数据结构与调度原语 | 兼容 |
| 35 | `tracing-subscriber` | 0.3.23 | `MIT` | `yachiyo-cli`, `yachiyo-e2e` | 日志订阅、格式化与分发管道 | 兼容 |
| 36 | `unicode-ident` | 1.0.27 | `(MIT OR Apache-2.0) AND Unicode-3.0` | `proc-macro2`, `syn` | Unicode 变量标识符规范验证 | 兼容 (编译期，Unicode 自由许可) |
| 37 | `wasi` | 0.11.1+wasi-snapshot-preview1 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `mio` | WASI 系统调用绑定原型 | 兼容 (MIT / LLVM Exception) |
| 38 | `windows-link` | 0.2.1 | `MIT OR Apache-2.0` | `windows-sys` | Windows 动态库导出链接支持 | 兼容 (平台特定) |
| 39 | `windows-sys` | 0.61.2 | `MIT OR Apache-2.0` | `errno`, `mio`, `nu-ansi-term`, `socket2`, `tokio` | Windows Win32 API 基础类型与常量绑定 | 兼容 (平台特定) |

---

## 6. 后续维护与发布合规流程

为防止后续开发引入不兼容的许可证，建议落实以下制度性与工具链约束：

1. **新依赖引入审查标准**：
   - 任何修改 `Cargo.toml` 引入新依赖的 PR / 提交，必须在审查说明中附带该依赖的许可证与用途。
   - 严禁引入任何带有专有商业条款或 GPLv2-only 传染性的依赖。
2. **发布归档材料准备**：
   - 在构建发布二进制时，应提取所有依赖项的版权声明与许可正文（可采用 `cargo-about` 自动生成综合第三方法律声明文件 `THIRD_PARTY_LICENSES`），随可执行程序一同打包发布。
3. **网络用户源码入口**：
   - 按照 `docs/LICENSING.md` §3，CLI 需通过 `--version` 或专用子命令展示当前运行版本的精确 Git Commit 与对应源码托管地址，完全履行 AGPL-3.0 第 13 条合规承诺。
