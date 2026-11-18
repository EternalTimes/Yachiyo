<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# 第三方依赖与 AGPL-3.0-only 许可证合规审计

决策与依据参考：ADR-001（语言与运行时，见 [DECISIONS.md](DECISIONS.md) §2）、ADR-002（开源许可证，见 [DECISIONS.md](DECISIONS.md) §3）、[LICENSING.md](LICENSING.md)。  
审计日期：2026-11-18；基准版本：Yachiyo `0.1.0-alpha.0`（Milestone M2 验收闭环）。

---

## 1. 审计背景与合规原则

根据 Project Yachiyo 核心规范（[PROJECT.md](PROJECT.md) 及 [LICENSING.md](LICENSING.md) §4），本项目原创代码、配置示例与配套文档严格采用 **GNU Affero General Public License version 3 only**（SPDX 标识：`AGPL-3.0-only`）。

在 Rust Cargo workspace 中引入第三方代码或根证书数据依赖时，执行前置与持续许可证审查，确保：
1. **组合合法性**：第三方依赖的许可证必须与 `AGPL-3.0-only` 兼容，允许以静态链接或源码/数据内联形式组合到受 `AGPL-3.0-only` 约束的最终二进制（`yachiyo`）中，且不违反原许可条款。
2. **无专有或不可兼容限制**：严禁引入带有商业排他（如 Commons Clause、BSL）、网络服务排他限制（如 SSPL）或历史不兼容传染许可（如 GPLv2-only、4-clause BSD / 旧版 OpenSSL SSLeay 广告条款）的组件。
3. **保留原版权声明与许可文本**：宽松型许可证（MIT、Apache-2.0、ISC、BSD-3-Clause、Unicode-3.0）及开放数据许可（CDLA-Permissive-2.0）要求在分发副本或对应数据时保留原作者版权声明、免责声明或许可正文。
4. **满足 AGPL-3.0 第 13 条网络交互要求**：修改后的程序若通过计算机网络提供交互，必须向相应远程用户提供获取对应源码（Corresponding Source）的机会；所有被依赖组件必须允许随对应源码无附加限制地向公众提供。

---

## 2. 审计结论总览（M2 状态）

经过对根目录 `Cargo.toml`、`Cargo.lock` 以及 4 个 workspace 子包（`yachiyo-core`、`yachiyo-inbound`、`yachiyo-cli`、`yachiyo-e2e`）的核查：

- **直接生产依赖（Direct Production Dependencies）**：11 个（`tokio`、`tracing`、`tracing-subscriber`、`clap`、`thiserror`、`serde`、`serde_yml`、`rustls`、`tokio-rustls`、`rustls-pki-types`、`webpki-roots`；M2 清理移除了未使用的 `anyhow`，并按纯 Rust 实现 Trojan SHA-224，未引入额外哈希或代理框架库）。
- **直接测试专用依赖（Direct E2E Test Dependencies，仅 `tests/Cargo.toml`，不进入发布二进制）**：`libc`、`ring`（以及复用工作区已声明的 `tokio`、`rustls`、`tokio-rustls`、`rustls-pki-types` 用于端到端临时测试证书签发与受控 TLS 服务端）。
- **解析锁定的第三方包条目总数（Total Third-Party Lockfile Packages）**：70 个（对应 69 个唯一 crate 名称，其中平台条件依赖 `windows-sys` 同时锁定 `0.52.0` 与 `0.61.2`；连同 4 个内部 workspace 包，全图共 74 个包）。
- **许可证类型分布（共 70 项）**：
  - `MIT OR Apache-2.0` / `Apache-2.0 OR MIT`：50 个（`MIT OR Apache-2.0` 45 个 + `Apache-2.0 OR MIT` 5 个）
  - `MIT`：10 个（`tokio`、`tokio-macros`、`tracing`、`tracing-core`、`tracing-subscriber`、`bytes`、`mio`、`matchers`、`nu-ansi-term`、`sharded-slab`）
  - `ISC`：2 个（`rustls-webpki`、`untrusted`）
  - `Unlicense OR MIT`：2 个（`aho-corasick`、`memchr`）
  - `Apache-2.0 OR ISC OR MIT`：1 个（`rustls`）
  - `Apache-2.0 AND ISC`：1 个（`ring 0.17.14`）
  - `BSD-3-Clause`：1 个（`subtle`）
  - `CDLA-Permissive-2.0`：1 个（`webpki-roots`）
  - `(MIT OR Apache-2.0) AND Unicode-3.0`：1 个（`unicode-ident`）
  - `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`：1 个（`wasi`）
- **合规评定**：**100% 审计通过**。全部 70 个第三方锁定包均采用 FSF 认可与 GPLv3 / AGPLv3 兼容的宽松自由软件许可证或宽松开放数据许可证，不存在任何阻碍静态编译并按 `AGPL-3.0-only` 分发及提供对应源码的冲突条款。

---

## 3. 工作区直接依赖逐项审查详表

| 依赖名称 | 声明版本约束 | 锁定版本 (`Cargo.lock`) | SPDX 许可证 | 引入模块及启用特性 | 项目内核心用途 | AGPL-3.0-only 兼容性与依据 |
|---|---|---|---|---|---|---|
| **tokio** | `^1.43` | `1.54.1` | `MIT` | `yachiyo-core` (`net`, `io-util`, `time`, `sync`, `rt`)<br>`yachiyo-inbound` (`net`, `io-util`, `time`, `sync`)<br>`yachiyo-cli` (`rt-multi-thread`, `net`, `io-util`, `time`, `sync`, `signal`, `macros`)<br>`yachiyo-e2e` (`rt-multi-thread`, `net`, `io-util`, `time`, `sync`, `process`, `macros`) | 异步运行时内核、TCP / Unix Socket 监听与拨号、定时器（握手/连接/空闲/排空超时）、并发控制及信号监听 | **完全兼容**。MIT 为 FSF 明确确认兼容 AGPLv3 的宽松许可，保留原版权声明与免责声明即可。 |
| **tracing** | `^0.1` | `0.1.44` | `MIT` | `yachiyo-core` (`std`)<br>`yachiyo-inbound` (`std`)<br>`yachiyo-cli` (`std`) | 结构化诊断与事件埋点；严格遵守零载荷日志策略，不记录口令与数据载荷 | **完全兼容**。MIT 许可。 |
| **tracing-subscriber** | `^0.3` | `0.3.23` | `MIT` | `yachiyo-cli` (`fmt`, `env-filter`, `ansi`) | 日志过滤与终端格式化订阅器，支持 `RUST_LOG` 与 `--log-level` | **完全兼容**。MIT 许可。 |
| **clap** | `^4.5` | `4.6.7` | `MIT OR Apache-2.0` | `yachiyo-cli` (`derive`, `std`, `help`, `usage`) | CLI 参数与诊断子命令（`status` / `nodes` / `connections` / `stats` / `ping`）解析 | **完全兼容**。MIT 与 Apache-2.0 双许可均与 AGPLv3 兼容。 |
| **thiserror** | `^2.0` | `2.0.21` | `MIT OR Apache-2.0` | `yachiyo-core`<br>`yachiyo-inbound`<br>`yachiyo-cli` | 强类型错误枚举与 `Display` / `Error` 派生 | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **serde** | `^1.0` | `1.0.229` | `MIT OR Apache-2.0` | `yachiyo-core` (`derive`) | 原生配置 schema 反序列化与 `deny_unknown_fields` 严格校验 | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **serde_yml** | `^0.0.13` | `0.0.13` | `MIT OR Apache-2.0` | `yachiyo-core` | 原生 YAML 配置解析（配合前置文件体积、嵌套深度与锚点/别名拦截） | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **rustls** | `^0.23` | `0.23.26` | `Apache-2.0 OR ISC OR MIT` | `yachiyo-core` (`ring`, `std`, `tls12`)<br>`yachiyo-e2e` (dev, 同上) | Trojan TCP 出站的现代 TLS 1.2 / 1.3 客户端协议栈与证书校验配置 | **完全兼容**。三选一宽松许可（MIT / ISC / Apache-2.0）均兼容 AGPLv3。 |
| **tokio-rustls** | `^0.26` | `0.26.2` | `MIT OR Apache-2.0` | `yachiyo-core` (`ring`, `tls12`)<br>`yachiyo-e2e` (dev, 同上) | 将 `rustls` 连接器适配为 Tokio `AsyncRead` / `AsyncWrite` 流（支持 TLS `close_notify` 半关闭） | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **rustls-pki-types** | `^1` | `1.11.0` | `MIT OR Apache-2.0` | `yachiyo-core` (`std`)<br>`yachiyo-e2e` (dev, `std`) | TLS `ServerName`（SNI / IP）、`CertificateDer` 与私钥基础类型定义 | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **webpki-roots** | `^0.26` | `0.26.10` | `CDLA-Permissive-2.0` | `yachiyo-core` | Mozilla CA 根证书信任锚静态数据集，供默认开启的 TLS 服务端证书校验使用 | **完全兼容**。Linux 基金会宽松数据许可，仅要求共享数据时附带 `CDLA-Permissive-2.0` 协议文本，对编译产物与源码公开无排他限制。 |
| **libc** | `^0.2` | `0.2.191` | `MIT OR Apache-2.0` | `yachiyo-e2e`（测试专用） | 端到端测试向子进程发送 `SIGINT` / `SIGTERM` / `SIGHUP` 信号 | **完全兼容**。MIT / Apache-2.0 双许可。 |
| **ring** | `^0.17` | `0.17.14` | `Apache-2.0 AND ISC` | `yachiyo-e2e`（dev 测试专用；生产路径亦由 `rustls` 传递引入） | TLS 底层密码学原语提供者；在 E2E 测试中生成内存临时 ECDSA P-256 证书链 | **完全兼容**。见 §4.2 专项核查，无旧版 OpenSSL 广告条款。 |

---

## 4. AGPL-3.0-only 许可证组合与专项法律核查

### 4.1 宽松软件许可（MIT / Apache-2.0 / ISC / BSD-3-Clause）组合机制
- **MIT 与 ISC 许可证**：功能等价的极简宽松许可，允许无限制使用、修改、静态链接和再分发，仅要求保留版权声明与免责声明。组合进 `AGPL-3.0-only` 作品时，整体衍生作品遵循 `AGPL-3.0-only`，完全满足原许可条件。
- **BSD-3-Clause（`subtle`）**：修订版三句式 BSD 许可（不含 4-clause BSD 广告条款），FSF 明确列为与 GPLv3 / AGPLv3 完全兼容的自由软件许可证。
- **Apache-2.0**：其专利授权与终止条款受 GNU AGPLv3 第 7 条明确接纳，FSF 官方确认为与 GPLv3 / AGPLv3 兼容（仅与历史 GPLv2 不兼容）。分发时保留对应版权声明及 `NOTICE`（若上游提供）即可。

### 4.2 `ring 0.17.14` 许可证实地核查（消除旧版 OpenSSL 风险）
早期密码学库常因混入遗留 OpenSSL / SSLeay 四句式广告条款而与 GPL 系列产生冲突。本次对本地 Cargo 缓存中 `ring-0.17.14` 的 `Cargo.toml` 及 `LICENSE`、`LICENSE-BoringSSL`、`LICENSE-other-bits` 进行了逐文件核查：
- `ring 0.17.14` 的 SPDX 声明已正式规范为 **`Apache-2.0 AND ISC`**（其中新代码采用 `ISC`，源自 BoringSSL 的代码采用 `Apache-2.0` 与 `ISC`，内部 `once_cell` polyfill 采用 `Apache-2.0 OR MIT`）。
- 已无旧版 OpenSSL/SSLeay 广告条款残留。`Apache-2.0` 与 `ISC` 同时适用时，二者义务（保留版权声明、免责声明及 Apache-2.0 条款文本）彼此兼容，且均与 `AGPL-3.0-only` 完全兼容。

### 4.3 `webpki-roots 0.26.10`（`CDLA-Permissive-2.0`）核查
- `webpki-roots` 将 Mozilla 公共根证书列表编译为 Rust 常量，采用 **Community Data License Agreement – Permissive, Version 2.0 (`CDLA-Permissive-2.0`)**。
- 根据其第 2.1 条（共享数据时提供协议正文）与第 3.1 条（**No Restrictions on Results**：对使用数据产生的编译结果不施加任何限制），将其链接进 `AGPL-3.0-only` 二进制及公开源码仓库完全合法；发布归档时在 `THIRD_PARTY_LICENSES` 中附带 `CDLA-Permissive-2.0` 文本即可履行全部义务。

---

## 5. `Cargo.lock` 全量第三方依赖审计清单（70 项）

以下为当前工作区 `Cargo.lock` 解析出的全部 70 个第三方包条目（按包名与版本字典序排列）：

| # | Crate 名称 | 锁定版本 | SPDX 标识 | 依赖引入方 (Parent Callers) | 兼容性判定 |
|---|---|---|---|---|---|
| 1 | `aho-corasick` | `1.1.5` | `Unlicense OR MIT` | `regex-automata` | 兼容（MIT 分支） |
| 2 | `anstyle` | `1.0.14` | `MIT OR Apache-2.0` | `clap_builder` | 兼容 |
| 3 | `bytes` | `1.12.1` | `MIT` | `tokio` | 兼容 |
| 4 | `cc` | `1.2.21` | `MIT OR Apache-2.0` | `ring`（编译期构建脚本） | 兼容 |
| 5 | `cfg-if` | `1.0.5` | `MIT OR Apache-2.0` | `getrandom`, `ring`, `thread_local` | 兼容 |
| 6 | `clap` | `4.6.7` | `MIT OR Apache-2.0` | `yachiyo-cli` | 兼容 |
| 7 | `clap_builder` | `4.6.7` | `MIT OR Apache-2.0` | `clap` | 兼容 |
| 8 | `clap_derive` | `4.6.7` | `MIT OR Apache-2.0` | `clap`（编译期过程宏） | 兼容 |
| 9 | `clap_lex` | `1.1.1` | `MIT OR Apache-2.0` | `clap_builder` | 兼容 |
| 10 | `equivalent` | `1.0.3` | `Apache-2.0 OR MIT` | `indexmap` | 兼容 |
| 11 | `errno` | `0.3.14` | `MIT OR Apache-2.0` | `signal-hook-registry` | 兼容 |
| 12 | `getrandom` | `0.2.16` | `MIT OR Apache-2.0` | `ring` | 兼容 |
| 13 | `hashbrown` | `0.17.1` | `MIT OR Apache-2.0` | `indexmap` | 兼容 |
| 14 | `heck` | `0.5.0` | `MIT OR Apache-2.0` | `clap_derive`（编译期） | 兼容 |
| 15 | `indexmap` | `2.14.2` | `Apache-2.0 OR MIT` | `noyalib` | 兼容 |
| 16 | `lazy_static` | `1.5.1` | `MIT OR Apache-2.0` | `sharded-slab` | 兼容 |
| 17 | `libc` | `0.2.191` | `MIT OR Apache-2.0` | `errno`, `getrandom`, `mio`, `ring`, `signal-hook-registry`, `socket2`, `tokio`, `yachiyo-e2e` | 兼容 |
| 18 | `matchers` | `0.2.0` | `MIT` | `tracing-subscriber` | 兼容 |
| 19 | `memchr` | `2.8.3` | `Unlicense OR MIT` | `aho-corasick`, `noyalib`, `regex-automata` | 兼容（MIT 分支） |
| 20 | `mio` | `1.2.4` | `MIT` | `tokio` | 兼容 |
| 21 | `noyalib` | `0.0.5` | `MIT OR Apache-2.0` | `serde_yml` | 兼容 |
| 22 | `nu-ansi-term` | `0.50.3` | `MIT` | `tracing-subscriber` | 兼容 |
| 23 | `once_cell` | `1.21.4` | `MIT OR Apache-2.0` | `rustls`, `tracing-core`, `tracing-subscriber` | 兼容 |
| 24 | `pin-project-lite` | `0.2.17` | `Apache-2.0 OR MIT` | `tokio`, `tracing` | 兼容 |
| 25 | `proc-macro2` | `1.0.107` | `MIT OR Apache-2.0` | `clap_derive`, `quote`, `serde_derive`, `syn`, `thiserror-impl`, `tokio-macros` | 兼容（编译期） |
| 26 | `quote` | `1.0.47` | `MIT OR Apache-2.0` | `clap_derive`, `serde_derive`, `syn`, `thiserror-impl`, `tokio-macros` | 兼容（编译期） |
| 27 | `regex-automata` | `0.4.18` | `MIT OR Apache-2.0` | `matchers`, `tracing-subscriber` | 兼容 |
| 28 | `regex-syntax` | `0.8.11` | `MIT OR Apache-2.0` | `regex-automata` | 兼容 |
| 29 | `ring` | `0.17.14` | `Apache-2.0 AND ISC` | `rustls`, `rustls-webpki`, `yachiyo-e2e` | 兼容（见 §4.2） |
| 30 | `rustc-hash` | `2.1.3` | `Apache-2.0 OR MIT` | `noyalib` | 兼容 |
| 31 | `rustls` | `0.23.26` | `Apache-2.0 OR ISC OR MIT` | `tokio-rustls`, `yachiyo-core`, `yachiyo-e2e` | 兼容 |
| 32 | `rustls-pki-types` | `1.11.0` | `MIT OR Apache-2.0` | `rustls`, `rustls-webpki`, `webpki-roots`, `yachiyo-core`, `yachiyo-e2e` | 兼容 |
| 33 | `rustls-webpki` | `0.103.1` | `ISC` | `rustls` | 兼容 |
| 34 | `serde` | `1.0.229` | `MIT OR Apache-2.0` | `indexmap`, `noyalib`, `serde_yml`, `yachiyo-core` | 兼容 |
| 35 | `serde_core` | `1.0.229` | `MIT OR Apache-2.0` | `indexmap`, `serde` | 兼容 |
| 36 | `serde_derive` | `1.0.229` | `MIT OR Apache-2.0` | `serde`, `serde_core`（编译期过程宏） | 兼容 |
| 37 | `serde_yml` | `0.0.13` | `MIT OR Apache-2.0` | `yachiyo-core` | 兼容 |
| 38 | `sharded-slab` | `0.1.7` | `MIT` | `tracing-subscriber` | 兼容 |
| 39 | `shlex` | `1.3.0` | `MIT OR Apache-2.0` | `cc`（编译期） | 兼容 |
| 40 | `signal-hook-registry` | `1.4.8` | `MIT OR Apache-2.0` | `tokio` | 兼容 |
| 41 | `smallvec` | `1.16.5` | `MIT OR Apache-2.0` | `noyalib` | 兼容 |
| 42 | `socket2` | `0.6.5` | `MIT OR Apache-2.0` | `tokio` | 兼容 |
| 43 | `subtle` | `2.6.1` | `BSD-3-Clause` | `rustls` | 兼容 |
| 44 | `syn` | `3.0.10` | `MIT OR Apache-2.0` | `clap_derive`, `serde_derive`, `thiserror-impl`, `tokio-macros` | 兼容（编译期） |
| 45 | `thiserror` | `2.0.21` | `MIT OR Apache-2.0` | `yachiyo-cli`, `yachiyo-core`, `yachiyo-inbound` | 兼容 |
| 46 | `thiserror-impl` | `2.0.21` | `MIT OR Apache-2.0` | `thiserror`（编译期过程宏） | 兼容 |
| 47 | `thread_local` | `1.1.10` | `MIT OR Apache-2.0` | `tracing-subscriber` | 兼容 |
| 48 | `tokio` | `1.54.1` | `MIT` | `tokio-rustls`, `yachiyo-cli`, `yachiyo-core`, `yachiyo-e2e`, `yachiyo-inbound` | 兼容 |
| 49 | `tokio-macros` | `2.7.2` | `MIT` | `tokio`（编译期过程宏） | 兼容 |
| 50 | `tokio-rustls` | `0.26.2` | `MIT OR Apache-2.0` | `yachiyo-core`, `yachiyo-e2e` | 兼容 |
| 51 | `tracing` | `0.1.44` | `MIT` | `tracing-subscriber`, `yachiyo-cli`, `yachiyo-core`, `yachiyo-inbound` | 兼容 |
| 52 | `tracing-core` | `0.1.36` | `MIT` | `tracing`, `tracing-subscriber` | 兼容 |
| 53 | `tracing-subscriber` | `0.3.23` | `MIT` | `yachiyo-cli` | 兼容 |
| 54 | `unicode-ident` | `1.0.27` | `(MIT OR Apache-2.0) AND Unicode-3.0` | `proc-macro2`, `syn` | 兼容（编译期） |
| 55 | `untrusted` | `0.9.0` | `ISC` | `ring`, `rustls-webpki` | 兼容 |
| 56 | `wasi` | `0.11.1+wasi-snapshot-preview1` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `getrandom`, `mio`（目标平台条件依赖） | 兼容 |
| 57 | `webpki-roots` | `0.26.10` | `CDLA-Permissive-2.0` | `yachiyo-core` | 兼容（见 §4.3） |
| 58 | `windows-link` | `0.2.1` | `MIT OR Apache-2.0` | `windows-sys`（Windows 条件依赖） | 兼容 |
| 59 | `windows-sys` | `0.52.0` | `MIT OR Apache-2.0` | `ring`（Windows 条件依赖） | 兼容 |
| 60 | `windows-sys` | `0.61.2` | `MIT OR Apache-2.0` | `errno`, `mio`, `nu-ansi-term`, `socket2`, `tokio`（Windows 条件依赖） | 兼容 |
| 61 | `windows-targets` | `0.52.6` | `MIT OR Apache-2.0` | `windows-sys`（Windows 条件依赖） | 兼容 |
| 62 | `windows_aarch64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 63 | `windows_aarch64_msvc` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 64 | `windows_i686_gnu` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 65 | `windows_i686_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 66 | `windows_i686_msvc` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 67 | `windows_x86_64_gnu` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 68 | `windows_x86_64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 69 | `windows_x86_64_msvc` | `0.52.6` | `MIT OR Apache-2.0` | `windows-targets`（Windows 条件依赖） | 兼容 |
| 70 | `zeroize` | `1.8.1` | `Apache-2.0 OR MIT` | `rustls` | 兼容 |

---

## 6. 后续维护与发布合规流程

为防止后续里程碑（M3 UDP / DNS / macOS TUN）引入不兼容的许可证，持续执行以下约束：

1. **新依赖引入审查标准**：
   - 任何修改 `Cargo.toml` 引入新依赖的提交，必须核查其版本、SPDX 标识及上游 `LICENSE` 正文，并同步更新本台账。
   - 严禁引入任何带有专有商业限制、SSPL 或 GPLv2-only 传染性的依赖。
2. **发布归档材料准备**：
   - 构建正式发布产物时，提取所有依赖项的版权声明与许可正文（含 `MIT`、`Apache-2.0`、`ISC`、`BSD-3-Clause`、`CDLA-Permissive-2.0`），形成 `THIRD_PARTY_LICENSES` 随二进制一同打包分发。
3. **网络用户源码入口**：
   - 按照 [LICENSING.md](LICENSING.md) §3，发布版本须明确对应精确 Git 标签 / Commit 与构建材料，履行 `AGPL-3.0-only` 第 13 条合规承诺。
