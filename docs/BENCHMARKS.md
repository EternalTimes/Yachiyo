<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# 资源、吞吐与稳定性基线报告（M2 / v0.1）

依据：[ROADMAP.md](ROADMAP.md) §1、§4 及 [AGENTS.md](../AGENTS.md) 性能记录约定。  
更新日期：2026-11-18。本文仅记录本机可复现的实测数据与测量限制，不做跨语言对比，亦不将短时压测宣称为 8 小时浸泡已完成。

---

## 1. 测量环境、版本与配置

- **硬件与系统**：Apple M1 Pro（10 核 CPU，16 GiB 内存），`macOS-27.3-arm64`（`Darwin 27.3.0 arm64`）
- **工具链与构建配置**：`rustc 1.100.0 (0ef1bc386 2026-11-09)`，`cargo build --release -p yachiyo-cli`（默认优化 `release` profile，未 strip 调试符号外额外压缩）
- **被测产物**：`target/release/yachiyo`，二进制体积 **`5,606,544` bytes（`5.35 MiB`）**
- **压测与采样脚本**：[bench_m2_load.py](../scripts/bench_m2_load.py)（Python `3.9.6` `asyncio` 单进程压测端 + 本地回环 Echo / HTTP 204 探针服务）
- **被测配置摘要**：
  - `schema_version: 1`，`listeners.mixed: 127.0.0.1:<ephemeral>`，`limits.max_connections: 1024`，`logging.level: info`
  - 出站与规则：`MATCH,auto_direct`（`type: url-test` -> `DIRECT`，开启后台 HTTP 204 探针）
  - 采样周期：`250 ms`（通过 POSIX `ps -o rss=` 采集 RSS，通过 `lsof -a -n -P -d 0-65535 -p <pid>` 采集数值型文件描述符数，通过 Unix 域套接字 `STATUS` / `STATS` 采集活跃连接与配置代际）
  - 连续性约束：四个阶段在**同一个 `yachiyo` 守护进程实例**内连续执行，中间不重启进程。

复现命令：

```bash
cargo build --release -p yachiyo-cli
python3 -B scripts/bench_m2_load.py --mode baseline --bin target/release/yachiyo
```

---

## 2. 四阶段实测基线数据（单实例连续运行）

| 阶段 | 负载规格 | 建连 / 请求速率 | 吞吐 / 延迟指标 | RSS 峰值 | 阶段后 RSS 回稳 | FD 峰值 | 阶段后 FD 回落 | 阶段后 IPC 活跃连接 |
|---|---|---|---|---|---|---|---|---|
| **1. 空闲基线** | 0 连接静默运行 `2.0 s` | — | — | `4,160 KiB` (`4.06 MiB`) | `4,160 KiB` | `11` | `11` | `0` |
| **2. 200 空闲/低流量连接** | 200 并发 SOCKS5 连接，每 `400 ms` 往返 `64 B` 心跳 × 4 轮 | `1,966.3 conns/s` | 心跳 100% 校验一致 | `9,024 KiB` (`8.81 MiB`) | `9,024 KiB` | `411` | `11` | `0` |
| **3. 200 活动连接可重复流量** | 200 并发 SOCKS5 连接 × `16` 轮 × `16 KiB` 双向回显（共 `100.0 MiB` 代理载荷） | `2,505.7 conns/s` | 双向吞吐 **`472.06 MiB/s`** (`3,776.5 Mbps`)；单块 `16 KiB` RTT `p50 = 13.16 ms`、`p95 = 15.18 ms` | `9,232 KiB` (`9.02 MiB`) | `9,232 KiB` | `412` | `11` | `0` |
| **4. 短连接风暴 + 反复热重载** | `1,000` 次短连接（并发度 `50`）叠加 `25` 次连续 `SIGHUP` 配置重载 | `1,364.7 short conns/s`（`0` 失败） | `config_generation: 1 -> 26`；重载 IPC 生效耗时 `p50 = 1.82 ms`、`max = 6.95 ms` | `9,792 KiB` (`9.56 MiB`) | `9,792 KiB` | `61` | `11` | `0` |

退出回收核验：阶段 4 结束后发送 `SIGINT`，进程以退出码 `0` 干净退出，Unix 域套接字文件自动清理，累计处理 `1,400` 条连接，零失败。

### 结果说明与方法限制

1. **文件描述符与连接计数精确回落**：空闲态 FD 为 `11`；200 并发连接在途时 FD 为 `411`（`11` 基础句柄 + `200` 入站 TCP + `200` 出站 TCP），断开后在全部阶段均精确回落至 **`11`**，IPC `active_connections` 回落至 **`0`**，未见套接字泄漏。
2. **内存（RSS）趋势解释**：首次建立 200 并发连接时，Tokio 线程本地缓冲与 macOS `libsystem_malloc` 页缓存从 `4.06 MiB` 预热至 `8.81 MiB`；随后在同一进程内继续执行 `100 MiB` 活动流量及 `1,000` 次短连接 + `25` 次 `SIGHUP` 热重载，RSS 仅在 `8.81 MiB`–`9.56 MiB` 窄幅波动，未出现随连接数或重载次数线性增长的趋势。
3. **压测端瓶颈说明**：阶段 3 的客户端与回显服务端均由单进程 Python `asyncio` 在本机 loopback 驱动，测得的 `472.06 MiB/s`（`3.78 Gbps`）受限于 Python 压测端事件循环开销，代表单机可复现下界基线而非 `yachiyo` 内核极限上限。

---

## 3. 独立 Trojan 服务端互通记录（M2 门槛）

- **独立服务端实现与版本**：`Xray 26.3.27 (go1.26.1 darwin/arm64)`（本机路径 `/opt/zerobrew/bin/xray`）
- **测试拓扑**：SOCKS5 客户端 → `yachiyo`（`type: trojan`，`sni: trojan.example.org`，`ca_cert` 临时 ECDSA P-256 根证书，**`skip_cert_verify: false` 开启完整证书链与 SAN 校验**）→ `Xray`（Trojan over TLS 1.3 入站 → `freedom` 出站）→ 本地 `EchoServer`
- **验证命令与结果**：
  ```bash
  cargo test -p yachiyo-e2e --test tier9_trojan_and_ipc test_trojan_independent_xray_server_interop
  ```
  实测通过双向载荷一致性校验与客户端 `shutdown(Write)` 半关闭（FIN / TLS `close_notify`）传播验证。

---

## 4. 8 小时浸泡测试（Soak Test）执行入口与当前状态

- **当前状态声明**：[bench_m2_load.py](../scripts/bench_m2_load.py) 的 `--mode soak` 已通过本机短时烟测验证（`6 s`，完成 300 条连接与 2 次 `SIGHUP` 重载，输出 JSONL 采样序列并干净退出）；**完整的 8 小时（`28,800 s`）无人值守浸泡尚未在本次交互会话中挂机跑满**，按项目诚实记录原则在此明确区分。
- **8 小时浸泡启动命令**（输出时间序列至本地忽略目录 `local/`）：
  ```bash
  mkdir -p local
  python3 -B scripts/bench_m2_load.py \
    --mode soak \
    --bin target/release/yachiyo \
    --duration-secs 28800 \
    --reload-interval-secs 60 \
    --sample-interval-secs 10 \
    --output local/m2_soak_8h.jsonl
  ```
- **验收判据**（对照 [ROADMAP.md](ROADMAP.md) §4）：预热后 `rss_kib` 与 `fd_count` 围绕周期负载稳态波动，无持续单调爬升，结束后 `SIGINT` 退出码为 `0`。
