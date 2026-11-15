# 原生配置 Schema 说明（YAC-005）

状态：v0.1 最小原生 schema（`schema_version: 1`）。

## 1. 格式与安全限制

- 格式：YAML（UTF-8）。
- 文件体积上限：1 MiB（`1048576` 字节）。
- 禁止使用 YAML 锚点与别名（`&anchor` / `*alias`），防止别名展开炸弹。
- 嵌套深度上限：16 层。
- 规则数量上限：`10000` 条。
- 严格字段校验：所有配置结构体均启用 `deny_unknown_fields`，任何未定义或尚未支持的字段都会直接报错，不会静默忽略。
- 禁止执行配置内脚本。

## 2. 顶层字段

| 字段 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `schema_version` | `u32` | 是 | — | 当前仅支持 `1` |
| `listeners` | object | 否 | `mixed: 127.0.0.1:18484`, `allow_lan: false` | 监听端点配置 |
| `timeouts` | object | 否 | `10 / 10 / 300 / 5` 秒 | 超时配置 |
| `limits` | object | 否 | `max_connections: 1024` | 资源与并发限制 |
| `logging` | object | 否 | `level: "info"` | 日志级别配置 |
| `outbounds` | `Map<string, object>` | 否 | `{}` | 命名出站节点定义（键为策略名） |
| `rules` | `Vec<string>` | 是 | — | 顺序规则列表，末尾必须为 `MATCH,<POLICY>` |

### `listeners`

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `mixed` | `SocketAddr`（可选） | 当 `mixed`/`socks`/`http` 均未设置时为 `127.0.0.1:18484` | 首字节嗅探混合端口（`0x05` 为 SOCKS5，其余按 HTTP CONNECT 处理） |
| `socks` | `SocketAddr`（可选） | `null` | 独立 SOCKS5 监听端点 |
| `http` | `SocketAddr`（可选） | `null` | 独立 HTTP CONNECT 监听端点 |
| `allow_lan` | `bool` | `false` | 为 `false` 时拒绝任何非 loopback 地址（含 `0.0.0.0`、`[::]` 与局域网 IP） |

约束：三个端点不能配置重复的监听地址。

### `timeouts`

所有超时值必须大于 `0` 秒：
- `handshake_secs`（默认 `10`）：入站协议握手超时。
- `connect_secs`（默认 `10`）：出站拨号超时。
- `idle_secs`（默认 `300`）：双向转发空闲超时。
- `drain_secs`（默认 `5`）：收到 SIGINT / SIGTERM 后的最大连接排空时间。

### `limits`

- `max_connections`（默认 `1024`，必须 `> 0`）：最大并发连接数上限。

### `logging`

- `level`（默认 `"info"`）：tracing 日志过滤指令；所有级别均严格遵守零载荷日志策略（不输出应用数据载荷）。

### `outbounds`（YAC-008 & M2）

以 `<name>: <outbound_config>` 映射定义命名出站节点与选择策略组，规则中的 `<POLICY>` 可直接引用此处定义的 `<name>`：

- 名称约束：不能为空、仅由 ASCII 字母、数字、`-` 或 `_` 组成，且不能使用保留策略名 `DIRECT` / `REJECT`（大小写不敏感）。
- 当前支持类型：
  - `type: socks5`：标准 SOCKS5 TCP 出站（支持 RFC 1928 无认证 `0x00` 与 RFC 1929 用户名/密码认证 `0x02`）。
    - `server`（必填，`string`）：上游 SOCKS5 地址（`host:port` 或 `[ipv6]:port`，端口范围 `1..=65535`）。
    - `username`（可选，`string`）：RFC 1929 用户名（1..=255 字节，不可为空）。
    - `password`（可选，`string`）：RFC 1929 密码（1..=255 字节，不可为空）。
    - 约束：`username` 与 `password` 必须同时提供或同时省略；日志与 `Debug` 输出会对 `password` 脱敏。
  - `type: selector`（选择策略组）：静态或手动选择候选节点。
    - `outbounds`（必填，`Vec<string>`）：非空候选出站列表（可引用其他已定义的出站节点或 `DIRECT` / `REJECT`）。
    - `selected`（可选，`string`）：初始激活的目标（若省略则默认取 `outbounds` 首项；若指定则必须存在于 `outbounds` 列表中）。
  - `type: url-test`（自动测速健康检查组）：根据定期 HTTP GET 探针结果选择延迟最低的可用候选节点。
    - `outbounds`（必填，`Vec<string>`）：非空候选出站列表。
    - `url`（可选，`string`，默认 `"http://cp.cloudflare.com/generate_204"`）：健康检查探活 HTTP URL。
    - `interval_secs`（可选，`u64`，默认 `300`，必须 `> 0`）：探针执行间隔秒数。
    - `timeout_secs`（可选，`u64`，默认 `5`，必须 `> 0`）：单次探活超时秒数。
    - `tolerance_ms`（可选，`u64`，默认 `50`）：延迟容差阈值（毫秒）；仅当新最优候选比当前选定候选快超过容差时才切换，防止网络微小抖动引发频繁路由跳变。
  - `type: fallback`（故障转移健康检查组）：按声明顺序选用首个处于可用状态的候选节点。
    - `outbounds`（必填，`Vec<string>`）：非空候选出站列表（按优先级从前至后排列）。
    - `url`（可选，`string`，默认 `"http://cp.cloudflare.com/generate_204"`）：健康检查探活 HTTP URL。
    - `interval_secs`（可选，`u64`，默认 `300`，必须 `> 0`）：探针执行间隔秒数。
    - `timeout_secs`（可选，`u64`，默认 `5`，必须 `> 0`）：单次探活超时秒数。
- 依赖图与环路约束：出站组之间允许嵌套引用，但严禁形成环路（例如 A -> B -> A）或自引用，配置校验阶段会执行拓扑检测并在发现环路时立即拒绝。

## 3. 规则语义与求值顺序

规则按声明顺序**首个匹配生效**，末尾**必须**有一条显式的 `MATCH,<POLICY>` 默认动作，且 `MATCH` 不能出现在末尾之前。

当前支持策略（`<POLICY>`）：
- `DIRECT`：通过系统 DNS 解析并直连目标。
- `REJECT`：拒绝连接，不发起出站拨号；SOCKS5 返回 `REP = 0x02`（Connection not allowed by ruleset），HTTP CONNECT 返回 `403 Forbidden`。
- `<outbound_name>`：将连接经由 `outbounds` 中已声明的对应命名出站节点转发；引用未定义的出站名称会在配置校验阶段直接失败。

当前支持规则类型：
1. `DOMAIN,<host>,<POLICY>`：精确域名匹配（大小写不敏感，规范化尾随 `.`；国际化域名需与请求中的 ASCII / Punycode 形式一致）。
2. `DOMAIN-SUFFIX,<suffix>,<POLICY>`：按 DNS 标签边界匹配域名后缀（例如 `example.org` 匹配 `example.org` 与 `sub.example.org`，不匹配 `badexample.org`）。
3. `IP-CIDR,<cidr>,<POLICY>[,no-resolve]`：IPv4 或 IPv6 CIDR 匹配。
   - 若目标本身是 IP，直接匹配。
   - 若目标为域名且**未**指定 `no-resolve`，则仅在求值到达该规则时触发系统 DNS 解析（在单次求值内缓存结果并保留原始域名）；若解析失败则跳过该条继续向下匹配。
   - 若目标为域名且指定了 `no-resolve`，则不触发 DNS 解析，直接跳过。
4. `MATCH,<POLICY>`：显式默认动作，必须位于规则列表末尾。

## 4. CLI 用法与配置快照重载

- 校验配置而不启动监听：`yachiyo --config docs/examples/config.example.yaml --check`
- 使用配置文件启动：`yachiyo --config docs/examples/config.example.yaml`
- 不传 `--config` 时保持纯 CLI 参数模式，默认监听 `127.0.0.1:18484` 并将全部连接转发至 `DIRECT`。

### 配置快照重载（`SIGHUP`，M2）

使用 `--config` 启动时，向进程发送 `SIGHUP` 会触发原子快照重载：
- 可热重载字段：`timeouts.handshake_secs`、`timeouts.connect_secs`、`timeouts.idle_secs`、`outbounds`、`rules`。重载成功后新连接立即使用新快照（`config_generation` 递增），已建立连接继续使用其接入时捕获的旧快照完成。
- 需重启字段：`listeners`（监听地址）与 `limits.max_connections`。若这些字段发生变化或新配置解析/语义校验失败，本次重载会被拒绝并记录错误日志，**当前运行中的快照保持不变**。`logging.level` 变更同样需要重启才能生效，重载时会记录告警并保留当前日志级别。

参考示例：[config.example.yaml](examples/config.example.yaml)。
