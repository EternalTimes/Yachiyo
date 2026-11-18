<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Project Yachiyo E2E Test Infrastructure & Methodology

## 1. Overview
The Yachiyo E2E test suite provides an **opaque-box (black box)** verification harness designed in parallel with the implementation track per the Project Pattern Dual Track. It treats the proxy system as a black box:
- Client interactions occur over standard TCP sockets using standard protocol frames (RFC 1928 SOCKS5 and RFC 7231 / RFC 9110 HTTP CONNECT).
- Server lifecycle and process management occur via CLI arguments, loopback endpoints, and POSIX signals (`SIGINT` / `SIGTERM`).
- All tests are completely isolated, allocate collision-free dynamic ephemeral ports, and clean up spawned server tasks and child processes upon completion.

---

## 2. Test Harness Components (`tests/common/`)

### 2.1 Multi-Protocol Echo Server (`tests/common/echo.rs`)
An in-process asynchronous TCP server that acts as the target server for proxy forwarding tests.
- **Protocol & Network Support**:
  - IPv4 binding (`127.0.0.1:0`).
  - IPv6 binding (`[::1]:0`).
  - System DNS resolution via `localhost`.
- **Supported Operating Modes**:
  - `BidirectionalEcho`: Standard stream echo; reads until EOF and writes received bytes back.
  - `HalfCloseClientFin`: Reads until client half-closes write half (client FIN / EOF), records received bytes, then writes `HALF_CLOSE_ACK:<payload>` back to client.
  - `HalfCloseServerFin`: Reads initial greeting, sends response, shuts down write half (`shutdown(Write)`), and continues reading client's subsequent stream until EOF.
  - `DelayedEcho(Duration)`: Sleeps before responding to simulate slow upstream targets or test timeout behaviors.
  - `Blackhole`: Accepts TCP connection but neither reads nor writes (sleeps until peer disconnects).
  - `DropImmediately`: Accepts TCP connection and closes immediately (FIN / RST).
  - `Discard`: High-throughput sink that reads and counts all incoming bytes.
  - `HttpServer { body }`: Returns standard `HTTP/1.1 200 OK` responses with content-length.
- **Metrics Tracking (`EchoStats`)**:
  - `connections_accepted: AtomicUsize`
  - `bytes_received: AtomicUsize`
  - `bytes_sent: AtomicUsize`
  - `half_close_detected: AtomicBool`

### 2.2 Protocol Client Utilities (`tests/common/client.rs`)
- **SOCKS5 Client**:
  - High-level connector: `socks5_connect(proxy_addr, target, timeout)` supporting IPv4, IPv6, and Domain destinations.
  - Boundary frame crafting: `socks5_handshake_raw` and `socks5_send_raw_request` for testing custom methods, invalid versions (e.g. 0x04), unsupported commands (BIND 0x02, UDP 0x03), and unsupported address types (ATYP 0x02, 0x05).
- **HTTP CONNECT Client**:
  - High-level connector: `http_connect(proxy_addr, target, timeout)` supporting standard and IPv6 bracketed host authorities.
  - Pipelined connector: `http_connect_with_pipeline` that concatenates CONNECT headers and initial application payload into a single atomic TCP write, testing unconsumed byte preservation.
  - Raw response reader: `read_http_response` parsing status code, headers, and any trailing bytes.
- **Data Verifiers**:
  - `verify_bidirectional_echo`: Verifies byte-exact payload fidelity.

### 2.3 Proxy Process Runner (`tests/common/proxy.rs`)
- Spawns the compiled `yachiyo` CLI binary with configurable flags:
  - `--mixed <addr>`
  - `--socks <addr>`
  - `--http <addr>`
  - `--allow-lan`
  - Custom extra arguments.
- Ephemeral port allocator: `get_available_addr()`.
- Captures stdout/stderr in memory.
- `assert_zero_payload_logging`: Verifies that no payload data or confidential headers appear in proxy logs.
- Signal coordinator: sends `SIGINT` / `SIGTERM` and awaits process exit with configurable timeout, asserting exit code 0 (clean drain) or 1 (forced).

---

## 3. Test Tier Breakdown

### Tier 1 — Feature Coverage (>=5 tests per feature)
- **SOCKS5 CONNECT**:
  - `test_socks5_connect_ipv4_echo`
  - `test_socks5_connect_ipv6_echo`
  - `test_socks5_connect_domain_echo`
  - `test_socks5_connect_multiple_exchanges`
  - `test_socks5_connect_large_payload`
- **HTTP CONNECT**:
  - `test_http_connect_ipv4_echo`
  - `test_http_connect_ipv6_echo`
  - `test_http_connect_domain_echo`
  - `test_http_connect_http10_version`
  - `test_http_connect_large_payload`
- **Mixed-Port Sniffing**:
  - `test_mixed_port_socks5_demux`
  - `test_mixed_port_http_demux`
  - `test_mixed_port_interleaved_clients`
  - `test_mixed_port_zero_byte_connection`
  - `test_mixed_port_concurrent_socks_and_http`
- **Independent Listeners**:
  - `test_independent_listeners_socks_only`
  - `test_independent_listeners_http_only`
  - `test_independent_listeners_simultaneous`
  - `test_independent_listeners_custom_ports`
  - `test_independent_listeners_mixed_plus_dedicated`

### Tier 2 — Boundary & Corner Cases (>=5 tests per feature)
- **SOCKS5 Boundary & Error Handling**:
  - `test_socks5_auth_unsupported_method`
  - `test_socks5_unsupported_cmd_bind`
  - `test_socks5_unsupported_cmd_udp`
  - `test_socks5_unsupported_atyp`
  - `test_socks5_invalid_version_in_auth`
  - `test_socks5_destination_unreachable`
- **HTTP CONNECT Boundary & Error Handling**:
  - `test_http_connect_missing_port`
  - `test_http_connect_invalid_method`
  - `test_http_connect_invalid_ipv6_syntax`
  - `test_http_connect_header_exceeds_8kb`
  - `test_http_connect_invalid_http_version`
  - `test_http_connect_unreachable_target`
- **Pipelined Data Preservation**:
  - `test_http_pipelined_simple_payload`
  - `test_http_pipelined_large_payload`
  - `test_http_pipelined_binary_data`
  - `test_http_pipelined_split_delimiter`
  - `test_http_pipelined_tls_client_hello`
- **Timeouts & Security Bindings**:
  - `test_handshake_timeout_socks5`
  - `test_handshake_timeout_http`
  - `test_outbound_connect_timeout`
  - `test_loopback_binding_security_rejection`
  - `test_loopback_binding_with_allow_lan`

### Tier 3 — Cross-Feature Combinations
- `test_tcp_half_close_client_to_target`: Client sends FIN; proxy propagates FIN to target; target responds with ACK and data.
- `test_tcp_half_close_target_to_client`: Target sends FIN; proxy propagates FIN to client; client completes upload to target.
- `test_concurrency_limit_1024_rejection`: Proxy accepts 1024 active connections; connection 1025 is rejected without crashing proxy; recovery after drain.
- `test_graceful_shutdown_during_active_transfer`: Active data transfer in progress; proxy receives `SIGINT`; accept loop stops; transfers drain within 5s; clean exit code 0.
- `test_mixed_port_under_concurrent_half_close`: Interleaved SOCKS5 and HTTP CONNECT connections performing asymmetric half-close on mixed port simultaneously.

### Tier 4 — Real-World Scenarios
- `test_curl_socks5_hostname_http_get`: Real `curl` CLI client using `--socks5-hostname` proxy option.
- `test_curl_http_connect_get`: Real `curl` CLI client using `-x http://` proxy tunnel.
- `test_curl_large_file_download`: Real client streaming 5MB test payload through proxy tunnel.
- `test_netcat_pipelined_stream`: Simulated netcat raw TCP stream with pipelined payload.
- `test_tokio_multithreaded_clients`: High concurrency simulated browser/application clients running parallel sessions.
- `test_zero_payload_logging_audit`: Scans proxy stdout/stderr logs across all operations to ensure zero payload content is leaked.

### Tier 5 — Native YAML Config, Sequential Rules & REJECT (`tier5_config_rules.rs`)
- Validates `--config` & `--check` CLI paths, `DOMAIN`, `DOMAIN-SUFFIX`, `IP-CIDR` (`no-resolve`), and `REJECT` replies (`0x02` for SOCKS5, `403 Forbidden` for HTTP CONNECT).

### Tier 6 — SOCKS5 TCP Outbound (`tier6_socks5_outbound.rs`)
- Validates upstream SOCKS5 no-auth (`0x00`) & RFC 1929 username/password (`0x02`) dialing, failure handling, and password redaction.

### Tier 7 — SIGHUP Atomic Config Snapshot Reload (`tier7_config_reload.rs`)
- Validates live `SIGHUP` snapshot switching while in-flight connections continue uninterrupted on their captured prior snapshot, and preservation of active state on invalid reload configs.

### Tier 8 — Outbound Selection Groups & Health Probing (`tier8_outbound_groups.rs`)
- Validates `selector`, `fallback`, and `url-test` groups with HTTP 204 health probing and hysteresis tolerance.

### Tier 9 — Trojan TCP Outbound, IPC Diagnostics & Independent Server Interop (`tier9_trojan_and_ipc.rs`)
- `test_trojan_strict_tls_forwarding_and_half_close`: Ephemeral ECDSA P-256 Root CA + SAN leaf (`trojan.example.org`), `skip_cert_verify: false` + `ca_cert`, SOCKS5 IPv4/Domain, HTTP CONNECT pipelined payload, and client `shutdown()` FIN half-close over TLS.
- `test_trojan_tls_certificate_and_sni_verification_enforced`: Rejects untrusted cert when `skip_cert_verify: false`, rejects SNI mismatch, and verifies explicit `skip_cert_verify: true`.
- `test_trojan_wrong_password_and_fallback_group_failover`: Rejects wrong SHA-224 Trojan credentials and fails over to healthy Trojan node via active HTTP 204 health check over TLS.
- `test_ipc_diagnostics_cli_queries_reload_and_redaction`: Exercises `ping`, `status` (`--ipc-path` / `--socket`), live in-flight `connections`, `stats` byte telemetry, `SIGHUP` reload generation/node sync, socket unlink on `SIGINT`, and zero-payload/credential redaction audit.
- `test_trojan_independent_xray_server_interop`: When an independent `xray` binary is installed on the host, verifies real-world Trojan TLS + Freedom outbound interop and half-close with `skip_cert_verify: false`.

---

## 4. Authoritative Output Derivation Table

| Behavior / Scenario | Input | Expected Output / State | Authoritative Source |
|---|---|---|---|
| SOCKS5 Auth (no-auth supported) | `[0x05, 0x01, 0x00]` | `[0x05, 0x00]` | RFC 1928 §3 |
| SOCKS5 Auth (unsupported methods) | `[0x05, 0x01, 0x02]` | `[0x05, 0xFF]` | RFC 1928 §3 |
| SOCKS5 CONNECT IPv4 Success | `[0x05, 0x01, 0x00, 0x01, IP, Port]` | `[0x05, 0x00, 0x00, 0x01, BndIP, BndPort]` | RFC 1928 §4 |
| SOCKS5 CONNECT Command BIND | `[0x05, 0x02, 0x00, ...]` | `REP = 0x07` (Command not supported) | RFC 1928 §5 |
| SOCKS5 CONNECT Command UDP | `[0x05, 0x03, 0x00, ...]` | `REP = 0x07` (Command not supported) | RFC 1928 §5 |
| SOCKS5 CONNECT Invalid ATYP | `[0x05, 0x01, 0x00, 0x02, ...]` | `REP = 0x08` (Address type not supported) | RFC 1928 §5 |
| SOCKS5 Destination Unreachable | CONNECT to non-listening port | `REP = 0x04` or `0x05` | RFC 1928 §5 |
| HTTP CONNECT Success | `CONNECT host:port HTTP/1.1\r\n\r\n` | `HTTP/1.1 200 Connection Established\r\n\r\n` | RFC 9110 §9.3.6 |
| HTTP CONNECT Missing Port | `CONNECT host HTTP/1.1\r\n\r\n` | `HTTP/1.1 400 Bad Request` | RFC 9110 §9.3.6 |
| HTTP Non-CONNECT Method | `GET / HTTP/1.1\r\n\r\n` | `HTTP/1.1 405 Method Not Allowed` | ROADMAP §3.1, RFC 9110 |
| HTTP Header Oversized | > 8192 bytes before `\r\n\r\n` | `HTTP/1.1 431` or `400` | RFC 9110 §9.3.6 |
| HTTP Pipelined Data | `CONNECT host:port\r\n\r\n<data>` | Target receives exact `<data>` without loss | RFC 9110 §9.3.6 |
| Mixed Port Sniffing | First byte `0x05` | Dispatches to SOCKS5 state machine | ROADMAP §3.1 |
| Mixed Port Sniffing | First byte `!= 0x05` | Dispatches to HTTP CONNECT parser | ROADMAP §3.1 |
| Non-loopback Bind without `--allow-lan` | `--mixed 0.0.0.0:18484` | Process exits with code `1` | ORIGINAL_REQUEST R3 |
| Non-loopback Bind with `--allow-lan` | `--mixed 0.0.0.0:18484 --allow-lan` | Process starts successfully (code `0`) | ORIGINAL_REQUEST R3 |
| Concurrency Limit (1024) | 1025 concurrent connections | Connection 1025 rejected immediately | ORIGINAL_REQUEST R3 |
| Handshake Timeout | 10s inactivity during handshake | Connection dropped | ORIGINAL_REQUEST R3 |
| Outbound Connect Timeout | 10s unable to connect to upstream | Error response (SOCKS REP / HTTP 502/504) | ORIGINAL_REQUEST R3 |
| Graceful Drain | `SIGINT`/`SIGTERM` during transfer | Stop accept, drain <= 5s, exit code 0 | ORIGINAL_REQUEST R3 |
| Zero Payload Logging | All proxy activities | Logs contain `host:port`, zero payload | ORIGINAL_REQUEST R3 |

---

## 5. Execution Commands

To execute the test suite:

```bash
# Run all E2E test suites:
cargo test -p yachiyo-e2e

# Run individual tiers:
cargo test -p yachiyo-e2e --test tier1_feature_coverage
cargo test -p yachiyo-e2e --test tier2_boundary_corner
cargo test -p yachiyo-e2e --test tier3_cross_feature
cargo test -p yachiyo-e2e --test tier4_real_world

# Run with verbose logging:
RUST_LOG=debug cargo test -p yachiyo-e2e -- --nocapture
```
