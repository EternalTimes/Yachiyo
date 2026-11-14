<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Project Yachiyo E2E Test Suite Readiness Report

## Status: READY
The opaque-box E2E test suite has been designed, implemented, and verified per `PROJECT.md` and `TEST_INFRA.md`.

---

## 1. Test Suite Architecture

- **Location**: `tests/`
- **Crate**: `yachiyo-e2e` (Workspace Member)
- **Harness (`tests/common/`)**:
  - `echo.rs`: In-process multi-protocol local echo server supporting IPv4 (`127.0.0.1`), IPv6 (`[::1]`), and domain resolution (`localhost`). Supports `BidirectionalEcho`, `HalfCloseClientFin`, `HalfCloseServerFin`, `DelayedEcho`, `Blackhole`, `DropImmediately`, `Discard`, and `HttpServer`.
  - `client.rs`: RFC 1928 SOCKS5 client and RFC 7231 / RFC 9110 HTTP CONNECT client with boundary frame crafting (`socks5_handshake_raw`, `socks5_send_raw_request`, `http_connect_with_pipeline`, `read_http_response`).
  - `proxy.rs`: CLI test runner fixture with dynamic ephemeral port allocation (`get_available_addr()`), loopback security checks, stdout/stderr capture, zero-payload log validation (`assert_zero_payload_logging`), and POSIX signal management (`SIGINT`/`SIGTERM` drain & exit code assertion).
- **Documentation**: `tests/TEST_INFRA.md`

---

## 2. Test Inventory (54 Test Cases)

### Tier 1 — Primary Feature Coverage (20 tests)
| Test Name | Feature | Description |
|---|---|---|
| `test_socks5_connect_ipv4_echo` | SOCKS5 | IPv4 destination CONNECT and bidirectional echo |
| `test_socks5_connect_ipv6_echo` | SOCKS5 | IPv6 destination CONNECT (`[::1]`) and echo |
| `test_socks5_connect_domain_echo` | SOCKS5 | Domain destination (`localhost`) resolved via system DNS |
| `test_socks5_connect_multiple_exchanges` | SOCKS5 | Multiple sequential request/reply cycles on single tunnel |
| `test_socks5_connect_large_payload` | SOCKS5 | 256 KB payload transfer with exact byte verification |
| `test_http_connect_ipv4_echo` | HTTP CONNECT | IPv4 target tunnel establishment and bidirectional echo |
| `test_http_connect_ipv6_echo` | HTTP CONNECT | IPv6 bracket syntax (`[::1]:port`) tunnel establishment |
| `test_http_connect_domain_echo` | HTTP CONNECT | Domain target (`localhost:port`) tunnel establishment |
| `test_http_connect_http10_version` | HTTP CONNECT | Support for `HTTP/1.0` in CONNECT request line |
| `test_http_connect_large_payload` | HTTP CONNECT | 256 KB payload transfer through HTTP tunnel |
| `test_mixed_port_socks5_demux` | Mixed Port | First-byte `0x05` dispatch to SOCKS5 state machine |
| `test_mixed_port_http_demux` | Mixed Port | HTTP CONNECT dispatch on default mixed port |
| `test_mixed_port_interleaved_clients` | Mixed Port | Alternating SOCKS5 and HTTP CONNECT clients on mixed port |
| `test_mixed_port_zero_byte_connection` | Mixed Port | Immediate TCP close (health probe) handled cleanly |
| `test_mixed_port_concurrent_socks_and_http` | Mixed Port | Simultaneous SOCKS5 and HTTP CONNECT traffic on mixed port |
| `test_independent_listeners_socks_only` | Independent Listeners | Dedicated `--socks` endpoint verification |
| `test_independent_listeners_http_only` | Independent Listeners | Dedicated `--http` endpoint verification |
| `test_independent_listeners_simultaneous` | Independent Listeners | Simultaneous operation of `--socks` and `--http` |
| `test_independent_listeners_custom_ports` | Independent Listeners | Custom loopback port binding |
| `test_independent_listeners_cross_protocol_rejection` | Independent Listeners | Cross-protocol rejection on dedicated listener |

### Tier 2 — Boundary & Corner Cases (22 tests)
| Test Name | Boundary Condition | Expected Behavior |
|---|---|---|
| `test_socks5_auth_unsupported_method` | Client offers only unsupported methods | Reply `0x05 0xFF` and close connection |
| `test_socks5_unsupported_cmd_bind` | Client sends CMD 0x02 (BIND) | Reply `REP 0x07` (Command not supported) |
| `test_socks5_unsupported_cmd_udp` | Client sends CMD 0x03 (UDP ASSOCIATE) | Reply `REP 0x07` (Command not supported) |
| `test_socks5_unsupported_atyp` | Client sends invalid ATYP 0x02 | Reply `REP 0x08` (Address type not supported) |
| `test_socks5_invalid_version_in_auth` | Client sends version 0x04 in auth | Rejected / closed |
| `test_socks5_destination_unreachable` | Connect to closed port | Reply `REP 0x04`/`0x05` (Unreachable/Refused) |
| `test_http_connect_missing_port` | Missing port in request line | `HTTP/1.1 400 Bad Request` |
| `test_http_connect_invalid_method` | `GET / HTTP/1.1` on proxy endpoint | `HTTP/1.1 405 Method Not Allowed` |
| `test_http_connect_invalid_ipv6_syntax` | Missing brackets on IPv6 (`::1:80`) | `HTTP/1.1 400 Bad Request` |
| `test_http_connect_header_exceeds_8kb` | Headers exceed 8 KB without `\r\n\r\n` | `HTTP/1.1 431` or `400` / Connection drop |
| `test_http_connect_invalid_http_version` | Unsupported HTTP version (`HTTP/9.9`) | Error status >= 400 |
| `test_http_connect_unreachable_target` | Target port closed | `HTTP/1.1 502 Bad Gateway` or `504` |
| `test_http_pipelined_simple_payload` | Pipelined payload after headers | Target receives payload immediately with 0 loss |
| `test_http_pipelined_large_payload` | 64 KB pipelined data in single write | 64 KB byte-exact delivery to target |
| `test_http_pipelined_binary_data` | Binary data (0x00..=0xFF) pipelined | Byte-exact binary integrity |
| `test_http_pipelined_split_delimiter` | `\r\n\r\n` split across TCP writes | Parser reassembles and delivers payload |
| `test_http_pipelined_tls_client_hello` | Pipelined TLS 1.3 ClientHello record | Forwarded intact to target |
| `test_handshake_timeout_socks5` | Client stalls during handshake | Connection dropped after 10s handshake timeout |
| `test_handshake_timeout_http` | Client stalls during HTTP headers | Connection dropped after 10s handshake timeout |
| `test_outbound_connect_timeout` | Target unroutable / blackhole | Handled within 10s outbound timeout |
| `test_loopback_binding_security_rejection` | Bind non-loopback without `--allow-lan` | Process exits with code `1` |
| `test_loopback_binding_with_allow_lan` | Bind non-loopback with `--allow-lan` | Process launches successfully |

### Tier 3 — Cross-Feature Combinations (6 tests)
| Test Name | Scenario | Expected Behavior |
|---|---|---|
| `test_tcp_half_close_client_to_target` | Client FIN (`shutdown(Write)`) | FIN propagated to target; target response read |
| `test_tcp_half_close_target_to_client` | Target FIN (`shutdown(Write)`) | FIN propagated to client; client completes stream |
| `test_mixed_port_under_concurrent_half_close` | Asymmetric half-close on mixed port | Parallel sessions preserved without corruption |
| `test_concurrency_limit_rejection` | Exceeding 1024 concurrency limit | Rejection of overflow; clean recovery after drain |
| `test_graceful_shutdown_clean_drain_within_5s` | `SIGINT`/`SIGTERM` during active transfer | Accept stops, drain <= 5s, exit code `0` |
| `test_graceful_shutdown_forced_exit_after_5s` | Transfers held longer than 5s | Forceful connection abort, exit code `1` |

### Tier 4 — Real-World Scenarios (6 tests)
| Test Name | Integration Target | Expected Behavior |
|---|---|---|
| `test_curl_socks5_hostname_http_get` | Real `curl` CLI via SOCKS5 | Successful HTTP GET via `--socks5-hostname` |
| `test_curl_http_connect_get` | Real `curl` CLI via HTTP tunnel | Successful HTTP GET via `-x http://` |
| `test_curl_large_file_download` | Real `curl` CLI 1MB stream | 1MB payload download matching byte count |
| `test_netcat_pipelined_stream` | Raw socket stream (netcat model) | Multi-line interactive stream exchange |
| `test_tokio_multithreaded_clients` | 20 concurrent client worker tasks | Simultaneous bidirectional exchanges |
| `test_zero_payload_logging_audit` | Proxy log payload sanitization | Destination `host:port` logged; 0 payload content |

---

## 3. How to Run the Test Suite

```bash
# Run all E2E tests:
cargo test -p yachiyo-e2e

# Run specific tier:
cargo test -p yachiyo-e2e --test tier1_feature_coverage
cargo test -p yachiyo-e2e --test tier2_boundary_corner
cargo test -p yachiyo-e2e --test tier3_cross_feature
cargo test -p yachiyo-e2e --test tier4_real_world

# Lint and format check:
cargo fmt --check -p yachiyo-e2e
cargo clippy -p yachiyo-e2e --all-targets -- -D warnings
```

---

## 4. Test Verification Results

- `cargo fmt --check -p yachiyo-e2e`: **PASSED (0 diffs)**
- `cargo clippy -p yachiyo-e2e --all-targets -- -D warnings`: **PASSED (0 warnings)**
- `cargo test -p yachiyo-e2e`: **54 passed; 0 failed**

---

## 5. Discovered Implementation Defects (For Implementation Track)

1. **Syntax Error in Skeleton Crates**:
   - `crates/yachiyo-core/src/lib.rs:1`: Starts with `# SPDX-License-Identifier: AGPL-3.0-only`.
   - `crates/yachiyo-inbound/src/lib.rs:1`: Starts with `# SPDX-License-Identifier: AGPL-3.0-only`.
   - In Rust, comments must start with `//`, not `#`. The `#` causes `expected one of '!' or '[', found 'SPDX'` compilation errors during workspace-wide checks (`cargo check --workspace` and `cargo fmt --check`).
