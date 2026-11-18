#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Repeatable M2 load baseline and 8-hour soak harness for Project Yachiyo.

Covers ROADMAP.md §4 workload profiles on a single continuous daemon instance:
  1. Idle baseline
  2. 200 idle / low-traffic TCP connections
  3. 200 active TCP connections with repeatable bidirectional payload
  4. Short-connection storm + repeated SIGHUP configuration snapshot reloads
  5. Optional long-running soak mode (`--mode soak --duration-secs 28800`)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import statistics
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def raise_nofile_limit(target_soft: int = 16384) -> tuple[int, int]:
    """Raise soft RLIMIT_NOFILE so 200+ concurrent proxy tunnels do not hit macOS 256-FD soft cap."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = target_soft if hard == resource.RLIM_INFINITY else min(target_soft, hard)
    if soft < desired:
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
    return resource.getrlimit(resource.RLIMIT_NOFILE)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def sample_rss_kib(pid: int) -> int:
    """Return resident set size (RSS) in KiB via POSIX `ps`."""
    res = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    val = res.stdout.strip()
    return int(val) if val.isdigit() else 0


def sample_open_fds(pid: int) -> int:
    """Return count of numeric open file descriptors owned by `pid`."""
    proc_fd = Path(f"/proc/{pid}/fd")
    if proc_fd.is_dir():
        try:
            return sum(1 for _ in proc_fd.iterdir())
        except OSError:
            return 0

    res = subprocess.run(
        ["lsof", "-a", "-n", "-P", "-d", "0-65535", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
    return max(0, len(lines) - 1)


async def ipc_query(sock_path: Path, command: str) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    try:
        writer.write(f"{command}\n".encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=3.0)
        return json.loads(line.decode("utf-8"))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def socks5_open_ipv4(
    proxy_port: int, target_port: int, timeout: float = 5.0
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", proxy_port), timeout=timeout
    )
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        auth = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if auth != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 auth failed: {auth!r}")

        req = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()
        rep = await asyncio.wait_for(reader.readexactly(10), timeout=timeout)
        if rep[1] != 0x00:
            raise RuntimeError(f"SOCKS5 connect failed with REP={rep[1]}")
        return reader, writer
    except Exception:
        writer.close()
        raise


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


def render_yaml_config(
    mixed_port: int, probe_port: int, variant: int = 0, log_level: str = "info"
) -> str:
    extra_rule = (
        f"  - DOMAIN,reload-{variant}.example.org,DIRECT\n" if variant > 0 else ""
    )
    return (
        "# SPDX-License-Identifier: AGPL-3.0-only\n"
        "schema_version: 1\n"
        "listeners:\n"
        f"  mixed: 127.0.0.1:{mixed_port}\n"
        "timeouts:\n"
        "  handshake_secs: 10\n"
        "  connect_secs: 10\n"
        "  idle_secs: 300\n"
        "  drain_secs: 5\n"
        "limits:\n"
        "  max_connections: 1024\n"
        "logging:\n"
        f"  level: {log_level}\n"
        "outbounds:\n"
        "  auto_direct:\n"
        "    type: url-test\n"
        "    outbounds:\n"
        "      - DIRECT\n"
        f"    url: http://127.0.0.1:{probe_port}/generate_204\n"
        "    interval_secs: 30\n"
        "    timeout_secs: 3\n"
        "    tolerance_ms: 50\n"
        "rules:\n"
        f"{extra_rule}"
        "  - MATCH,auto_direct\n"
    )


async def start_echo_and_probe_servers() -> tuple[
    asyncio.AbstractServer, int, asyncio.AbstractServer, int
]:
    async def handle_echo(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            await close_writer(writer)

    async def handle_probe(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await reader.read(512)
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except OSError:
            pass
        finally:
            await close_writer(writer)

    echo_srv = await asyncio.start_server(handle_echo, "127.0.0.1", 0, backlog=1024)
    probe_srv = await asyncio.start_server(handle_probe, "127.0.0.1", 0, backlog=256)
    echo_port = int(echo_srv.sockets[0].getsockname()[1])
    probe_port = int(probe_srv.sockets[0].getsockname()[1])
    return echo_srv, echo_port, probe_srv, probe_port


class BackgroundSampler:
    def __init__(self, pid: int, sock_path: Path, interval_s: float = 0.25) -> None:
        self.pid = pid
        self.sock_path = sock_path
        self.interval_s = interval_s
        self.samples: list[dict[str, Any]] = []
        self._stop = False
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._stop = False
        self.samples.clear()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> list[dict[str, Any]]:
        self._stop = True
        if self._task is not None:
            await self._task
        return list(self.samples)

    async def snapshot_once(self) -> dict[str, Any]:
        rss = sample_rss_kib(self.pid)
        fds = sample_open_fds(self.pid)
        try:
            st = await ipc_query(self.sock_path, "STATUS")
        except Exception:
            st = {}
        return {
            "ts": time.time(),
            "rss_kib": rss,
            "fd_count": fds,
            "active_connections": st.get("active_connections", -1),
            "config_generation": st.get("config_generation", -1),
        }

    async def _loop(self) -> None:
        while not self._stop:
            self.samples.append(await self.snapshot_once())
            await asyncio.sleep(self.interval_s)


async def run_baseline_suite(bin_path: Path, log_level: str) -> dict[str, Any]:
    nofile_soft, _ = raise_nofile_limit()
    echo_srv, echo_port, probe_srv, probe_port = await start_echo_and_probe_servers()
    mixed_port = get_free_port()
    pid_tag = os.getpid()
    cfg_path = Path(f"/tmp/yb_cfg_{pid_tag}.yaml")
    sock_path = Path(f"/tmp/yb_{pid_tag}.sock")
    log_path = Path(f"/tmp/yb_{pid_tag}.stderr")

    cfg_path.write_text(
        render_yaml_config(mixed_port, probe_port, variant=0, log_level=log_level),
        encoding="utf-8",
    )
    if sock_path.exists():
        sock_path.unlink()

    log_fp = log_path.open("wb")
    proc = subprocess.Popen(
        [
            str(bin_path),
            "--config",
            str(cfg_path),
            "--ipc-path",
            str(sock_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=log_fp,
    )

    results: dict[str, Any] = {
        "binary": str(bin_path),
        "binary_size_bytes": bin_path.stat().st_size,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "nofile_soft_limit": nofile_soft,
        "log_level": log_level,
        "sample_interval_ms": 250,
        "stages": {},
    }

    try:
        # Wait for IPC socket & mixed listener readiness
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if sock_path.exists():
                try:
                    ping = await ipc_query(sock_path, "PING")
                    if ping.get("ok"):
                        break
                except Exception:
                    pass
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("Timed out waiting for yachiyo IPC readiness")

        sampler = BackgroundSampler(proc.pid, sock_path, interval_s=0.25)

        # Stage 1: Idle baseline (2.0s)
        sampler.start()
        await asyncio.sleep(2.0)
        s1_samples = await sampler.stop()
        idle_rss_kib = max(s["rss_kib"] for s in s1_samples)
        idle_fds = s1_samples[-1]["fd_count"]
        results["stages"]["1_idle"] = {
            "rss_min_kib": min(s["rss_kib"] for s in s1_samples),
            "rss_peak_kib": idle_rss_kib,
            "fd_steady": idle_fds,
            "active_connections": s1_samples[-1]["active_connections"],
        }

        # Stage 2: 200 idle / low-traffic connections (64B heartbeat x 4 rounds)
        sampler.start()
        t0 = time.perf_counter()
        conns_200 = await asyncio.gather(
            *[socks5_open_ipv4(mixed_port, echo_port) for _ in range(200)]
        )
        establish_s = time.perf_counter() - t0

        heartbeat = b"yachiyo-low-traffic-heartbeat-64bytes-padding-0123456789abcdef!!"
        for _ in range(4):
            await asyncio.sleep(0.4)
            async def beat(pair: tuple[asyncio.StreamReader, asyncio.StreamWriter]) -> None:
                r, w = pair
                w.write(heartbeat)
                await w.drain()
                got = await r.readexactly(len(heartbeat))
                if got != heartbeat:
                    raise RuntimeError("Heartbeat mismatch")

            await asyncio.gather(*[beat(c) for c in conns_200])

        mid_snap_2 = await sampler.snapshot_once()
        await asyncio.gather(*[close_writer(w) for _, w in conns_200])
        await asyncio.sleep(1.0)
        s2_samples = await sampler.stop()
        settle_2 = await sampler.snapshot_once()
        results["stages"]["2_200_idle_low_traffic"] = {
            "connections": 200,
            "connect_rate_per_sec": round(200.0 / establish_s, 1),
            "rss_peak_kib": max(s["rss_kib"] for s in s2_samples),
            "rss_settle_kib": settle_2["rss_kib"],
            "fd_in_flight": mid_snap_2["fd_count"],
            "fd_settle": settle_2["fd_count"],
            "active_settle": settle_2["active_connections"],
        }

        # Stage 3: 200 active concurrent connections with repeatable traffic
        # 200 conns * 16 chunks * 16 KiB = 50 MiB upload + 50 MiB download (100 MiB bidirectional)
        chunk = os.urandom(16384)
        chunks_per_conn = 16
        rtts_ms: list[float] = []

        sampler.start()
        t_start = time.perf_counter()
        active_conns = await asyncio.gather(
            *[socks5_open_ipv4(mixed_port, echo_port) for _ in range(200)]
        )
        t_connected = time.perf_counter()

        async def pump_conn(
            pair: tuple[asyncio.StreamReader, asyncio.StreamWriter]
        ) -> None:
            r, w = pair
            for _ in range(chunks_per_conn):
                c0 = time.perf_counter()
                w.write(chunk)
                await w.drain()
                echoed = await r.readexactly(len(chunk))
                if echoed != chunk:
                    raise RuntimeError("Payload mismatch under 200-conn load")
                rtts_ms.append((time.perf_counter() - c0) * 1000.0)

        await asyncio.gather(*[pump_conn(c) for c in active_conns])
        transfer_elapsed = time.perf_counter() - t_connected
        mid_snap_3 = await sampler.snapshot_once()

        await asyncio.gather(*[close_writer(w) for _, w in active_conns])
        await asyncio.sleep(1.0)
        s3_samples = await sampler.stop()
        settle_3 = await sampler.snapshot_once()

        one_way_mib = (200 * chunks_per_conn * len(chunk)) / (1024.0 * 1024.0)
        bi_mib = one_way_mib * 2.0
        rtts_sorted = sorted(rtts_ms)
        p50_ms = statistics.median(rtts_sorted)
        p95_ms = rtts_sorted[int(len(rtts_sorted) * 0.95)]

        results["stages"]["3_200_active_traffic"] = {
            "connections": 200,
            "one_way_mib": round(one_way_mib, 2),
            "bidirectional_mib": round(bi_mib, 2),
            "connect_rate_per_sec": round(200.0 / (t_connected - t_start), 1),
            "bidirectional_throughput_mib_s": round(bi_mib / transfer_elapsed, 2),
            "bidirectional_throughput_mbps": round((bi_mib * 8.0) / transfer_elapsed, 1),
            "chunk_16k_rtt_p50_ms": round(p50_ms, 3),
            "chunk_16k_rtt_p95_ms": round(p95_ms, 3),
            "rss_peak_kib": max(s["rss_kib"] for s in s3_samples),
            "rss_settle_kib": settle_3["rss_kib"],
            "fd_peak": max(mid_snap_3["fd_count"], max(s["fd_count"] for s in s3_samples)),
            "fd_settle": settle_3["fd_count"],
            "active_settle": settle_3["active_connections"],
        }

        # Stage 4: Short-connection storm (1,000 short sessions, concurrency=50) + 25 SIGHUP reloads
        sem = asyncio.Semaphore(50)
        short_payload = b"short-storm-ping-256" * 12
        storm_errors = 0

        async def one_short_session() -> None:
            nonlocal storm_errors
            async with sem:
                try:
                    r, w = await socks5_open_ipv4(mixed_port, echo_port)
                    w.write(short_payload)
                    await w.drain()
                    got = await r.readexactly(len(short_payload))
                    if got != short_payload:
                        storm_errors += 1
                    await close_writer(w)
                except Exception:
                    storm_errors += 1

        reload_latencies_ms: list[float] = []

        async def reload_driver(count: int) -> None:
            for i in range(1, count + 1):
                cfg_path.write_text(
                    render_yaml_config(
                        mixed_port, probe_port, variant=i, log_level=log_level
                    ),
                    encoding="utf-8",
                )
                r0 = time.perf_counter()
                os.kill(proc.pid, signal.SIGHUP)
                expected_gen = i + 1
                while True:
                    st = await ipc_query(sock_path, "STATUS")
                    if st.get("config_generation", 0) >= expected_gen:
                        reload_latencies_ms.append((time.perf_counter() - r0) * 1000.0)
                        break
                    if time.perf_counter() - r0 > 5.0:
                        raise RuntimeError(
                            f"SIGHUP reload stuck before generation {expected_gen}"
                        )
                    await asyncio.sleep(0.005)
                await asyncio.sleep(0.02)

        sampler.start()
        storm_t0 = time.perf_counter()
        await asyncio.gather(
            asyncio.gather(*[one_short_session() for _ in range(1000)]),
            reload_driver(25),
        )
        storm_elapsed = time.perf_counter() - storm_t0
        await asyncio.sleep(1.2)
        s4_samples = await sampler.stop()
        settle_4 = await sampler.snapshot_once()
        final_stats = await ipc_query(sock_path, "STATS")

        results["stages"]["4_short_storm_and_sighup_reloads"] = {
            "short_connections_total": 1000,
            "short_connections_errors": storm_errors,
            "short_conn_rate_per_sec": round(1000.0 / storm_elapsed, 1),
            "sighup_reloads": 25,
            "final_config_generation": settle_4["config_generation"],
            "reload_p50_ms": round(statistics.median(reload_latencies_ms), 2),
            "reload_max_ms": round(max(reload_latencies_ms), 2),
            "rss_peak_kib": max(s["rss_kib"] for s in s4_samples),
            "rss_settle_kib": settle_4["rss_kib"],
            "fd_peak": max(s["fd_count"] for s in s4_samples),
            "fd_settle": settle_4["fd_count"],
            "active_settle": settle_4["active_connections"],
            "ipc_total_connections": final_stats.get("total_connections"),
        }

        # Clean SIGINT shutdown verification
        proc.send_signal(signal.SIGINT)
        exit_rc = proc.wait(timeout=5.0)
        results["clean_sigint_exit_code"] = exit_rc
        results["socket_unlinked_on_exit"] = not sock_path.exists()
        return results
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3.0)
        log_fp.close()
        echo_srv.close()
        probe_srv.close()
        await echo_srv.wait_closed()
        await probe_srv.wait_closed()
        for p in (cfg_path, sock_path, log_path):
            try:
                p.unlink()
            except OSError:
                pass


async def run_soak_loop(
    bin_path: Path,
    duration_secs: int,
    reload_interval_secs: int,
    sample_interval_secs: int,
    output_jsonl: Path | None,
    log_level: str,
) -> int:
    """Continuous M2 soak harness (e.g. 28800s = 8 hours) monitoring RSS, FDs, and SIGHUP reloads."""
    raise_nofile_limit()
    echo_srv, echo_port, probe_srv, probe_port = await start_echo_and_probe_servers()
    mixed_port = get_free_port()
    pid_tag = os.getpid()
    cfg_path = Path(f"/tmp/ysoak_cfg_{pid_tag}.yaml")
    sock_path = Path(f"/tmp/ysoak_{pid_tag}.sock")

    cfg_path.write_text(
        render_yaml_config(mixed_port, probe_port, variant=0, log_level=log_level),
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [str(bin_path), "--config", str(cfg_path), "--ipc-path", str(sock_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    out_fp = output_jsonl.open("w", encoding="utf-8") if output_jsonl else None
    try:
        for _ in range(100):
            if sock_path.exists():
                break
            await asyncio.sleep(0.05)

        start = time.monotonic()
        next_reload = start + reload_interval_secs
        reload_seq = 0
        payload = b"soak-wave-frame-1024" * 51

        while time.monotonic() - start < duration_secs:
            conns = await asyncio.gather(
                *[socks5_open_ipv4(mixed_port, echo_port) for _ in range(100)]
            )
            for _, w in conns:
                w.write(payload)
            await asyncio.gather(*[w.drain() for _, w in conns])
            await asyncio.gather(*[r.readexactly(len(payload)) for r, _ in conns])
            await asyncio.gather(*[close_writer(w) for _, w in conns])

            now = time.monotonic()
            if now >= next_reload:
                reload_seq += 1
                cfg_path.write_text(
                    render_yaml_config(
                        mixed_port, probe_port, variant=reload_seq, log_level=log_level
                    ),
                    encoding="utf-8",
                )
                os.kill(proc.pid, signal.SIGHUP)
                next_reload = now + reload_interval_secs

            st = await ipc_query(sock_path, "STATUS")
            stats = await ipc_query(sock_path, "STATS")
            record = {
                "elapsed_secs": round(now - start, 1),
                "rss_kib": sample_rss_kib(proc.pid),
                "fd_count": sample_open_fds(proc.pid),
                "active_connections": st.get("active_connections"),
                "config_generation": st.get("config_generation"),
                "total_connections": stats.get("total_connections"),
            }
            line = json.dumps(record, ensure_ascii=False)
            print(line, flush=True)
            if out_fp is not None:
                out_fp.write(line + "\n")
                out_fp.flush()

            remaining = duration_secs - (time.monotonic() - start)
            if remaining <= 0:
                break
            await asyncio.sleep(min(float(sample_interval_secs), remaining))

        proc.send_signal(signal.SIGINT)
        return proc.wait(timeout=5.0)
    finally:
        if out_fp is not None:
            out_fp.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3.0)
        echo_srv.close()
        probe_srv.close()
        await echo_srv.wait_closed()
        await probe_srv.wait_closed()
        for p in (cfg_path, sock_path):
            try:
                p.unlink()
            except OSError:
                pass


def find_default_binary() -> Path:
    for rel in ("target/release/yachiyo", "target/debug/yachiyo"):
        cand = ROOT / rel
        if cand.is_file():
            return cand
    raise SystemExit(
        "yachiyo binary not found; build first with `cargo build --release -p yachiyo-cli`."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Project Yachiyo M2 load baseline and 8-hour soak test runner"
    )
    parser.add_argument(
        "--mode",
        choices=("baseline", "soak"),
        default="baseline",
        help="Run the 4-stage baseline suite or continuous soak loop",
    )
    parser.add_argument(
        "--bin",
        type=Path,
        default=None,
        help="Path to compiled yachiyo binary (defaults to target/release/yachiyo)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        help="Daemon logging.level during measurement (default: info)",
    )
    parser.add_argument(
        "--duration-secs",
        type=int,
        default=28800,
        help="Soak duration in seconds when --mode=soak (default: 28800 = 8h)",
    )
    parser.add_argument(
        "--reload-interval-secs",
        type=int,
        default=60,
        help="SIGHUP reload period in seconds when --mode=soak (default: 60)",
    )
    parser.add_argument(
        "--sample-interval-secs",
        type=int,
        default=5,
        help="Sampling period in seconds when --mode=soak (default: 5)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON (baseline) or JSONL (soak) output file path",
    )
    args = parser.parse_args()
    bin_path = args.bin.resolve() if args.bin else find_default_binary()

    if args.mode == "baseline":
        summary = asyncio.run(run_baseline_suite(bin_path, args.log_level))
        rendered = json.dumps(summary, indent=2, ensure_ascii=False)
        print(rendered)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 0 if summary.get("clean_sigint_exit_code") == 0 else 1

    return asyncio.run(
        run_soak_loop(
            bin_path=bin_path,
            duration_secs=args.duration_secs,
            reload_interval_secs=args.reload_interval_secs,
            sample_interval_secs=args.sample_interval_secs,
            output_jsonl=args.output,
            log_level=args.log_level,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
