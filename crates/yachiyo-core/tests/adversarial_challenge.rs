// SPDX-License-Identifier: AGPL-3.0-only

//! Comprehensive empirical stress and adversarial challenge test suite for `crates/yachiyo-core`.
//!
//! Evaluates:
//! 1. Concurrency: 1024 limit exact boundary, CAS churn under contention, racing drain tasks.
//! 2. Address parsing: Malformed IPv6 brackets, injection characters, extreme domain lengths, RFC boundaries.
//! 3. Formatting & Display roundtrip contracts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use yachiyo_core::{AddressParseError, ConnectionTracker, TargetAddr, TargetHost};

fn run_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// =========================================================================
// Category 1: Concurrency & ConnectionTracker Empirical Stress Tests
// =========================================================================

#[test]
fn test_exact_1024_boundary_and_no_leak_under_rejection() {
    let tracker = ConnectionTracker::new(1024);
    assert_eq!(tracker.limit(), 1024);
    assert_eq!(tracker.active_count(), 0);

    // 1. Acquire exactly 1024 connections
    let mut guards = Vec::with_capacity(1024);
    for i in 0..1024 {
        let guard = tracker
            .try_acquire()
            .unwrap_or_else(|| panic!("failed to acquire slot {i}"));
        guards.push(guard);
    }
    assert_eq!(tracker.active_count(), 1024);

    // 2. 1025th acquire MUST be rejected immediately (None)
    assert!(tracker.try_acquire().is_none());
    assert_eq!(tracker.active_count(), 1024);

    // 3. 5000 successive rejection attempts MUST NOT leak count
    for _ in 0..5000 {
        assert!(tracker.try_acquire().is_none());
    }
    assert_eq!(
        tracker.active_count(),
        1024,
        "count must remain exactly 1024 after rejections"
    );

    // 4. Release 50 guards
    guards.truncate(974);
    assert_eq!(tracker.active_count(), 974);

    // 5. Re-acquire 50 guards
    for i in 0..50 {
        let g = tracker
            .try_acquire()
            .unwrap_or_else(|| panic!("failed to re-acquire slot {i}"));
        guards.push(g);
    }
    assert_eq!(tracker.active_count(), 1024);
    assert!(tracker.try_acquire().is_none());

    // 6. Release all guards
    guards.clear();
    assert_eq!(tracker.active_count(), 0);

    // 7. Drain should succeed immediately
    run_async(async {
        let drain_res = tracker.wait_drained(Duration::from_millis(100)).await;
        assert_eq!(drain_res, Ok(()));
    });
}

#[test]
fn test_high_contention_multi_threaded_cas_churn() {
    // Limit = 8, with 16 threads hammering acquire/drop concurrently.
    let tracker = Arc::new(ConnectionTracker::new(8));
    let num_threads = 16;
    let rounds = 50;
    let barrier = Arc::new(std::sync::Barrier::new(num_threads));
    let acquired_total = Arc::new(AtomicUsize::new(0));
    let rejected_total = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let t = Arc::clone(&tracker);
        let b = Arc::clone(&barrier);
        let acq = Arc::clone(&acquired_total);
        let rej = Arc::clone(&rejected_total);

        handles.push(std::thread::spawn(move || {
            for _ in 0..rounds {
                b.wait();
                let guard = t.try_acquire();
                if let Some(ref _g) = guard {
                    acq.fetch_add(1, Ordering::Relaxed);
                    let active = t.active_count();
                    assert!(
                        (1..=8).contains(&active),
                        "active count {active} out of bounds [1, 8]"
                    );
                } else {
                    rej.fetch_add(1, Ordering::Relaxed);
                }
                b.wait();
                // All threads hold until barrier, guaranteeing exactly 8 acquires and 8 rejects per round
                drop(guard);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        tracker.active_count(),
        0,
        "all acquired guards must have dropped cleanly"
    );
    let total_acq = acquired_total.load(Ordering::Relaxed);
    let total_rej = rejected_total.load(Ordering::Relaxed);
    assert_eq!(
        total_acq,
        rounds * 8,
        "exactly limit=8 slots should be acquired per round"
    );
    assert_eq!(
        total_rej,
        rounds * (num_threads - 8),
        "exactly 8 rejections should occur per round"
    );

    run_async(async {
        assert_eq!(
            tracker.wait_drained(Duration::from_millis(100)).await,
            Ok(())
        );
    });
}

#[test]
fn test_racing_drain_tasks_under_concurrent_churn() {
    run_async(async {
        let tracker = ConnectionTracker::new(32);
        let mut active_guards = Vec::new();
        for _ in 0..16 {
            active_guards.push(tracker.try_acquire().unwrap());
        }
        assert_eq!(tracker.active_count(), 16);

        // Spawn 10 concurrent tasks all calling wait_drained
        let num_drainers = 10;
        let mut drain_handles = Vec::new();
        for i in 0..num_drainers {
            let t = tracker.clone();
            drain_handles.push(tokio::spawn(async move {
                t.wait_drained(Duration::from_secs(3)).await
            }));
            if i % 3 == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Gradually drop guards across multiple asynchronous steps
        while let Some(g) = active_guards.pop() {
            tokio::time::sleep(Duration::from_millis(5)).await;
            drop(g);
        }

        assert_eq!(tracker.active_count(), 0);

        // ALL drainers MUST complete with Ok(())
        for h in drain_handles {
            let res = h.await.expect("drain task panicked");
            assert_eq!(res, Ok(()), "all concurrent drainers must succeed");
        }
    });
}

#[test]
fn test_drain_under_racing_acquire_and_drop_cycles() {
    run_async(async {
        let tracker = ConnectionTracker::new(10);
        let stop_flag = Arc::new(AtomicBool::new(false));

        // Background task continuously acquiring and releasing
        let worker_tracker = tracker.clone();
        let worker_stop = Arc::clone(&stop_flag);
        let worker_handle = tokio::spawn(async move {
            while !worker_stop.load(Ordering::Acquire) {
                let mut local_guards = Vec::new();
                for _ in 0..5 {
                    if let Some(g) = worker_tracker.try_acquire() {
                        local_guards.push(g);
                    }
                }
                tokio::task::yield_now().await;
                drop(local_guards);
            }
        });

        // Let churn run for 50ms
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Stop the worker and wait for it to exit
        stop_flag.store(true, Ordering::Release);
        worker_handle.await.unwrap();

        // Now drain MUST cleanly succeed
        let drain_res = tracker.wait_drained(Duration::from_millis(500)).await;
        assert_eq!(drain_res, Ok(()));
        assert_eq!(tracker.active_count(), 0);
    });
}

#[test]
fn test_drain_timeout_remaining_count_consistency() {
    run_async(async {
        let tracker = ConnectionTracker::new(10);
        let mut g = Vec::new();
        for _ in 0..5 {
            g.push(tracker.try_acquire().unwrap());
        }

        // 5 active guards held
        let res = tracker.wait_drained(Duration::from_millis(20)).await;
        assert_eq!(res, Err(5), "should report exactly 5 remaining guards");

        // Release 2 guards
        g.truncate(3);
        let res2 = tracker.wait_drained(Duration::from_millis(20)).await;
        assert_eq!(res2, Err(3), "should report exactly 3 remaining guards");

        // Release all remaining guards
        g.clear();
        let res3 = tracker.wait_drained(Duration::from_millis(20)).await;
        assert_eq!(
            res3,
            Ok(()),
            "should succeed with Ok(()) when all guards released"
        );
    });
}

#[test]
fn test_drain_future_cancellation_safety() {
    run_async(async {
        let tracker = ConnectionTracker::new(10);
        let guard = tracker.try_acquire().unwrap();

        // Start wait_drained and drop future halfway through
        tokio::select! {
            _ = tracker.wait_drained(Duration::from_secs(10)) => {
                panic!("should not drain while guard held");
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                // Cancelled wait_drained future by exiting select
            }
        }

        // Drop guard
        drop(guard);

        // Subsequent drain must still succeed cleanly
        let res = tracker.wait_drained(Duration::from_millis(100)).await;
        assert_eq!(
            res,
            Ok(()),
            "subsequent drain must succeed after cancelled future"
        );
    });
}

#[test]
fn test_tracker_zero_and_single_slot_limits() {
    // Zero limit
    let t0 = ConnectionTracker::new(0);
    assert_eq!(t0.limit(), 0);
    assert_eq!(t0.active_count(), 0);
    assert!(t0.try_acquire().is_none());
    assert_eq!(t0.active_count(), 0);

    // Single slot limit (limit = 1)
    let t1 = ConnectionTracker::new(1);
    assert_eq!(t1.limit(), 1);
    let g1 = t1.try_acquire().expect("slot 1");
    assert_eq!(t1.active_count(), 1);
    assert!(t1.try_acquire().is_none(), "slot 2 must be rejected");

    drop(g1);
    assert_eq!(t1.active_count(), 0);
    let g2 = t1.try_acquire().expect("slot 1 after drop");
    assert_eq!(t1.active_count(), 1);
    drop(g2);
}

// =========================================================================
// Category 2: Address & Parsing Boundary Adversarial Tests
// =========================================================================

#[test]
fn test_malformed_ipv6_brackets() {
    let unclosed_brackets = vec![
        "[::1",
        "[::1:8080",
        "[2001:db8::1",
        "[fe80::",
        "[",
        "[:8080",
        "[]",
    ];
    for input in unclosed_brackets {
        let res = TargetAddr::from_str(input);
        assert!(
            res.is_err(),
            "input '{input}' should fail parsing, got: {res:?}"
        );
        match res.unwrap_err() {
            AddressParseError::MissingClosingBracket(_)
            | AddressParseError::MissingPort(_)
            | AddressParseError::InvalidIpv6(_) => {}
            other => panic!("unexpected error for '{input}': {other:?}"),
        }
    }
}

#[test]
fn test_ipv6_missing_and_invalid_ports() {
    // Missing port
    let missing_ports = vec!["[::1]", "[2001:db8::1]", "[::]", "[::1]abc"];
    for input in missing_ports {
        let res = TargetAddr::from_str(input);
        assert!(
            matches!(res, Err(AddressParseError::MissingPort(_))),
            "expected MissingPort for '{input}', got: {res:?}"
        );
    }

    // Invalid port values (non-numeric, overflow, negative, whitespace)
    let invalid_ports = vec![
        ("[::1]:", "empty port"),
        ("[::1]:99999", "port overflow > 65535"),
        ("[::1]:65536", "port overflow == 65536"),
        ("[::1]:-1", "negative port"),
        ("[::1]:abc", "alphabetic port"),
        ("[::1]:80extra", "trailing garbage in port"),
        ("[::1]: 80", "space before port"),
    ];
    for (input, desc) in invalid_ports {
        let res = TargetAddr::from_str(input);
        assert!(
            matches!(res, Err(AddressParseError::InvalidPort(_))),
            "expected InvalidPort for '{input}' ({desc}), got: {res:?}"
        );
    }
}

#[test]
fn test_unbracketed_ipv6_rejection() {
    let unbracketed = vec![
        "::1:8080",
        "::1",
        "2001:db8::1:80",
        "fe80::1:18484",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334:8080",
    ];
    for input in unbracketed {
        let res = TargetAddr::from_str(input);
        assert!(
            matches!(res, Err(AddressParseError::UnbracketedIpv6(_))),
            "expected UnbracketedIpv6 for '{input}', got: {res:?}"
        );
    }
}

#[test]
fn test_valid_ipv6_bracketed_cases() {
    let valid_cases = vec![
        ("[::1]:8080", IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        ("[::]:18484", IpAddr::V6(Ipv6Addr::UNSPECIFIED), 18484),
        ("[::1]:0", IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        ("[::1]:65535", IpAddr::V6(Ipv6Addr::LOCALHOST), 65535),
        (
            "[2001:db8::1]:443",
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            443,
        ),
        (
            "[::ffff:192.0.2.1]:80",
            IpAddr::V6("::ffff:192.0.2.1".parse().unwrap()),
            80,
        ),
    ];

    for (input, expected_ip, expected_port) in valid_cases {
        let addr = TargetAddr::from_str(input)
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"));
        assert_eq!(addr.port(), expected_port);
        assert_eq!(addr.host(), &TargetHost::Ip(expected_ip));
    }
}

#[test]
fn test_injection_characters_rejected() {
    let malicious = vec![
        // CRLF injection inside host
        "example.com\r\nHost: evil.com:80",
        "example\r.com:80",
        // Null byte injection
        "example.com\0:80",
        "example\0.com:80",
        // URL/URI delimiters
        "example.com/path:80",
        "example.com:80/path",
        "http://example.com:80",
        "example.com?query=1:80",
        "example.com:80?query=1",
        "example.com#fragment:80",
        "example.com:80#fragment",
        // Userinfo injection
        "user:pass@example.com:80",
        "user@example.com:80",
        // Shell injection metacharacters
        "example.com;rm -rf /:80",
        "example.com|cat:80",
        "$(whoami).com:80",
        "`whoami`.com:80",
        // Non-ASCII and emojis
        "exämple.com:80",
        "🌐.com:80",
        "💩.com:80",
        "中文域名.com:80",
        // Internal whitespace inside domain labels
        "example .com:80",
    ];

    for input in malicious {
        let res = TargetAddr::from_str(input);
        assert!(
            res.is_err(),
            "malicious/injection input '{input}' should be rejected, got: {res:?}"
        );
    }
}

/// Adversarial probe verifying whether whitespace/newlines immediately preceding the port colon
/// are improperly trimmed rather than rejected as malformed syntax.
#[test]
fn test_probe_whitespace_newline_preceding_colon_anomaly() {
    // In strict RFC 3986 / RFC 7231 syntax, whitespace before the colon is invalid.
    // However, TargetHost::parse currently trims input, masking these characters.
    let inputs = vec![
        ("example.com\n:80", "newline before colon"),
        ("example.com\r:80", "carriage return before colon"),
        ("example.com\t:80", "tab before colon"),
        ("example.com :80", "space before colon"),
    ];

    for (input, desc) in inputs {
        let res = TargetAddr::from_str(input);
        // Empirically observe that TargetHost::parse(host_part) trims host_part,
        // causing these malformed addresses to be accepted as Ok("example.com", 80)
        assert!(
            res.is_ok(),
            "Empirical finding: input '{input}' ({desc}) unexpectedly succeeds due to inner trim"
        );
    }
}

/// Adversarial probe verifying loopback behavior on FQDN trailing dot.
#[test]
fn test_probe_fqdn_trailing_dot_is_loopback_inconsistency() {
    let plain_localhost: TargetAddr = "localhost:80".parse().unwrap();
    assert!(plain_localhost.is_loopback());

    let fqdn_localhost: TargetAddr = "localhost.:80".parse().unwrap();
    // Observation: TargetHost::is_loopback() checks domain == "localhost" or ends_with(".localhost").
    // For "localhost.", ends_with has a trailing dot, so is_loopback() returns false!
    let is_fqdn_loopback = fqdn_localhost.is_loopback();
    assert!(
        !is_fqdn_loopback,
        "FQDN localhost. returns false due to trailing dot"
    );
}

#[test]
fn test_extreme_domain_lengths() {
    // Label length boundaries (RFC 1035: max 63 chars per label)
    let label_63 = "a".repeat(63);
    let valid_63 = format!("{label_63}.com:80");
    let parsed_63 = TargetAddr::from_str(&valid_63);
    assert!(
        parsed_63.is_ok(),
        "63-char label should be valid, got: {parsed_63:?}"
    );

    let label_64 = "a".repeat(64);
    let invalid_64 = format!("{label_64}.com:80");
    let parsed_64 = TargetAddr::from_str(&invalid_64);
    assert!(
        matches!(parsed_64, Err(AddressParseError::InvalidDomain(_))),
        "64-char label should fail with InvalidDomain, got: {parsed_64:?}"
    );

    // Total domain length boundaries (RFC 1035: max 253 chars)
    // 3 labels of 63 chars + 1 label of 61 chars + 3 dots = 63*3 + 61 + 3 = 189 + 61 + 3 = 253 chars
    let domain_253 = format!(
        "{}.{}.{}.{}:80",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let parsed_253 = TargetAddr::from_str(&domain_253);
    assert!(
        parsed_253.is_ok(),
        "253-char domain should be valid, got: {parsed_253:?}"
    );

    // 254 chars domain
    let domain_254 = format!(
        "{}.{}.{}.{}:80",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    let parsed_254 = TargetAddr::from_str(&domain_254);
    assert!(
        matches!(parsed_254, Err(AddressParseError::InvalidDomain(_))),
        "254-char domain should fail with InvalidDomain, got: {parsed_254:?}"
    );

    // 1000 chars domain
    let domain_1000 = format!("{}:80", "a".repeat(1000));
    let parsed_1000 = TargetAddr::from_str(&domain_1000);
    assert!(
        matches!(parsed_1000, Err(AddressParseError::InvalidDomain(_))),
        "1000-char domain should fail, got: {parsed_1000:?}"
    );
}

#[test]
fn test_domain_label_boundary_formats() {
    let invalid_cases = vec![
        ("-example.com:80", "leading hyphen in label"),
        ("example-.com:80", "trailing hyphen in label"),
        ("-.com:80", "label is just a hyphen"),
        ("example..com:80", "consecutive dots / empty label"),
        (".example.com:80", "leading dot"),
        ("example.com..:80", "double trailing dot"),
        (".:80", "single dot"),
        ("..:80", "double dot"),
    ];
    for (input, desc) in invalid_cases {
        let res = TargetAddr::from_str(input);
        assert!(
            matches!(res, Err(AddressParseError::InvalidDomain(_))),
            "expected InvalidDomain for '{input}' ({desc}), got: {res:?}"
        );
    }

    // Trailing dot for FQDN should be accepted
    let fqdn = "example.com.:80";
    let parsed_fqdn = TargetAddr::from_str(fqdn);
    assert!(
        parsed_fqdn.is_ok(),
        "FQDN with trailing dot should be accepted, got: {parsed_fqdn:?}"
    );
    assert_eq!(
        parsed_fqdn.unwrap().host(),
        &TargetHost::Domain("example.com.".to_string())
    );
}

#[test]
fn test_display_and_from_str_roundtrip() {
    let test_cases = vec![
        TargetAddr::from_ip(Ipv4Addr::new(127, 0, 0, 1), 18484),
        TargetAddr::from_ip(Ipv4Addr::new(192, 168, 1, 100), 80),
        TargetAddr::from_ip(Ipv6Addr::LOCALHOST, 9050),
        TargetAddr::from_ip(Ipv6Addr::UNSPECIFIED, 0),
        TargetAddr::from_ip(Ipv6Addr::from_str("2001:db8::ff00:42:8329").unwrap(), 65535),
        TargetAddr::new(TargetHost::Domain("example.com".into()), 443),
        TargetAddr::new(TargetHost::Domain("sub.domain.example.org".into()), 8080),
        TargetAddr::new(TargetHost::Domain("example.com.".into()), 80),
    ];

    for original in test_cases {
        let formatted = original.to_string();
        let parsed: TargetAddr = formatted
            .parse()
            .unwrap_or_else(|e| panic!("failed to roundtrip parse '{formatted}': {e}"));
        assert_eq!(
            original, parsed,
            "roundtrip mismatch for original: {original:?}"
        );
    }
}

#[test]
fn test_is_loopback_classification() {
    // Loopback IPv4
    assert!(TargetAddr::from_ip(Ipv4Addr::new(127, 0, 0, 1), 80).is_loopback());
    assert!(TargetAddr::from_ip(Ipv4Addr::new(127, 10, 20, 30), 80).is_loopback());

    // Loopback IPv6
    assert!(TargetAddr::from_ip(Ipv6Addr::LOCALHOST, 80).is_loopback());

    // Localhost domain
    assert!(TargetAddr::new(TargetHost::Domain("localhost".into()), 80).is_loopback());
    assert!(TargetAddr::new(TargetHost::Domain("LOCALHOST".into()), 80).is_loopback());
    assert!(TargetAddr::new(TargetHost::Domain("sub.localhost".into()), 80).is_loopback());
    assert!(TargetAddr::new(TargetHost::Domain("SUB.LOCALHOST".into()), 80).is_loopback());

    // Non-loopback
    assert!(!TargetAddr::from_ip(Ipv4Addr::new(192, 168, 1, 1), 80).is_loopback());
    assert!(!TargetAddr::from_ip(Ipv4Addr::new(10, 0, 0, 1), 80).is_loopback());
    assert!(!TargetAddr::from_ip(Ipv6Addr::UNSPECIFIED, 80).is_loopback());
    assert!(!TargetAddr::new(TargetHost::Domain("notlocalhost".into()), 80).is_loopback());
    assert!(!TargetAddr::new(TargetHost::Domain("example.com".into()), 80).is_loopback());
    assert!(!TargetAddr::new(TargetHost::Domain("localhost.example.com".into()), 80).is_loopback());
}
