use super::*;
use ic_types::time::Time;

const HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
// A realistic "now" (~2023) that is well away from the u64 boundary.
const NOW_NANOS: u64 = 1_700_000_000 * 1_000_000_000;

fn t(nanos: u64) -> Time {
    Time::from_nanos_since_unix_epoch(nanos)
}

// A window whose span exceeds the documented 24h bound would make the loop
// build a huge list of ingress expiries, so it is rejected before the loop.
#[test]
fn oversized_ingress_window_is_rejected() {
    assert!(
        validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + 48 * HOUR_NANOS))
            .is_err()
    );
}

// A near-zero start together with a near-`u64::MAX` end spans almost the
// entire u64 range; that enormous span is rejected (it would otherwise
// iterate billions of times).
#[test]
fn unbounded_ingress_span_is_rejected() {
    assert!(validate_ingress_window(t(NOW_NANOS), t(0), t(u64::MAX)).is_err());
}

// A window ending at (near) `u64::MAX` has a small span but an end far in the
// future; without the future bound the loop counter would wrap past
// `u64::MAX` and never terminate. The future bound rejects it.
#[test]
fn near_u64_max_ingress_window_is_rejected() {
    let start = t(u64::MAX - 50 * 1_000_000_000);
    assert!(validate_ingress_window(t(NOW_NANOS), start, t(u64::MAX)).is_err());
}

// A reversed or empty window (ingress_end <= ingress_start) is rejected
// rather than silently producing an empty set of payloads.
#[test]
fn reversed_ingress_window_is_rejected() {
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS + 1), t(NOW_NANOS)).is_err());
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS)).is_err());
}

// Negative control: a realistic window (5 minutes ahead of now) is accepted.
#[test]
fn valid_ingress_window_is_accepted() {
    let end = t(NOW_NANOS + 5 * 60 * 1_000_000_000);
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), end).is_ok());
}

// Boundary: a window of exactly 24h ending exactly 24h from now is accepted,
// one nanosecond more is rejected.
#[test]
fn ingress_window_boundary_is_inclusive() {
    let max = MAX_INGRESS_WINDOW.as_nanos() as u64;
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + max)).is_ok());
    assert!(validate_ingress_window(t(NOW_NANOS), t(NOW_NANOS), t(NOW_NANOS + max + 1)).is_err());
}

// Boundary: exactly the maximum number of (request, ingress expiry) pairs is
// accepted, one more request or one more expiry is rejected.
#[test]
fn request_ingress_expiry_pairs_boundary_is_inclusive() {
    const EXPIRIES: usize = 720;
    const MAX_REQUESTS: usize = MAX_REQUEST_INGRESS_EXPIRY_PAIRS / EXPIRIES;
    assert_eq!(MAX_REQUESTS * EXPIRIES, MAX_REQUEST_INGRESS_EXPIRY_PAIRS);

    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS - 1, EXPIRIES).is_ok());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS, EXPIRIES).is_ok());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUESTS + 1, EXPIRIES).is_err());
    assert!(validate_request_ingress_expiry_pairs(MAX_REQUEST_INGRESS_EXPIRY_PAIRS, 1).is_ok());
    assert!(
        validate_request_ingress_expiry_pairs(MAX_REQUEST_INGRESS_EXPIRY_PAIRS + 1, 1).is_err()
    );
}

// The product of the counts must not wrap around and slip under the bound.
#[test]
fn request_ingress_expiry_pairs_overflow_is_rejected() {
    assert!(validate_request_ingress_expiry_pairs(usize::MAX, 2).is_err());
    assert!(validate_request_ingress_expiry_pairs(2, usize::MAX).is_err());
}
