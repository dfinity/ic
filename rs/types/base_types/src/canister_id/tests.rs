use super::*;
use proptest::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// Hashes a value with the standard-library hasher and returns the finished
/// hash, so we can assert `Hash`/`Eq` consistency.
fn hash_of(id: &CanisterId) -> u64 {
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

/// A diverse set of canister IDs exercising both the `u64` fast path and the
/// opaque/long slow path (including a length-10 opaque principal that is *not*
/// a `u64` canister ID).
fn test_canister_ids() -> Vec<CanisterId> {
    let mut ids: Vec<CanisterId> = [
        0,
        1,
        2,
        42,
        0xFF,
        0x100,
        0x0123_4567_89ab_cdef,
        u64::MAX - 1,
        u64::MAX,
    ]
    .into_iter()
    .map(CanisterId::from_u64)
    .collect();

    // Opaque / non-`u64` canister IDs (slow path).
    ids.push(CanisterId::ic_00());
    // A self-authenticating principal (29 bytes), definitely not a `u64` ID.
    ids.push(CanisterId::unchecked_from_principal(
        PrincipalId::from_str("ubktz-haghv-fqsdh-23fhi-3urex-bykoz-pvpfd-5rs6w-qpo3t-nf2dv-oae")
            .unwrap(),
    ));
    // An opaque principal of a different length.
    ids.push(CanisterId::unchecked_from_principal(
        PrincipalId::new_opaque(&[0xDE, 0xAD, 0xBE, 0xEF][..]),
    ));
    // Opaque, length 10, but the penultimate byte is not 0x01: same length as a
    // `u64` canister ID, yet not one.
    ids.push(CanisterId::unchecked_from_principal(
        PrincipalId::new_opaque(&[42; 10][..]),
    ));

    ids
}

/// `eq`, `cmp` and `partial_cmp` must be indistinguishable from comparing the
/// underlying `PrincipalId`s; and equal / different IDs must have equal /
/// different hashes.
#[test]
fn eq_cmp_hash_match_underlying_principal() {
    let ids = test_canister_ids();
    for a in &ids {
        for b in &ids {
            assert_eq!(
                a == b,
                a.get() == b.get(),
                "eq disagrees with principal eq for {a} vs {b}"
            );
            assert_eq!(
                a.cmp(b),
                a.get().cmp(&b.get()),
                "cmp disagrees with principal cmp for {a} vs {b}"
            );
            assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));

            assert_eq!(
                a == b,
                hash_of(a) == hash_of(b),
                "eq disagrees with hash equality for {a} vs {b}"
            );
        }
    }
}

/// The `is_u64` fast path must be invariant to *how* an ID was constructed: a
/// `u64` canister ID reached via a non-`u64`-aware constructor must still be
/// equal to, hash like, and report the same `as_u64` as one built via
/// `from_u64`. This is the linchpin that keeps `eq`/`cmp`/`hash` correct.
#[test]
fn u64_fast_path_is_construction_independent() {
    let via_u64 = CanisterId::from_u64(42);
    assert!(via_u64.is_u64, "{via_u64:?} should be a u64 canister ID");
    assert_eq!(via_u64.as_u64(), Some(42));

    let principal = via_u64.get();
    let via_principal = CanisterId::unchecked_from_principal(principal);
    let via_try = CanisterId::try_from_principal_id(principal).unwrap();

    for other in [via_principal, via_try] {
        assert!(other.is_u64, "{other:?} should be a u64 canister ID");
        assert_eq!(via_u64, other);
        assert_eq!(via_u64.cmp(&other), std::cmp::Ordering::Equal);
        assert_eq!(via_u64.as_u64(), other.as_u64());
        assert_eq!(hash_of(&via_u64), hash_of(&other));
    }
}

/// `as_u64` round-trips `from_u64` and returns `None` for opaque IDs.
#[test]
fn as_u64_round_trips() {
    for n in [0, 1, 42, 0xFF, 0x0123_4567_89ab_cdef, u64::MAX] {
        let id = CanisterId::from_u64(n);
        assert_eq!(id.as_u64(), Some(n));
        // Reconstructing from the reported `u64` yields an equal ID.
        assert_eq!(CanisterId::from_u64(id.as_u64().unwrap()), id);
    }

    // Opaque / non-`u64` canister IDs report `None`.
    assert_eq!(CanisterId::ic_00().as_u64(), None);
    let opaque_len_10 = CanisterId::unchecked_from_principal(PrincipalId::new_opaque(&[42; 9][..]));
    assert_eq!(opaque_len_10.as_u64(), None);
}

/// Ordering of `u64` canister IDs must match numeric ordering of the `u64`s
/// (the big-endian encoding in `from_u64` is what guarantees this).
#[test]
fn u64_ordering_matches_numeric() {
    let mut values = [u64::MAX, 0, 0x100, 1, 42, 0x0123_4567_89ab_cdef, 0xFF, 2];
    let mut ids: Vec<CanisterId> = values.iter().copied().map(CanisterId::from_u64).collect();

    ids.sort();
    values.sort();

    let sorted_via_ids: Vec<u64> = ids.iter().map(|id| id.as_u64().unwrap()).collect();
    assert_eq!(sorted_via_ids, values.to_vec());
}

proptest! {
    /// Over random `u64` pairs, the fast path must agree with both numeric
    /// comparison and comparison of the underlying principals, and `as_u64` must
    /// round-trip.
    #[test]
    fn u64_fast_path_matches_reference(a: u64, b: u64) {
        let ca = CanisterId::from_u64(a);
        let cb = CanisterId::from_u64(b);

        prop_assert_eq!(ca == cb, a == b);
        prop_assert_eq!(ca.cmp(&cb), a.cmp(&b));
        // ... and, equivalently, the underlying-principal behaviour.
        prop_assert_eq!(ca == cb, ca.get() == cb.get());
        prop_assert_eq!(ca.cmp(&cb), ca.get().cmp(&cb.get()));

        prop_assert_eq!(ca.as_u64(), Some(a));
        prop_assert_eq!(cb.as_u64(), Some(b));
    }
}

#[test]
fn test_try_from_principal_id() {
    // Happy case.
    let canister_id = CanisterId::from_u64(42);
    let principal_id: PrincipalId = canister_id.get();
    assert_eq!(
        CanisterId::try_from_principal_id(principal_id),
        Ok(canister_id)
    );

    // Typical sad case: not even opaque (here, self-authenticating).
    let definitely_not_a_canister_id =
        PrincipalId::from_str("ubktz-haghv-fqsdh-23fhi-3urex-bykoz-pvpfd-5rs6w-qpo3t-nf2dv-oae")
            .unwrap();
    match CanisterId::try_from_principal_id(definitely_not_a_canister_id) {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["selfauthenticating", "class"] {
                assert!(
                    description.contains(key_word),
                    "{key_word} not in {description:?}"
                );
            }
        }
        wrong => panic!("{wrong:?}"),
    }

    // Opaque, but wrong length.
    match CanisterId::try_from_principal_id(PrincipalId::new_opaque(&[0xDE, 0xAD, 0xBE, 0xEF][..]))
    {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["5", "bytes"] {
                assert!(
                    description.contains(key_word),
                    "{key_word} not in {description:?}"
                );
            }
        }
        wrong => panic!("{wrong:?}"),
    }

    // Near miss: opaque, length 10, but penultimate is not 0x01 (?!).
    match CanisterId::try_from_principal_id(PrincipalId::new_opaque(&[42; 9][..])) {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["10", "bytes"] {
                assert!(
                    description.contains(key_word),
                    "{key_word} not in {description:?}"
                );
            }
        }
        wrong => panic!("{wrong:?}"),
    }
}
