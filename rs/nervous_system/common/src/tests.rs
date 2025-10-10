use super::*;

use crate::{hash_to_hex_string, ledger::compute_neuron_staking_subaccount_bytes};
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;

// In NNS, 1 "month" is defined as exactly 1/12th of a year. However, it is
// maybe non-obvious that the number of seconds in 1 year is dividible by 12,
// particularly since 1 "year" is defined as exactly 365.25 days. Therefore, the
// "point" here is to make sure that there is no remainder that throws off the
// definition of ONE_MONTH_SECONDS.
const _: () = {
    assert!(ONE_MONTH_SECONDS * 12 == ONE_YEAR_SECONDS);
};

#[test]
fn test_wide_range_of_u64_values() {
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&0));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&1));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&8));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&43));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&57));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&u64::MAX));
}

#[test]
fn test_e8s_to_tokens() {
    for e8s in &*WIDE_RANGE_OF_U64_VALUES {
        let e8s = *e8s;
        assert_eq!(
            denominations_to_tokens(e8s, E8),
            Some(Decimal::from(e8s) / Decimal::from(E8)),
            "{e8s}"
        );
    }
}

#[test]
fn test_compute_neuron_staking_subaccount_bytes() {
    let principal_id = PrincipalId::new_user_test_id(1);
    let nonce = 42u64;

    // The equivalent implementation in the ic-js is at
    // https://github.com/dfinity/ic-js/blob/0dd5c1954d94dad6911b73707c454f978624f607/packages/nns/src/governance.canister.ts#L952-L967.
    let mut hasher = Sha256::new();
    hasher.write(&[0x0c]);
    hasher.write(b"neuron-stake");
    hasher.write(principal_id.as_slice());
    hasher.write(&nonce.to_be_bytes());
    let hash = hasher.finish();

    assert_eq!(
        compute_neuron_staking_subaccount_bytes(principal_id, nonce),
        hash
    );
}

#[test]
fn test_hash_to_hex_string_empty() {
    let empty: [u8; 0] = [];
    assert_eq!(hash_to_hex_string(&empty), "");
}

#[test]
fn test_hash_to_hex_string_single_byte() {
    let single = [0xAB];
    assert_eq!(hash_to_hex_string(&single), "ab");
}

#[test]
fn test_hash_to_hex_string_multiple_bytes() {
    let bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    assert_eq!(hash_to_hex_string(&bytes), "123456789abcdef0");
}
