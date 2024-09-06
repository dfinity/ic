use super::*;

use crate::ledger::compute_neuron_staking_subaccount_bytes;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;

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
            "{}",
            e8s
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
