use crate::blocklist::{is_blocked, ETH_ADDRESS_BLOCKLIST};
use ic_ethereum_types::Address;
use std::str::FromStr;

#[test]
fn check_blocklist_is_sorted() {
    let original = ETH_ADDRESS_BLOCKLIST.to_vec();
    let mut sorted = ETH_ADDRESS_BLOCKLIST.to_vec();
    sorted.sort();
    assert_eq!(original, sorted);
}

#[test]
fn should_find_blocked_address() {
    let blocked_address = Address::from_str("0x2f50508a8a3d323b91336fa3ea6ae50e55f32185").unwrap();
    assert!(is_blocked(&blocked_address));
    let blocked_address = Address::from_str("0x2f50508A8a3d323b91336fa3ea6ae50e55f32185").unwrap();
    assert!(is_blocked(&blocked_address));

    let not_blocked_address =
        Address::from_str("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();
    assert!(!is_blocked(&not_blocked_address));
    let not_blocked_address =
        Address::from_str("0x4838B106FCe9647Bdf1E7877bF73cE8B0BAD5f97").unwrap();
    assert!(!is_blocked(&not_blocked_address));
}

#[test]
fn should_block_blocked_addresses() {
    for address in ETH_ADDRESS_BLOCKLIST {
        assert!(is_blocked(address));
    }
}
