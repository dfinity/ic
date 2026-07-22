use super::*;
use crate::test_fixtures::initial_state;
use candid::Principal;
use ic_secp256k1::PrivateKey;

fn master_key() -> (PublicKey, [u8; 32]) {
    let private_key = PrivateKey::generate_from_seed(b"ic-cketh-minter-deposit-erc20-test-seed");
    (private_key.public_key(), [7_u8; 32])
}

fn account() -> Account {
    Account {
        owner: Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
        subaccount: None,
    }
}

#[test]
fn should_derive_and_store_deposit_address() {
    let mut state = initial_state();
    let (pk, cc) = master_key();
    let now = Timestamp::from_nanos(0);

    let result = register_deposit_address(&mut state, &pk, &cc, now, account());

    let expected = deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &account());
    let expected_valid_until = Timestamp::from_nanos(
        now.as_nanos()
            + crate::state::automatic_deposits::DEPOSIT_ADDRESS_SCAN_WINDOW.as_nanos() as u64,
    );
    assert_eq!(result, Ok((expected, expected_valid_until)));
    assert_eq!(state.automatic_deposits.watchlist_iter().count(), 1);
    assert_eq!(
        state.automatic_deposits.get(now, &account()),
        Some(&expected)
    );
}

#[test]
fn should_return_same_address_without_growing_registry_on_reregistration() {
    let mut state = initial_state();
    let (pk, cc) = master_key();

    let first = register_deposit_address(&mut state, &pk, &cc, Timestamp::from_nanos(0), account());
    let second =
        register_deposit_address(&mut state, &pk, &cc, Timestamp::from_nanos(1), account());

    assert!(first.is_ok());
    assert_eq!(first, second);
    assert_eq!(state.automatic_deposits.watchlist_iter().count(), 1);
}
