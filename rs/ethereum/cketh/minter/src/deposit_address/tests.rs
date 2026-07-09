use crate::address::ecdsa_public_key_to_address;
use crate::deposit_address::{
    DepositAddressSchema, deposit_address, deposit_derivation_path, sweeper_address,
};
use crate::test_fixtures::arb::arb_principal;
use candid::Principal;
use ic_secp256k1::{PrivateKey, PublicKey};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use proptest::array::uniform32;
use proptest::collection::btree_set;
use proptest::option;
use proptest::prelude::any;
use proptest::{prop_assert_eq, proptest};
use std::collections::BTreeSet;

proptest! {
    #[test]
    fn should_derive_distinct_addresses_for_distinct_principals(
        owners in btree_set(arb_principal(), 1..=100),
        subaccount in option::of(uniform32(any::<u8>())),
    ) {
        let (pk, cc) = master_key();

        let addresses: BTreeSet<_> = owners
            .iter()
            .map(|owner| {
                deposit_address(
                    &pk,
                    &cc,
                    DepositAddressSchema::CkErc20,
                    &account(*owner, subaccount),
                )
            })
            .collect();

        prop_assert_eq!(addresses.len(), owners.len());
    }

    #[test]
    fn should_derive_distinct_addresses_for_distinct_subaccounts(
        owner in arb_principal(),
        subaccounts in btree_set(uniform32(any::<u8>()), 1..=100),
    ) {
        let (pk, cc) = master_key();

        let addresses: BTreeSet<_> = subaccounts
            .iter()
            .map(|subaccount| {
                deposit_address(
                    &pk,
                    &cc,
                    DepositAddressSchema::CkErc20,
                    &account(owner, Some(*subaccount)),
                )
            })
            .collect();

        prop_assert_eq!(addresses.len(), subaccounts.len());
    }
}

#[test]
fn should_derive_distinct_addresses_for_distinct_schema_tags() {
    let (pk, cc) = master_key();
    let account = account(principal(1), Some(subaccount(1)));

    let ckerc20 = deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &account);
    let cketh = deposit_address(&pk, &cc, DepositAddressSchema::CkEth, &account);
    let sweeper = sweeper_address(&pk, &cc);

    let distinct: BTreeSet<_> = [ckerc20, cketh, sweeper].into_iter().collect();
    assert_eq!(distinct.len(), 3);
}

#[test]
fn should_not_collide_with_main_address() {
    let (pk, cc) = master_key();
    let main_address = ecdsa_public_key_to_address(&pk);
    let account = account(principal(1), None);

    assert!(!deposit_derivation_path(DepositAddressSchema::CkErc20, &account).is_empty());

    assert_ne!(
        deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &account),
        main_address
    );
    assert_ne!(
        deposit_address(&pk, &cc, DepositAddressSchema::CkEth, &account),
        main_address
    );
    assert_ne!(sweeper_address(&pk, &cc), main_address);
}

fn master_key() -> (PublicKey, [u8; 32]) {
    let (private_key, chain_code) = master_private_key();
    (private_key.public_key(), chain_code)
}

fn master_private_key() -> (PrivateKey, [u8; 32]) {
    let private_key = PrivateKey::generate_from_seed(b"ic-cketh-minter-deposit-address-test-seed");
    (private_key, [7_u8; 32])
}

fn account(owner: Principal, subaccount: Option<Subaccount>) -> Account {
    Account { owner, subaccount }
}

fn principal(i: u8) -> Principal {
    Principal::from_slice(&[i, 1, 2, 3, 4, 5, 6, 7, 8, 9])
}

fn subaccount(i: u8) -> Subaccount {
    let mut bytes = [0_u8; 32];
    bytes[31] = i;
    bytes
}
