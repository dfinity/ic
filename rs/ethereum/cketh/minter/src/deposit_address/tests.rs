use crate::address::ecdsa_public_key_to_address;
use crate::deposit_address::{DepositAddressSchema, deposit_address, sweeper_address};
use crate::test_fixtures::arb::arb_principal;
use candid::Principal;
use ic_secp256k1::{PrivateKey, PublicKey};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use proptest::array::uniform32;
use proptest::collection::btree_set;
use proptest::option;
use proptest::prelude::any;
use proptest::{prop_assert_eq, prop_assert_ne, proptest};
use std::collections::BTreeSet;

proptest! {
    #[test]
    fn should_derive_distinct_addresses_for_distinct_principals(
        owners in btree_set(arb_principal(), 1..=100),
        subaccount in option::of(uniform32(any::<u8>())),
    ) {
        let (pk, cc) = master_key();

        for schema in [DepositAddressSchema::CkErc20, DepositAddressSchema::CkEth] {
            let addresses: BTreeSet<_> = owners
                .iter()
                .map(|owner| deposit_address(&pk, &cc, schema, &account(*owner, subaccount)))
                .collect();

            prop_assert_eq!(addresses.len(), owners.len());
        }
    }

    #[test]
    fn should_derive_distinct_addresses_for_distinct_subaccounts(
        owner in arb_principal(),
        subaccounts in btree_set(uniform32(any::<u8>()), 1..=100),
    ) {
        let (pk, cc) = master_key();

        for schema in [DepositAddressSchema::CkErc20, DepositAddressSchema::CkEth] {
            let addresses: BTreeSet<_> = subaccounts
                .iter()
                .map(|subaccount| deposit_address(&pk, &cc, schema, &account(owner, Some(*subaccount))))
                .collect();

            prop_assert_eq!(addresses.len(), subaccounts.len());
        }
    }

    #[test]
    fn should_not_collide_with_main_or_sweeper_address(
        owner in arb_principal(),
        subaccount in option::of(uniform32(any::<u8>())),
    ) {
        let (pk, cc) = master_key();
        let main_address = ecdsa_public_key_to_address(&pk);
        let sweeper = sweeper_address(&pk, &cc);
        let account = account(owner, subaccount);

        for schema in [DepositAddressSchema::CkErc20, DepositAddressSchema::CkEth] {
            let deposit = deposit_address(&pk, &cc, schema, &account);
            prop_assert_ne!(deposit.as_address(), &main_address);
            prop_assert_ne!(deposit.as_address(), &sweeper);
        }
    }

    #[test]
    fn should_derive_distinct_addresses_for_distinct_schemas(
        owner in arb_principal(),
        subaccount in option::of(uniform32(any::<u8>())),
    ) {
        let (pk, cc) = master_key();
        let account = account(owner, subaccount);

        let ckerc20 = deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &account);
        let cketh = deposit_address(&pk, &cc, DepositAddressSchema::CkEth, &account);

        prop_assert_ne!(ckerc20, cketh);
    }
}

#[test]
fn should_derive_stable_addresses() {
    let (pk, cc) = master_key();
    let p1 = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
    let p2 = Principal::from_text("ss2fx-dyaaa-aaaar-qacoq-cai").unwrap();
    let s1 = [0_u8; 32];
    let mut s2 = [0_u8; 32];
    s2[31] = 1;

    // (owner, subaccount, expected ckERC20 address, expected ckETH address)
    let cases = [
        (
            p1,
            s1,
            "0xD89FE581Db8Dbcb45736c5A9d6abdBE78913bD89",
            "0xBdB75DE85a7E7221525180d559F57FdE80a3709f",
        ),
        (
            p1,
            s2,
            "0xB4fB9b1fA6820deF3E4417a074497000F58ef167",
            "0x8c08A03915F5E15AC41381500219100f92d8e4d5",
        ),
        (
            p2,
            s1,
            "0x98c8C7b65485928e6cffDAA806a8eE27Cf1fF39C",
            "0xE9400F21Ef90d541A605725114F59037919E05b7",
        ),
        (
            p2,
            s2,
            "0x5D396800716451E5202Fb935e436Ab82aCe52881",
            "0x7513b3849F4B53301f620487cD5304240A5E963d",
        ),
    ];

    for (owner, subaccount, expected_ckerc20, expected_cketh) in cases {
        let account = account(owner, Some(subaccount));
        assert_eq!(
            deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &account).to_string(),
            expected_ckerc20
        );
        assert_eq!(
            deposit_address(&pk, &cc, DepositAddressSchema::CkEth, &account).to_string(),
            expected_cketh
        );
    }
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

mod derive_public_key {
    use crate::deposit_address::{
        DepositAddressSchema, deposit_address, derive_public_key, sweeper_derivation_path,
    };
    use crate::{MAIN_DERIVATION_PATH, address::ecdsa_public_key_to_address};
    use candid::Principal;
    use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};
    use icrc_ledger_types::icrc1::account::Account;
    use serde_bytes::ByteBuf;

    const CHAIN_CODE: [u8; 32] = [7_u8; 32];

    #[test]
    fn should_derive_the_key_whose_address_is_the_deposit_address() {
        let master = master_private_key().public_key();
        let account = account();

        for schema in [DepositAddressSchema::CkErc20, DepositAddressSchema::CkEth] {
            let path = super::super::deposit_derivation_path(schema, &account);
            let derived = derive_public_key(&master, &CHAIN_CODE, &path);

            assert_eq!(
                &ecdsa_public_key_to_address(&derived),
                deposit_address(&master, &CHAIN_CODE, schema, &account).as_address()
            );
        }
    }

    #[test]
    fn should_derive_the_master_key_for_the_main_address() {
        let master = master_private_key().public_key();

        assert_eq!(
            derive_public_key(&master, &CHAIN_CODE, &MAIN_DERIVATION_PATH),
            master
        );
    }

    /// A signature made under a derivation path only recovers against the key derived along that
    /// same path: recovering it against the master key finds no parity bit at all, which is why
    /// `compute_recovery_id` derives before recovering.
    #[test]
    fn should_recover_a_derived_signature_only_against_the_derived_key() {
        let master = master_private_key();
        let digest = [0x42_u8; 32];

        for path in [
            super::super::deposit_derivation_path(DepositAddressSchema::CkErc20, &account()),
            sweeper_derivation_path(),
        ] {
            let (signing_key, _chain_code) =
                master.derive_subkey_with_chain_code(&to_derivation_path(&path), &CHAIN_CODE);
            let signature = signing_key.sign_digest_with_ecdsa(&digest);

            let derived_public_key = derive_public_key(&master.public_key(), &CHAIN_CODE, &path);
            assert_eq!(derived_public_key, signing_key.public_key());
            assert!(
                derived_public_key
                    .try_recovery_from_digest(&digest, &signature)
                    .is_ok()
            );
            assert!(
                master
                    .public_key()
                    .try_recovery_from_digest(&digest, &signature)
                    .is_err()
            );
        }
    }

    fn master_private_key() -> PrivateKey {
        PrivateKey::generate_from_seed(b"ck-deposit-address-derivation")
    }

    fn account() -> Account {
        Account {
            owner: Principal::from_slice(&[1, 2, 3, 4]),
            subaccount: Some([9_u8; 32]),
        }
    }

    fn to_derivation_path(path: &[ByteBuf]) -> DerivationPath {
        DerivationPath::new(
            path.iter()
                .map(|index| DerivationIndex(index.to_vec()))
                .collect(),
        )
    }
}
