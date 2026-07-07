use crate::address::ecdsa_public_key_to_address;
use crate::deposit_address::{
    DepositAddressSchema, deposit_address, deposit_derivation_path, sweeper_address,
    sweeper_derivation_path,
};
use crate::eth_logs::LedgerSubaccount;
use candid::Principal;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey, PublicKey};
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;
use std::str::FromStr;

#[test]
fn should_derive_deterministically() {
    let (pk, cc) = master_key();
    let owner = principal(1);
    let subaccount = subaccount(1);

    for schema in [DepositAddressSchema::CkErc20, DepositAddressSchema::CkEth] {
        let first = deposit_address(&pk, &cc, schema, &owner, Some(&subaccount));
        let second = deposit_address(&pk, &cc, schema, &owner, Some(&subaccount));
        assert_eq!(first, second);
    }
    assert_eq!(sweeper_address(&pk, &cc), sweeper_address(&pk, &cc));
}

#[test]
fn should_derive_address_matching_its_signing_subkey() {
    let (master_private_key, cc) = master_private_key();
    let master_public_key = master_private_key.public_key();
    let owner = principal(1);
    let subaccount = subaccount(1);

    let ckerc20_path = to_derivation_path(deposit_derivation_path(
        DepositAddressSchema::CkErc20,
        &owner,
        Some(&subaccount),
    ));
    let (ckerc20_subkey, _cc) =
        master_private_key.derive_subkey_with_chain_code(&ckerc20_path, &cc);
    assert_eq!(
        ecdsa_public_key_to_address(&ckerc20_subkey.public_key()),
        deposit_address(
            &master_public_key,
            &cc,
            DepositAddressSchema::CkErc20,
            &owner,
            Some(&subaccount),
        ),
    );

    let sweeper_path = to_derivation_path(sweeper_derivation_path());
    let (sweeper_subkey, _cc) =
        master_private_key.derive_subkey_with_chain_code(&sweeper_path, &cc);
    assert_eq!(
        ecdsa_public_key_to_address(&sweeper_subkey.public_key()),
        sweeper_address(&master_public_key, &cc),
    );
}

#[test]
fn should_derive_distinct_addresses_for_distinct_principals() {
    let (pk, cc) = master_key();

    let addresses: BTreeSet<_> = (0..16_u8)
        .map(|i| deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &principal(i), None))
        .collect();

    assert_eq!(addresses.len(), 16);
}

#[test]
fn should_derive_distinct_addresses_for_distinct_subaccounts() {
    let (pk, cc) = master_key();
    let owner = principal(1);

    let mut addresses = BTreeSet::new();
    addresses.insert(deposit_address(
        &pk,
        &cc,
        DepositAddressSchema::CkErc20,
        &owner,
        None,
    ));
    for i in 1..16_u8 {
        addresses.insert(deposit_address(
            &pk,
            &cc,
            DepositAddressSchema::CkErc20,
            &owner,
            Some(&subaccount(i)),
        ));
    }

    assert_eq!(addresses.len(), 16);
}

#[test]
fn should_derive_distinct_addresses_for_distinct_schema_tags() {
    let (pk, cc) = master_key();
    let owner = principal(1);
    let subaccount = subaccount(1);

    let ckerc20 = deposit_address(
        &pk,
        &cc,
        DepositAddressSchema::CkErc20,
        &owner,
        Some(&subaccount),
    );
    let cketh = deposit_address(
        &pk,
        &cc,
        DepositAddressSchema::CkEth,
        &owner,
        Some(&subaccount),
    );
    let sweeper = sweeper_address(&pk, &cc);

    let distinct: BTreeSet<_> = [ckerc20, cketh, sweeper].into_iter().collect();
    assert_eq!(distinct.len(), 3);
}

#[test]
fn should_not_collide_with_main_address() {
    let (pk, cc) = master_key();
    let main_address = ecdsa_public_key_to_address(&pk);
    let owner = principal(1);

    assert!(!deposit_derivation_path(DepositAddressSchema::CkErc20, &owner, None).is_empty());

    assert_ne!(
        deposit_address(&pk, &cc, DepositAddressSchema::CkErc20, &owner, None),
        main_address
    );
    assert_ne!(
        deposit_address(&pk, &cc, DepositAddressSchema::CkEth, &owner, None),
        main_address
    );
    assert_ne!(sweeper_address(&pk, &cc), main_address);
}

#[test]
fn should_encode_derived_address_using_eip55_checksum() {
    let (pk, cc) = master_key();
    let derived = deposit_address(
        &pk,
        &cc,
        DepositAddressSchema::CkErc20,
        &principal(1),
        Some(&subaccount(1)),
    );

    let checksummed = derived.to_string();
    assert_eq!(
        Address::from_str(&checksummed.to_lowercase())
            .unwrap()
            .to_string(),
        checksummed
    );
}

#[test]
fn should_match_eip55_reference_vectors() {
    for checksummed in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ] {
        let parsed = Address::from_str(&checksummed.to_lowercase()).unwrap();
        assert_eq!(parsed.to_string(), checksummed);
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

fn to_derivation_path(path: Vec<ByteBuf>) -> DerivationPath {
    DerivationPath::new(
        path.into_iter()
            .map(|index| DerivationIndex(index.into_vec()))
            .collect(),
    )
}

fn principal(i: u8) -> Principal {
    Principal::from_slice(&[i, 1, 2, 3, 4, 5, 6, 7, 8, 9])
}

fn subaccount(i: u8) -> LedgerSubaccount {
    let mut bytes = [0_u8; 32];
    bytes[31] = i;
    LedgerSubaccount::from_bytes(bytes).expect("non-zero subaccount")
}
