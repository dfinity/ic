use crate::attestation::attestation_digest;
use crate::eth_logs::encode_principal;
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;

const CHAIN_ID: u64 = 1;
const HELPER: &str = "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38";

// Keccak-256 of the 132-byte packed preimage, computed independently of this crate (pycryptodome
// over "ck-deposit-owner" || 32-byte chain id || 20-byte helper || 32-byte principal || 32-byte
// subaccount), i.e. over exactly what `abi.encodePacked` produces in
// `CkSweeperAttested._attestationDigest`.
#[test]
fn should_produce_the_documented_digest() {
    assert_eq!(
        hex::encode(attestation_digest(CHAIN_ID, &helper(), &account()).0),
        "79323693ff051d86d7509056f4919a4602775f86c926bf09a8823c4caa239251"
    );
}

#[test]
fn should_bind_the_digest_to_every_field() {
    let other_helper = Address::new([0xab; 20]);
    let other_owner = Account {
        owner: Principal::from_slice(&[9, 9, 9]),
        subaccount: account().subaccount,
    };
    let other_subaccount = Account {
        owner: account().owner,
        subaccount: Some([1_u8; 32]),
    };

    let digests = BTreeSet::from_iter([
        attestation_digest(CHAIN_ID, &helper(), &account()).0,
        attestation_digest(CHAIN_ID + 1, &helper(), &account()).0,
        attestation_digest(CHAIN_ID, &other_helper, &account()).0,
        attestation_digest(CHAIN_ID, &helper(), &other_owner).0,
        attestation_digest(CHAIN_ID, &helper(), &other_subaccount).0,
    ]);

    assert_eq!(digests.len(), 5, "every field must change the digest");
}

#[test]
fn should_treat_an_absent_subaccount_as_the_default_one() {
    let explicit_default = Account {
        owner: account().owner,
        subaccount: Some([0_u8; 32]),
    };
    let absent = Account {
        owner: account().owner,
        subaccount: None,
    };

    assert_eq!(
        attestation_digest(CHAIN_ID, &helper(), &explicit_default),
        attestation_digest(CHAIN_ID, &helper(), &absent)
    );
}

#[test]
fn should_encode_a_principal_the_way_the_helper_carries_one() {
    for principal in [
        Principal::from_slice(&[1, 2, 3, 4]),
        Principal::anonymous(),
        Principal::from_slice(&[0xff; 29]),
    ] {
        let bytes = principal.as_slice();
        let encoded = encode_principal(&principal);

        assert_eq!(encoded[0] as usize, bytes.len());
        assert_eq!(&encoded[1..=bytes.len()], bytes);
        assert!(encoded[1 + bytes.len()..].iter().all(|byte| *byte == 0));
    }
}

fn helper() -> Address {
    HELPER.parse().unwrap()
}

fn account() -> Account {
    Account {
        owner: Principal::from_slice(&[1, 2, 3, 4]),
        subaccount: Some([42_u8; 32]),
    }
}
