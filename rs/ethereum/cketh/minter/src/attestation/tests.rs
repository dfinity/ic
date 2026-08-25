use crate::attestation::AttestationRequest;
use crate::deposit_address::DepositAddressSchema;
use crate::eth_logs::{LedgerSubaccount, encode_principal};
use crate::test_fixtures::arb::{arb_address, arb_ledger_subaccount, arb_principal};
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use proptest::prelude::{any, proptest};
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
        hex::encode(request(CHAIN_ID, helper(), account()).digest().0),
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
        request(CHAIN_ID, helper(), account()).digest().0,
        request(CHAIN_ID + 1, helper(), account()).digest().0,
        request(CHAIN_ID, other_helper, account()).digest().0,
        request(CHAIN_ID, helper(), other_owner).digest().0,
        request(CHAIN_ID, helper(), other_subaccount).digest().0,
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
        request(CHAIN_ID, helper(), explicit_default).digest(),
        request(CHAIN_ID, helper(), absent).digest()
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

proptest! {
    /// The delegate reads the preimage as fixed-length fields, so its length must not depend on
    /// what is in them — a principal shorter than 29 bytes is padded, not truncated.
    #[test]
    fn should_always_produce_a_132_byte_preimage(
        chain_id in any::<u64>(),
        deposit_helper in arb_address(),
        owner in arb_principal(),
        subaccount in arb_ledger_subaccount(),
    ) {
        let request = AttestationRequest::new(
            chain_id,
            deposit_helper,
            DepositAddressSchema::CkErc20,
            Account {
                owner,
                subaccount: subaccount.map(LedgerSubaccount::to_bytes),
            },
        );

        assert_eq!(request.preimage().len(), 16 + 32 + 20 + 32 + 32);
    }
}

fn request(chain_id: u64, deposit_helper: Address, account: Account) -> AttestationRequest {
    AttestationRequest::new(
        chain_id,
        deposit_helper,
        DepositAddressSchema::CkErc20,
        account,
    )
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

mod recorded {
    use crate::state::State;
    use crate::state::audit::apply_state_transition;
    use crate::state::eth_logs_scraping::LogScrapingId;
    use crate::state::event::EventType;
    use crate::test_fixtures::initial_state;
    use crate::tx::TransactionSignature;
    use candid::Principal;
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_replay_an_attestation_under_the_helper_it_names() {
        let mut state = configured_state(helper());

        apply_state_transition(&mut state, &attested(helper(), account()));

        assert_eq!(state.attestation(&account()), Some(&signature()));
    }

    #[test]
    fn should_not_reuse_an_attestation_signed_for_another_helper() {
        let mut state = configured_state(helper());
        apply_state_transition(&mut state, &attested(Address::new([0xab; 20]), account()));

        assert_eq!(state.attestation(&account()), None);
    }

    #[test]
    fn should_keep_an_attestation_per_account() {
        let other = Account {
            owner: Principal::from_slice(&[9, 9, 9]),
            subaccount: None,
        };
        let mut state = configured_state(helper());

        apply_state_transition(&mut state, &attested(helper(), account()));

        assert_eq!(state.attestation(&account()), Some(&signature()));
        assert_eq!(state.attestation(&other), None);
    }

    fn configured_state(deposit_helper: Address) -> State {
        let mut state = initial_state();
        state.log_scrapings.set_contract_address(
            LogScrapingId::EthOrErc20DepositWithSubaccount,
            deposit_helper,
        );
        state
    }

    fn attested(deposit_helper: Address, account: Account) -> EventType {
        EventType::AttestedDepositAddress {
            chain_id: 1,
            deposit_helper,
            owner: account.owner,
            subaccount: account.subaccount,
            signature: signature(),
        }
    }

    fn signature() -> TransactionSignature {
        TransactionSignature {
            signature_y_parity: true,
            r: u256::from_be_bytes([0xaa; 32]),
            s: u256::from_be_bytes([0xbb; 32]),
        }
    }

    fn helper() -> Address {
        super::helper()
    }

    fn account() -> Account {
        super::account()
    }
}
