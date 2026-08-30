use crate::attestation::AttestationRequest;
use crate::eth_logs::{LedgerSubaccount, encode_principal};
use crate::test_fixtures::arb::{arb_address, arb_ledger_subaccount, arb_principal};
use crate::test_fixtures::{account, deposit_helper};
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use proptest::prelude::{any, proptest};
use std::collections::BTreeSet;

const CHAIN_ID: u64 = 1;

// Keccak-256 of the 132-byte packed preimage, computed independently of this crate (pycryptodome
// over "ck-deposit-owner" || 32-byte chain id || 20-byte helper || 32-byte principal || 32-byte
// subaccount), i.e. over exactly what `abi.encodePacked` produces in
// `CkSweeperAttested._attestationDigest`.
#[test]
fn should_produce_the_documented_digest() {
    assert_eq!(
        hex::encode(request(CHAIN_ID, deposit_helper(), account()).digest().0),
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
        request(CHAIN_ID, deposit_helper(), account()).digest().0,
        request(CHAIN_ID + 1, deposit_helper(), account())
            .digest()
            .0,
        request(CHAIN_ID, other_helper, account()).digest().0,
        request(CHAIN_ID, deposit_helper(), other_owner).digest().0,
        request(CHAIN_ID, deposit_helper(), other_subaccount)
            .digest()
            .0,
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
        request(CHAIN_ID, deposit_helper(), explicit_default).digest(),
        request(CHAIN_ID, deposit_helper(), absent).digest()
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
            Account {
                owner,
                subaccount: subaccount.map(LedgerSubaccount::to_bytes),
            },
        );

        assert_eq!(request.preimage().len(), 16 + 32 + 20 + 32 + 32);
    }
}

fn request(chain_id: u64, deposit_helper: Address, account: Account) -> AttestationRequest {
    AttestationRequest::new(chain_id, deposit_helper, account)
}

mod recorded {
    use crate::attestation::AttestationRequest;
    use crate::state::audit::apply_state_transition;
    use crate::state::event::EventType;
    use crate::test_fixtures::{
        account, deposit_helper, state_with_deposit_helper, transaction_signature,
    };
    use candid::Principal;
    use ic_ethereum_types::Address;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_replay_an_attestation_signed_for_the_configuration_in_force() {
        let mut state = state_with_deposit_helper(deposit_helper());
        let request = state
            .attestation_request(account())
            .expect("BUG: the deposit helper is configured");

        apply_state_transition(&mut state, &attested(request));

        assert_eq!(state.attestation(account()), Some(&transaction_signature()));
    }

    #[test]
    fn should_not_reuse_an_attestation_signed_for_another_helper() {
        let mut state = state_with_deposit_helper(deposit_helper());
        let another_helper = super::request(
            state.ethereum_network.chain_id(),
            Address::new([0xab; 20]),
            account(),
        );

        apply_state_transition(&mut state, &attested(another_helper));

        assert_eq!(state.attestation(account()), None);
    }

    #[test]
    fn should_not_reuse_an_attestation_signed_for_another_chain() {
        let mut state = state_with_deposit_helper(deposit_helper());
        let another_chain = super::request(
            state.ethereum_network.chain_id() + 1,
            deposit_helper(),
            account(),
        );

        apply_state_transition(&mut state, &attested(another_chain));

        assert_eq!(state.attestation(account()), None);
    }

    #[test]
    fn should_keep_an_attestation_per_account() {
        let mut state = state_with_deposit_helper(deposit_helper());
        let another_account = Account {
            owner: Principal::from_slice(&[9, 9, 9]),
            subaccount: None,
        };
        let request = state
            .attestation_request(account())
            .expect("BUG: the deposit helper is configured");

        apply_state_transition(&mut state, &attested(request));

        assert_eq!(state.attestation(account()), Some(&transaction_signature()));
        assert_eq!(state.attestation(another_account), None);
    }

    fn attested(request: AttestationRequest) -> EventType {
        EventType::AttestedDepositAddress {
            request,
            signature: transaction_signature(),
        }
    }
}
