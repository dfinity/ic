use super::*;
use crate::request_handler::make_sig_data;
use ic_types::{
    PrincipalId,
    messages::{Blob, HttpCallContent, HttpRequestEnvelope},
};
use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair};

fn controller() -> PrincipalId {
    PrincipalId::new_user_test_id(1)
}

fn ledger() -> CanisterId {
    CanisterId::from_u64(1)
}

fn governance() -> CanisterId {
    CanisterId::from_u64(2)
}

fn verify(request_type: &RequestType, update: &HttpCanisterUpdate) -> Result<(), ApiError> {
    verify_signed_target(request_type, update, &ledger(), &governance())
}

#[track_caller]
fn assert_rejected<T: std::fmt::Debug>(result: Result<T, ApiError>, expected: &str) {
    let err = result.expect_err("expected the request to be rejected");
    assert!(
        format!("{err:?}").contains(expected),
        "expected an error containing {expected:?}, got {err:?}"
    );
}

fn update(arg: &[u8]) -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(vec![1]),
        method_name: "manage_neuron".to_string(),
        arg: Blob(arg.to_vec()),
        nonce: None,
        sender: Blob(signer().generate_principal_id().unwrap().into_vec()),
        ingress_expiry: 1_000,
        sender_info: None,
    }
}

fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::deserialize_raw(&[7; 32]).unwrap()
}

fn other_key() -> Ed25519KeyPair {
    Ed25519KeyPair::deserialize_raw(&[8; 32]).unwrap()
}

fn pair(update: HttpCanisterUpdate) -> EnvelopePair {
    signed_pair(update, &signer(), &signer())
}

fn signed_pair(
    update: HttpCanisterUpdate,
    update_key: &Ed25519KeyPair,
    read_state_key: &Ed25519KeyPair,
) -> EnvelopePair {
    let read_state = HttpReadStateContent::ReadState {
        read_state: convert::make_read_state_from_update(&update),
    };
    let update_sig = update_key.sign(&make_sig_data(&update.id()));
    let read_state_sig = read_state_key.sign(&make_sig_data(&read_state.id()));
    let pubkey = |key: &Ed25519KeyPair| {
        Some(Blob(
            Ed25519KeyPair::der_encode_pk(key.get_pb_key()).unwrap(),
        ))
    };
    EnvelopePair {
        update: HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call { update },
            sender_pubkey: pubkey(update_key),
            sender_sig: Some(Blob(update_sig)),
            sender_delegation: None,
        },
        read_state: HttpRequestEnvelope::<HttpReadStateContent> {
            content: read_state,
            sender_pubkey: pubkey(read_state_key),
            sender_sig: Some(Blob(read_state_sig)),
            sender_delegation: None,
        },
    }
}

#[test]
fn envelopes_must_differ_only_in_ingress_expiry() {
    let base = update(b"disburse neuron 7");
    let mut later = base.clone();
    later.ingress_expiry = base.ingress_expiry + 1_000;

    let envelopes = [pair(base.clone()), pair(later)];
    assert_eq!(representative_envelope(&envelopes).unwrap(), &base);

    assert_rejected(
        representative_envelope(&[pair(base), pair(update(b"disburse neuron 9"))]),
        "must differ only in their ingress",
    );
}

#[test]
fn a_read_state_for_another_message_is_rejected() {
    let base = update(b"disburse neuron 7");
    let mut later = base.clone();
    later.ingress_expiry = base.ingress_expiry + 1_000;

    let mut spliced = pair(base.clone());
    spliced.read_state = pair(later).read_state;
    assert_rejected(
        representative_envelope(&[spliced]),
        "must read the result of that",
    );

    let mut spliced = pair(base);
    spliced.read_state = pair(update(b"disburse neuron 9")).read_state;
    assert_rejected(
        representative_envelope(&[spliced]),
        "must read the result of that",
    );
}

#[test]
fn every_call_must_be_signed_by_its_sender() {
    let base = update(b"disburse neuron 7");
    let mut later = base.clone();
    later.ingress_expiry = base.ingress_expiry + 1_000;

    let mut corrupted = pair(later.clone());
    corrupted.read_state.sender_sig = Some(Blob(vec![0; 64]));
    let cases = [
        signed_pair(later.clone(), &signer(), &other_key()),
        signed_pair(later, &other_key(), &signer()),
        corrupted,
    ];
    for envelope in cases {
        assert_rejected(
            representative_envelope(&[pair(base.clone()), envelope]),
            "whose envelope the IC would reject",
        );
    }
}

#[test]
fn a_request_without_envelopes_is_rejected() {
    assert_rejected(representative_envelope(&[]), "No request payload provided");
}

#[test]
fn a_transfer_to_another_ledger_is_rejected() {
    let args = icp_ledger::SendArgs {
        memo: icp_ledger::Memo(0),
        amount: icp_ledger::Tokens::from_e8s(100_000_000),
        fee: icp_ledger::Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: icp_ledger::AccountIdentifier::from(controller()),
        created_at_time: None,
    };
    let send = |canister_id: CanisterId| HttpCanisterUpdate {
        canister_id: Blob(canister_id.get().to_vec()),
        method_name: SEND_PB.to_string(),
        arg: Blob(convert::to_arg(args.clone())),
        nonce: None,
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    verify(&RequestType::Send, &send(ledger())).unwrap();
    assert_rejected(
        verify(&RequestType::Send, &send(CanisterId::from_u64(99))),
        "A transfer must be addressed to canister",
    );
}

#[test]
fn a_transfer_out_of_a_subaccount_is_rejected() {
    let send = |from_subaccount| HttpCanisterUpdate {
        canister_id: Blob(ledger().get().to_vec()),
        method_name: SEND_PB.to_string(),
        arg: Blob(convert::to_arg(icp_ledger::SendArgs {
            memo: icp_ledger::Memo(0),
            amount: icp_ledger::Tokens::from_e8s(100_000_000),
            fee: icp_ledger::Tokens::from_e8s(10_000),
            from_subaccount,
            to: icp_ledger::AccountIdentifier::from(PrincipalId::new_user_test_id(2)),
            created_at_time: None,
        })),
        nonce: None,
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    verify(&RequestType::Send, &send(None)).unwrap();
    assert_rejected(
        verify(
            &RequestType::Send,
            &send(Some(icp_ledger::Subaccount([1; 32]))),
        ),
        "draws on a subaccount of the sender",
    );
}

#[test]
fn a_transfer_calling_another_method_is_rejected() {
    let update = HttpCanisterUpdate {
        canister_id: Blob(ledger().get().to_vec()),
        method_name: "notify_pb".to_string(),
        arg: Blob(convert::to_arg(icp_ledger::SendArgs {
            memo: icp_ledger::Memo(0),
            amount: icp_ledger::Tokens::from_e8s(1),
            fee: icp_ledger::Tokens::from_e8s(10_000),
            from_subaccount: None,
            to: icp_ledger::AccountIdentifier::from(controller()),
            created_at_time: None,
        })),
        nonce: None,
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    assert_rejected(
        verify(&RequestType::Send, &update),
        "Expected the signed update to call 'send_pb'",
    );
}
