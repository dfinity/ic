use super::*;
use ic_types::{
    PrincipalId,
    messages::{Blob, HttpCallContent, HttpRequestEnvelope},
};

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
        sender: Blob(vec![2]),
        ingress_expiry: 1_000,
        sender_info: None,
    }
}

fn pair(update: HttpCanisterUpdate) -> EnvelopePair {
    let read_state = convert::make_read_state_from_update(&update);
    EnvelopePair {
        update: HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call { update },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        },
        read_state: HttpRequestEnvelope::<HttpReadStateContent> {
            content: HttpReadStateContent::ReadState { read_state },
            sender_pubkey: None,
            sender_sig: None,
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
