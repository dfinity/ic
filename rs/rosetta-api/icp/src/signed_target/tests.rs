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

mod read_state_signatures {
    use super::*;
    use crate::{
        models::SignedTransaction, request_handler::make_sig_data, request_types::RequestType,
    };
    use ic_types::messages::{Delegation, SignedDelegation};
    use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair};

    const NOW: u64 = 1_700_000_000_000_000_000;

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::deserialize_raw(&[seed; 32]).unwrap()
    }

    fn signed(read_state_key: &Ed25519KeyPair, ingress_expiry: u64) -> EnvelopePair {
        let signer = key(1);
        let mut envelope = pair(HttpCanisterUpdate {
            sender: Blob(signer.generate_principal_id().unwrap().into_vec()),
            ingress_expiry,
            ..update(b"disburse neuron 7")
        });
        let read_state_id = envelope.read_state.content.id();
        envelope.read_state.sender_pubkey = Some(Blob(
            Ed25519KeyPair::der_encode_pk(read_state_key.get_pb_key()).unwrap(),
        ));
        envelope.read_state.sender_sig =
            Some(Blob(read_state_key.sign(&make_sig_data(&read_state_id))));
        envelope
    }

    fn current(read_state_key: &Ed25519KeyPair) -> EnvelopePair {
        signed(read_state_key, NOW + 60_000_000_000)
    }

    fn verify(requests: Vec<Vec<EnvelopePair>>) -> Result<(), ApiError> {
        let transaction = SignedTransaction {
            requests: requests
                .into_iter()
                .map(|envelopes| (RequestType::Send, envelopes))
                .collect(),
        };
        verify_read_state_signatures(&transaction, Time::from_nanos_since_unix_epoch(NOW))
    }

    #[test]
    fn the_read_state_call_of_every_unexpired_envelope_must_be_signed_by_its_sender() {
        let expired = signed(&key(2), NOW);
        let future =
            |read_state_key: &Ed25519KeyPair| signed(read_state_key, NOW + 600_000_000_000);
        let mut corrupted = current(&key(1));
        corrupted.read_state.sender_sig = Some(Blob(vec![0; 64]));
        let mut without_credentials = current(&key(1));
        without_credentials.read_state.sender_pubkey = None;
        without_credentials.read_state.sender_sig = None;
        let mut malformed_key = current(&key(1));
        malformed_key.read_state.sender_pubkey = Some(Blob(vec![1, 2, 3]));

        verify(vec![
            vec![current(&key(1))],
            vec![expired, current(&key(1)), future(&key(1))],
        ])
        .unwrap();
        for bad in [
            vec![corrupted],
            vec![current(&key(2))],
            vec![current(&key(1)), future(&key(2))],
            vec![without_credentials],
            vec![malformed_key],
        ] {
            assert_rejected(
                verify(vec![vec![current(&key(1))], bad]),
                "whose read-state call the IC would reject",
            );
        }
    }

    #[test]
    fn submit_sends_the_valid_envelope_that_expires_last() {
        let now = Time::from_nanos_since_unix_epoch(NOW);
        let expired = signed(&key(1), NOW);
        let expiring = signed(&key(1), NOW + 1_000_000_000);
        let fresh = signed(&key(1), NOW + 200_000_000_000);
        let future = signed(&key(1), NOW + 600_000_000_000);

        let envelopes = [expired, expiring, fresh.clone(), future];
        assert_eq!(current_envelope(&envelopes, now), Some(&fresh));
        assert_eq!(current_envelope(&envelopes[..1], now), None);
    }

    fn delegation() -> Option<Vec<SignedDelegation>> {
        Some(vec![SignedDelegation::new(
            Delegation::new(vec![1, 2, 3], Time::from_nanos_since_unix_epoch(NOW + 1)),
            vec![0; 64],
        )])
    }

    fn canister_key() -> Blob {
        let mut der = vec![
            0x30, 0x1b, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43,
            0x01, 0x02, 0x03, 0x0b, 0x00,
        ];
        der.extend_from_slice(b"public key");
        let (key, _) = user_public_key_from_bytes(&der).unwrap();
        assert_eq!(key.algorithm_id, AlgorithmId::IcCanisterSignature);
        Blob(der)
    }

    #[test]
    fn delegated_and_canister_signed_read_state_calls_must_be_from_their_sender() {
        let mut delegated = current(&key(1));
        delegated.read_state.sender_delegation = delegation();
        let mut canister_signed = pair(HttpCanisterUpdate {
            sender: Blob(PrincipalId::new_self_authenticating(&canister_key().0).into_vec()),
            ingress_expiry: NOW + 60_000_000_000,
            ..update(b"disburse neuron 7")
        });
        canister_signed.read_state.sender_pubkey = Some(canister_key());
        canister_signed.read_state.sender_sig = Some(Blob(vec![0; 64]));
        let anonymous = pair(HttpCanisterUpdate {
            sender: Blob(PrincipalId::new_anonymous().into_vec()),
            ingress_expiry: NOW + 60_000_000_000,
            ..update(b"disburse neuron 7")
        });
        verify(vec![
            vec![delegated],
            vec![canister_signed],
            vec![anonymous],
        ])
        .unwrap();

        let mut empty_delegation = current(&key(1));
        empty_delegation.read_state.sender_delegation = Some(vec![]);
        empty_delegation.read_state.sender_sig = Some(Blob(vec![0; 64]));
        let mut foreign_delegation = current(&key(2));
        foreign_delegation.read_state.sender_delegation = delegation();
        let mut foreign_canister_key = current(&key(1));
        foreign_canister_key.read_state.sender_pubkey = Some(canister_key());
        for bad in [empty_delegation, foreign_delegation, foreign_canister_key] {
            assert_rejected(
                verify(vec![vec![bad]]),
                "whose read-state call the IC would reject",
            );
        }
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
