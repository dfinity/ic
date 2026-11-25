use super::*;
use candid::Encode;
use ic_nns_governance_api::{ManageNeuronCommandRequest, manage_neuron};
use ic_types::messages::{Blob, HttpCallContent, HttpRequestEnvelope};
use proptest::prelude::*;

const NEURON_INDEX: u64 = 7;

fn owner() -> PrincipalId {
    PrincipalId::new_user_test_id(1)
}

fn hotkey() -> PrincipalId {
    PrincipalId::new_user_test_id(9)
}

fn stranger() -> PrincipalId {
    PrincipalId::new_user_test_id(4)
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

fn verify_envelopes(
    request_type: &RequestType,
    envelopes: &[EnvelopePair],
) -> Result<(), ApiError> {
    verify_signed_envelopes(request_type, envelopes, &ledger(), &governance()).map(|_| ())
}

#[track_caller]
fn assert_rejected(name: &str, result: Result<(), ApiError>, expected: &str) {
    let err = result.expect_err(name);
    assert!(
        format!("{err:?}").contains(expected),
        "{name}: expected an error containing {expected:?}, got {err:?}"
    );
}

fn update(
    canister_id: CanisterId,
    method: &str,
    arg: Vec<u8>,
    nonce: Option<u64>,
    sender: PrincipalId,
) -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(canister_id.get().to_vec()),
        method_name: method.to_string(),
        arg: Blob(arg),
        nonce: nonce.map(|nonce| Blob(Encode!(&nonce).unwrap())),
        sender: Blob(sender.into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    }
}

fn subaccount(owner: PrincipalId, neuron_index: u64) -> NeuronIdOrSubaccount {
    NeuronIdOrSubaccount::Subaccount(
        convert::neuron_subaccount_bytes_from_principal(&owner, neuron_index).to_vec(),
    )
}

fn manage_neuron_update(
    sender: PrincipalId,
    neuron_index: u64,
    manage: &ManageNeuronRequest,
) -> HttpCanisterUpdate {
    update(
        governance(),
        MANAGE_NEURON,
        Encode!(manage).unwrap(),
        Some(neuron_index),
        sender,
    )
}

fn command_update(
    sender: PrincipalId,
    owner: PrincipalId,
    neuron_index: u64,
    command: ManageNeuronCommandRequest,
) -> HttpCanisterUpdate {
    manage_neuron_update(
        sender,
        neuron_index,
        &ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(subaccount(owner, neuron_index)),
            command: Some(command),
        },
    )
}

fn disburse_command() -> ManageNeuronCommandRequest {
    ManageNeuronCommandRequest::Disburse(manage_neuron::Disburse {
        amount: None,
        to_account: None,
    })
}

fn disburse() -> RequestType {
    RequestType::Disburse {
        neuron_index: NEURON_INDEX,
    }
}

fn neuron_info_update(
    sender: PrincipalId,
    owner: PrincipalId,
    neuron_index: u64,
) -> HttpCanisterUpdate {
    update(
        governance(),
        GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT,
        Encode!(&subaccount(owner, neuron_index)).unwrap(),
        None,
        sender,
    )
}

fn stake_update(controller: Option<PrincipalId>, memo: u64) -> HttpCanisterUpdate {
    update(
        governance(),
        CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT,
        Encode!(&ClaimOrRefreshNeuronFromAccount { controller, memo }).unwrap(),
        Some(NEURON_INDEX),
        owner(),
    )
}

fn list_neurons_update(args: &ListNeurons) -> HttpCanisterUpdate {
    update(
        governance(),
        LIST_NEURONS,
        Encode!(args).unwrap(),
        None,
        owner(),
    )
}

fn manage_neuron_requests(neuron_index: u64) -> Vec<(RequestType, ManageNeuronCommandRequest)> {
    use ManageNeuronCommandRequest as Cmd;
    use manage_neuron::configure::Operation as Op;
    let configure = |operation| {
        Cmd::Configure(manage_neuron::Configure {
            operation: Some(operation),
        })
    };
    let hot_key = Some(PrincipalId::new_user_test_id(5));
    vec![
        (RequestType::Disburse { neuron_index }, disburse_command()),
        (
            RequestType::DisburseMaturity { neuron_index },
            Cmd::DisburseMaturity(manage_neuron::DisburseMaturity {
                percentage_to_disburse: 100,
                to_account_identifier: None,
                to_account: None,
            }),
        ),
        (
            RequestType::SetDissolveTimestamp { neuron_index },
            configure(Op::SetDissolveTimestamp(
                manage_neuron::SetDissolveTimestamp {
                    dissolve_timestamp_seconds: 1_000,
                },
            )),
        ),
        (
            RequestType::ChangeAutoStakeMaturity { neuron_index },
            configure(Op::ChangeAutoStakeMaturity(
                manage_neuron::ChangeAutoStakeMaturity {
                    requested_setting_for_auto_stake_maturity: true,
                },
            )),
        ),
        (
            RequestType::StartDissolve { neuron_index },
            configure(Op::StartDissolving(manage_neuron::StartDissolving {})),
        ),
        (
            RequestType::StopDissolve { neuron_index },
            configure(Op::StopDissolving(manage_neuron::StopDissolving {})),
        ),
        (
            RequestType::AddHotKey { neuron_index },
            configure(Op::AddHotKey(manage_neuron::AddHotKey {
                new_hot_key: hot_key,
            })),
        ),
        (
            RequestType::RemoveHotKey { neuron_index },
            configure(Op::RemoveHotKey(manage_neuron::RemoveHotKey {
                hot_key_to_remove: hot_key,
            })),
        ),
        (
            RequestType::Spawn { neuron_index },
            Cmd::Spawn(manage_neuron::Spawn {
                new_controller: None,
                percentage_to_spawn: None,
                nonce: Some(neuron_index + 1),
            }),
        ),
        (
            RequestType::StakeMaturity { neuron_index },
            Cmd::StakeMaturity(manage_neuron::StakeMaturity {
                percentage_to_stake: None,
            }),
        ),
        (
            RequestType::RegisterVote { neuron_index },
            Cmd::RegisterVote(manage_neuron::RegisterVote {
                proposal: Some(ic_nns_common::pb::v1::ProposalId { id: 1 }),
                vote: 1,
            }),
        ),
        (
            RequestType::Follow {
                neuron_index,
                controller: None,
            },
            Cmd::Follow(manage_neuron::Follow {
                topic: 0,
                followees: vec![ic_nns_common::pb::v1::NeuronId { id: 1 }],
            }),
        ),
        (
            RequestType::RefreshVotingPower {
                neuron_index,
                controller: None,
            },
            Cmd::RefreshVotingPower(manage_neuron::RefreshVotingPower {}),
        ),
    ]
}

fn neuron_targets(neuron_index: u64) -> Vec<(RequestType, Option<ManageNeuronCommandRequest>)> {
    manage_neuron_requests(neuron_index)
        .into_iter()
        .map(|(request_type, command)| (request_type, Some(command)))
        .chain([(
            RequestType::NeuronInfo {
                neuron_index,
                controller: None,
            },
            None,
        )])
        .collect()
}

fn displaying_controller(
    request_type: RequestType,
    controller: Option<PrincipalId>,
) -> RequestType {
    let controller = controller.map(PublicKeyOrPrincipal::Principal);
    match request_type {
        RequestType::Follow { neuron_index, .. } => RequestType::Follow {
            neuron_index,
            controller,
        },
        RequestType::RefreshVotingPower { neuron_index, .. } => RequestType::RefreshVotingPower {
            neuron_index,
            controller,
        },
        RequestType::NeuronInfo { neuron_index, .. } => RequestType::NeuronInfo {
            neuron_index,
            controller,
        },
        other => {
            assert!(controller.is_none());
            other
        }
    }
}

proptest! {
    #[test]
    fn a_neuron_request_is_accepted_iff_it_displays_the_signed_neuron(
        target in 0..neuron_targets(0).len(),
        signed_index in 0..3_u64,
        displayed_index in 0..3_u64,
        signer in prop::sample::select(vec![owner(), hotkey()]),
        displayed_controller in prop::option::of(prop::sample::select(vec![owner(), stranger()])),
    ) {
        let (signed_type, command) = neuron_targets(signed_index).swap_remove(target);
        let (displayed_type, _) = neuron_targets(displayed_index).swap_remove(target);
        prop_assume!(
            displayed_controller.is_none()
                || matches!(
                    signed_type,
                    RequestType::Follow { .. }
                        | RequestType::RefreshVotingPower { .. }
                        | RequestType::NeuronInfo { .. }
                )
        );
        let update = match command {
            Some(command) => command_update(signer, owner(), signed_index, command),
            None => neuron_info_update(signer, owner(), signed_index),
        };
        let displayed = displaying_controller(displayed_type, displayed_controller);

        prop_assert_eq!(
            verify(&displayed, &update).is_ok(),
            displayed_index == signed_index && displayed_controller.unwrap_or(signer) == owner()
        );
    }
}

#[test]
fn every_manage_neuron_request_is_bound_to_the_signed_command() {
    let requests = manage_neuron_requests(NEURON_INDEX);
    for (request_type, _) in &requests {
        for (other, command) in &requests {
            let update = command_update(owner(), owner(), NEURON_INDEX, command.clone());
            let name = format!(
                "{} signed as {}",
                request_type.clone().into_str(),
                other.clone().into_str()
            );
            if request_type == other {
                verify(request_type, &update).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            } else {
                assert_rejected(
                    &name,
                    verify(request_type, &update),
                    "The signed manage_neuron command is not the",
                );
            }
        }
    }
}

#[test]
fn a_manage_neuron_request_must_name_its_neuron_by_signed_nonce_and_subaccount() {
    let manage = |id, neuron_id_or_subaccount| ManageNeuronRequest {
        id,
        neuron_id_or_subaccount,
        command: Some(disburse_command()),
    };
    let neuron_id = ic_nns_common::pb::v1::NeuronId { id: 99 };
    let honest = manage(None, Some(subaccount(owner(), NEURON_INDEX)));

    let cases = [
        (
            "missing nonce",
            HttpCanisterUpdate {
                nonce: None,
                ..manage_neuron_update(owner(), NEURON_INDEX, &honest)
            },
            "carries no nonce",
        ),
        (
            "other nonce",
            manage_neuron_update(owner(), 0, &honest),
            "neuron_index 7, but the signed nonce says 0",
        ),
        (
            "legacy id",
            manage_neuron_update(
                owner(),
                NEURON_INDEX,
                &manage(Some(neuron_id), Some(subaccount(owner(), NEURON_INDEX))),
            ),
            "legacy `id` field",
        ),
        (
            "neuron id",
            manage_neuron_update(
                owner(),
                NEURON_INDEX,
                &manage(None, Some(NeuronIdOrSubaccount::NeuronId(neuron_id))),
            ),
            "identifies the neuron by id",
        ),
        (
            "no neuron",
            manage_neuron_update(owner(), NEURON_INDEX, &manage(None, None)),
            "does not identify a neuron",
        ),
        (
            "invalid sender",
            HttpCanisterUpdate {
                sender: Blob(vec![0xff; 30]),
                ..manage_neuron_update(owner(), NEURON_INDEX, &honest)
            },
            "Could not parse the signed update's sender",
        ),
    ];

    verify(
        &disburse(),
        &manage_neuron_update(owner(), NEURON_INDEX, &honest),
    )
    .unwrap();
    for (name, update, expected) in cases {
        assert_rejected(name, verify(&disburse(), &update), expected);
    }
}

#[test]
fn every_governance_request_is_bound_to_the_governance_canister_and_method() {
    let requests = [
        (
            RequestType::Stake {
                neuron_index: NEURON_INDEX,
            },
            stake_update(None, NEURON_INDEX),
        ),
        (
            RequestType::NeuronInfo {
                neuron_index: NEURON_INDEX,
                controller: None,
            },
            neuron_info_update(owner(), owner(), NEURON_INDEX),
        ),
        (
            RequestType::ListNeurons { page_number: 0 },
            list_neurons_update(&list_neurons_arg(None)),
        ),
        (
            disburse(),
            command_update(owner(), owner(), NEURON_INDEX, disburse_command()),
        ),
    ];

    for (request_type, update) in requests {
        let name = request_type.clone().into_str();
        verify(&request_type, &update).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        for canister_id in [ledger(), ic_nns_constants::GOVERNANCE_CANISTER_ID] {
            assert_rejected(
                name,
                verify(
                    &request_type,
                    &HttpCanisterUpdate {
                        canister_id: Blob(canister_id.get().to_vec()),
                        ..update.clone()
                    },
                ),
                "A neuron request must be addressed to canister",
            );
        }
        assert_rejected(
            name,
            verify(
                &request_type,
                &HttpCanisterUpdate {
                    method_name: "some_other_method".to_string(),
                    ..update
                },
            ),
            "Expected the signed update to call",
        );
    }
}

#[test]
fn stake_is_bound_to_the_signed_nonce_memo_and_controller() {
    let stake = |neuron_index| RequestType::Stake { neuron_index };

    verify(&stake(NEURON_INDEX), &stake_update(None, NEURON_INDEX)).unwrap();
    verify(
        &stake(NEURON_INDEX),
        &stake_update(Some(owner()), NEURON_INDEX),
    )
    .unwrap();
    assert_rejected(
        "rewritten index",
        verify(&stake(0), &stake_update(None, NEURON_INDEX)),
        "neuron_index 0, but the signed nonce says 7",
    );
    assert_rejected(
        "other memo",
        verify(&stake(NEURON_INDEX), &stake_update(None, 0)),
        "neuron_index 7, but the signed claim_or_refresh_neuron_from_account memo says 0",
    );
    assert_rejected(
        "other controller",
        verify(
            &stake(NEURON_INDEX),
            &stake_update(Some(stranger()), NEURON_INDEX),
        ),
        "names controller",
    );
}

#[test]
fn list_neurons_must_be_the_argument_construction_payloads_builds() {
    let displayed = RequestType::ListNeurons { page_number: 3 };
    verify(&displayed, &list_neurons_update(&list_neurons_arg(Some(3)))).unwrap();
    assert_rejected(
        "other page",
        verify(
            &RequestType::ListNeurons { page_number: 0 },
            &list_neurons_update(&list_neurons_arg(Some(3))),
        ),
        "page_number 0, but the signed list_neurons argument says 3",
    );

    let honest = || list_neurons_arg(Some(3));
    let mutated = [
        ListNeurons {
            neuron_ids: vec![1],
            ..honest()
        },
        ListNeurons {
            include_neurons_readable_by_caller: false,
            ..honest()
        },
        ListNeurons {
            include_empty_neurons_readable_by_caller: Some(true),
            ..honest()
        },
        ListNeurons {
            include_public_neurons_in_full_neurons: Some(true),
            ..honest()
        },
        ListNeurons {
            page_size: Some(1),
            ..honest()
        },
        ListNeurons {
            neuron_subaccounts: Some(vec![]),
            ..honest()
        },
    ];
    for args in mutated {
        assert_rejected(
            &format!("{args:?}"),
            verify(&displayed, &list_neurons_update(&args)),
            "sets fields other than the page number",
        );
    }
}

#[test]
fn a_transfer_must_be_a_send_from_the_default_account_on_the_configured_ledger() {
    let send = |canister_id, method: &str, from_subaccount| {
        update(
            canister_id,
            method,
            convert::to_arg(icp_ledger::SendArgs {
                memo: icp_ledger::Memo(0),
                amount: icp_ledger::Tokens::from_e8s(100_000_000),
                fee: icp_ledger::Tokens::from_e8s(10_000),
                from_subaccount,
                to: icp_ledger::AccountIdentifier::from(stranger()),
                created_at_time: None,
            }),
            None,
            owner(),
        )
    };

    verify(&RequestType::Send, &send(ledger(), SEND_PB, None)).unwrap();
    assert_rejected(
        "other ledger",
        verify(
            &RequestType::Send,
            &send(CanisterId::from_u64(99), SEND_PB, None),
        ),
        "A transfer must be addressed to canister",
    );
    assert_rejected(
        "other method",
        verify(&RequestType::Send, &send(ledger(), "notify_pb", None)),
        "Expected the signed update to call 'send_pb'",
    );
    assert_rejected(
        "subaccount",
        verify(
            &RequestType::Send,
            &send(ledger(), SEND_PB, Some(icp_ledger::Subaccount([1; 32]))),
        ),
        "draws on a subaccount of the sender",
    );
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
fn envelopes_must_carry_the_same_update_and_read_its_own_result() {
    let base = command_update(owner(), owner(), NEURON_INDEX, disburse_command());
    let later = HttpCanisterUpdate {
        ingress_expiry: base.ingress_expiry + 1_000,
        ..base.clone()
    };
    let other = command_update(owner(), owner(), 9, disburse_command());

    verify_envelopes(&disburse(), &[pair(base.clone()), pair(later.clone())]).unwrap();

    let mut read_state_of_later = pair(base.clone());
    read_state_of_later.read_state = pair(later).read_state;
    let mut read_state_of_other = pair(base.clone());
    read_state_of_other.read_state = pair(other.clone()).read_state;

    let cases = [
        (
            "other update",
            vec![pair(base), pair(other)],
            "must differ only in their ingress",
        ),
        (
            "read state of a later envelope",
            vec![read_state_of_later],
            "must read the result of that",
        ),
        (
            "read state of another update",
            vec![read_state_of_other],
            "must read the result of that",
        ),
        ("no envelope", vec![], "No request payload provided"),
    ];
    for (name, envelopes, expected) in cases {
        assert_rejected(name, verify_envelopes(&disburse(), &envelopes), expected);
    }
}
