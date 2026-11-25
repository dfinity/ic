use super::*;
use crate::models::EnvelopePair;
use candid::Encode;
use ic_nns_governance_api::{ManageNeuronCommandRequest, manage_neuron};
use ic_types::messages::{Blob, HttpCallContent, HttpRequestEnvelope};

const NEURON_INDEX: u64 = 7;

fn controller() -> PrincipalId {
    PrincipalId::new_user_test_id(1)
}

fn ledger() -> CanisterId {
    CanisterId::from_u64(1)
}

fn governance() -> CanisterId {
    CanisterId::from_u64(2)
}

#[track_caller]
fn assert_rejected(result: Result<(), ApiError>, expected: &str) {
    let err = result.expect_err("expected the request to be rejected");
    assert!(
        format!("{err:?}").contains(expected),
        "expected an error containing {expected:?}, got {err:?}"
    );
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

fn manage_neuron_update(sender: PrincipalId, neuron_index: u64) -> HttpCanisterUpdate {
    let manage = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&sender, neuron_index).to_vec(),
        )),
        command: Some(ManageNeuronCommandRequest::Disburse(
            manage_neuron::Disburse {
                amount: None,
                to_account: None,
            },
        )),
    };
    HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: MANAGE_NEURON.to_string(),
        arg: Blob(Encode!(&manage).unwrap()),
        nonce: Some(Blob(Encode!(&neuron_index).unwrap())),
        sender: Blob(sender.into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    }
}

fn disburse(neuron_index: u64) -> RequestType {
    RequestType::Disburse { neuron_index }
}

#[test]
fn faithful_update_is_accepted() {
    let update = manage_neuron_update(controller(), NEURON_INDEX);
    verify(&disburse(NEURON_INDEX), &update).unwrap();
}

#[test]
fn rewritten_neuron_index_is_rejected() {
    let update = manage_neuron_update(controller(), NEURON_INDEX);
    assert_rejected(
        verify(&disburse(0), &update),
        "neuron_index 0, but the signed nonce says 7",
    );
}

#[test]
fn missing_nonce_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    update.nonce = None;
    assert_rejected(verify(&disburse(NEURON_INDEX), &update), "carries no nonce");
}

#[test]
fn nonce_agreeing_with_a_foreign_subaccount_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    let manage = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(
                &PrincipalId::new_user_test_id(2),
                NEURON_INDEX,
            )
            .to_vec(),
        )),
        command: Some(ManageNeuronCommandRequest::Disburse(
            manage_neuron::Disburse {
                amount: None,
                to_account: None,
            },
        )),
    };
    update.arg = Blob(Encode!(&manage).unwrap());
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "signed neuron subaccount does not belong",
    );
}

#[test]
fn legacy_neuron_id_field_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    let manage = ManageNeuronRequest {
        id: Some(ic_nns_common::pb::v1::NeuronId { id: 99 }),
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&controller(), NEURON_INDEX).to_vec(),
        )),
        command: Some(ManageNeuronCommandRequest::Disburse(
            manage_neuron::Disburse {
                amount: None,
                to_account: None,
            },
        )),
    };
    update.arg = Blob(Encode!(&manage).unwrap());
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "legacy `id` field",
    );
}

#[test]
fn neuron_id_instead_of_subaccount_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    let manage = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
            ic_nns_common::pb::v1::NeuronId { id: 99 },
        )),
        command: Some(ManageNeuronCommandRequest::Disburse(
            manage_neuron::Disburse {
                amount: None,
                to_account: None,
            },
        )),
    };
    update.arg = Blob(Encode!(&manage).unwrap());
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "identifies the neuron by id",
    );
}

#[test]
fn foreign_canister_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    update.canister_id = Blob(PrincipalId::new_user_test_id(3).to_vec());
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "must be addressed to canister",
    );

    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    update.canister_id = Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec());
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "must be addressed to canister",
    );
}

#[test]
fn unexpected_method_name_is_rejected() {
    let mut update = manage_neuron_update(controller(), NEURON_INDEX);
    update.method_name = "some_other_method".to_string();
    assert_rejected(
        verify(&disburse(NEURON_INDEX), &update),
        "Expected the signed update to call 'manage_neuron'",
    );
}

#[test]
fn substituted_controller_is_rejected() {
    let hotkey = PrincipalId::new_user_test_id(9);
    let manage = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&controller(), NEURON_INDEX).to_vec(),
        )),
        command: Some(ManageNeuronCommandRequest::Follow(manage_neuron::Follow {
            topic: 0,
            followees: vec![],
        })),
    };
    let mut update = manage_neuron_update(hotkey, NEURON_INDEX);
    update.arg = Blob(Encode!(&manage).unwrap());

    let honest = RequestType::Follow {
        neuron_index: NEURON_INDEX,
        controller: Some(PublicKeyOrPrincipal::Principal(controller())),
    };
    verify(&honest, &update).unwrap();

    let substituted = RequestType::Follow {
        neuron_index: NEURON_INDEX,
        controller: Some(PublicKeyOrPrincipal::Principal(
            PrincipalId::new_user_test_id(4),
        )),
    };
    assert_rejected(
        verify(&substituted, &update),
        "signed neuron subaccount does not belong",
    );
}

#[test]
fn stake_is_bound_to_the_signed_memo() {
    let sender = controller();
    let args = ClaimOrRefreshNeuronFromAccount {
        controller: None,
        memo: NEURON_INDEX,
    };
    let update = HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
        arg: Blob(Encode!(&args).unwrap()),
        nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
        sender: Blob(sender.into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    verify(
        &RequestType::Stake {
            neuron_index: NEURON_INDEX,
        },
        &update,
    )
    .unwrap();
    assert_rejected(
        verify(&RequestType::Stake { neuron_index: 0 }, &update),
        "neuron_index 0, but the signed nonce says 7",
    );
}

#[test]
fn list_neurons_page_number_is_bound_to_the_signed_argument() {
    let args = ic_nns_governance_api::ListNeurons {
        neuron_ids: vec![],
        include_neurons_readable_by_caller: true,
        include_empty_neurons_readable_by_caller: None,
        include_public_neurons_in_full_neurons: None,
        page_number: Some(3),
        page_size: None,
        neuron_subaccounts: None,
    };
    let update = HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: LIST_NEURONS.to_string(),
        arg: Blob(Encode!(&args).unwrap()),
        nonce: None,
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    verify(&RequestType::ListNeurons { page_number: 3 }, &update).unwrap();
    assert_rejected(
        verify(&RequestType::ListNeurons { page_number: 0 }, &update),
        "page_number 0, but the signed list_neurons argument says 3",
    );
}

#[test]
fn neuron_info_is_bound_to_the_signed_subaccount() {
    let sender = controller();
    let args = NeuronIdOrSubaccount::Subaccount(
        convert::neuron_subaccount_bytes_from_principal(&sender, NEURON_INDEX).to_vec(),
    );
    let update = HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT.to_string(),
        arg: Blob(Encode!(&args).unwrap()),
        nonce: None,
        sender: Blob(sender.into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };

    verify(
        &RequestType::NeuronInfo {
            neuron_index: NEURON_INDEX,
            controller: None,
        },
        &update,
    )
    .unwrap();
    assert_rejected(
        verify(
            &RequestType::NeuronInfo {
                neuron_index: 0,
                controller: None,
            },
            &update,
        ),
        "signed neuron subaccount does not belong",
    );
}

#[test]
fn substituted_command_is_rejected() {
    let update = manage_neuron_update(controller(), NEURON_INDEX);
    assert_rejected(
        verify(
            &RequestType::StartDissolve {
                neuron_index: NEURON_INDEX,
            },
            &update,
        ),
        "The signed manage_neuron command is not the",
    );
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
fn stake_with_foreign_controller_is_rejected() {
    let sender = controller();
    let signed_stake = |controller: Option<PrincipalId>| {
        let args = ClaimOrRefreshNeuronFromAccount {
            controller,
            memo: NEURON_INDEX,
        };
        HttpCanisterUpdate {
            canister_id: Blob(governance().get().to_vec()),
            method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        }
    };
    let stake = RequestType::Stake {
        neuron_index: NEURON_INDEX,
    };

    verify(&stake, &signed_stake(None)).unwrap();
    verify(&stake, &signed_stake(Some(sender))).unwrap();
    assert_rejected(
        verify(
            &stake,
            &signed_stake(Some(PrincipalId::new_user_test_id(77))),
        ),
        "names controller",
    );
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
        (
            RequestType::Disburse { neuron_index },
            Cmd::Disburse(manage_neuron::Disburse {
                amount: None,
                to_account: None,
            }),
        ),
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

fn manage_neuron_update_with(
    sender: PrincipalId,
    neuron_index: u64,
    command: ManageNeuronCommandRequest,
) -> HttpCanisterUpdate {
    let manage = ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&sender, neuron_index).to_vec(),
        )),
        command: Some(command),
    };
    HttpCanisterUpdate {
        arg: Blob(Encode!(&manage).unwrap()),
        ..manage_neuron_update(sender, neuron_index)
    }
}

#[test]
fn every_manage_neuron_request_is_bound_to_the_signed_neuron() {
    for (request_type, command) in manage_neuron_requests(NEURON_INDEX) {
        let update = manage_neuron_update_with(controller(), NEURON_INDEX, command);
        let name = request_type.clone().into_str();

        if let Err(err) = verify(&request_type, &update) {
            panic!("{name}: the genuine update was rejected: {err:?}");
        }

        let (rewritten, _) = manage_neuron_requests(0)
            .into_iter()
            .find(|(other, _)| other.clone().into_str() == name)
            .unwrap();
        let err = verify(&rewritten, &update).expect_err(name);
        assert!(
            format!("{err:?}").contains("neuron_index 0, but the signed nonce says 7"),
            "{name}: unexpected error {err:?}"
        );
    }
}

#[track_caller]
fn assert_rejected_as(name: &str, result: Result<(), ApiError>, expected: &str) {
    let err = result.expect_err(name);
    assert!(
        format!("{err:?}").contains(expected),
        "{name}: expected an error containing {expected:?}, got {err:?}"
    );
}

#[test]
fn every_manage_neuron_request_is_bound_to_the_signed_subaccount() {
    for (request_type, command) in manage_neuron_requests(NEURON_INDEX) {
        let update = HttpCanisterUpdate {
            sender: Blob(controller().into_vec()),
            ..manage_neuron_update_with(PrincipalId::new_user_test_id(2), NEURON_INDEX, command)
        };
        assert_rejected_as(
            request_type.clone().into_str(),
            verify(&request_type, &update),
            "signed neuron subaccount does not belong",
        );
    }
}

#[test]
fn every_manage_neuron_request_is_bound_to_the_signed_command() {
    let requests = manage_neuron_requests(NEURON_INDEX);
    for (request_type, _) in &requests {
        for (other, command) in &requests {
            if other.clone().into_str() == request_type.clone().into_str() {
                continue;
            }
            let update = manage_neuron_update_with(controller(), NEURON_INDEX, command.clone());
            assert_rejected_as(
                &format!(
                    "{} signed as {}",
                    request_type.clone().into_str(),
                    other.clone().into_str()
                ),
                verify(request_type, &update),
                "The signed manage_neuron command is not the",
            );
        }
    }
}

fn neuron_info_update(sender: PrincipalId, owner: PrincipalId) -> HttpCanisterUpdate {
    let args = NeuronIdOrSubaccount::Subaccount(
        convert::neuron_subaccount_bytes_from_principal(&owner, NEURON_INDEX).to_vec(),
    );
    HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT.to_string(),
        arg: Blob(Encode!(&args).unwrap()),
        nonce: None,
        sender: Blob(sender.into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    }
}

#[test]
fn every_hotkey_request_is_bound_to_the_displayed_controller() {
    let hotkey = PrincipalId::new_user_test_id(9);
    let follow = manage_neuron_requests(NEURON_INDEX)
        .into_iter()
        .filter(|(request_type, _)| {
            matches!(
                request_type,
                RequestType::Follow { .. } | RequestType::RefreshVotingPower { .. }
            )
        })
        .map(|(request_type, command)| {
            let update = HttpCanisterUpdate {
                sender: Blob(hotkey.into_vec()),
                ..manage_neuron_update_with(controller(), NEURON_INDEX, command)
            };
            (request_type, update)
        });
    let neuron_info = (
        RequestType::NeuronInfo {
            neuron_index: NEURON_INDEX,
            controller: None,
        },
        neuron_info_update(hotkey, controller()),
    );

    for (request_type, update) in follow.chain([neuron_info]) {
        let name = request_type.clone().into_str();
        let displaying = |controller: Option<PrincipalId>| {
            let controller = controller.map(PublicKeyOrPrincipal::Principal);
            match request_type.clone() {
                RequestType::Follow { neuron_index, .. } => RequestType::Follow {
                    neuron_index,
                    controller,
                },
                RequestType::RefreshVotingPower { neuron_index, .. } => {
                    RequestType::RefreshVotingPower {
                        neuron_index,
                        controller,
                    }
                }
                RequestType::NeuronInfo { neuron_index, .. } => RequestType::NeuronInfo {
                    neuron_index,
                    controller,
                },
                _ => unreachable!(),
            }
        };

        verify(&displaying(Some(controller())), &update)
            .unwrap_or_else(|e| panic!("{name}: the genuine update was rejected: {e:?}"));
        for displayed in [None, Some(PrincipalId::new_user_test_id(4))] {
            assert_rejected_as(
                name,
                verify(&displaying(displayed), &update),
                "signed neuron subaccount does not belong",
            );
        }
    }
}

#[test]
fn stake_memo_must_match_the_displayed_neuron_index() {
    let args = ClaimOrRefreshNeuronFromAccount {
        controller: None,
        memo: 0,
    };
    let update = HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
        arg: Blob(Encode!(&args).unwrap()),
        nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };
    assert_rejected(
        verify(
            &RequestType::Stake {
                neuron_index: NEURON_INDEX,
            },
            &update,
        ),
        "neuron_index 7, but the signed claim_or_refresh_neuron_from_account memo says 0",
    );
}

fn list_neurons_update(args: &ic_nns_governance_api::ListNeurons) -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: LIST_NEURONS.to_string(),
        arg: Blob(Encode!(args).unwrap()),
        nonce: None,
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    }
}

#[test]
fn list_neurons_must_be_the_argument_construction_payloads_builds() {
    let displayed = RequestType::ListNeurons { page_number: 3 };
    verify(&displayed, &list_neurons_update(&list_neurons_arg(Some(3)))).unwrap();

    let mutations: [fn(&mut ic_nns_governance_api::ListNeurons); 6] = [
        |args| args.neuron_ids = vec![1],
        |args| args.include_neurons_readable_by_caller = false,
        |args| args.include_empty_neurons_readable_by_caller = Some(true),
        |args| args.include_public_neurons_in_full_neurons = Some(true),
        |args| args.page_size = Some(1),
        |args| args.neuron_subaccounts = Some(vec![]),
    ];
    for mutate in mutations {
        let mut args = list_neurons_arg(Some(3));
        mutate(&mut args);
        assert_rejected(
            verify(&displayed, &list_neurons_update(&args)),
            "sets fields other than the page number",
        );
    }
}

#[test]
fn every_governance_request_is_bound_to_the_governance_canister_and_method() {
    let stake = HttpCanisterUpdate {
        canister_id: Blob(governance().get().to_vec()),
        method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
        arg: Blob(
            Encode!(&ClaimOrRefreshNeuronFromAccount {
                controller: None,
                memo: NEURON_INDEX,
            })
            .unwrap(),
        ),
        nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
        sender: Blob(controller().into_vec()),
        ingress_expiry: 0,
        sender_info: None,
    };
    let requests = [
        (
            RequestType::Stake {
                neuron_index: NEURON_INDEX,
            },
            stake,
        ),
        (
            RequestType::NeuronInfo {
                neuron_index: NEURON_INDEX,
                controller: None,
            },
            neuron_info_update(controller(), controller()),
        ),
        (
            RequestType::ListNeurons { page_number: 0 },
            list_neurons_update(&list_neurons_arg(None)),
        ),
        (
            disburse(NEURON_INDEX),
            manage_neuron_update(controller(), NEURON_INDEX),
        ),
    ];

    for (request_type, update) in requests {
        let name = request_type.clone().into_str();
        verify(&request_type, &update)
            .unwrap_or_else(|e| panic!("{name}: the genuine update was rejected: {e:?}"));
        assert_rejected_as(
            name,
            verify(
                &request_type,
                &HttpCanisterUpdate {
                    canister_id: Blob(ledger().get().to_vec()),
                    ..update.clone()
                },
            ),
            "A neuron request must be addressed to canister",
        );
        assert_rejected_as(
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
    let base = manage_neuron_update(controller(), NEURON_INDEX);
    let mut later = base.clone();
    later.ingress_expiry = base.ingress_expiry + 1_000;

    verify_envelopes(&disburse(NEURON_INDEX), &[pair(base.clone()), pair(later)]).unwrap();

    let other = manage_neuron_update(controller(), 9);
    assert_rejected(
        verify_envelopes(&disburse(NEURON_INDEX), &[pair(base), pair(other)]),
        "must differ only in their ingress",
    );

    assert_rejected(
        verify_envelopes(&disburse(NEURON_INDEX), &[]),
        "No request payload provided",
    );
}

#[test]
fn a_read_state_for_another_message_is_rejected() {
    let base = manage_neuron_update(controller(), NEURON_INDEX);
    let mut later = base.clone();
    later.ingress_expiry = base.ingress_expiry + 1_000;

    let mut spliced = pair(base.clone());
    spliced.read_state = pair(later).read_state;
    assert_rejected(
        verify_envelopes(&disburse(NEURON_INDEX), &[spliced]),
        "must read the result of that",
    );

    let mut spliced = pair(base);
    spliced.read_state = pair(manage_neuron_update(controller(), 9)).read_state;
    assert_rejected(
        verify_envelopes(&disburse(NEURON_INDEX), &[spliced]),
        "must read the result of that",
    );
}
