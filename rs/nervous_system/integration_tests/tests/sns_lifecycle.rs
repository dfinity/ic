use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_ledger_core::Tokens;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResultV2,
};
use ic_nervous_system_common::{
    assert_is_ok, ledger::compute_distribution_subaccount_bytes, E8, SECONDS_PER_DAY,
};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nervous_system_proto::pb::v1::{Duration as DurationPb, Tokens as TokensPb};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution,
    get_neurons_fund_audit_info_response, manage_neuron, manage_neuron_response, proposal,
    CreateServiceNervousSystem, ExecuteNnsFunction, GetNeuronsFundAuditInfoRequest,
    GetNeuronsFundAuditInfoResponse, ListNeurons, ListNeuronsResponse, ManageNeuron,
    ManageNeuronResponse, NnsFunction, Proposal, ProposalInfo,
};
use ic_nns_test_utils::{
    common::{
        build_ledger_wasm, build_root_wasm, build_sns_wasms_wasm, build_test_governance_wasm,
        NnsInitPayloadsBuilder,
    },
    ids::TEST_NEURON_1_ID,
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_index_sns_wasm,
        build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm,
    },
};
use ic_sns_governance::{governance::TREASURY_SUBACCOUNT_NONCE, pb::v1 as sns_pb};
use ic_sns_init::distributions::MAX_DEVELOPER_DISTRIBUTION_COUNT;
use ic_sns_swap::{
    pb::v1::{
        ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapResponse,
        GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse,
        GetDerivedStateRequest, GetDerivedStateResponse, GetLifecycleRequest, GetLifecycleResponse,
        Lifecycle, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
    },
    swap::principal_to_subaccount,
};
use ic_sns_wasm::pb::v1::{
    get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult, AddWasmRequest,
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse, SnsCanisterType,
    SnsWasm,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use maplit::hashmap;
use num_traits::ToPrimitive;
use pocket_ic::{PocketIc, PocketIcBuilder, WasmResult};
use prost::Message;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};

const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

fn canister_status(pocket_ic: &PocketIc, canister_id: CanisterId) -> CanisterStatusResultV2 {
    let result = pocket_ic
        .update_call(
            CanisterId::ic_00().into(),
            Principal::anonymous(),
            "canister_status",
            Encode!(&CanisterIdRecord { canister_id }).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("canister_status was rejected: {:#?}", reject)
        }
    };
    Decode!(&result, CanisterStatusResultV2).unwrap()
}

/// Manage an NNS neuron, e.g., to make an NNS Governance proposal.
fn manage_neuron(
    pocket_ic: &PocketIc,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: manage_neuron::Command,
) -> ManageNeuronResponse {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::from(sender),
            "manage_neuron",
            Encode!(&ManageNeuron {
                id: Some(neuron_id),
                command: Some(command),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to (NNS) manage_neuron failed: {:#?}", s),
    };
    Decode!(&result, ManageNeuronResponse).unwrap()
}

mod sns {
    use super::*;

    pub mod governance {
        use super::*;

        pub fn get_mode(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> sns_pb::GetModeResponse {
            let result = pocket_ic
                .update_call(
                    sns_governance_canister_id.into(),
                    Principal::anonymous(),
                    "get_mode",
                    Encode!(&sns_pb::GetMode {}).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to get_mode failed: {:#?}", s),
            };
            Decode!(&result, sns_pb::GetModeResponse).unwrap()
        }

        /// Manage an SNS neuron, e.g., to make an SNS Governance proposal.
        fn manage_neuron(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            sender: PrincipalId,
            // subaccount: &[u8],
            neuron_id: sns_pb::NeuronId,
            command: sns_pb::manage_neuron::Command,
        ) -> sns_pb::ManageNeuronResponse {
            let sub_account = neuron_id.subaccount().unwrap();
            let result = pocket_ic
                .update_call(
                    sns_governance_canister_id.into(),
                    sender.into(),
                    "manage_neuron",
                    Encode!(&sns_pb::ManageNeuron {
                        subaccount: sub_account.to_vec(),
                        command: Some(command),
                    })
                    .unwrap(),
                )
                .expect("Error calling manage_neuron");
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to (SNS) manage_neuron failed: {:#?}", s),
            };
            Decode!(&result, sns_pb::ManageNeuronResponse).unwrap()
        }

        pub fn start_dissolving_neuron(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
        ) -> sns_pb::ManageNeuronResponse {
            let command =
                sns_pb::manage_neuron::Command::Configure(sns_pb::manage_neuron::Configure {
                    operation: Some(
                        sns_pb::manage_neuron::configure::Operation::StartDissolving(
                            sns_pb::manage_neuron::StartDissolving {},
                        ),
                    ),
                });
            manage_neuron(
                pocket_ic,
                sns_governance_canister_id,
                sender,
                neuron_id,
                command,
            )
        }

        pub fn propose_and_wait(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
            proposal: sns_pb::Proposal,
        ) -> Result<sns_pb::ProposalData, sns_pb::GovernanceError> {
            let response = manage_neuron(
                pocket_ic,
                sns_governance_canister_id,
                sender,
                neuron_id,
                sns_pb::manage_neuron::Command::MakeProposal(proposal),
            );
            use sns_pb::manage_neuron_response::Command;
            let response = match response.command {
                Some(Command::MakeProposal(response)) => Ok(response),
                Some(Command::Error(err)) => Err(err),
                _ => panic!("Proposal failed unexpectedly: {:#?}", response),
            }?;
            let proposal_id = response.proposal_id.unwrap_or_else(|| {
                panic!(
                    "First SNS proposal response did not contain a proposal_id: {:#?}",
                    response
                )
            });
            wait_for_proposal_execution(pocket_ic, sns_governance_canister_id, proposal_id)
        }

        /// This function assumes that the proposal submission succeeded (and panics otherwise).
        fn wait_for_proposal_execution(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
        ) -> Result<sns_pb::ProposalData, sns_pb::GovernanceError> {
            // We create some blocks until the proposal has finished executing (`pocket_ic.tick()`).
            let mut last_proposal_data = None;
            for _attempt_count in 1..=50 {
                pocket_ic.tick();
                let proposal = get_proposal(
                    pocket_ic,
                    sns_governance_canister_id,
                    proposal_id,
                    PrincipalId::new_anonymous(),
                );
                let proposal = proposal
                    .result
                    .expect("GetProposalResponse.result must be set.");
                let proposal_data = match proposal {
                    sns_pb::get_proposal_response::Result::Error(err) => {
                        panic!("Proposal data cannot be found: {:?}", err);
                    }
                    sns_pb::get_proposal_response::Result::Proposal(proposal_data) => proposal_data,
                };
                if proposal_data.executed_timestamp_seconds > 0 {
                    return Ok(proposal_data);
                }
                proposal_data.failure_reason.clone().map_or(Ok(()), Err)?;
                last_proposal_data = Some(proposal_data);
                pocket_ic.advance_time(Duration::from_millis(100));
            }
            panic!(
                "Looks like the SNS proposal {:?} is never going to be decided: {:#?}",
                proposal_id, last_proposal_data
            );
        }

        fn get_proposal(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
            sender: PrincipalId,
        ) -> sns_pb::GetProposalResponse {
            let result = pocket_ic
                .update_call(
                    sns_governance_canister_id.into(),
                    Principal::from(sender),
                    "get_proposal",
                    Encode!(&sns_pb::GetProposal {
                        proposal_id: Some(proposal_id)
                    })
                    .unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(reply) => reply,
                WasmResult::Reject(reject) => {
                    panic!(
                        "get_proposal was rejected by the SNS governance canister: {:#?}",
                        reject
                    )
                }
            };
            Decode!(&result, sns_pb::GetProposalResponse).unwrap()
        }

        pub fn list_neurons(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> sns_pb::ListNeuronsResponse {
            let result = pocket_ic
                .update_call(
                    sns_governance_canister_id.into(),
                    Principal::from(PrincipalId::new_anonymous()),
                    "list_neurons",
                    Encode!(&sns_pb::ListNeurons::default()).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(reply) => reply,
                WasmResult::Reject(reject) => {
                    panic!(
                        "list_neurons was rejected by the SNS governance canister: {:#?}",
                        reject
                    )
                }
            };
            Decode!(&result, sns_pb::ListNeuronsResponse).unwrap()
        }

        /// Searches for the ID and controller principal of an SNS neuron that can submit proposals.
        pub fn find_neuron_with_majority_voting_power(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> Option<(sns_pb::NeuronId, PrincipalId)> {
            let sns_neurons = list_neurons(pocket_ic, sns_governance_canister_id).neurons;
            sns_neurons
                .iter()
                .find(|neuron| {
                    neuron.dissolve_delay_seconds(neuron.created_timestamp_seconds)
                        >= 6 * 30 * SECONDS_PER_DAY
                })
                .map(|sns_neuron| {
                    (
                        sns_neuron.id.clone().unwrap(),
                        sns_neuron.permissions.last().unwrap().principal.unwrap(),
                    )
                })
        }
    }

    pub mod ledger {
        use super::*;

        pub fn icrc1_total_supply(pocket_ic: &PocketIc, swap_canister_id: PrincipalId) -> Nat {
            let result = pocket_ic
                .update_call(
                    swap_canister_id.into(),
                    Principal::anonymous(),
                    "icrc1_total_supply",
                    Encode!().unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to icrc1_total_supply failed: {:#?}", s),
            };
            Decode!(&result, Nat).unwrap()
        }

        pub fn icrc1_balance_of(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            account: Account,
        ) -> Nat {
            let result = pocket_ic
                .update_call(
                    swap_canister_id.into(),
                    Principal::anonymous(),
                    "icrc1_balance_of",
                    Encode!(&account).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to icrc1_balance_of failed: {:#?}", s),
            };
            Decode!(&result, Nat).unwrap()
        }
    }
}

fn refresh_buyer_tokens(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    buyer: PrincipalId,
    confirmation_text: Option<String>,
) -> Result<RefreshBuyerTokensResponse, String> {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: buyer.to_string(),
                confirmation_text,
            })
            .unwrap(),
        )
        .map_err(|err| err.to_string())?;
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to refresh_buyer_tokens failed: {:#?}", s),
    };
    Ok(Decode!(&result, RefreshBuyerTokensResponse).unwrap())
}

fn error_refund_icp(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    source_principal_id: PrincipalId,
) -> ErrorRefundIcpResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "error_refund_icp",
            Encode!(&ErrorRefundIcpRequest {
                source_principal_id: Some(source_principal_id),
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to error_refund_icp failed: {:#?}", s),
    };
    Decode!(&result, ErrorRefundIcpResponse).unwrap()
}

fn get_derived_state(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> GetDerivedStateResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_derived_state",
            Encode!(&GetDerivedStateRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_derived_state failed: {:#?}", s),
    };
    Decode!(&result, GetDerivedStateResponse).unwrap()
}

fn get_lifecycle(pocket_ic: &PocketIc, swap_canister_id: PrincipalId) -> GetLifecycleResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_lifecycle",
            Encode!(&GetLifecycleRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_lifecycle failed: {:#?}", s),
    };
    Decode!(&result, GetLifecycleResponse).unwrap()
}

fn await_swap_lifecycle(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    expected_lifecycle: Lifecycle,
) -> Result<(), String> {
    let mut last_lifecycle = None;
    for _attempt_count in 1..=50 {
        pocket_ic.tick();
        let lifecycle = get_lifecycle(pocket_ic, swap_canister_id);
        let lifecycle = lifecycle.lifecycle.unwrap();
        if lifecycle == expected_lifecycle as i32 {
            return Ok(());
        }
        last_lifecycle = Some(lifecycle);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the SNS lifecycle {:?} is never going to be reached: {:#?}",
        expected_lifecycle, last_lifecycle,
    ))
}

/// Returns:
/// * `Ok(None)` if any of the top-level fields of this `auto_finalization_status` are unset, i.e.:
///   `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///   or `auto_finalize_swap_response`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
/// * `Ok(Some(response))` -- otherwise.
fn validate_auto_finalization_status(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<Option<&FinalizeSwapResponse>, String> {
    if auto_finalization_status
        .has_auto_finalize_been_attempted
        .is_none()
        || auto_finalization_status.is_auto_finalize_enabled.is_none()
    {
        return Ok(None);
    }
    let Some(ref auto_finalize_swap_response) =
        auto_finalization_status.auto_finalize_swap_response
    else {
        return Ok(None);
    };
    if let Some(ref error_message) = auto_finalize_swap_response.error_message {
        // If auto_finalization_status contains an error, we return that error.
        return Err(error_message.clone());
    }
    Ok(Some(auto_finalize_swap_response))
}

/// Returns:
/// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Committed`.
/// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
///   other than Committed), i.e., one of the following conditions holds:
///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
///       `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///        or `auto_finalize_swap_response`.
///     2. `auto_finalize_swap_response` does not match the expected pattern for a *committed* SNS
///        Swap's `auto_finalize_swap_response`. In particular:
///        - `set_dapp_controllers_call_result` must be `None`,
///        - `sweep_sns_result` must be `Some`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
fn is_auto_finalization_status_committed_or_err(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<bool, String> {
    let Some(auto_finalize_swap_response) =
        validate_auto_finalization_status(auto_finalization_status)?
    else {
        return Ok(false);
    };
    // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
    // indicate that the swap has been committed yet.
    Ok(matches!(
        auto_finalize_swap_response,
        FinalizeSwapResponse {
            sweep_icp_result: Some(_),
            create_sns_neuron_recipes_result: Some(_),
            settle_neurons_fund_participation_result: Some(_),
            sweep_sns_result: Some(_),
            claim_neuron_result: Some(_),
            set_mode_call_result: Some(_),
            set_dapp_controllers_call_result: None,
            settle_community_fund_participation_result: None,
            error_message: None,
        }
    ))
}

/// Returns:
/// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Aborted`.
/// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
///   other than Aborted), i.e., one of the following conditions holds:
///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
///       `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///        or `auto_finalize_swap_response`.
///     2. `auto_finalize_swap_response` does not match the expected pattern for an *aborted* SNS
///        Swap's `auto_finalize_swap_response`. In particular:
///        - `set_dapp_controllers_call_result` must be `Some`,
///        - `sweep_sns_result` must be `None`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
fn is_auto_finalization_status_aborted_or_err(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<bool, String> {
    let Some(auto_finalize_swap_response) =
        validate_auto_finalization_status(auto_finalization_status)?
    else {
        return Ok(false);
    };
    // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
    // indicate that the swap has been aborted yet.
    Ok(matches!(
        auto_finalize_swap_response,
        FinalizeSwapResponse {
            sweep_icp_result: Some(_),
            set_dapp_controllers_call_result: Some(_),
            settle_neurons_fund_participation_result: Some(_),
            create_sns_neuron_recipes_result: None,
            sweep_sns_result: None,
            claim_neuron_result: None,
            set_mode_call_result: None,
            settle_community_fund_participation_result: None,
            error_message: None,
        }
    ))
}

/// Subset of `Lifecycle` indicating terminal statuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SwapFinalizationStatus {
    Aborted,
    Committed,
}

fn await_swap_finalization_status(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    status: SwapFinalizationStatus,
) -> Result<GetAutoFinalizationStatusResponse, String> {
    let mut last_auto_finalization_status = None;
    for _attempt_count in 1..=100 {
        pocket_ic.tick();
        let auto_finalization_status = get_auto_finalization_status(pocket_ic, swap_canister_id);
        match status {
            SwapFinalizationStatus::Aborted => {
                if is_auto_finalization_status_aborted_or_err(&auto_finalization_status)? {
                    return Ok(auto_finalization_status);
                }
            }
            SwapFinalizationStatus::Committed => {
                if is_auto_finalization_status_committed_or_err(&auto_finalization_status)? {
                    return Ok(auto_finalization_status);
                }
            }
        }
        last_auto_finalization_status = Some(auto_finalization_status);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the expected SNS auto-finalization status is never going to be reached: {:#?}",
        last_auto_finalization_status,
    ))
}

fn get_auto_finalization_status(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> GetAutoFinalizationStatusResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_auto_finalization_status",
            Encode!(&GetAutoFinalizationStatusRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_auto_finalization_status failed: {:#?}", s),
    };
    Decode!(&result, GetAutoFinalizationStatusResponse).unwrap()
}

fn get_deployed_sns_by_proposal_id(
    pocket_ic: &PocketIc,
    proposal_id: ProposalId,
) -> GetDeployedSnsByProposalIdResponse {
    let result = pocket_ic
        .update_call(
            SNS_WASM_CANISTER_ID.into(),
            Principal::anonymous(),
            "get_deployed_sns_by_proposal_id",
            Encode!(&GetDeployedSnsByProposalIdRequest {
                proposal_id: proposal_id.id
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_deployed_sns_by_proposal_id failed: {:#?}", s),
    };
    Decode!(&result, GetDeployedSnsByProposalIdResponse).unwrap()
}

fn get_neurons_fund_audit_info(
    pocket_ic: &PocketIc,
    proposal_id: ProposalId,
) -> GetNeuronsFundAuditInfoResponse {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::anonymous(),
            "get_neurons_fund_audit_info",
            Encode!(&GetNeuronsFundAuditInfoRequest {
                nns_proposal_id: Some(proposal_id)
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_neurons_fund_audit_info failed: {:#?}", s),
    };
    Decode!(&result, GetNeuronsFundAuditInfoResponse).unwrap()
}

fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
    let result = pocket_ic
        .update_call(
            LEDGER_CANISTER_ID.into(),
            Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL),
            "account_balance",
            Encode!(&BinaryAccountBalanceArgs {
                account: account.to_address(),
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to account_balance failed: {:#?}", s),
    };
    Decode!(&result, Tokens).unwrap()
}

fn icrc1_transfer(
    pocket_ic: &PocketIc,
    sender: PrincipalId,
    transfer_arg: TransferArg,
) -> Result<Nat, TransferError> {
    let result = pocket_ic
        .update_call(
            LEDGER_CANISTER_ID.into(),
            Principal::from(sender),
            "icrc1_transfer",
            Encode!(&transfer_arg).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to icrc1_transfer failed: {:#?}", s),
    };
    Decode!(&result, Result<Nat, TransferError>).unwrap()
}

fn nns_get_proposal_info(
    pocket_ic: &PocketIc,
    proposal_id: u64,
    sender: PrincipalId,
) -> ProposalInfo {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::from(sender),
            "get_proposal_info",
            Encode!(&proposal_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_proposal_info was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Option<ProposalInfo>).unwrap().unwrap()
}

fn propose_and_wait(pocket_ic: &PocketIc, proposal: Proposal) -> Result<ProposalInfo, String> {
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let command: manage_neuron::Command = manage_neuron::Command::MakeProposal(Box::new(proposal));
    let response = manage_neuron(
        pocket_ic,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        command,
    );
    let response = match response.command {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        _ => panic!("Proposal failed: {:#?}", response),
    };
    let proposal_id = response
        .proposal_id
        .unwrap_or_else(|| {
            panic!(
                "First proposal response did not contain a proposal_id: {:#?}",
                response
            )
        })
        .id;
    nns_wait_for_proposal_execution(pocket_ic, proposal_id)
}

fn nns_wait_for_proposal_execution(
    pocket_ic: &PocketIc,
    proposal_id: u64,
) -> Result<ProposalInfo, String> {
    // We create some blocks until the proposal has finished executing (`pocket_ic.tick()`).
    let mut last_proposal_info = None;
    for _attempt_count in 1..=50 {
        pocket_ic.tick();
        let proposal_info =
            nns_get_proposal_info(pocket_ic, proposal_id, PrincipalId::new_anonymous());
        if proposal_info.executed_timestamp_seconds > 0 {
            return Ok(proposal_info);
        }
        assert_eq!(
            proposal_info.failure_reason, None,
            "Proposal execution failed: {:#?}",
            proposal_info
        );
        last_proposal_info = Some(proposal_info);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like proposal {:?} is never going to be executed: {:#?}",
        proposal_id, last_proposal_info,
    ))
}

pub fn list_neurons(pocket_ic: &PocketIc, sender: PrincipalId) -> ListNeuronsResponse {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::from(sender),
            "list_neurons",
            // Instead of listing neurons by ID, opt for listing all neurons readable by `sender`.
            Encode!(&ListNeurons {
                neuron_ids: vec![],
                include_neurons_readable_by_caller: true,
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "list_neurons was rejected by the SNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, ListNeuronsResponse).unwrap()
}

fn add_wasm(pocket_ic: &PocketIc, wasm: SnsWasm) -> Result<ProposalInfo, String> {
    let hash = wasm.sha256_hash();
    let canister_type = wasm.canister_type;
    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm),
    };
    let proposal = Proposal {
        title: Some(format!("Add WASM for SNS canister type {}", canister_type)),
        summary: "summary".to_string(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AddSnsWasm as i32,
            payload: Encode!(&payload).expect("Error encoding proposal payload"),
        })),
    };
    propose_and_wait(pocket_ic, proposal)
}

fn add_real_wasms_to_sns_wasm(
    pocket_ic: &PocketIc,
) -> Result<HashMap<SnsCanisterType, (ProposalInfo, SnsWasm)>, String> {
    let root_wasm = build_root_sns_wasm();
    let root_proposal_info = add_wasm(pocket_ic, root_wasm.clone())?;

    let gov_wasm = build_governance_sns_wasm();
    let gov_proposal_info = add_wasm(pocket_ic, gov_wasm.clone())?;

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_proposal_info = add_wasm(pocket_ic, ledger_wasm.clone())?;

    let swap_wasm = build_swap_sns_wasm();
    let swap_proposal_info = add_wasm(pocket_ic, swap_wasm.clone())?;

    let archive_wasm = build_archive_sns_wasm();
    let archive_proposal_info = add_wasm(pocket_ic, archive_wasm.clone())?;

    let index_wasm = build_index_sns_wasm();
    let index_proposal_info = add_wasm(pocket_ic, index_wasm.clone())?;

    Ok(hashmap! {
        SnsCanisterType::Root => (root_proposal_info, root_wasm),
        SnsCanisterType::Governance => (gov_proposal_info, gov_wasm),
        SnsCanisterType::Ledger => (ledger_proposal_info, ledger_wasm),
        SnsCanisterType::Swap => (swap_proposal_info, swap_wasm),
        SnsCanisterType::Archive => (archive_proposal_info, archive_wasm),
        SnsCanisterType::Index => (index_proposal_info, index_wasm),
    })
}

fn install_canister(pocket_ic: &PocketIc, name: &str, id: CanisterId, arg: Vec<u8>, wasm: Wasm) {
    let canister_id = pocket_ic
        .create_canister_with_id(None, None, id.into())
        .unwrap();
    pocket_ic.install_canister(canister_id, wasm.bytes(), arg, None);
    pocket_ic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    let subnet_id = pocket_ic.get_subnet(canister_id).unwrap();
    println!(
        "Installed the {} canister ({}) onto {:?}",
        name, canister_id, subnet_id
    );
}

/// Installs the NNS canisters.
///
/// Argument `initial_balances` is a `Vec` of
/// `(test_user_icp_ledger_account, test_user_icp_ledger_initial_balance)` pairs, representing
/// some initial ICP balances.
///
/// Returns a list of `controller_principal_id`s of pre-configured NNS neurons.
fn install_nns_canisters(
    pocket_ic: &PocketIc,
    initial_balances: Vec<(AccountIdentifier, Tokens)>,
) -> Vec<PrincipalId> {
    let topology = pocket_ic.topology();

    let sns_subnet_id = topology.get_sns().unwrap();
    let sns_subnet_id = PrincipalId::from(sns_subnet_id);
    let sns_subnet_id = SubnetId::from(sns_subnet_id);
    println!("sns_subnet_id = {:?}", sns_subnet_id);
    let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();
    nns_init_payload_builder
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons_fund_neurons(1_500_000 * E8)
        .with_sns_dedicated_subnets(vec![sns_subnet_id])
        .with_sns_wasm_access_controls(true);

    for (test_user_icp_ledger_account, test_user_icp_ledger_initial_balance) in initial_balances {
        nns_init_payload_builder.with_ledger_account(
            test_user_icp_ledger_account,
            test_user_icp_ledger_initial_balance,
        );
    }

    let nns_init_payload = nns_init_payload_builder.build();
    install_canister(
        pocket_ic,
        "ICP Ledger",
        LEDGER_CANISTER_ID,
        Encode!(&nns_init_payload.ledger).unwrap(),
        build_ledger_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS Root",
        ROOT_CANISTER_ID,
        Encode!(&nns_init_payload.root).unwrap(),
        build_root_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS Governance",
        GOVERNANCE_CANISTER_ID,
        nns_init_payload.governance.encode_to_vec(),
        build_test_governance_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS SNS-W",
        SNS_WASM_CANISTER_ID,
        Encode!(&nns_init_payload.sns_wasms).unwrap(),
        build_sns_wasms_wasm(),
    );
    add_real_wasms_to_sns_wasm(pocket_ic).unwrap();

    nns_init_payload
        .governance
        .neurons
        .values()
        .map(|neuron| neuron.controller.unwrap())
        .collect()
}

/// This is a parametric test function for the testing the SNS lifecycle. A test instance should
/// end by calling this function, instantiating it with a set of parameter values that define
/// a particular testing scenario. If this function panics, the test fails. Otherwise, it succeeds.
///
/// The direct participants represented by `direct_participant_principal_ids` participate with
/// `(1_000_000 ICP / N)` each, where `N == direct_participant_principal_ids.len()`.
///
/// At a high level, the following aspects of an SNS are covered in this function:
/// 1. Basic properties on an SNS instance:
/// 1.1. An SNS instance can be deployed successfully by submitting an NNS proposal.
/// 1.2. A new SNS instance automatically transitions into `Lifecycle::Open`.
/// 1.3. Direct participation works as expected.
///
/// 2. Auto-finalization works as expected.
///
/// 3. The SNS instance obeys the following Hoare triples:
///
///    Abbreviations. (See diagram in rs/sns/swap/proto/ic_sns_swap/pb/v1/swap.proto for more details.)
///    - `FinalizeUnSuccessfully` is an operation that brings the SNS instance from an initial state
///      `Lifecycle::Open` to the terminal state `Lifecycle::Aborted`, i.e., the following assertion
///      holds by-definition: `{ Lifecycle::Open } FinalizeUnSuccessfully { Lifecycle::Aborted }`.
///    - `FinalizeSuccessfully` is an operation that brings the SNS instance from an initial state
///      `Lifecycle::Open` to the terminal state `Lifecycle::Committed`, i.e., the following assertion
///      holds by-definition: `{ Lifecycle::Open } FinalizeUnSuccessfully { Lifecycle::Committed }`.
///    - `Finalize` is the same as
///      ```
///      if ensure_swap_timeout_is_reached {
///          FinalizeUnSuccessfully
///      } else {
///          FinalizeSuccessfully
///      }
///      ```
///    - `Canister.function()` refers to calling `Canister`s public API `function`.
///
///    Notation.
///    - Hoare triples are in pseudo code, e.g., `{ Precondition } Operation { Postcondition }`.
///    - `old(P)` in `{ Postcondition }` refers to condition `P` evaluated in `{ Precondition }`.
///    - `snake_case` is used to refer to values and structures.
///    - `CamelCase` is used to refer to operations.
///    - `Operation.is_enabled()` refers to the possibility of calling `Operation` in this state.
///
/// 3.1. State machine:
/// 3.1.1. `{ governance::Mode::PreInitializationSwap } FinalizeUnSuccessfully { governance::Mode::PreInitializationSwap }`
/// 3.1.2. `{ governance::Mode::PreInitializationSwap } FinalizeSuccessfully   { governance::Mode::Normal }`
///
/// 3.2. Availability of SNS operations in different states:
/// 3.2.1. `{ !ManageNervousSystemParameters.is_enabled() } FinalizeUnSuccessfully { !ManageNervousSystemParameters.is_enabled() }`
/// 3.2.2. `{ !ManageNervousSystemParameters.is_enabled() } FinalizeSuccessfully   {  ManageNervousSystemParameters.is_enabled() }`
/// 3.2.3. `{ !DissolveSnsNeuron.is_enabled() } FinalizeUnSuccessfully { !DissolveSnsNeuron.is_enabled() }`
/// 3.2.4. `{ !DissolveSnsNeuron.is_enabled() } FinalizeSuccessfully   {  DissolveSnsNeuron.is_enabled() }`
/// 3.2.5. `{ RefreshBuyerTokens.is_enabled() } Finalize { !RefreshBuyerTokens.is_enabled() }`
///
/// 3.3. ICP refunding mechanism and ICP balances:
/// 3.3.1. `{ true } FinalizeUnSuccessfully; Swap.error_refund_icp() { All directly participated ICP (minus the fees) are refunded. }`
/// 3.3.2. `{ true } FinalizeSuccessfully;   Swap.error_refund_icp() { Excess directly participated ICP (minus the fees) are refunded. }`
///
/// 4. The Neurons' Fund works as expected:
/// 4.1.1. `{  neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeUnSuccessfully { direct_participation_icp_e8s==0            && neurons_fund_participation_icp_e8s==0 }`
/// 4.1.2. `{  neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeSuccessfully   { direct_participation_icp_e8s==650_000 * E8 && neurons_fund_participation_icp_e8s==150_000 * E8 }`
/// 4.1.3. `{ !neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeUnSuccessfully { direct_participation_icp_e8s==0            && neurons_fund_participation_icp_e8s==0 }`
/// 4.1.4. `{ !neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeSuccessfully   { direct_participation_icp_e8s==650_000 * E8 && neurons_fund_participation_icp_e8s==0 }`
/// 4.2. Unused portions of Neurons' Fund maturity reserved at SNS creation time are refunded.
///
/// 5. Control over the dapp:
/// 5.1. `{ dapp_canister_status.controllers() == vec![developer] } FinalizeUnSuccessfully { dapp_canister_status.controllers() == vec![developer] }`
/// 5.2. `{ dapp_canister_status.controllers() == vec![developer] } FinalizeSuccessfully   { dapp_canister_status.controllers() == vec![sns_governance] }`
///
/// 6. SNS neuron creation:
/// 6.1. `{ true } FinalizeUnSuccessfully { No additional SNS neurons are created. }`
/// 6.2. `{ true } FinalizeSuccessfully   { New SNS neurons are created as expected. }`
///
/// 7. SNS token balances:
/// 7.1. `{ true } FinalizeUnSuccessfully { sns_token_balances == old(sns_token_balances) }`
/// 7.2. `{ true } FinalizeSuccessfully   { SNS token balances are as expected. }`
fn test_sns_lifecycle(
    ensure_swap_timeout_is_reached: bool,
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
    direct_participant_principal_ids: Vec<PrincipalId>,
) {
    // 0. Deconstruct and clone some immutable objects for convenience.
    let initial_token_distribution = create_service_nervous_system_proposal
        .initial_token_distribution
        .clone()
        .unwrap();
    let developer_neurons = initial_token_distribution
        .developer_distribution
        .as_ref()
        .unwrap()
        .developer_neurons
        .clone();
    let developer_neuron_controller_principal_ids: BTreeSet<_> = developer_neurons
        .iter()
        .map(|x| x.controller.unwrap())
        .collect();
    let swap_parameters = create_service_nervous_system_proposal
        .swap_parameters
        .clone()
        .unwrap();
    let (developer_neuron_stake_sns_e8s, treasury_distribution_sns_e8s, swap_distribution_sns_e8s) = {
        let treasury_distribution_sns_e8s = initial_token_distribution
            .treasury_distribution
            .unwrap()
            .total
            .unwrap()
            .e8s
            .unwrap();
        let swap_distribution_sns_e8s = initial_token_distribution
            .swap_distribution
            .unwrap()
            .total
            .unwrap()
            .e8s
            .unwrap();
        (
            developer_neurons
                .iter()
                .fold(0_u64, |acc, x| acc + x.stake.unwrap().e8s.unwrap()),
            treasury_distribution_sns_e8s,
            swap_distribution_sns_e8s,
        )
    };
    let transaction_fee_sns_e8s = create_service_nervous_system_proposal
        .ledger_parameters
        .as_ref()
        .unwrap()
        .transaction_fee
        .unwrap()
        .e8s
        .unwrap();

    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let participation_amount_per_direct_participant_icp =
        Tokens::from_e8s((1_000_000 * E8) / (direct_participant_principal_ids.len() as u64));

    let direct_participants: BTreeMap<PrincipalId, _> = direct_participant_principal_ids
        .iter()
        .map(|direct_participant| {
            (
                *direct_participant,
                (
                    AccountIdentifier::new(*direct_participant, None),
                    participation_amount_per_direct_participant_icp,
                ),
            )
        })
        .collect();
    let nns_neuron_controller_principal_ids =
        install_nns_canisters(&pocket_ic, direct_participants.values().cloned().collect());
    let original_nns_neurons_per_controller: BTreeMap<PrincipalId, Vec<u64>> =
        nns_neuron_controller_principal_ids
            .into_iter()
            .map(|controller_principal_id| {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                (
                    controller_principal_id,
                    response
                        .full_neurons
                        .iter()
                        .map(|neuron| neuron.maturity_e8s_equivalent)
                        .collect(),
                )
            })
            .collect();

    // Install the test dapp.
    let dapp_canister_ids: Vec<_> = create_service_nervous_system_proposal
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();
    for dapp_canister_id in dapp_canister_ids.clone() {
        install_canister(
            &pocket_ic,
            "My Test Dapp",
            dapp_canister_id,
            vec![],
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM),
        );
    }

    // Check who has control over the dapp before the swap.
    for dapp_canister_id in dapp_canister_ids.clone() {
        let controllers: BTreeSet<_> = canister_status(&pocket_ic, dapp_canister_id)
            .controllers()
            .into_iter()
            .collect();
        assert_eq!(controllers, developer_neuron_controller_principal_ids);
    }

    // 2. Create an SNS instance
    let proposal_info = propose_and_wait(
        &pocket_ic,
        Proposal {
            title: Some(format!("Create SNS #{}", 1)),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::CreateServiceNervousSystem(
                create_service_nervous_system_proposal,
            )),
        },
    )
    .unwrap();
    let proposal_id = proposal_info.id.unwrap();

    let Some(GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns)) =
        get_deployed_sns_by_proposal_id(&pocket_ic, proposal_id)
            .get_deployed_sns_by_proposal_id_result
    else {
        panic!(
            "Proposal {:?} did not result in a successfully deployed SNS",
            proposal_id
        );
    };

    // The proposal created a Swap and SNS Governance canisters that we can now start
    // interacting with.
    let sns_governance_canister_id = deployed_sns.governance_canister_id.unwrap();
    let swap_canister_id = deployed_sns.swap_canister_id.unwrap();
    let sns_ledger_canister_id = deployed_sns.ledger_canister_id.unwrap();

    // Check that total SNS Ledger supply adds up.
    let original_total_supply_sns_e8s =
        sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
            .0
            .to_u64()
            .unwrap();
    assert_eq!(
        original_total_supply_sns_e8s,
        developer_neuron_stake_sns_e8s + treasury_distribution_sns_e8s + swap_distribution_sns_e8s,
        "original_total_supply_sns_e8s ({}) should = developer_neuron_stake_sns_e8s ({}) + \
        treasury_distribution_sns_e8s ({}) + swap_distribution_sns_e8s ({})",
        original_total_supply_sns_e8s,
        developer_neuron_stake_sns_e8s,
        treasury_distribution_sns_e8s,
        swap_distribution_sns_e8s,
    );

    // Assert that the mode of SNS Governance is `PreInitializationSwap`.
    assert_eq!(
        sns::governance::get_mode(&pocket_ic, sns_governance_canister_id)
            .mode
            .unwrap(),
        sns_pb::governance::Mode::PreInitializationSwap as i32
    );

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this neuron
    // either holds the majority of the voting power or the follow graph is set up s.t. when this
    // neuron submits a proposal, that proposal gets through without the need for any voting.
    let (sns_neuron_id, sns_neuron_principal_id) =
        sns::governance::find_neuron_with_majority_voting_power(
            &pocket_ic,
            sns_governance_canister_id,
        )
        .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    // Currently, we are not allowed to make `ManageNervousSystemParameter` proposals.
    {
        let err = sns::governance::propose_and_wait(
            &pocket_ic,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_pb::Proposal {
                title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                        in PreInitializationSwap mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(sns_pb::proposal::Action::ManageNervousSystemParameters(
                    sns_pb::NervousSystemParameters {
                        reject_cost_e8s: Some(20_000), // More strongly discourage spam
                        ..Default::default()
                    },
                )),
            },
        )
        .unwrap_err();
        let sns_pb::GovernanceError {
            error_type,
            error_message,
        } = &err;
        use sns_pb::governance_error::ErrorType;
        assert_eq!(
            ErrorType::try_from(*error_type).unwrap(),
            ErrorType::PreconditionFailed,
            "{:#?}",
            err
        );
        assert!(
            error_message.contains("PreInitializationSwap"),
            "{:#?}",
            err
        );
    }

    // Currently, the neuron cannot start dissolving (an error is expected).
    {
        let start_dissolving_response = sns::governance::start_dissolving_neuron(
            &pocket_ic,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
        );
        match start_dissolving_response.command {
            Some(sns_pb::manage_neuron_response::Command::Error(error)) => {
                let sns_pb::GovernanceError {
                    error_type,
                    error_message,
                } = &error;
                use sns_pb::governance_error::ErrorType;
                assert_eq!(
                    ErrorType::try_from(*error_type).unwrap(),
                    ErrorType::PreconditionFailed,
                    "{:#?}",
                    error
                );
                assert!(
                    error_message.contains("PreInitializationSwap"),
                    "{:#?}",
                    error
                );
            }
            response => {
                panic!("{:#?}", response);
            }
        };
    }

    await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Open).unwrap();
    let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
    assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
    assert_eq!(derived_state.neurons_fund_participation_icp_e8s.unwrap(), 0);

    // 3. Transfer ICP to our direct participants' SNSes subaccounts.
    for (
        direct_participant,
        (direct_participant_icp_account, direct_participant_icp_account_initial_balance_icp),
    ) in direct_participants.clone()
    {
        let direct_participant_swap_subaccount = Some(principal_to_subaccount(&direct_participant));
        let direct_participant_swap_account = Account {
            owner: swap_canister_id.0,
            subaccount: direct_participant_swap_subaccount,
        };
        // Participate with as much as we have minus the transfer fee
        assert_eq!(
            account_balance(&pocket_ic, &direct_participant_icp_account),
            direct_participant_icp_account_initial_balance_icp,
        );
        let attempted_participation_amount_e8s = direct_participant_icp_account_initial_balance_icp
            .get_e8s()
            - DEFAULT_TRANSFER_FEE.get_e8s();
        icrc1_transfer(
            &pocket_ic,
            direct_participant,
            TransferArg {
                from_subaccount: None,
                to: direct_participant_swap_account,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(attempted_participation_amount_e8s),
            },
        )
        .unwrap();
        // Ensure there are no tokens left on this user's account (this slightly simplifies the checks).
        assert_eq!(
            account_balance(&pocket_ic, &direct_participant_icp_account),
            Tokens::from_e8s(0)
        );
    }

    // 4. Force the swap to reach either Aborted, or Committed.
    if ensure_swap_timeout_is_reached {
        // Await the end of the swap period.
        pocket_ic.advance_time(Duration::from_secs(30 * SECONDS_PER_DAY)); // 30 days
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Aborted).unwrap();
    } else {
        for (direct_participant, (_, direct_participant_icp_account_initial_balance_icp)) in
            direct_participants.clone()
        {
            let attempted_participation_amount_e8s =
                direct_participant_icp_account_initial_balance_icp.get_e8s()
                    - DEFAULT_TRANSFER_FEE.get_e8s();
            let accepted_participation_amount_e8s = attempted_participation_amount_e8s.min(
                swap_parameters
                    .maximum_direct_participation_icp
                    .unwrap()
                    .e8s
                    .unwrap(),
            );
            assert_eq!(
                refresh_buyer_tokens(&pocket_ic, swap_canister_id, direct_participant, None),
                Ok(RefreshBuyerTokensResponse {
                    icp_accepted_participation_e8s: accepted_participation_amount_e8s,
                    icp_ledger_account_balance_e8s: attempted_participation_amount_e8s,
                })
            );
        }
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Committed).unwrap();
    };

    // 5. Double check that auto-finalization worked as expected, i.e.,
    // `Swap.get_auto_finalization_status` returns a structure with the top-level fields being set,
    // no errors, and matching the expected pattern (different for `Aborted` and `Committed`).
    // It may take some time for the process to complete, so we should await (implemented via a busy
    // loop) rather than try just once.
    let expected_swap_finalization_status = if ensure_swap_timeout_is_reached {
        SwapFinalizationStatus::Aborted
    } else {
        SwapFinalizationStatus::Committed
    };
    if let Err(err) = await_swap_finalization_status(
        &pocket_ic,
        swap_canister_id,
        expected_swap_finalization_status,
    ) {
        println!("{}", err);
        panic!(
            "Awaiting Swap finalization status {:?} failed.",
            expected_swap_finalization_status
        );
    }

    // Participation is no longer possible due to Swap being in a terminal state.
    for (direct_participant, _) in direct_participants.clone() {
        let err = assert_matches!(refresh_buyer_tokens(&pocket_ic, swap_canister_id, direct_participant, None), Err(err) => err);
        assert!(err.contains("Participation is possible only when the Swap is in the OPEN state."));
    }

    // 6. Check that refunding works as expected.
    for (
        direct_participant,
        (direct_participant_icp_account, direct_participant_icp_account_initial_balance_icp),
    ) in direct_participants
    {
        let attempted_participation_amount_e8s = direct_participant_icp_account_initial_balance_icp
            .get_e8s()
            - DEFAULT_TRANSFER_FEE.get_e8s();
        let accepted_participation_amount_e8s = attempted_participation_amount_e8s.min(
            swap_parameters
                .maximum_direct_participation_icp
                .unwrap()
                .e8s
                .unwrap(),
        );
        let expected_refund_e8s = if ensure_swap_timeout_is_reached {
            // Expecting to get refunded with Transferred - (ICP Ledger transfer fee).
            attempted_participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s()
        } else {
            // Expecting to get refunded with Transferred - Accepted - (ICP Ledger transfer fee).
            attempted_participation_amount_e8s
                - accepted_participation_amount_e8s
                - DEFAULT_TRANSFER_FEE.get_e8s()
        };

        let result = error_refund_icp(&pocket_ic, swap_canister_id, direct_participant)
            .result
            .expect("Error while calling Swap.error_refund_icp");
        if let ic_sns_swap::pb::v1::error_refund_icp_response::Result::Err(err) = result {
            panic!("{:?}", err);
        };

        // This assertion assumes works because we have consumed all of the tokens from this user's
        // account up to the last e8.
        assert_eq!(
            account_balance(&pocket_ic, &direct_participant_icp_account),
            Tokens::from_e8s(expected_refund_e8s)
        );
    }

    // Inspect the final derived state
    let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
    if ensure_swap_timeout_is_reached {
        assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
    } else {
        assert_eq!(
            derived_state.direct_participation_icp_e8s.unwrap(),
            650_000 * E8
        );
    }

    // Assert that the mode of SNS Governance is correct
    if ensure_swap_timeout_is_reached {
        assert_eq!(
            sns::governance::get_mode(&pocket_ic, sns_governance_canister_id)
                .mode
                .unwrap(),
            sns_pb::governance::Mode::PreInitializationSwap as i32,
        );
    } else {
        assert_eq!(
            sns::governance::get_mode(&pocket_ic, sns_governance_canister_id)
                .mode
                .unwrap(),
            sns_pb::governance::Mode::Normal as i32
        );
    }

    // Ensure that the proposal submission is possible if and only if the SNS governance has
    // launched, and that `PreInitializationSwap` mode limitations are still in place if and only
    // if the swap aborted.
    {
        let proposal_result = sns::governance::propose_and_wait(
            &pocket_ic,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_pb::Proposal {
                title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                        in PreInitializationSwap mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(sns_pb::proposal::Action::ManageNervousSystemParameters(
                    sns_pb::NervousSystemParameters {
                        reject_cost_e8s: Some(20_000), // More strongly discourage spam
                        ..Default::default()
                    },
                )),
            },
        );
        if ensure_swap_timeout_is_reached {
            let err = proposal_result.unwrap_err();
            let sns_pb::GovernanceError {
                error_type,
                error_message,
            } = &err;
            use sns_pb::governance_error::ErrorType;
            assert_eq!(
                ErrorType::try_from(*error_type).unwrap(),
                ErrorType::PreconditionFailed,
                "{:#?}",
                err
            );
            assert!(
                error_message.contains("PreInitializationSwap"),
                "{:#?}",
                err
            );
        } else {
            assert_is_ok!(proposal_result);
        }
    }

    // Ensure that the neuron can start dissolving now if and only if the SNS governance has
    // launched.
    {
        let start_dissolving_response = sns::governance::start_dissolving_neuron(
            &pocket_ic,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id,
        );
        if ensure_swap_timeout_is_reached {
            match start_dissolving_response.command {
                Some(sns_pb::manage_neuron_response::Command::Error(error)) => {
                    let sns_pb::GovernanceError {
                        error_type,
                        error_message,
                    } = &error;
                    use sns_pb::governance_error::ErrorType;
                    assert_eq!(
                        ErrorType::try_from(*error_type).unwrap(),
                        ErrorType::PreconditionFailed,
                        "{:#?}",
                        error
                    );
                    assert!(
                        error_message.contains("PreInitializationSwap"),
                        "{:#?}",
                        error
                    );
                }
                response => {
                    panic!("{:#?}", response);
                }
            };
        } else {
            match start_dissolving_response.command {
                Some(sns_pb::manage_neuron_response::Command::Configure(_)) => (),
                _ => panic!("{:#?}", start_dissolving_response),
            };
        }
    }

    // Inspect SNS token balances.
    // A. Inspect the SNS Governance (treasury) balance.
    {
        let sns_governance_canister_balance_sns_e8s = {
            let treasury_subaccount = compute_distribution_subaccount_bytes(
                sns_governance_canister_id,
                TREASURY_SUBACCOUNT_NONCE,
            );
            let sns_treasury_account = Account {
                owner: sns_governance_canister_id.0,
                subaccount: Some(treasury_subaccount),
            };
            sns::ledger::icrc1_balance_of(&pocket_ic, sns_ledger_canister_id, sns_treasury_account)
                .0
                .to_u64()
                .unwrap()
        };
        assert_eq!(
            sns_governance_canister_balance_sns_e8s,
            treasury_distribution_sns_e8s
        );
    }

    // B. Inspect Swap's balance.
    {
        let swap_canister_balance_sns_e8s = sns::ledger::icrc1_balance_of(
            &pocket_ic,
            sns_ledger_canister_id,
            Account {
                owner: swap_canister_id.0,
                subaccount: None,
            },
        )
        .0
        .to_u64()
        .unwrap();
        if ensure_swap_timeout_is_reached {
            // If the swap fails, the SNS swap does not distribute any tokens.
            assert_eq!(swap_canister_balance_sns_e8s, swap_distribution_sns_e8s);
        } else {
            // In a happy scenario, the SNS swap distributes all the tokens.
            assert_eq!(swap_canister_balance_sns_e8s, 0);
        }
    }

    // C. The total supply has decreased by `N * transaction_fee_sns_e8s`, where `N` is
    //    the number of transactions from the creation of this SNS.
    {
        let total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
                .0
                .to_u64()
                .unwrap();
        assert_eq!(
            (original_total_supply_sns_e8s - total_supply_sns_e8s) % transaction_fee_sns_e8s,
            0,
            "original_total_supply_sns_e8s ({}) - total_supply_sns_e8s ({}) should be a multiple \
            of transaction_fee_sns_e8s ({})",
            original_total_supply_sns_e8s,
            total_supply_sns_e8s,
            transaction_fee_sns_e8s,
        );
    }

    // Inspect SNS neurons. We perform these checks by comparing neuron controllers.
    {
        let expected_neuron_controller_principal_ids = {
            let neurons_fund_neuron_controller_principal_ids: BTreeSet<_> = if swap_parameters
                .neurons_fund_participation
                .unwrap_or_default()
            {
                let Some(get_neurons_fund_audit_info_response::Result::Ok(
                    get_neurons_fund_audit_info_response::Ok {
                        neurons_fund_audit_info: Some(neurons_fund_audit_info),
                    },
                )) = get_neurons_fund_audit_info(&pocket_ic, proposal_id).result
                else {
                    panic!(
                        "Proposal {:?} did not result in a successfully deployed SNS",
                        proposal_id
                    );
                };
                neurons_fund_audit_info
                    .final_neurons_fund_participation
                    .unwrap()
                    .neurons_fund_reserves
                    .unwrap()
                    .neurons_fund_neuron_portions
                    .iter()
                    .map(|neurons_fund_neuron_portion| {
                        neurons_fund_neuron_portion.hotkey_principal.unwrap()
                    })
                    .collect()
            } else {
                BTreeSet::new()
            };

            let mut expected_neuron_controller_principal_ids = BTreeSet::new();
            // Initial neurons are always expected to be present.
            expected_neuron_controller_principal_ids
                .extend(developer_neuron_controller_principal_ids.iter());

            if !ensure_swap_timeout_is_reached {
                // Direct and Neurons' Fund participants are only expected to get their SNS neurons
                // in case the swap succeeds.
                expected_neuron_controller_principal_ids.extend(direct_participant_principal_ids);

                // Note that we include SNS neuron hotkeys into the set of expected controllers. For
                // the Neuron's Fund participants, we could make a stricted check that would assert
                // that the NNS neurons' controllers are the hotkeys of the corresponding SNS
                // neurons, where a hotkey is represented by:
                // ```
                // NeuronPermission {
                //     principal: Some(NF_NNS_NEURON_CONTROLLER_PRINCIPAL),
                //     permission_type: [
                //         ManageVotingPermission, SubmitProposal, Vote
                //     ]
                // }
                // ```
                // while (full) controllers are represented by:
                // ```
                // NeuronPermission {
                //     principal: Some(NNS_GOVERNANCE),
                //     permission_type: [
                //         Unspecified, ConfigureDissolveState, ManagePrincipals, SubmitProposal, Vote, Disburse, Split, MergeMaturity, DisburseMaturity, StakeMaturity, ManageVotingPermission
                //     ]
                // }
                // ```
                expected_neuron_controller_principal_ids
                    .extend(neurons_fund_neuron_controller_principal_ids.iter());
                if swap_parameters
                    .neurons_fund_participation
                    .unwrap_or_default()
                {
                    // NNS Governance is the expected controller of SNS neurons created for
                    // the Neurons' Fund participants.
                    expected_neuron_controller_principal_ids.insert(GOVERNANCE_CANISTER_ID.get());
                }
            }
            expected_neuron_controller_principal_ids
        };
        let observed_neuron_controller_principal_ids =
            sns::governance::list_neurons(&pocket_ic, sns_governance_canister_id)
                .neurons
                .iter()
                .flat_map(|neuron| {
                    neuron
                        .permissions
                        .iter()
                        .map(|neuron_permission| neuron_permission.principal.unwrap())
                })
                .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_neuron_controller_principal_ids,
            expected_neuron_controller_principal_ids
        );
    }

    if swap_parameters
        .neurons_fund_participation
        .unwrap_or_default()
    {
        if ensure_swap_timeout_is_reached {
            assert_eq!(
                derived_state.neurons_fund_participation_icp_e8s.unwrap(),
                0,
                "Neurons' Fund participation should not be provided to an aborted SNS swap.",
            );
        } else {
            assert_eq!(
                derived_state.neurons_fund_participation_icp_e8s.unwrap(),
                150_000 * E8,
                "Neurons' Fund participation is expected to be at 10% of its total maturity.",
            );
        }
    } else {
        assert_eq!(
            derived_state.neurons_fund_participation_icp_e8s.unwrap(),
            0,
            "Neurons' Fund participation has not been requested, yet there is some.",
        );
    }

    // Check that the maturity of the Neurons' Fund neurons adds up.
    if swap_parameters
        .neurons_fund_participation
        .unwrap_or_default()
    {
        let Some(get_neurons_fund_audit_info_response::Result::Ok(
            get_neurons_fund_audit_info_response::Ok {
                neurons_fund_audit_info: Some(neurons_fund_audit_info),
            },
        )) = get_neurons_fund_audit_info(&pocket_ic, proposal_id).result
        else {
            panic!(
                "Proposal {:?} did not result in a successfully deployed SNS",
                proposal_id
            );
        };
        // Maps neuron IDs to maturity equivalent ICP e8s.
        let mut final_neurons_fund_participation: BTreeMap<PrincipalId, Vec<u64>> =
            neurons_fund_audit_info
                .final_neurons_fund_participation
                .unwrap()
                .neurons_fund_reserves
                .unwrap()
                .neurons_fund_neuron_portions
                .iter()
                .fold(
                    BTreeMap::new(),
                    |mut neuron_portions_per_controller, neuron_portion| {
                        let controller_principal_id = neuron_portion.hotkey_principal.unwrap();
                        let amount_icp_e8s = neuron_portion.amount_icp_e8s.unwrap();
                        neuron_portions_per_controller
                            .entry(controller_principal_id)
                            .and_modify(|neuron_portions| neuron_portions.push(amount_icp_e8s))
                            .or_insert(vec![amount_icp_e8s]);
                        neuron_portions_per_controller
                    },
                );
        for (controller_principal_id, mut original_neurons) in original_nns_neurons_per_controller {
            let mut current_neurons: Vec<u64> = {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                original_neurons.len(),
                current_neurons.len(),
                "Controller {} is expected to have {} neurons, but it actually has {}. \
                original_neurons = {:#?}, current_neurons = {:#?}",
                controller_principal_id,
                original_neurons.len(),
                current_neurons.len(),
                original_neurons,
                current_neurons,
            );

            let mut participated_neurons = final_neurons_fund_participation
                .remove(&controller_principal_id)
                .unwrap_or_default();

            // Reverse the order to process the largest neurons first.
            {
                original_neurons.sort_by(|a, b| b.cmp(a));
                current_neurons.sort_by(|a, b| b.cmp(a));
                // This collection will be popped, so the order does not need to be reversed.
                participated_neurons.sort();
            }

            for (original_maturity_icp_e8s, current_maturity_icp_e8s) in
                original_neurons.into_iter().zip(current_neurons.iter())
            {
                // If the neuron is not in `final_neurons_fund_participation`, it didn't participate.
                let participated_amount_icp_e8s = participated_neurons.pop().unwrap_or(0);
                assert_eq!(
                    current_maturity_icp_e8s + participated_amount_icp_e8s,
                    original_maturity_icp_e8s,
                    "current_maturity_icp_e8s ({}) + participated_amount_icp_e8s ({}) should equal original_maturity_icp_e8s ({})",
                    current_maturity_icp_e8s,
                    participated_amount_icp_e8s,
                    original_maturity_icp_e8s,
                );
            }
        }
        assert!(
            final_neurons_fund_participation.is_empty(),
            "Neurons' Fund participants must be a subset of initial NNS neurons"
        );
    } else {
        // Neuron's Fund maturity should be completely unchanged.
        for (controller_principal_id, original_neurons) in original_nns_neurons_per_controller {
            let current_neurons: Vec<u64> = {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                current_neurons, original_neurons,
                "Unexpected mismatch in maturity ICP equivalent for controller {}. \
                current_neurons={:?} e8s, original_neurons({:?}) e8s.",
                controller_principal_id, current_neurons, original_neurons,
            );
        }
    }

    // Check who has control over the dapp after the swap.
    for dapp_canister_id in dapp_canister_ids {
        let controllers: BTreeSet<_> = canister_status(&pocket_ic, dapp_canister_id)
            .controllers()
            .into_iter()
            .collect();
        if ensure_swap_timeout_is_reached {
            // The SNS swap has failed  ==>  control should be returned to the dapp developers.
            assert_eq!(controllers, developer_neuron_controller_principal_ids);
        } else {
            assert_eq!(controllers, BTreeSet::from([sns_governance_canister_id]));
        }
    }
}

#[test]
fn test_sns_lifecycle_happy_scenario_with_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        vec![PrincipalId::new_user_test_id(1)],
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_without_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        vec![PrincipalId::new_user_test_id(1)],
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_with_neurons_fund_participation_same_principal() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        // Direct participant has the same principal as the one controlling the Neurons' Fund neuron.
        vec![*TEST_NEURON_1_OWNER_PRINCIPAL],
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_with_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        vec![PrincipalId::new_user_test_id(1)],
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_without_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        vec![PrincipalId::new_user_test_id(1)],
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_with_lots_of_dev_neurons() {
    let num_neurons = MAX_DEVELOPER_DISTRIBUTION_COUNT as u64;
    let mut developer_neurons: Vec<_> = (0..num_neurons - 1)
        .map(|i| NeuronDistribution {
            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            memo: Some(i),
            // Set the dissolve delay to ~10 days, which is somewhat arbitrary. It needs to be less
            // than or equal to the maximum dissolve delay (as defined
            // in `CreateServiceNervousSystemBuilder::default()`), but high enough that it still has
            // some voting power.
            dissolve_delay: Some(DurationPb::from_secs(927391)),
            stake: Some(TokensPb::from_e8s(E8)),
            vesting_period: Some(DurationPb::from_secs(0)),
        })
        .collect();
    // One developer neuron needs to have the voting power majority for the underlying tests to
    // be able to get SNS proposals through without arranging any following or voting. The dissolve
    // delay of this neuron needs to be sufficient for voting (we set it to 7 months).
    developer_neurons.push(NeuronDistribution {
        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        memo: Some(num_neurons - 1),
        dissolve_delay: Some(DurationPb::from_secs(SECONDS_PER_DAY * 30 * 7)),
        // All other neurons together have `num_neurons - 1` e8s, so this one has the majority.
        stake: Some(TokensPb::from_e8s(num_neurons * E8)),
        vesting_period: Some(DurationPb::from_secs(0)),
    });

    let create_service_nervous_system_proposal = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(false)
        .initial_token_distribution_developer_neurons(developer_neurons)
        .initial_token_distribution_total(TokensPb::from_e8s((num_neurons * 2 - 1) * E8))
        .build();

    test_sns_lifecycle(
        true,
        create_service_nervous_system_proposal,
        vec![PrincipalId::new_user_test_id(1)],
    );
}
