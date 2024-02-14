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
    get_neurons_fund_audit_info_response, manage_neuron, manage_neuron_response,
    neurons_fund_snapshot::NeuronsFundNeuronPortion, proposal, CreateServiceNervousSystem,
    ExecuteNnsFunction, GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse,
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Neuron, NnsFunction,
    Proposal, ProposalInfo,
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
        new_sale_ticket_response, set_dapp_controllers_call_result, set_mode_call_result,
        settle_neurons_fund_participation_result, BuyerState, ErrorRefundIcpRequest,
        ErrorRefundIcpResponse, FinalizeSwapRequest, FinalizeSwapResponse,
        GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
        GetBuyerStateResponse, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
        GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, Lifecycle,
        ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse, NewSaleTicketRequest,
        NewSaleTicketResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
        SetDappControllersCallResult, SetDappControllersResponse, SetModeCallResult,
        SettleNeuronsFundParticipationResult, SweepResult,
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
use maplit::btreemap;
use pocket_ic::{PocketIc, PocketIcBuilder, WasmResult};
use prost::Message;
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
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

        pub fn get_nervous_system_parameters(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> sns_pb::NervousSystemParameters {
            let result = pocket_ic
                .update_call(
                    sns_governance_canister_id.into(),
                    Principal::from(PrincipalId::new_anonymous()),
                    "get_nervous_system_parameters",
                    Encode!().unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(reply) => reply,
                WasmResult::Reject(reject) => {
                    panic!(
                        "get_nervous_system_parameters rejected by SNS governance: {:#?}",
                        reject
                    )
                }
            };
            Decode!(&result, sns_pb::NervousSystemParameters).unwrap()
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

    pub mod swap {
        use super::*;

        pub fn get_init(pocket_ic: &PocketIc, swap_canister_id: PrincipalId) -> GetInitResponse {
            let result = pocket_ic
                .update_call(
                    swap_canister_id.into(),
                    Principal::anonymous(),
                    "get_init",
                    Encode!(&GetInitRequest {}).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to new_sale_ticket failed: {:#?}", s),
            };
            Decode!(&result, GetInitResponse).unwrap()
        }

        // TODO: Make this function traverse all pages.
        pub fn list_sns_neuron_recipes(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> ListSnsNeuronRecipesResponse {
            let result = pocket_ic
                .update_call(
                    swap_canister_id.into(),
                    Principal::anonymous(),
                    "list_sns_neuron_recipes",
                    Encode!(&ListSnsNeuronRecipesRequest {
                        limit: None,
                        offset: None,
                    })
                    .unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to new_sale_ticket failed: {:#?}", s),
            };
            Decode!(&result, ListSnsNeuronRecipesResponse).unwrap()
        }
    }
}

fn new_sale_ticket(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    buyer: PrincipalId,
    amount_icp_e8s: u64,
) -> Result<NewSaleTicketResponse, String> {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            buyer.into(),
            "new_sale_ticket",
            Encode!(&NewSaleTicketRequest {
                amount_icp_e8s,
                subaccount: None,
            })
            .unwrap(),
        )
        .map_err(|err| err.to_string())?;
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to new_sale_ticket failed: {:#?}", s),
    };
    Ok(Decode!(&result, NewSaleTicketResponse).unwrap())
}

fn get_buyer_state(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    buyer: PrincipalId,
) -> Result<GetBuyerStateResponse, String> {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_buyer_state",
            Encode!(&GetBuyerStateRequest {
                principal_id: Some(buyer)
            })
            .unwrap(),
        )
        .map_err(|err| err.to_string())?;
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_buyer_state failed: {:#?}", s),
    };
    Ok(Decode!(&result, GetBuyerStateResponse).unwrap())
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

fn finalize_swap(pocket_ic: &PocketIc, swap_canister_id: PrincipalId) -> FinalizeSwapResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "finalize_swap",
            Encode!(&FinalizeSwapRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_derived_state failed: {:#?}", s),
    };
    Decode!(&result, FinalizeSwapResponse).unwrap()
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
) -> Result<BTreeMap<SnsCanisterType, (ProposalInfo, SnsWasm)>, String> {
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

    Ok(btreemap! {
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

#[derive(Clone, Copy, Debug)]
struct DirectParticipantConfig {
    pub use_ticketing_system: bool,
}

/// This is a parametric test function for the testing the SNS lifecycle. A test instance should
/// end by calling this function, instantiating it with a set of parameter values that define
/// a particular testing scenario. If this function panics, the test fails. Otherwise, it succeeds.
///
/// The direct participants represented by `direct_participant_principal_ids` participate with
/// `maximum_direct_participation_icp / N` each, where `N==direct_participant_principal_ids.len()`.
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
    direct_participant_principal_ids: BTreeMap<PrincipalId, DirectParticipantConfig>,
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
    let max_direct_participation_icp_e8s = swap_parameters
        .maximum_direct_participation_icp
        .unwrap()
        .e8s
        .unwrap();
    let min_participant_icp_e8s = swap_parameters
        .minimum_participant_icp
        .unwrap()
        .e8s
        .unwrap();
    let max_participant_icp_e8s = swap_parameters
        .maximum_participant_icp
        .unwrap()
        .e8s
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

    let participation_amount_per_direct_participant_icp = Tokens::from_e8s(
        (max_direct_participation_icp_e8s / (direct_participant_principal_ids.len() as u64))
            + DEFAULT_TRANSFER_FEE.get_e8s(),
    );
    // Sanity check
    assert!(participation_amount_per_direct_participant_icp.get_e8s() >= min_participant_icp_e8s);

    let direct_participants: BTreeMap<PrincipalId, _> = direct_participant_principal_ids
        .iter()
        .map(|(direct_participant, direct_participant_config)| {
            (
                *direct_participant,
                (
                    AccountIdentifier::new(*direct_participant, None),
                    participation_amount_per_direct_participant_icp,
                    direct_participant_config,
                ),
            )
        })
        .collect();

    // Install the pre-configured NNS canisters, obtaining information about the original neuron(s).
    let original_nns_controller_to_neurons: BTreeMap<PrincipalId, Vec<Neuron>> = {
        let direct_participant_initial_icp_balances = direct_participants
            .values()
            .map(|(account_identifier, balance_icp, _)| (*account_identifier, *balance_icp))
            .collect();
        let nns_neuron_controller_principal_ids =
            install_nns_canisters(&pocket_ic, direct_participant_initial_icp_balances);
        nns_neuron_controller_principal_ids
            .into_iter()
            .map(|controller_principal_id| {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                (controller_principal_id, response.full_neurons)
            })
            .collect()
    };
    let original_nns_controller_to_maturities_e8s: BTreeMap<PrincipalId, Vec<u64>> =
        original_nns_controller_to_neurons
            .iter()
            .map(|(controller_principal_id, nns_neurons)| {
                (
                    *controller_principal_id,
                    nns_neurons
                        .iter()
                        .map(|nns_neuron| nns_neuron.maturity_e8s_equivalent)
                        .collect(),
                )
            })
            .collect();
    let nns_controller_to_neurons_fund_neurons: BTreeMap<PrincipalId, Vec<Neuron>> =
        original_nns_controller_to_neurons
            .iter()
            .filter_map(|(controller_principal_id, nns_neurons)| {
                let neurons_fund_nns_neurons: Vec<_> = nns_neurons
                    .iter()
                    .filter_map(|nns_neuron| {
                        if nns_neuron.joined_community_fund_timestamp_seconds.is_some() {
                            Some(nns_neuron.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                if neurons_fund_nns_neurons.is_empty() {
                    None
                } else {
                    Some((*controller_principal_id, neurons_fund_nns_neurons))
                }
            })
            .collect();
    let neurons_fund_nns_neurons: BTreeSet<_> = nns_controller_to_neurons_fund_neurons
        .values()
        .flat_map(|nns_neurons| {
            nns_neurons
                .iter()
                .map(|nns_neuron| (nns_neuron.id, nns_neuron.maturity_e8s_equivalent))
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

    let nervous_system_parameters =
        sns::governance::get_nervous_system_parameters(&pocket_ic, sns_governance_canister_id);
    let sns_neurons_per_backet = {
        let swap_init = sns::swap::get_init(&pocket_ic, swap_canister_id)
            .init
            .unwrap();
        swap_init
            .neuron_basket_construction_parameters
            .unwrap()
            .count
    };

    // This set is used to determine SNS neurons created as a result of the swap (by excluding those
    // which are in this collection).
    let original_sns_neuron_ids: BTreeSet<_> =
        sns::governance::list_neurons(&pocket_ic, sns_governance_canister_id)
            .neurons
            .into_iter()
            .map(|sns_neuron| sns_neuron.id.unwrap())
            .collect();

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

    // Check that the swap cannot be finalized yet.
    {
        let response = finalize_swap(&pocket_ic, swap_canister_id);
        let error_message = assert_matches!(response, FinalizeSwapResponse {
            error_message: Some(error_message),
            sweep_icp_result: None,
            sweep_sns_result: None,
            claim_neuron_result: None,
            set_mode_call_result: None,
            set_dapp_controllers_call_result: None,
            settle_community_fund_participation_result: None,
            create_sns_neuron_recipes_result: None,
            settle_neurons_fund_participation_result: None
        } => error_message);
        assert_eq!(
            error_message,
            "The Swap can only be finalized in the COMMITTED or ABORTED states. \
            Current state is Open",
        );
    }

    // Check that the derived state correctly reflects the pre-state of the swap.
    {
        let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
        assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
        assert_eq!(derived_state.neurons_fund_participation_icp_e8s.unwrap(), 0);
    }

    // 3. Transfer ICP to our direct participants' SNSes subaccounts.
    for (
        direct_participant,
        (
            direct_participant_icp_account,
            direct_participant_icp_account_initial_balance_icp,
            direct_participant_config,
        ),
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

        // The ticketing system is optional in the current implementation, so the participants are
        // free to choose if they use it or not.
        if direct_participant_config.use_ticketing_system {
            let expected_accepted_participation_amount_e8s =
                if attempted_participation_amount_e8s < min_participant_icp_e8s {
                    0
                } else {
                    attempted_participation_amount_e8s.min(max_participant_icp_e8s)
                };
            // Creating a ticket for this participation should succeed even before the ICP transfer.
            let response = new_sale_ticket(
                &pocket_ic,
                swap_canister_id,
                direct_participant,
                expected_accepted_participation_amount_e8s,
            )
            .expect("Swap.new_sale_ticket response should be Ok.");
            assert_matches!(
            response.result,
            Some(new_sale_ticket_response::Result::Ok(new_sale_ticket_response::Ok {
                ticket
            })) => {
                ticket.expect("field ticket must be specified in new_sale_ticket_response::Ok")
            });
        }
        // Make the actual ICP transfer
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

    // 4. Force the swap to reach either Aborted, or Committed. Collect the de facto participants.
    let direct_sns_neuron_recipients = if ensure_swap_timeout_is_reached {
        // Await the end of the swap period.
        pocket_ic.advance_time(Duration::from_secs(30 * SECONDS_PER_DAY)); // 30 days
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Aborted).unwrap();
        vec![]
    } else {
        let mut direct_sns_neuron_recipients = vec![];
        for (direct_participant, (_, direct_participant_icp_account_initial_balance_icp, _)) in
            direct_participants.clone()
        {
            let attempted_participation_amount_e8s =
                direct_participant_icp_account_initial_balance_icp.get_e8s()
                    - DEFAULT_TRANSFER_FEE.get_e8s();
            let expected_accepted_participation_amount_e8s =
                if attempted_participation_amount_e8s < min_participant_icp_e8s {
                    0
                } else {
                    attempted_participation_amount_e8s.min(max_participant_icp_e8s)
                };

            // Precondition: The buyer does not have a buyer state.
            {
                let response = get_buyer_state(&pocket_ic, swap_canister_id, direct_participant)
                    .expect("Swap.get_buyer_state response should be Ok.");
                assert_eq!(response.buyer_state, None);
            }

            // Execute the operation under test.
            let response =
                refresh_buyer_tokens(&pocket_ic, swap_canister_id, direct_participant, None);

            // Postcondition A: accepted amount matches our expectations.
            assert_eq!(
                response,
                Ok(RefreshBuyerTokensResponse {
                    icp_ledger_account_balance_e8s: attempted_participation_amount_e8s,
                    icp_accepted_participation_e8s: expected_accepted_participation_amount_e8s,
                })
            );

            // Postcondition B: The buyer has an expected buyer state.
            {
                let response = get_buyer_state(&pocket_ic, swap_canister_id, direct_participant)
                    .expect("Swap.get_buyer_state response should be Ok.");
                let (icp, has_created_neuron_recipes) = assert_matches!(
                    response.buyer_state,
                    Some(BuyerState {
                        icp,
                        has_created_neuron_recipes,
                    }) => (
                        icp.expect("buyer_state.icp must be specified."),
                        has_created_neuron_recipes
                            .expect("buyer_state.has_created_neuron_recipes must be specified.")
                    )
                );
                assert!(
                    !has_created_neuron_recipes,
                    "Neuron recipes are expected to be created only after the swap is adopted"
                );
                assert_eq!(icp.amount_e8s, expected_accepted_participation_amount_e8s);
            }

            direct_sns_neuron_recipients.push(direct_participant);
        }
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Committed).unwrap();
        direct_sns_neuron_recipients
    };

    // 5. Double check that auto-finalization worked as expected, i.e.,
    // `Swap.get_auto_finalization_status` returns a structure with the top-level fields being set,
    // no errors, and matching the expected pattern (different for `Aborted` and `Committed`).
    // It may take some time for the process to complete, so we should await (implemented via a busy
    // loop) rather than try just once.
    let swap_finalization_status = {
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
        expected_swap_finalization_status
    };

    // Participation is no longer possible due to Swap being in a terminal state.
    for direct_participant in direct_participants.keys() {
        let err = assert_matches!(
            refresh_buyer_tokens(&pocket_ic, swap_canister_id, *direct_participant, None),
            Err(err) => err
        );
        assert!(err.contains("Participation is possible only when the Swap is in the OPEN state."));
    }

    // 6. Check that refunding works as expected.
    for (
        direct_participant,
        (direct_participant_icp_account, direct_participant_icp_account_initial_balance_icp, _),
    ) in direct_participants.clone()
    {
        let attempted_participation_amount_e8s = direct_participant_icp_account_initial_balance_icp
            .get_e8s()
            - DEFAULT_TRANSFER_FEE.get_e8s();
        let accepted_participation_amount_e8s =
            if attempted_participation_amount_e8s < min_participant_icp_e8s {
                0
            } else {
                attempted_participation_amount_e8s.min(max_participant_icp_e8s)
            };

        let error_refund_icp_result =
            error_refund_icp(&pocket_ic, swap_canister_id, direct_participant)
                .result
                .expect("Error while calling Swap.error_refund_icp");

        use ic_sns_swap::pb::v1::error_refund_icp_response;
        let expected_refund_e8s = if swap_finalization_status == SwapFinalizationStatus::Aborted {
            // Case A: Expecting to get refunded with Transferred - (ICP Ledger transfer fee).
            assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Ok(_)
            );

            attempted_participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s()
        } else if accepted_participation_amount_e8s == 0
            || accepted_participation_amount_e8s == attempted_participation_amount_e8s
        {
            // Case B: (No tokens accepted) || (All tokens accepted)  ==>  nothing to refund.

            let error_text = assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Err(err) => {
                    err.description.expect("ICP Ledger errors should have a description.")
                }
            );
            assert!(error_text.contains(
                "the debit account doesn't have enough funds to complete the transaction"
            ));

            0
        } else {
            // Case C: Expecting to get refunded with Transferred - Accepted - (ICP Ledger transfer fee).
            assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Ok(_)
            );

            attempted_participation_amount_e8s
                - accepted_participation_amount_e8s
                - DEFAULT_TRANSFER_FEE.get_e8s()
        };

        // This assertion works because we have consumed all of the tokens from this user's
        // account up to the last e8.
        assert_eq!(
            account_balance(&pocket_ic, &direct_participant_icp_account),
            Tokens::from_e8s(expected_refund_e8s)
        );
    }

    // Inspect the finalize swap response after swap finalization. Note that `Swap.finalize_swap` is
    // idempotent only from the second call, e.g., success counters in sweep results are counted
    // towards skipped in the responses of the second (and all consecutive) calls.
    {
        let expected_neuron_count = if swap_finalization_status == SwapFinalizationStatus::Aborted {
            0
        } else {
            let swap_participating_nns_neuron_count = if swap_parameters
                .neurons_fund_participation
                .unwrap_or_default()
            {
                direct_participants.len() as u128 + neurons_fund_nns_neurons.len() as u128
            } else {
                direct_participants.len() as u128
            };
            (swap_participating_nns_neuron_count * sns_neurons_per_backet as u128) as u32
        };

        let expected_sweep_icp_result = Some(SweepResult {
            success: 0,
            failure: 0,
            skipped: if swap_finalization_status == SwapFinalizationStatus::Aborted {
                0
            } else {
                direct_participants.len() as u32
            },
            invalid: 0,
            global_failures: 0,
        });

        let expected_create_sns_neuron_recipes_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_sweep_sns_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_claim_neuron_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_set_mode_call_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SetModeCallResult {
                    possibility: Some(set_mode_call_result::Possibility::Ok(
                        set_mode_call_result::SetModeResult {},
                    )),
                })
            };

        let expected_settle_neurons_fund_participation_result = {
            let (neurons_fund_participation_icp_e8s, neurons_fund_neurons_count) =
                if swap_finalization_status == SwapFinalizationStatus::Committed
                    && swap_parameters
                        .neurons_fund_participation
                        .unwrap_or_default()
                {
                    (
                        Some(150_000 * E8),
                        Some(neurons_fund_nns_neurons.len() as u64),
                    )
                } else {
                    (Some(0), Some(0))
                };
            use settle_neurons_fund_participation_result::{Ok, Possibility};
            Some(SettleNeuronsFundParticipationResult {
                possibility: Some(Possibility::Ok(Ok {
                    neurons_fund_participation_icp_e8s,
                    neurons_fund_neurons_count,
                })),
            })
        };

        let expected_set_dapp_controllers_call_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                Some(SetDappControllersCallResult {
                    possibility: Some(set_dapp_controllers_call_result::Possibility::Ok(
                        SetDappControllersResponse {
                            failed_updates: vec![],
                        },
                    )),
                })
            } else {
                None
            };

        assert_eq!(
            finalize_swap(&pocket_ic, swap_canister_id),
            FinalizeSwapResponse {
                sweep_icp_result: expected_sweep_icp_result,
                create_sns_neuron_recipes_result: expected_create_sns_neuron_recipes_result,
                sweep_sns_result: expected_sweep_sns_result,
                claim_neuron_result: expected_claim_neuron_result,
                set_mode_call_result: expected_set_mode_call_result,
                settle_neurons_fund_participation_result:
                    expected_settle_neurons_fund_participation_result,

                settle_community_fund_participation_result: None, // deprecated field
                set_dapp_controllers_call_result: expected_set_dapp_controllers_call_result,
                error_message: None,
            }
        );
    }

    // Inspect the final derived state
    let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
    if swap_finalization_status == SwapFinalizationStatus::Aborted {
        assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
    } else {
        assert_eq!(
            derived_state.direct_participation_icp_e8s.unwrap(),
            650_000 * E8
        );
    }

    // Assert that the mode of SNS Governance is correct
    if swap_finalization_status == SwapFinalizationStatus::Aborted {
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
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
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
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
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
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
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

    let neurons_fund_neuron_controllers_to_neuron_portions: BTreeMap<
        PrincipalId,
        NeuronsFundNeuronPortion,
    > = if swap_parameters
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
            .into_iter()
            .map(|neurons_fund_neuron_portion| {
                (
                    neurons_fund_neuron_portion.hotkey_principal.unwrap(),
                    neurons_fund_neuron_portion,
                )
            })
            .collect()
    } else {
        btreemap! {}
    };

    // Inspect SNS neurons. We perform these checks by comparing neuron controllers.
    {
        let expected_neuron_controller_principal_ids = {
            let neurons_fund_neuron_controller_principal_ids: BTreeSet<_> =
                neurons_fund_neuron_controllers_to_neuron_portions
                    .values()
                    .map(|neurons_fund_neuron_portion| {
                        neurons_fund_neuron_portion.hotkey_principal.unwrap()
                    })
                    .collect();

            // The set of principal IDs of all neuron hotkeys and controllers of this SNS.
            let mut expected_neuron_controller_principal_ids = BTreeSet::new();
            // Initial neurons are always expected to be present.
            expected_neuron_controller_principal_ids
                .extend(developer_neuron_controller_principal_ids.iter());

            if swap_finalization_status == SwapFinalizationStatus::Committed {
                // Direct and Neurons' Fund participants are only expected to get their SNS neurons
                // in case the swap succeeds.
                expected_neuron_controller_principal_ids
                    .extend(direct_participant_principal_ids.keys());

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
        let sns_neurons =
            sns::governance::list_neurons(&pocket_ic, sns_governance_canister_id).neurons;
        // Validate that the set of SNS neuron hotkeys and controllers is expected.
        {
            let observed_neuron_controller_principal_ids = sns_neurons
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
        // Collect all SNS neurons except the initial ones that were not created as a result of
        // the SNS swap.
        let swap_sns_neurons: Vec<_> = sns_neurons
            .into_iter()
            .filter(|sns_neuron| !original_sns_neuron_ids.contains(sns_neuron.id.as_ref().unwrap()))
            .collect();
        // Check SNS neuron balances for direct swap participants.
        let total_participation_icp_e8s = {
            // We assume that all direct participations were fully accepted.
            let total_direct_participation_icp_e8s: u64 = direct_participants
                .values()
                .map(|(_, amount_icp, _)| amount_icp.get_e8s())
                .sum();
            let total_neurons_fund_participation_icp_e8s: u64 =
                neurons_fund_neuron_controllers_to_neuron_portions
                    .values()
                    .map(|neuron_portion| neuron_portion.amount_icp_e8s.unwrap())
                    .sum();
            total_direct_participation_icp_e8s + total_neurons_fund_participation_icp_e8s
        };
        let swap_participants = direct_sns_neuron_recipients
            .iter()
            .chain(neurons_fund_neuron_controllers_to_neuron_portions.keys());
        for principal_id in swap_participants {
            // Contains `(source_nns_neuron_id, neuron_basket)` for this controller. For direct
            // participants, `source_nns_neuron_id` is `None`. Some Neurons' Fund neurons,
            // `source_nns_neuron_id` is `Some`.
            let swap_neuron_baskets_of_this_principal: BTreeMap<Option<u64>, Vec<_>> =
                swap_sns_neurons
                    .iter()
                    .filter(|sns_neuron| {
                        sns_neuron.permissions.iter().any(|neuron_permission| {
                            neuron_permission.principal.unwrap() == *principal_id
                        })
                    })
                    .fold(BTreeMap::new(), |mut baskets, sns_neuron| {
                        let sns_neuron = sns_neuron.clone();
                        if let Some(basket) = baskets.get_mut(&sns_neuron.source_nns_neuron_id) {
                            basket.push(sns_neuron);
                        } else {
                            baskets.insert(sns_neuron.source_nns_neuron_id, vec![sns_neuron]);
                        }
                        baskets
                    });

            // Validate that the number of swap SNS neurons obtained by this participant falls into
            // some number of equally-sized neuron baskets.
            {
                let swap_neurons_of_this_principal: Vec<_> = swap_neuron_baskets_of_this_principal
                    .values()
                    .flatten()
                    .collect();
                assert_eq!(
                    swap_neurons_of_this_principal.len() as u64,
                    sns_neurons_per_backet * (swap_neuron_baskets_of_this_principal.len() as u64),
                    "sns_neurons_per_backet = {}, swap_neuron_baskets_of_this_principal.len() = {}",
                    sns_neurons_per_backet,
                    swap_neuron_baskets_of_this_principal.len(),
                );
            }

            // Validate each SNS neuron basket in isolation and sum up the swapped SNS token
            // amounts for direct and Neurons' Fund participants, resp.
            let mut actually_swapped_direct_sns_tokens_e8s = 0;
            let mut actually_swapped_neurons_fund_sns_tokens_e8s = 0;
            for (_, swap_neuron_basket) in swap_neuron_baskets_of_this_principal {
                let longest_dissolve_delay_sns_neuron_id = {
                    let now_seconds = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let longest_dissolve_delay_sns_neuron = swap_neuron_basket
                        .iter()
                        .max_by_key(|neuron| neuron.dissolve_delay_seconds(now_seconds))
                        .expect(
                            "Expected to have at least one swap SNS neuron for each participant.",
                        );
                    longest_dissolve_delay_sns_neuron.id.clone().unwrap()
                };

                // The purpose of this loop is to check individual neurons' fields.
                for sns_neuron in swap_neuron_basket {
                    let is_neuron_from_direct_participation =
                        sns_neuron.source_nns_neuron_id.is_none();

                    // Validate `auto_stake_maturity`:
                    {
                        let expected_auto_stake_maturity = if is_neuron_from_direct_participation {
                            None
                        } else {
                            Some(true)
                        };
                        assert_eq!(
                            sns_neuron.auto_stake_maturity, expected_auto_stake_maturity,
                            "{:#?}",
                            sns_neuron
                        );
                    }
                    // Validate `permissions`:
                    {
                        // TODO: derive `Ord` for `sns_pb::NeuronPermission` and use `BTreeSet`s.
                        fn sorted_permissions(
                            permissions: &[sns_pb::NeuronPermission],
                        ) -> Vec<sns_pb::NeuronPermission> {
                            let mut permissions = permissions.to_vec();
                            permissions
                                .sort_by(|x, y| y.principal.unwrap().cmp(&x.principal.unwrap()));
                            permissions
                        }
                        let claimer_permissions = nervous_system_parameters
                            .neuron_claimer_permissions
                            .as_ref()
                            .expect("Expected neuron_claimer_permissions to be set");
                        let expected_permissions = if is_neuron_from_direct_participation {
                            vec![sns_pb::NeuronPermission {
                                principal: Some(*principal_id),
                                permission_type: claimer_permissions.permissions.clone(),
                            }]
                        } else {
                            sorted_permissions(&[
                                sns_pb::NeuronPermission {
                                    principal: Some(*principal_id),
                                    permission_type: vec![
                                        sns_pb::NeuronPermissionType::ManageVotingPermission as i32,
                                        sns_pb::NeuronPermissionType::SubmitProposal as i32,
                                        sns_pb::NeuronPermissionType::Vote as i32,
                                    ],
                                },
                                sns_pb::NeuronPermission {
                                    principal: Some(GOVERNANCE_CANISTER_ID.get()),
                                    permission_type: claimer_permissions.permissions.clone(),
                                },
                            ])
                        };
                        assert_eq!(
                            sorted_permissions(&sns_neuron.permissions),
                            expected_permissions,
                            "{:#?}",
                            sns_neuron
                        );
                    }
                    // Validate the SNS neuron baskets' follow graph.
                    {
                        if sns_neuron.id.as_ref().unwrap() == &longest_dissolve_delay_sns_neuron_id
                        {
                            for followees in sns_neuron.followees.values() {
                                assert_eq!(followees.followees, vec![], "{:#?}", sns_neuron);
                            }
                        } else {
                            for followees in sns_neuron.followees.values() {
                                assert_eq!(
                                    followees.followees,
                                    vec![longest_dissolve_delay_sns_neuron_id.clone()],
                                    "{:#?}",
                                    sns_neuron,
                                );
                            }
                        }
                    }
                    // Miscellaneous checks:
                    assert_eq!(sns_neuron.maturity_e8s_equivalent, 0, "{:#?}", sns_neuron);
                    assert_eq!(sns_neuron.neuron_fees_e8s, 0, "{:#?}", sns_neuron);

                    // Finally, check that the SNS Ledger balances add up.
                    {
                        let subaccount = sns_neuron.id.as_ref().unwrap().subaccount().unwrap();
                        let observed_balance_e8s = sns::ledger::icrc1_balance_of(
                            &pocket_ic,
                            sns_ledger_canister_id,
                            Account {
                                owner: sns_governance_canister_id.0,
                                subaccount: Some(subaccount),
                            },
                        )
                        .0
                        .to_u64()
                        .unwrap();

                        // Check that the cached balance of the sns_neuron is equal to the sns_neuron's
                        // account in the ledger.
                        assert_eq!(sns_neuron.cached_neuron_stake_e8s, observed_balance_e8s);

                        // Add to the actual total including the default transfer fee which was deducted
                        // during swap committal.
                        if is_neuron_from_direct_participation {
                            actually_swapped_direct_sns_tokens_e8s +=
                                observed_balance_e8s + transaction_fee_sns_e8s;
                        } else {
                            actually_swapped_neurons_fund_sns_tokens_e8s +=
                                observed_balance_e8s + transaction_fee_sns_e8s;
                        }
                    }
                }
            }

            if direct_participants.get(principal_id).is_none()
                || swap_finalization_status == SwapFinalizationStatus::Aborted
            {
                assert_eq!(actually_swapped_direct_sns_tokens_e8s, 0);
            } else {
                let expected_sns_token_e8s = (participation_amount_per_direct_participant_icp
                    .get_e8s() as u128)
                    * (swap_distribution_sns_e8s as u128)
                    / (total_participation_icp_e8s as u128);
                assert_eq!(
                    actually_swapped_direct_sns_tokens_e8s,
                    expected_sns_token_e8s as u64
                );
            }

            if neurons_fund_neuron_controllers_to_neuron_portions.is_empty()
                || swap_finalization_status == SwapFinalizationStatus::Aborted
                || nns_controller_to_neurons_fund_neurons
                    .get(principal_id)
                    .is_none()
            {
                // ((The Neuron's Fund has not participated at all)
                //  || (This is not a Neuron's Fund participant)
                //  || (The swap has aborted))
                //     ==>  There should not be any Neurons' Fund-related SNS neurons.
                assert_eq!(actually_swapped_neurons_fund_sns_tokens_e8s, 0);
            } else {
                // This is the amount of ICP participated by all Neurons' Fund neurons that this
                // controller has.
                let participation_amount_for_this_nf_neuron_icp_e8s =
                    neurons_fund_neuron_controllers_to_neuron_portions
                        .get(principal_id)
                        .unwrap()
                        .amount_icp_e8s
                        .unwrap();
                // Use fixed point to keep the precision as much as possible. In particular, we
                // round to the nearest integer, rather than always rounding down. This is typically
                // enough to keep up with the precision of the computation done by the actual
                // Swap canister. However, the ideal solution would be to replicate the exact
                // calculation done by Swap. This would result in an e8-precise spec, rather than
                // an approximate spec that we have here right now.
                let expected_sns_token_e8s =
                    Decimal::from_u64(participation_amount_for_this_nf_neuron_icp_e8s).unwrap()
                        * Decimal::from_u64(swap_distribution_sns_e8s).unwrap()
                        / Decimal::from_u64(total_participation_icp_e8s).unwrap();
                let expected_sns_token_e8s =
                    Decimal::to_u64(&Decimal::round(&expected_sns_token_e8s)).unwrap();
                assert_eq!(
                    actually_swapped_neurons_fund_sns_tokens_e8s,
                    expected_sns_token_e8s
                );
            }
        }
    }

    // Inspect SNS neuron recipes. TODO: Eventually, this check could be replaced with a single call
    // to a function in the `rs/sns/audit` crate.
    {
        let sns_neuron_recipes =
            sns::swap::list_sns_neuron_recipes(&pocket_ic, swap_canister_id).sns_neuron_recipes;
        use ic_sns_swap::pb::v1::sns_neuron_recipe::Investor;
        {
            let direct_participant_sns_neuron_recipes: Vec<_> = sns_neuron_recipes
                .iter()
                .filter_map(|recipe| {
                    if let Some(Investor::Direct(ref investment)) = recipe.investor {
                        let buyer_principal = investment.buyer_principal.clone();
                        let amount_sns_e8s = recipe.sns.clone().unwrap().amount_e8s;
                        Some((buyer_principal, amount_sns_e8s))
                    } else {
                        None
                    }
                })
                .collect();

            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                assert_eq!(direct_participant_sns_neuron_recipes, vec![]);
            } else {
                assert_eq!(
                    direct_participant_sns_neuron_recipes.len() as u128,
                    (sns_neurons_per_backet as u128)
                        * (direct_participant_principal_ids.len() as u128)
                );
            }
        }
        {
            let neurons_fund_sns_neuron_recipes: Vec<_> = sns_neuron_recipes
                .iter()
                .filter_map(|recipe| {
                    if let Some(Investor::CommunityFund(ref investment)) = recipe.investor {
                        let hotkey_principal = investment.hotkey_principal.clone();
                        let amount_sns_e8s = recipe.sns.clone().unwrap().amount_e8s;
                        Some((hotkey_principal, amount_sns_e8s))
                    } else {
                        None
                    }
                })
                .collect();

            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                assert_eq!(neurons_fund_sns_neuron_recipes, vec![]);
            } else {
                assert_eq!(
                    neurons_fund_sns_neuron_recipes.len() as u128,
                    (sns_neurons_per_backet as u128)
                        * (neurons_fund_neuron_controllers_to_neuron_portions.len() as u128)
                );
            }
        }
    }

    if swap_parameters
        .neurons_fund_participation
        .unwrap_or_default()
    {
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
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
        for (controller_principal_id, mut original_nns_neuron_maturities_e8s) in
            original_nns_controller_to_maturities_e8s
        {
            let mut nns_neuron_maturities_e8s: Vec<u64> = {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                original_nns_neuron_maturities_e8s.len(),
                nns_neuron_maturities_e8s.len(),
                "Controller {} is expected to have {} neurons, but it actually has {}. \
                original_nns_neuron_maturities_e8s = {:#?}, nns_neuron_maturities_e8s = {:#?}",
                controller_principal_id,
                original_nns_neuron_maturities_e8s.len(),
                nns_neuron_maturities_e8s.len(),
                original_nns_neuron_maturities_e8s,
                nns_neuron_maturities_e8s,
            );

            let mut participated_neurons = final_neurons_fund_participation
                .remove(&controller_principal_id)
                .unwrap_or_default();

            // Reverse the order to process the largest neurons first.
            {
                original_nns_neuron_maturities_e8s.sort_by(|a, b| b.cmp(a));
                nns_neuron_maturities_e8s.sort_by(|a, b| b.cmp(a));
                // This collection will be popped, so the order does not need to be reversed.
                participated_neurons.sort();
            }

            for (original_maturity_icp_e8s, current_maturity_icp_e8s) in
                original_nns_neuron_maturities_e8s
                    .into_iter()
                    .zip(nns_neuron_maturities_e8s.iter())
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
        for (controller_principal_id, original_nns_neuron_maturities_e8s) in
            original_nns_controller_to_maturities_e8s
        {
            let nns_neuron_maturities_e8s: Vec<u64> = {
                let response = list_neurons(&pocket_ic, controller_principal_id);
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                nns_neuron_maturities_e8s,
                original_nns_neuron_maturities_e8s,
                "Unexpected mismatch in maturity ICP equivalent for controller {}. \
                nns_neuron_maturities_e8s={:?} e8s, original_nns_neuron_maturities_e8s({:?}) e8s.",
                controller_principal_id,
                nns_neuron_maturities_e8s,
                original_nns_neuron_maturities_e8s,
            );
        }
    }

    // Check who has control over the dapp after the swap.
    for dapp_canister_id in dapp_canister_ids {
        let controllers: BTreeSet<_> = canister_status(&pocket_ic, dapp_canister_id)
            .controllers()
            .into_iter()
            .collect();
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
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
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_direct_participation_with_and_without_ticketing_with_neurons_fund_participation(
) {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        btreemap! {
            PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true },
            PrincipalId::new_user_test_id(2) => DirectParticipantConfig { use_ticketing_system: false },
        },
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_without_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
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
        btreemap! { *TEST_NEURON_1_OWNER_PRINCIPAL => DirectParticipantConfig { use_ticketing_system: true } },
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_with_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_without_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
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
        .neurons_fund_participation(true)
        .initial_token_distribution_developer_neurons(developer_neurons)
        .initial_token_distribution_total(TokensPb::from_e8s((num_neurons * 2 - 1) * E8))
        .build();

    test_sns_lifecycle(
        false,
        create_service_nervous_system_proposal,
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_with_lots_of_dev_neurons() {
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
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
    );
}
