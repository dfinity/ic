use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    self, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    manage_neuron, manage_neuron_response, proposal, ExecuteNnsFunction,
    GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse, ListNeurons,
    ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, NnsFunction, Proposal, ProposalInfo,
};
use ic_nns_test_utils::{
    common::{
        build_ledger_wasm, build_mainnet_sns_wasms_wasm, build_root_wasm, build_sns_wasms_wasm,
        build_test_governance_wasm, NnsInitPayloadsBuilder,
    },
    ids::TEST_NEURON_1_ID,
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_index_ng_sns_wasm,
        build_ledger_sns_wasm, build_mainnet_archive_sns_wasm, build_mainnet_index_sns_wasm,
        build_mainnet_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm,
    },
};
use ic_sns_governance::pb::v1::{self as sns_pb};
use ic_sns_swap::pb::v1::{
    ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest, FinalizeSwapResponse,
    GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
    GetBuyerStateResponse, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
    GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, Lifecycle,
    ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse, NewSaleTicketRequest,
    NewSaleTicketResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
};
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse,
    SnsCanisterType, SnsWasm,
};
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use maplit::btreemap;
use pocket_ic::{PocketIc, WasmResult};
use prost::Message;
use rust_decimal::prelude::ToPrimitive;
use std::{collections::BTreeMap, time::Duration};

pub const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

pub fn install_canister(
    pocket_ic: &PocketIc,
    name: &str,
    id: CanisterId,
    arg: Vec<u8>,
    wasm: Wasm,
    controller: Option<PrincipalId>,
) {
    let controller_principal = controller.map(|c| c.0);
    let canister_id = pocket_ic
        .create_canister_with_id(controller_principal, None, id.into())
        .unwrap();
    pocket_ic.install_canister(canister_id, wasm.bytes(), arg, controller_principal);
    pocket_ic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    let subnet_id = pocket_ic.get_subnet(canister_id).unwrap();
    println!(
        "Installed the {} canister ({}) onto {:?}",
        name, canister_id, subnet_id
    );
}

pub fn add_wasm_via_nns_proposal(
    pocket_ic: &PocketIc,
    wasm: SnsWasm,
) -> Result<ProposalInfo, String> {
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
    nns::governance::propose_and_wait(pocket_ic, proposal)
}

pub fn add_wasms_to_sns_wasm(
    pocket_ic: &PocketIc,
    with_mainnet_ledger_wasms: bool,
) -> Result<BTreeMap<SnsCanisterType, (ProposalInfo, SnsWasm)>, String> {
    let root_wasm = build_root_sns_wasm();
    let root_proposal_info = add_wasm_via_nns_proposal(pocket_ic, root_wasm.clone())?;

    let gov_wasm = build_governance_sns_wasm();
    let gov_proposal_info = add_wasm_via_nns_proposal(pocket_ic, gov_wasm.clone())?;

    let swap_wasm = build_swap_sns_wasm();
    let swap_proposal_info = add_wasm_via_nns_proposal(pocket_ic, swap_wasm.clone())?;

    let (index_wasm, ledger_wasm, archive_wasm) = if with_mainnet_ledger_wasms {
        (
            build_mainnet_index_sns_wasm(),
            build_mainnet_ledger_sns_wasm(),
            build_mainnet_archive_sns_wasm(),
        )
    } else {
        (
            build_index_ng_sns_wasm(),
            build_ledger_sns_wasm(),
            build_archive_sns_wasm(),
        )
    };

    let index_proposal_info = add_wasm_via_nns_proposal(pocket_ic, index_wasm.clone())?;
    let ledger_proposal_info = add_wasm_via_nns_proposal(pocket_ic, ledger_wasm.clone())?;
    let archive_proposal_info = add_wasm_via_nns_proposal(pocket_ic, archive_wasm.clone())?;
    Ok(btreemap! {
        SnsCanisterType::Swap => (swap_proposal_info, swap_wasm),
        SnsCanisterType::Root => (root_proposal_info, root_wasm),
        SnsCanisterType::Governance => (gov_proposal_info, gov_wasm),
        SnsCanisterType::Index => (index_proposal_info, index_wasm),
        SnsCanisterType::Ledger => (ledger_proposal_info, ledger_wasm),
        SnsCanisterType::Archive => (archive_proposal_info, archive_wasm),
    })
}

/// Installs the NNS canisters.
///
/// Arguments
/// 1. `initial_balances` is a `Vec` of `(test_user_icp_ledger_account,
///    test_user_icp_ledger_initial_balance)` pairs, representing some initial ICP balances.
/// 2. `with_mainnet_ledger_wasms` is a flag indicating whether the mainnet (or tip-of-this-branch)
///    WASM versions should be installed for the (Index, Ledger, Archive)  canisters.
/// 3. `with_mainnet_sns_wasm_wasm` is a flag indicating whether the mainnet (or tip-of-this-branch)
///     WASM versions should be installed for the SNS-W canister.
///
/// Returns
/// 1. A list of `controller_principal_id`s of pre-configured NNS neurons.
/// 2. The WASMs of SNS canisters added to SNS-W (built from the tip of this branch).
pub fn install_nns_canisters(
    pocket_ic: &PocketIc,
    initial_balances: Vec<(AccountIdentifier, Tokens)>,
    with_mainnet_sns_wasm_wasm: bool,
    with_mainnet_ledger_wasms: bool,
) -> (
    Vec<PrincipalId>,
    BTreeMap<SnsCanisterType, (ProposalInfo, SnsWasm)>,
) {
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
        Some(ROOT_CANISTER_ID.get()),
    );
    install_canister(
        pocket_ic,
        "NNS Root",
        ROOT_CANISTER_ID,
        Encode!(&nns_init_payload.root).unwrap(),
        build_root_wasm(),
        Some(LIFELINE_CANISTER_ID.get()),
    );
    install_canister(
        pocket_ic,
        "NNS Governance",
        GOVERNANCE_CANISTER_ID,
        nns_init_payload.governance.encode_to_vec(),
        build_test_governance_wasm(),
        Some(ROOT_CANISTER_ID.get()),
    );
    let sns_wasm_wasm = if with_mainnet_sns_wasm_wasm {
        build_mainnet_sns_wasms_wasm()
    } else {
        build_sns_wasms_wasm()
    };
    install_canister(
        pocket_ic,
        "NNS SNS-W",
        SNS_WASM_CANISTER_ID,
        Encode!(&nns_init_payload.sns_wasms).unwrap(),
        sns_wasm_wasm,
        Some(ROOT_CANISTER_ID.get()),
    );

    // Preserve the WASMs of SNS canisters to use them again in upgrade testsing.
    let sns_wasms = add_wasms_to_sns_wasm(pocket_ic, with_mainnet_ledger_wasms).unwrap();

    let nns_neurons = nns_init_payload
        .governance
        .neurons
        .values()
        .map(|neuron| neuron.controller.unwrap())
        .collect();

    (nns_neurons, sns_wasms)
}

pub mod nns {
    use super::*;

    pub mod governance {
        use super::*;

        pub fn list_neurons(pocket_ic: &PocketIc, sender: PrincipalId) -> ListNeuronsResponse {
            let result = pocket_ic
                .query_call(
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

        /// Manage an NNS neuron, e.g., to make an NNS Governance proposal.
        pub fn manage_neuron(
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

        pub fn propose_and_wait(
            pocket_ic: &PocketIc,
            proposal: Proposal,
        ) -> Result<ProposalInfo, String> {
            let neuron_id = NeuronId {
                id: TEST_NEURON_1_ID,
            };
            let command: manage_neuron::Command =
                manage_neuron::Command::MakeProposal(Box::new(proposal));
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

        pub fn nns_get_proposal_info(
            pocket_ic: &PocketIc,
            proposal_id: u64,
            sender: PrincipalId,
        ) -> ProposalInfo {
            let result = pocket_ic
                .query_call(
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

        pub fn nns_wait_for_proposal_execution(
            pocket_ic: &PocketIc,
            proposal_id: u64,
        ) -> Result<ProposalInfo, String> {
            // We create some blocks until the proposal has finished executing (`pocket_ic.tick()`).
            let mut last_proposal_info = None;
            for _attempt_count in 1..=100 {
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

        pub fn get_neurons_fund_audit_info(
            pocket_ic: &PocketIc,
            proposal_id: ProposalId,
        ) -> GetNeuronsFundAuditInfoResponse {
            let result = pocket_ic
                .query_call(
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
                WasmResult::Reject(s) => {
                    panic!("Call to get_neurons_fund_audit_info failed: {:#?}", s)
                }
            };
            Decode!(&result, GetNeuronsFundAuditInfoResponse).unwrap()
        }
    }

    pub mod ledger {
        use super::*;

        pub fn icrc1_transfer(
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

        pub fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
            let result = pocket_ic
                .query_call(
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
    }

    pub mod sns_wasm {
        use super::*;

        pub fn get_deployed_sns_by_proposal_id(
            pocket_ic: &PocketIc,
            proposal_id: ProposalId,
        ) -> GetDeployedSnsByProposalIdResponse {
            let result = pocket_ic
                .query_call(
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
                WasmResult::Reject(s) => {
                    panic!("Call to get_deployed_sns_by_proposal_id failed: {:#?}", s)
                }
            };
            Decode!(&result, GetDeployedSnsByProposalIdResponse).unwrap()
        }
    }
}

pub mod sns {
    use super::*;
    pub mod governance {
        use super::*;

        pub fn get_mode(pocket_ic: &PocketIc, canister_id: PrincipalId) -> sns_pb::GetModeResponse {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
            sender: PrincipalId,
            // subaccount: &[u8],
            neuron_id: sns_pb::NeuronId,
            command: sns_pb::manage_neuron::Command,
        ) -> sns_pb::ManageNeuronResponse {
            let sub_account = neuron_id.subaccount().unwrap();
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
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
            manage_neuron(pocket_ic, canister_id, sender, neuron_id, command)
        }

        pub fn propose_and_wait(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
            proposal: sns_pb::Proposal,
        ) -> Result<sns_pb::ProposalData, sns_pb::GovernanceError> {
            let response = manage_neuron(
                pocket_ic,
                canister_id,
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
            wait_for_proposal_execution(pocket_ic, canister_id, proposal_id)
        }

        /// This function assumes that the proposal submission succeeded (and panics otherwise).
        fn wait_for_proposal_execution(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
        ) -> Result<sns_pb::ProposalData, sns_pb::GovernanceError> {
            // We create some blocks until the proposal has finished executing (`pocket_ic.tick()`).
            let mut last_proposal_data = None;
            for _attempt_count in 1..=50 {
                pocket_ic.tick();
                let proposal = get_proposal(
                    pocket_ic,
                    canister_id,
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
            canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
            sender: PrincipalId,
        ) -> sns_pb::GetProposalResponse {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
        ) -> sns_pb::ListNeuronsResponse {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
        ) -> Option<(sns_pb::NeuronId, PrincipalId)> {
            let sns_neurons = list_neurons(pocket_ic, canister_id).neurons;
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
            canister_id: PrincipalId,
        ) -> sns_pb::NervousSystemParameters {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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

    pub mod index_ng {
        use candid::CandidType;
        use candid::Deserialize;
        use ic_icrc1_index_ng::GetBlocksResponse;
        use icrc_ledger_types::icrc1::transfer::BlockIndex;
        use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;

        use super::*;

        /// Copied from rs/rosetta-api/icrc1/index-ng/src/lib.rs
        #[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
        pub struct Status {
            pub num_blocks_synced: BlockIndex,
        }

        pub fn ledger_id(pocket_ic: &PocketIc, canister_id: PrincipalId) -> PrincipalId {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "ledger_id",
                    Encode!().unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to ledger_id failed: {:#?}", s),
            };
            Decode!(&result, PrincipalId).unwrap()
        }

        pub fn status(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Status {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "status",
                    Encode!().unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to status failed: {:#?}", s),
            };
            Decode!(&result, Status).unwrap()
        }

        pub fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> GetBlocksResponse
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetBlocksRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to get_blocks failed: {:#?}", s),
            };
            Decode!(&result, GetBlocksResponse).unwrap()
        }

        // Retrieves blocks from the Ledger and the Archives.
        pub fn get_all_blocks(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: u64,
            length: u64,
        ) -> GetBlocksResponse {
            let res = get_blocks(pocket_ic, canister_id, 0_u64, 0_u64);
            let length = length.min(res.chain_length);
            let mut blocks: Vec<_> = vec![];
            let mut curr_start = start;
            while length > blocks.len() as u64 {
                let new_blocks = get_blocks(
                    pocket_ic,
                    canister_id,
                    curr_start,
                    length - (curr_start - start),
                )
                .blocks;
                assert!(!new_blocks.is_empty());
                curr_start += new_blocks.len() as u64;
                blocks.extend(new_blocks);
            }
            GetBlocksResponse { blocks, ..res }
        }
    }

    pub mod ledger {
        use ic_sns_root::ArchiveInfo;
        use icrc_ledger_types::{
            icrc2::{
                allowance::{Allowance, AllowanceArgs},
                approve::{ApproveArgs, ApproveError},
                transfer_from::{TransferFromArgs, TransferFromError},
            },
            icrc3::blocks::{GetBlocksRequest, GetBlocksResponse},
        };

        use super::*;

        pub fn icrc1_total_supply(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Nat {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
            account: Account,
        ) -> Nat {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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

        pub fn icrc1_transfer(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            transfer_arg: TransferArg,
        ) -> Result<Nat, TransferError> {
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
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

        pub fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> GetBlocksResponse
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetBlocksRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to get_blocks failed: {:#?}", s),
            };
            Decode!(&result, GetBlocksResponse).unwrap()
        }

        // Retrieves blocks from the Ledger and the Archives.
        pub fn get_all_blocks(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: u64,
            length: u64,
        ) -> GetBlocksResponse {
            let res = get_blocks(pocket_ic, canister_id, start, length);
            let mut blocks = vec![];
            for archived in &res.archived_blocks {
                let archive_canister_id =
                    archived.callback.canister_id.as_ref().try_into().unwrap();
                // Archives paginate their results. We need to fetch all the blocks and
                // therefore we loop until all of them have been fetched.
                let mut curr_start = archived.start.clone();
                while curr_start < archived.length {
                    let block_range = archive::get_blocks(
                        pocket_ic,
                        archive_canister_id,
                        curr_start.clone(),
                        archived.length.clone() - (curr_start.clone() - archived.start.clone()),
                    );
                    assert!(!block_range.blocks.is_empty());
                    curr_start += block_range.blocks.len();
                    blocks.extend(block_range.blocks);
                }
            }
            blocks.extend(res.blocks);
            GetBlocksResponse { blocks, ..res }
        }

        pub fn archives(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Vec<ArchiveInfo> {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "archives",
                    Encode!().unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to archives failed: {:#?}", s),
            };
            Decode!(&result, Vec<ArchiveInfo>).unwrap()
        }

        pub fn icrc2_approve(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: ApproveArgs,
        ) -> Result<Nat, ApproveError> {
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_approve",
                    Encode!(&arg).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to icrc2_approve failed: {:#?}", s),
            };
            Decode!(&result, Result<Nat, ApproveError>).unwrap()
        }

        pub fn icrc2_allowance(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: AllowanceArgs,
        ) -> Allowance {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_allowance",
                    Encode!(&arg).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to icrc2_allowance failed: {:#?}", s),
            };
            Decode!(&result, Allowance).unwrap()
        }

        pub fn icrc2_transfer_from(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: TransferFromArgs,
        ) -> Result<Nat, TransferFromError> {
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_transfer_from",
                    Encode!(&arg).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to icrc2_transfer_from failed: {:#?}", s),
            };
            Decode!(&result, Result<Nat, TransferFromError>).unwrap()
        }
    }

    pub mod archive {
        use super::*;

        use icrc_ledger_types::icrc3::{blocks::BlockRange, transactions::GetTransactionsRequest};

        pub fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> BlockRange
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetTransactionsRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => panic!("Call to get_blocks failed: {:#?}", s),
            };
            Decode!(&result, BlockRange).unwrap()
        }
    }

    // Helper function that calls tick on env until either the index canister has synced all
    // the blocks up to the last one in the ledger or enough attempts passed and therefore it fails.
    pub fn wait_until_ledger_and_index_sync_is_completed(
        pocket_ic: &PocketIc,
        ledger_canister_id: PrincipalId,
        index_canister_id: PrincipalId,
    ) {
        const MAX_ATTEMPTS: u8 = 100; // No reason for this number.
        let mut num_blocks_synced = u64::MAX;
        let mut chain_length = u64::MAX;
        for _i in 0..MAX_ATTEMPTS {
            pocket_ic.advance_time(Duration::from_secs(10));
            pocket_ic.tick();
            num_blocks_synced = index_ng::status(pocket_ic, index_canister_id)
                .num_blocks_synced
                .0
                .to_u64()
                .unwrap();
            chain_length =
                ledger::get_blocks(pocket_ic, ledger_canister_id, 0_u64, 1_u64).chain_length;
            if num_blocks_synced == chain_length {
                return;
            }
        }
        panic!(
            "The index canister was unable to sync all the blocks with the ledger. Number of \
            blocks synced {} but the Ledger chain length is {}.\n",
            num_blocks_synced, chain_length,
        );
    }

    // Assert that the index canister contains the same blocks as the ledger.
    pub fn assert_ledger_index_parity(
        pocket_ic: &PocketIc,
        ledger_canister_id: PrincipalId,
        index_canister_id: PrincipalId,
    ) {
        use ic_icrc1::{blocks::generic_block_to_encoded_block, Block};
        use ic_icrc1_tokens_u64::U64;
        use ic_ledger_core::block::BlockType;
        use icrc_ledger_types::icrc::generic_value::Value;

        let ledger_blocks =
            ledger::get_all_blocks(pocket_ic, ledger_canister_id, 0, u64::MAX).blocks;
        let index_blocks =
            index_ng::get_all_blocks(pocket_ic, index_canister_id, 0, u64::MAX).blocks;
        assert_eq!(ledger_blocks.len(), index_blocks.len());

        fn convert_to_std_format(x: Value) -> Value {
            match x {
                Value::Int(x) => {
                    assert!(x >= 0, "cannot conver negative value {:?} to Nat64", x);
                    Value::Nat(x.0.to_biguint().unwrap().into())
                }
                Value::Nat64(x) => Value::Nat(x.into()),
                Value::Map(map) => Value::Map(
                    map.into_iter()
                        .map(|(key, value)| {
                            let value = convert_to_std_format(value);
                            (key, value)
                        })
                        .collect(),
                ),
                Value::Array(array) => {
                    Value::Array(array.into_iter().map(convert_to_std_format).collect())
                }
                _ => x,
            }
        }

        for idx in 0..ledger_blocks.len() {
            let generic_block_ledger = ledger_blocks[idx].clone();
            let generic_block_index = index_blocks[idx].clone();

            // TODO: Remove this conversion after the next ICRC1 Ledger upgrade.
            let generic_block_ledger = convert_to_std_format(generic_block_ledger);
            let generic_block_index = convert_to_std_format(generic_block_index);

            let encoded_block_ledger =
                generic_block_to_encoded_block(generic_block_ledger.clone()).unwrap();
            let encoded_block_index =
                generic_block_to_encoded_block(generic_block_index.clone()).unwrap();
            let block_ledger = Block::<U64>::decode(encoded_block_ledger.clone()).unwrap();
            let block_index = Block::<U64>::decode(encoded_block_index.clone()).unwrap();

            assert_eq!(
                generic_block_ledger, generic_block_index,
                "block_index: {}",
                idx
            );
            assert_eq!(generic_block_ledger, generic_block_index);
            assert_eq!(encoded_block_ledger, encoded_block_index);
            assert_eq!(block_ledger, block_index);
        }
    }

    pub mod swap {
        use super::*;

        pub fn get_init(pocket_ic: &PocketIc, canister_id: PrincipalId) -> GetInitResponse {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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
            canister_id: PrincipalId,
        ) -> ListSnsNeuronRecipesResponse {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
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

        pub fn new_sale_ticket(
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

        pub fn refresh_buyer_tokens(
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

        pub fn get_buyer_state(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            buyer: PrincipalId,
        ) -> Result<GetBuyerStateResponse, String> {
            let result = pocket_ic
                .query_call(
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

        pub fn error_refund_icp(
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

        pub fn get_derived_state(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetDerivedStateResponse {
            let result = pocket_ic
                .query_call(
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

        pub fn get_lifecycle(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetLifecycleResponse {
            let result = pocket_ic
                .query_call(
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

        pub fn await_swap_lifecycle(
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
        pub fn validate_auto_finalization_status(
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
        pub fn is_auto_finalization_status_committed_or_err(
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
        pub fn is_auto_finalization_status_aborted_or_err(
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

        pub fn finalize_swap(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> FinalizeSwapResponse {
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
                WasmResult::Reject(s) => panic!("Call to finalize_swap failed: {:#?}", s),
            };
            Decode!(&result, FinalizeSwapResponse).unwrap()
        }

        pub fn get_auto_finalization_status(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetAutoFinalizationStatusResponse {
            let result = pocket_ic
                .query_call(
                    swap_canister_id.into(),
                    Principal::anonymous(),
                    "get_auto_finalization_status",
                    Encode!(&GetAutoFinalizationStatusRequest {}).unwrap(),
                )
                .unwrap();
            let result = match result {
                WasmResult::Reply(result) => result,
                WasmResult::Reject(s) => {
                    panic!("Call to get_auto_finalization_status failed: {:#?}", s)
                }
            };
            Decode!(&result, GetAutoFinalizationStatusResponse).unwrap()
        }

        /// Subset of `Lifecycle` indicating terminal statuses.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum SwapFinalizationStatus {
            Aborted,
            Committed,
        }

        pub fn await_swap_finalization_status(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            status: SwapFinalizationStatus,
        ) -> Result<GetAutoFinalizationStatusResponse, String> {
            let mut last_auto_finalization_status = None;
            for _attempt_count in 1..=100 {
                pocket_ic.tick();
                let auto_finalization_status =
                    get_auto_finalization_status(pocket_ic, swap_canister_id);
                match status {
                    SwapFinalizationStatus::Aborted => {
                        if is_auto_finalization_status_aborted_or_err(&auto_finalization_status)? {
                            return Ok(auto_finalization_status);
                        }
                    }
                    SwapFinalizationStatus::Committed => {
                        if is_auto_finalization_status_committed_or_err(&auto_finalization_status)?
                        {
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
    }
}
