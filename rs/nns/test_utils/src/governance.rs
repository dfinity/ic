//! Utilities to submit proposals to the governance canister and to upgrade it
//! (in tests).
use crate::itest_helpers::{NnsCanisters, UpgradeTestingScenario};
use candid::{CandidType, Encode};
use canister_test::{Canister, Wasm};
use dfn_candid::{candid, candid_one};
use ic_btc_interface::SetConfigRequest;
use ic_canister_client_sender::Sender;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance_api::{
    bitcoin::{BitcoinNetwork, BitcoinSetConfigProposal},
    pb::v1::{
        add_or_remove_node_provider::Change, install_code::CanisterInstallMode,
        manage_neuron::NeuronIdOrSubaccount, manage_neuron_response::Command as CommandResponse,
        AddOrRemoveNodeProvider, ExecuteNnsFunction, GovernanceError, InstallCodeRequest,
        ListNodeProvidersResponse, MakeProposalRequest, ManageNeuronCommandRequest,
        ManageNeuronRequest, ManageNeuronResponse, NnsFunction, NodeProvider,
        ProposalActionRequest, ProposalInfo, ProposalStatus,
    },
};
pub use ic_nns_handler_lifeline_interface::{
    HardResetNnsRootToVersionPayload, UpgradeRootProposal,
};
use std::time::Duration;

/// Thin-wrapper around submit_proposal to handle
/// serialization/deserialization
pub async fn submit_proposal(
    governance_canister: &Canister<'_>,
    proposal: &MakeProposalRequest,
) -> ProposalId {
    governance_canister
        .update_("submit_proposal", candid_one, proposal)
        .await
        .unwrap()
}

/// Wraps the given nns_function_input into a proposal; sends it to the governance
/// canister; returns the proposal id or, in case of failure, a
/// `GovernanceError`.
pub async fn submit_external_update_proposal_allowing_error(
    governance_canister: &Canister<'_>,
    proposer: Sender,
    proposer_neuron_id: NeuronId,
    nns_function: NnsFunction,
    nns_function_input: impl CandidType,
    title: String,
    summary: String,
) -> Result<ProposalId, GovernanceError> {
    let proposal = MakeProposalRequest {
        title: Some(title),
        summary,
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: nns_function as i32,
                payload: Encode!(&nns_function_input).expect("Error encoding proposal payload"),
            },
        )),
    };

    let response: ManageNeuronResponse = governance_canister
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuronRequest {
                id: None,
                command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(proposal))),
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    proposer_neuron_id.into(),
                )),
            },
            &proposer,
        )
        .await
        .expect("Error calling the manage_neuron api.");
    match response.command.unwrap() {
        CommandResponse::MakeProposal(resp) => Ok(ProposalId::from(resp.proposal_id.unwrap())),
        CommandResponse::Error(err) => Err(err),
        other => panic!("Unexpected response: {:?}", other),
    }
}

/// Wraps the given nns_function_input into a proposal; sends it to the governance
/// canister; returns the proposal id.
pub async fn submit_external_update_proposal(
    governance_canister: &Canister<'_>,
    proposer: Sender,
    proposer_neuron_id: NeuronId,
    nns_function: NnsFunction,
    nns_function_input: impl CandidType,
    title: String,
    summary: String,
) -> ProposalId {
    let proposal = MakeProposalRequest {
        title: Some(title),
        summary,
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: nns_function as i32,
                payload: Encode!(&nns_function_input).expect("Error encoding proposal payload"),
            },
        )),
    };

    let response: ManageNeuronResponse = governance_canister
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuronRequest {
                id: None,
                command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(proposal))),
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    proposer_neuron_id.into(),
                )),
            },
            &proposer,
        )
        .await
        .expect("Error calling the manage_neuron api.");
    match response
        .panic_if_error("Error making proposal")
        .command
        .unwrap()
    {
        CommandResponse::MakeProposal(resp) => ProposalId::from(resp.proposal_id.unwrap()),
        other => panic!("Unexpected response: {:?}", other),
    }
}

/// Thin-wrapper around get_proposal_info to handle
/// serialization/deserialization
pub async fn get_proposal_info(
    governance_canister: &Canister<'_>,
    id: ProposalId,
) -> Option<ProposalInfo> {
    governance_canister
        .query_("get_proposal_info", candid_one, id)
        .await
        .unwrap()
}

/// Returns whether a proposal has been executed or failed.
pub async fn is_proposal_executed_or_failed(
    governance_canister: &Canister<'_>,
    id: ProposalId,
) -> bool {
    let pi: Option<ProposalInfo> = governance_canister
        .query_("get_proposal_info", candid, (id,))
        .await
        .unwrap();
    let pi = pi.expect("Proposal with id: {:?} not found.");
    println!("Proposal {:?} status: {:?}", id, pi.status());
    pi.status() == ProposalStatus::Executed
        || pi.status() == ProposalStatus::Failed
        || pi.status() == ProposalStatus::Rejected
}

/// Thin-wrapper around get_closed_proposals to handle
/// serialization/deserialization
pub async fn get_finalized_proposals(governance_canister: &Canister<'_>) -> Vec<ProposalInfo> {
    governance_canister
        .query_("get_finalized_proposals", candid, ())
        .await
        .unwrap()
}

/// Thin-wrapper around get_pending_proposals to handle
/// serialization/deserialization
pub async fn get_pending_proposals(governance_canister: &Canister<'_>) -> Vec<ProposalInfo> {
    governance_canister
        .query_("get_pending_proposals", candid, ())
        .await
        .unwrap()
}

/// Executes all eligible proposals.
pub async fn execute_eligible_proposals(governance_canister: &Canister<'_>) {
    governance_canister
        .update_("execute_eligible_proposals", candid, ())
        .await
        .unwrap()
}

// Wrapper around list_node_providers query to governance canister
pub async fn list_node_providers(governance_canister: &Canister<'_>) -> ListNodeProvidersResponse {
    governance_canister
        .query_("list_node_providers", candid_one, ())
        .await
        .expect("Response was expected from list_node_providers query to governance canister.")
}

/// Submit and execute a proposal to add the given node provider
pub async fn add_node_provider(nns_canisters: &NnsCanisters<'_>, np: NodeProvider) {
    let result: ManageNeuronResponse = nns_canisters
        .governance
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuronRequest {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId {
                        id: TEST_NEURON_1_ID,
                    },
                )),
                id: None,
                command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                    MakeProposalRequest {
                        title: Some("Add a Node Provider".to_string()),
                        summary: "".to_string(),
                        url: "".to_string(),
                        action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(
                            AddOrRemoveNodeProvider {
                                change: Some(Change::ToAdd(np)),
                            },
                        )),
                    },
                ))),
            },
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Error calling the manage_neuron api.");

    let pid = match result
        .panic_if_error("Error making proposal")
        .command
        .unwrap()
    {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
            .await
            .status(),
        ProposalStatus::Executed
    );
}

/// Polls on the state of the proposal until a final state is reached and
/// returns the reached final state.
///
/// Requires that the proposal has been submitted and it's deadline has
/// elapsed.
pub async fn wait_for_final_state(
    governance_canister: &Canister<'_>,
    id: ProposalId,
) -> ProposalInfo {
    let mut num_observed_accepted_state: usize = 0;
    while !is_proposal_executed_or_failed(governance_canister, id).await {
        // Without further instrumenting the IC, we can't guarantee that we will ever
        // see the `Accepted` state. So we just count how many times it happened for
        // information, without any assertion.
        num_observed_accepted_state += 1;
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "Non-final states were seen {} times for {}.",
        num_observed_accepted_state, id
    );
    // Return the final state
    get_proposal_info(governance_canister, id).await.unwrap()
}

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

/// Bumps the gzip timestamp of the provided gzipped Wasm.
/// Results in a functionally identical binary.
pub fn bump_gzip_timestamp(wasm: &Wasm) -> Wasm {
    // wasm is gzipped and the subslice [4..8]
    // is the little endian representation of a timestamp
    // so we just increment that timestamp
    let mut new_wasm = wasm.clone().bytes();
    assert!(is_gzipped_blob(&new_wasm));
    let t = u32::from_le_bytes(new_wasm[4..8].try_into().unwrap());
    new_wasm[4..8].copy_from_slice(&(t + 1).to_le_bytes());
    Wasm::from_bytes(new_wasm)
}

/// Perform a change on a canister by upgrading it or
/// reinstalling entirely, depending on the `how` argument.
/// Argument `wasm` is ensured to have a different
/// hash relative to the current binary.
/// In argument `arg` additional arguments can be provided
/// that serve as input to the upgrade hook or as init arguments
/// to the fresh installation.
///
/// This is an internal method.
async fn change_nns_canister_by_proposal(
    how: CanisterInstallMode,
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    stop_before_installing: bool,
    wasm: Wasm,
    arg: Option<Vec<u8>>,
) {
    let wasm = wasm.bytes();
    let new_module_hash = &ic_crypto_sha2::Sha256::hash(&wasm);

    let status: CanisterStatusResult = root
        .update_(
            "canister_status",
            candid_one,
            CanisterIdRecord::from(canister.canister_id()),
        )
        .await
        .unwrap();
    let old_module_hash = status.module_hash.unwrap();
    assert_ne!(
        old_module_hash.as_slice(),
        new_module_hash,
        "change_nns_canister_by_proposal: both module hashes prev, cur are \
         the same {:?}, but they should be different for upgrade",
        old_module_hash
    );

    let proposal = MakeProposalRequest {
        title: Some("Upgrade NNS Canister".to_string()),
        summary: "<proposal created by change_nns_canister_by_proposal>".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::InstallCode(InstallCodeRequest {
            canister_id: Some(canister.canister_id().get()),
            wasm_module: Some(wasm.clone()),
            install_mode: Some(how as i32),
            arg: Some(arg.unwrap_or_default()),
            skip_stopping_before_installing: Some(stop_before_installing),
        })),
    };

    // Submitting a proposal also implicitly records a vote from the proposer,
    // which with TEST_NEURON_1 is enough to trigger execution.
    let response: ManageNeuronResponse = governance
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuronRequest {
                id: None,
                command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(proposal))),
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    NeuronId(TEST_NEURON_1_ID).into(),
                )),
            },
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Error calling the manage_neuron api.");
    match response
        .panic_if_error("Error making proposal")
        .command
        .unwrap()
    {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.expect("No proposal id"),
        other => panic!("Unexpected response: {:?}", other),
    };

    // Wait 'till the hash matches and the canister is running again.
    loop {
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister.canister_id()),
            )
            .await
            .unwrap();
        if status.module_hash.unwrap().as_slice() == new_module_hash
            && status.status == CanisterStatusType::Running
        {
            break;
        }
    }
}

/// Upgrade the given root-controlled canister to the specified Wasm module.
/// This should only be called in NNS integration tests, where the NNS
/// canisters have their expected IDs.
///
/// This goes through MANY rounds of consensus, so expect it to be slow!
///
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
/// so it may have side effects!
pub async fn upgrade_nns_canister_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    stop_before_installing: bool,
    wasm: Wasm,
    arg: Option<Vec<u8>>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Upgrade,
        canister,
        governance,
        root,
        stop_before_installing,
        wasm,
        arg,
    )
    .await
}

/// Submits a proposal to upgrade an NNS canister, with the provided argument.
pub async fn upgrade_nns_canister_with_arg_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    wasm: Wasm,
    arg: Vec<u8>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Upgrade,
        canister,
        governance,
        root,
        false,
        wasm,
        Some(arg),
    )
    .await
}

/// Submits a proposal to upgrade an NNS canister, with the provided argument.
pub async fn upgrade_nns_canister_with_args_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    stop_before_installing: bool,
    wasm: Wasm,
    arg: Vec<u8>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Upgrade,
        canister,
        governance,
        root,
        stop_before_installing,
        wasm,
        Some(arg),
    )
    .await
}

/// Propose and execute the fresh re-installation of the canister. Wasm
/// and initialisation arguments can be specified.
/// This should only be called in NNS integration tests, where the NNS
/// canisters have their expected IDs.
///
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
/// so it may have side effects!
pub async fn reinstall_nns_canister_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    wasm: Wasm,
    arg: Vec<u8>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Reinstall,
        canister,
        governance,
        root,
        true,
        bump_gzip_timestamp(&wasm),
        Some(arg),
    )
    .await
}

/// Depending on the testing scenario, upgrade the given root-controlled
/// canister to itself, or do nothing. This should only be called in NNS
/// integration tests, where the NNS canisters have their expected IDs.
///
/// This goes through MANY rounds of consensus, so expect it to be slow!
///
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
/// so it may have side effects!
pub async fn maybe_upgrade_root_controlled_canister_to_self(
    // nns_canisters is NOT passed by reference because of the canister to upgrade,
    // for which we have a mutable borrow.
    nns_canisters: NnsCanisters<'_>,
    canister: &mut Canister<'_>,
    stop_before_installing: bool,
    scenario: UpgradeTestingScenario,
) {
    if UpgradeTestingScenario::Always != scenario {
        return;
    }

    // Copy the wasm of the canister to upgrade. We'll need it to upgrade back to
    // it. To observe that the upgrade happens, we need to make the binary different
    // post-upgrade.
    let wasm = bump_gzip_timestamp(canister.wasm().unwrap());
    let wasm_clone = wasm.clone().bytes();
    upgrade_nns_canister_by_proposal(
        canister,
        &nns_canisters.governance,
        &nns_canisters.root,
        stop_before_installing,
        wasm,
        None,
    )
    .await;
    canister.set_wasm(wasm_clone);
}

pub async fn bitcoin_set_config_by_proposal(
    network: BitcoinNetwork,
    governance: &Canister<'_>,
    set_config_request: SetConfigRequest,
) -> ProposalId {
    let proposal = BitcoinSetConfigProposal {
        network,
        payload: Encode!(&set_config_request).unwrap(),
    };

    // Submitting a proposal also implicitly records a vote from the proposer,
    // which with TEST_NEURON_1 is enough to trigger execution.
    submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::BitcoinSetConfig,
        proposal,
        "Set Bitcoin Config".to_string(),
        "".to_string(),
    )
    .await
}

pub async fn invalid_bitcoin_set_config_by_proposal(
    governance: &Canister<'_>,
    set_config_request: SetConfigRequest,
) -> ProposalId {
    // An invalid proposal payload to set the Bitcoin configuration.
    #[derive(Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
    pub struct BitcoinSetConfigProposalInvalid {
        pub payload: Vec<u8>,
    }

    let proposal = BitcoinSetConfigProposalInvalid {
        payload: Encode!(&set_config_request).unwrap(),
    };

    // Submitting a proposal also implicitly records a vote from the proposer,
    // which with TEST_NEURON_1 is enough to trigger execution.
    submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::BitcoinSetConfig,
        proposal,
        "Set Bitcoin Config".to_string(),
        "".to_string(),
    )
    .await
}
