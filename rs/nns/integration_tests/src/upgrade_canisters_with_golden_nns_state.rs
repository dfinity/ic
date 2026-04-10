use candid::{CandidType, Encode, Principal};
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{CanisterId, NodeId, PrincipalId, SubnetId};
use ic_crypto_sha2::Sha256;
use ic_crypto_test_utils_ni_dkg::dummy_initial_dkg_transcript_with_master_key;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_management_canister_types_private::SetupInitialDKGResponse;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID,
    NNS_UI_CANISTER_ID, NODE_REWARDS_CANISTER_ID, PROTOCOL_CANISTER_IDS, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::{
    ExecuteNnsFunction, MakeProposalRequest, MonthlyNodeProviderRewards, NnsFunction,
    ProposalActionRequest, ProposalStatus, Vote,
    manage_neuron_response::Command as CommandResponse,
};
use ic_nns_test_utils::state_test_helpers::{
    nns_get_most_recent_monthly_node_provider_rewards,
    nns_governance_get_proposal_info_as_anonymous, nns_governance_make_proposal,
    nns_wait_for_proposal_execution, registry_get_value, scrape_metrics,
};
use ic_nns_test_utils::{
    common::modify_wasm_bytes,
    state_test_helpers::{
        get_canister_status, nns_cast_vote, nns_create_super_powerful_neuron,
        nns_propose_upgrade_nns_canister, wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_protobuf::registry::subnet::v1::{
    SubnetFeatures as SubnetFeaturesPb, SubnetListRecord, SubnetRecord,
    SubnetType as SubnetTypePb,
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_resource_limits::ResourceLimits;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content;
use ic_state_machine_tests::{PayloadBuilder, StateMachine};
use ic_types::{
    NumBytes,
    batch::ConsensusResponse,
    crypto::threshold_sig::ni_dkg::NiDkgTag,
    messages::Payload as MsgPayload,
};
use icp_ledger::Tokens;
use prost::Message;
use rand::{SeedableRng, rngs::StdRng};
use registry_canister::mutations::do_create_subnet::{
    CanisterCyclesCostSchedule, CreateSubnetPayload,
};
use serde::Deserialize;
use std::{
    env,
    fmt::{Debug, Formatter},
    fs,
    str::FromStr,
    time::Duration,
};

struct NnsCanisterUpgrade {
    nns_canister_name: String,
    canister_id: CanisterId,
    environment_variable_name: &'static str,
    wasm_path: String,
    wasm_content: Vec<u8>,
    module_arg: Vec<u8>,
    wasm_hash: [u8; 32],
}

impl NnsCanisterUpgrade {
    fn new(nns_canister_name: &str) -> Self {
        #[rustfmt::skip]
        let (canister_id, environment_variable_name) = match nns_canister_name {
            // NNS Backend
            "cycles-minting" => (CYCLES_MINTING_CANISTER_ID,"CYCLES_MINTING_CANISTER_WASM_PATH"),
            "genesis-token"  => (GENESIS_TOKEN_CANISTER_ID,"GENESIS_TOKEN_CANISTER_WASM_PATH"),
            "governance"     => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_WASM_PATH"),
            "ledger"         => (LEDGER_CANISTER_ID, "LEDGER_CANISTER_WASM_PATH"),
            "lifeline"       => (LIFELINE_CANISTER_ID, "LIFELINE_CANISTER_WASM_PATH"),
            "migration"      => (MIGRATION_CANISTER_ID, "MIGRATION_CANISTER_WASM_PATH"),
            "registry"       => (REGISTRY_CANISTER_ID, "REGISTRY_CANISTER_WASM_PATH"),
            "root"           => (ROOT_CANISTER_ID, "ROOT_CANISTER_WASM_PATH"),
            "sns-wasm"       => (SNS_WASM_CANISTER_ID, "SNS_WASM_CANISTER_WASM_PATH"),

            // The Node Rewards canister is updated with test feature that simulates
            // calls to the management canister in order to retrieve blockmaker statistics for each node.
            // This is necessary because state_machine tests run only with an NNS subnet, where real
            // management canister calls are not possible (Just NNS subnet is present).
            "node-rewards"   => (NODE_REWARDS_CANISTER_ID, "NODE_REWARDS_CANISTER_TEST_WASM_PATH"),
            _ => panic!("Not a known NNS canister type: {nns_canister_name}",),
        };

        let module_arg = if nns_canister_name == "cycles-minting" {
            Encode!(
                &(Some(CyclesCanisterInitPayload {
                    cycles_ledger_canister_id: Some(CYCLES_LEDGER_CANISTER_ID),
                    ledger_canister_id: None,
                    governance_canister_id: None,
                    minting_account_id: None,
                    last_purged_notification: None,
                    exchange_rate_canister: None,
                }))
            )
            .unwrap()
        } else if nns_canister_name == "ledger" {
            Encode!(&()).unwrap()
        } else if nns_canister_name == "migration" {
            #[derive(CandidType, Deserialize, Default)]
            struct MigrationCanisterInitArgs {
                allowlist: Option<Vec<Principal>>,
            }
            Encode!(&MigrationCanisterInitArgs::default()).unwrap()
        } else {
            vec![]
        };

        let nns_canister_name = nns_canister_name.to_string();
        let wasm_path = env::var(environment_variable_name)
            .unwrap_or_else(|err| panic!("{err}: {environment_variable_name}",));
        let wasm_content = fs::read(&wasm_path).unwrap();
        let wasm_hash = Sha256::hash(&wasm_content);

        Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_content,
            module_arg,
            wasm_hash,
        }
    }

    fn modify_wasm_but_preserve_behavior(&mut self) {
        let old_wasm_hash = self.wasm_hash;

        self.wasm_content = modify_wasm_bytes(&self.wasm_content, 42);
        self.wasm_hash = Sha256::hash(&self.wasm_content);

        assert_ne!(self.wasm_hash, old_wasm_hash, "{self:#?}");
    }

    fn controller_principal_id(&self) -> PrincipalId {
        let result = if self.nns_canister_name == "root" {
            LIFELINE_CANISTER_ID
        } else {
            ROOT_CANISTER_ID
        };

        PrincipalId::from(result)
    }
}

impl Debug for NnsCanisterUpgrade {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_hash,
            module_arg,

            wasm_content: _,
        } = self;

        let wasm_hash = wasm_hash.map(|element| format!("{element:02X}")).join("");
        let wasm_hash = &wasm_hash;

        let module_arg = module_arg
            .iter()
            .map(|element| format!("{element:02X}"))
            .collect::<Vec<_>>()
            .join("");
        let module_arg = &module_arg;

        formatter
            .debug_struct("NnsCanisterUpgrade")
            .field("nns_canister_name", nns_canister_name)
            .field("wasm_path", wasm_path)
            .field("wasm_hash", wasm_hash)
            .field("module_arg", module_arg)
            .field("canister_id", canister_id)
            .field("environment_variable_name", environment_variable_name)
            .finish()
    }
}

/// Returns a list of well-known public neurons. Impersonating these neurons to vote a certain way
/// should be able to make the proposals pass instantly.
fn get_well_known_public_neurons() -> Vec<(NeuronId, PrincipalId)> {
    [
        (
            27,
            "4vnki-cqaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aae",
        ),
        (
            28,
            "4vnki-cqaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aae",
        ),
    ]
    .into_iter()
    .map(|(id, principal_str)| {
        let id = NeuronId { id };
        let principal = PrincipalId::from_str(principal_str).unwrap();
        (id, principal)
    })
    .collect()
}

/// Votes yes on the proposal with the given ID using well-known public neurons. Note that this is
/// needed because we should no longer be able to create a neuron with a huge stake and pass
/// proposals using this new neuron, as voting power spikes are automatically detected and a defense
/// mechanism is in place to prevent this exact situation. Instead, here we use the super power
/// given by the StateMachine test framework where any principal can be impersonated, which is
/// clearly unavailable on the mainnet.
fn vote_yes_with_well_known_public_neurons(state_machine: &StateMachine, proposal_id: u64) {
    for (voter_neuron_id, voter_controller) in get_well_known_public_neurons() {
        // Note that the voting can fail if the proposal already reaches absolute
        // majority and the NNS Governance starts to upgrade.
        let _ = nns_cast_vote(
            state_machine,
            voter_controller,
            voter_neuron_id,
            proposal_id,
            Vote::Yes,
        );
    }
}

#[test]
fn test_upgrade_canisters_with_golden_nns_state() {
    // Step 0: Read configuration. To wit, what canisters does the user want to upgrade in this
    // test? To do this, they set the NNS_CANISTER_UPGRADE_SEQUENCE environment variable.

    let all_canisters = [
        // Keep sorted.
        "cycles-minting",
        "genesis-token",
        "governance",
        "ledger",
        "lifeline",
        "migration",
        "registry",
        "node-rewards",
        "root",
        "sns-wasm",
    ]
    .join(",");

    let mut nns_canister_upgrade_sequence = env::var("NNS_CANISTER_UPGRADE_SEQUENCE")
        .unwrap_or_else(|_err| {
            panic!(
                "This test requires that the NNS_CANISTER_UPGRADE_SEQUENCE environment\n\
                 variable be set to something like 'governance,registry'.\n\
                 That is, it should be a comma-separated list of canister names.\n\
                 Alternatively, 'all' is equivalent to\n\
                 '{all_canisters}'\n\
                 (these are all the supported canister names, a large subset of\n\
                 those listed in rs/nns/canister_ids.json).",
            );
        });

    if nns_canister_upgrade_sequence == "all" {
        nns_canister_upgrade_sequence = all_canisters;
    }

    // TODO: The node-rewards canister must always be upgraded because its test WASM
    // simulates management canister calls for blockmaker statistics, which are not
    // possible in state_machine tests (only the NNS subnet is present). Without this
    // forced upgrade, the canister would run production code that fails in this environment.
    if !nns_canister_upgrade_sequence
        .split(',')
        .any(|canister_name| canister_name == "node-rewards")
    {
        nns_canister_upgrade_sequence.push_str(",node-rewards");
    }

    let mut nns_canister_upgrade_sequence = nns_canister_upgrade_sequence
        .split(',')
        .map(NnsCanisterUpgrade::new)
        .collect::<Vec<NnsCanisterUpgrade>>();

    // Step 1: Prepare the world

    // Step 1.1: Load golden nns state into a StateMachine.
    // TODO: Use PocketIc instead of StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    state_machine.reject_remote_callbacks();

    // Step 1.2: Create a super powerful Neuron.
    println!("Creating super powerful Neuron.");
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(
        &state_machine,
        neuron_controller,
        // Note that this number is chosen so that such an increase in voting power does not reach
        // 50% of the current voting power, which would be considered a spike and triggers a defense
        // mechanism designed to prevent a sudden takeover of the NNS.
        Tokens::from_tokens(100_000_000).unwrap(),
    );
    println!("Done creating super powerful Neuron.");

    let mut repetition_number = 1;
    // In order that nns_canister_upgrade_sequence can be modified outside this
    // lambda, this lambda takes it as an argument, rather than "inheriting" it
    // from the outer scope.
    let mut perform_sequence_of_upgrades =
        |nns_canister_upgrade_sequence: &[NnsCanisterUpgrade]| {
            for nns_canister_upgrade in nns_canister_upgrade_sequence {
                let NnsCanisterUpgrade {
                    nns_canister_name,
                    canister_id,
                    wasm_content,
                    module_arg,
                    wasm_hash,

                    wasm_path: _,
                    environment_variable_name: _,
                } = nns_canister_upgrade;
                println!("\nCurrent canister: {nns_canister_name}");

                // Step 1.3: Assert that the upgrade we are about to perform would
                // actually change the code in the canister. (This is "just" a
                // pre-flight check).
                let status_result = get_canister_status(
                    &state_machine,
                    nns_canister_upgrade.controller_principal_id(),
                    *canister_id,
                    CanisterId::ic_00(), // callee: management (virtual) canister.
                )
                .unwrap();
                assert_eq!(
                    status_result.status,
                    CanisterStatusType::Running,
                    "{status_result:#?}",
                );
                assert_ne!(
                    status_result.module_hash.as_ref().unwrap(),
                    &wasm_hash,
                    "Current code is the same as what is running in mainnet?!\n{status_result:#?}",
                );

                // Step 2: Call code under test: Upgrade the (current) canister.
                println!(
                    "Proposing to upgrade NNS {nns_canister_name} (attempt {repetition_number})...",
                );

                let proposal_id = nns_propose_upgrade_nns_canister(
                    &state_machine,
                    neuron_controller,
                    neuron_id,
                    *canister_id,
                    wasm_content.clone(),
                    module_arg.clone(),
                );

                // Impersonate some public neurons to vote on the proposal. Note that we do not
                // check whether votes succeed, as the governance upgrade can start at any point
                // which will make the canister unresponsive.
                vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);

                // Step 3: Verify result(s): In a short while, the canister should
                // be running the new code.
                wait_for_canister_upgrade_to_succeed(
                    &state_machine,
                    *canister_id,
                    wasm_hash,
                    nns_canister_upgrade.controller_principal_id(),
                    true,
                );
                println!(
                    "Attempt {repetition_number} to upgrade {nns_canister_name} was successful."
                );
            }

            repetition_number += 1;
        };

    let metrics_before = sanity_check::fetch_metrics(&state_machine);

    perform_sequence_of_upgrades(&nns_canister_upgrade_sequence);

    // Modify all WASMs, but preserve their behavior.
    for nns_canister_upgrade in &mut nns_canister_upgrade_sequence {
        nns_canister_upgrade.modify_wasm_but_preserve_behavior();
    }

    perform_sequence_of_upgrades(&nns_canister_upgrade_sequence);

    sanity_check::fetch_and_check_metrics_after_advancing_time(&state_machine, metrics_before);

    check_canisters_are_all_protocol_canisters(&state_machine);
}

// Check that all canisters in the NNS subnet (except for exempted ones) are protocol canisters. If
// this fails, either add the canister id into `non_protocol_canister_ids_in_nns_subnet` or
// `PROTOCOL_CANISTER_IDS`.
fn check_canisters_are_all_protocol_canisters(state_machine: &StateMachine) {
    let canister_ids = state_machine.get_canister_ids();
    let non_protocol_canister_ids_in_nns_subnet = [
        NNS_UI_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        MIGRATION_CANISTER_ID, /* TODO: temporary fix until this canister has real state */
    ];

    for canister_id in canister_ids {
        if non_protocol_canister_ids_in_nns_subnet.contains(&canister_id) {
            continue;
        }
        assert!(
            PROTOCOL_CANISTER_IDS.contains(&&canister_id),
            "Canister {canister_id} is in the NNS subnet but not a protocol canister",
        );
    }
}

fn get_subnet_list(state_machine: &StateMachine) -> SubnetListRecord {
    let response = registry_get_value(
        state_machine,
        make_subnet_list_record_key().as_bytes(),
    );
    assert!(
        response.error.is_none(),
        "Registry error: {:?}",
        response.error
    );
    match response.content.expect("No content in registry response") {
        Content::Value(bytes) => {
            SubnetListRecord::decode(bytes.as_slice()).expect("Failed to decode SubnetListRecord")
        }
        Content::LargeValueChunkKeys(_) => {
            panic!("SubnetListRecord was chunked; not supported here")
        }
    }
}

/// Builds the CreateSubnetPayload matching NNS proposal 141306:
/// "Create a test cloud engine" with 4 cloud nodes across aws, gcp, and azure.
/// See: https://dashboard.internetcomputer.org/proposal/141306
fn build_proposal_141306_payload() -> CreateSubnetPayload {
    let node_ids: Vec<NodeId> = [
        "lg45v-ktek6-6bca5-cd7cf-ptrwr-dovu4-ptt3k-6vkse-6hwsh-ogzhm-oqe",
        "sgrf7-u2i64-nmybq-qmldk-cq67h-fkpcg-mv55a-zuqsf-7dmc4-b5gcf-eqe",
        "y7han-ubz4t-qfs4j-uc27t-6t5ag-3zpyb-yoagk-vn7b3-dqz2m-eo6dz-uae",
        "sunbj-pky5k-bgeaw-5egfi-ywf37-j5fjr-jstjx-utqg4-zkoec-sdn44-3qe",
    ]
    .iter()
    .map(|s| NodeId::from(PrincipalId::from_str(s).unwrap()))
    .collect();

    CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        max_ingress_bytes_per_message: 3_670_016,
        max_ingress_bytes_per_block: None,
        max_ingress_messages_per_block: 1_000,
        max_block_payload_size: 4_194_304,
        unit_delay_millis: 3_000,
        initial_notary_delay_millis: 300,
        replica_version_id: "606cab75d9840e2e1c5ef1ce734a7e6a4f754f0b".to_string(),
        dkg_interval_length: 499,
        dkg_dealings_per_block: 1,
        start_as_nns: false,
        subnet_type: SubnetType::CloudEngine,
        is_halted: false,
        features: SubnetFeaturesPb {
            canister_sandboxing: false,
            http_requests: true,
            sev_enabled: None,
        },
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        chain_key_config: None,
        canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Free),
        subnet_admins: None,
        resource_limits: Some(ResourceLimits {
            maximum_state_size: Some(NumBytes::new(42_949_672_960)),
            maximum_state_delta: Some(NumBytes::new(10_737_418_240)),
        }),
        ingress_bytes_per_block_soft_cap: 0,
        gossip_max_artifact_streams_per_peer: 0,
        gossip_max_chunk_wait_ms: 0,
        gossip_max_duplicity: 0,
        gossip_max_chunk_size: 0,
        gossip_receive_check_cache_size: 0,
        gossip_pfn_evaluation_period_ms: 0,
        gossip_registry_poll_period_ms: 0,
        gossip_retransmission_request_ms: 0,
    }
}

/// Simulates the execution of NNS proposal 141306: "Create a test cloud engine".
/// Submits the CreateSubnetPayload and verifies that a new CloudEngine subnet
/// is added to the registry's subnet list with the expected 4 nodes.
/// See: https://dashboard.internetcomputer.org/proposal/141306
#[test]
fn test_create_cloud_engine_subnet_proposal_141306() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(
        &state_machine,
        neuron_controller,
        Tokens::from_tokens(100_000_000).unwrap(),
    );

    let subnet_list_before = get_subnet_list(&state_machine);
    let num_subnets_before = subnet_list_before.subnets.len();
    println!("Subnet count before proposal: {num_subnets_before}");

    let payload = build_proposal_141306_payload();
    let payload_bytes = Encode!(&payload).expect("Failed to Candid-encode CreateSubnetPayload");

    println!("Submitting CreateSubnet proposal (proposal 141306: Create a test cloud engine)...");
    let response = nns_governance_make_proposal(
        &state_machine,
        neuron_controller,
        neuron_id,
        &MakeProposalRequest {
            title: Some("Create a test cloud engine".to_string()),
            summary: "This proposal creates the first test cloud engine, which will be \
                made up of four cloud nodes that reside in aws, gcp and azure."
                .to_string(),
            action: Some(ProposalActionRequest::ExecuteNnsFunction(
                ExecuteNnsFunction {
                    nns_function: NnsFunction::CreateSubnet as i32,
                    payload: payload_bytes,
                },
            )),
            ..Default::default()
        },
    );

    let proposal_id = match response.command.unwrap() {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        other => panic!("Unexpected response: {other:?}"),
    };
    println!("Proposal submitted with id: {}", proposal_id.id);

    vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);

    // CreateSubnet triggers setup_initial_dkg on the management canister.
    // The golden NNS StateMachine doesn't have pocket_xnet/payload_builder,
    // so execute_round() cannot be used. Instead, we tick() normally and
    // when DKG contexts appear in the state, we build dummy DKG responses
    // and deliver them via tick_with_config().
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0..200 {
        let state = state_machine.get_latest_state();
        let dkg_contexts = &state
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts;

        if dkg_contexts.is_empty() {
            state_machine.tick();
        } else {
            let mut consensus_responses = Vec::new();
            for callback_id in dkg_contexts.keys() {
                let ni_dkg_transcript =
                    dummy_initial_dkg_transcript_with_master_key(&mut rng).0;
                let public_key = (&ni_dkg_transcript).try_into().unwrap();
                let public_key_der = threshold_sig_public_key_to_der(public_key).unwrap();
                let subnet_id =
                    PrincipalId::new_self_authenticating(&public_key_der).into();
                let mut high_threshold = ni_dkg_transcript.clone();
                high_threshold.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
                let mut low_threshold = ni_dkg_transcript;
                low_threshold.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
                let response = SetupInitialDKGResponse {
                    low_threshold_transcript_record: high_threshold.into(),
                    high_threshold_transcript_record: low_threshold.into(),
                    fresh_subnet_id: subnet_id,
                    subnet_threshold_public_key: public_key.into(),
                };
                consensus_responses.push(ConsensusResponse::new(
                    *callback_id,
                    MsgPayload::Data(response.encode()),
                ));
            }
            let payload = PayloadBuilder::new()
                .with_consensus_responses(consensus_responses);
            state_machine.tick_with_config(payload);
        }

        let proposal =
            nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
        if proposal.status == ProposalStatus::Executed as i32
            && proposal.executed_timestamp_seconds > 0
        {
            println!("Proposal executed after {i} ticks.");
            break;
        }
        if proposal.status == ProposalStatus::Failed as i32 {
            panic!("Proposal failed: {proposal:#?}");
        }
        state_machine.advance_time(Duration::from_millis(100));
    }
    let final_proposal =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
    assert_eq!(
        final_proposal.status,
        ProposalStatus::Executed as i32,
        "Proposal was not executed: {final_proposal:#?}",
    );
    println!("Proposal executed successfully.");

    let subnet_list_after = get_subnet_list(&state_machine);
    let num_subnets_after = subnet_list_after.subnets.len();
    println!("Subnet count after proposal: {num_subnets_after}");

    assert_eq!(
        num_subnets_after,
        num_subnets_before + 1,
        "Expected exactly one new subnet. Before: {num_subnets_before}, After: {num_subnets_after}",
    );

    let new_subnet_bytes: Vec<&Vec<u8>> = subnet_list_after
        .subnets
        .iter()
        .filter(|s| !subnet_list_before.subnets.contains(s))
        .collect();
    assert_eq!(new_subnet_bytes.len(), 1, "Expected exactly one new subnet ID");

    let new_subnet_principal =
        PrincipalId::try_from(new_subnet_bytes[0].as_slice()).expect("Invalid principal bytes");
    println!("New cloud engine subnet created: {new_subnet_principal}");

    let subnet_record_key = make_subnet_record_key(SubnetId::from(new_subnet_principal));
    let sr_response = registry_get_value(&state_machine, subnet_record_key.as_bytes());
    assert!(
        sr_response.error.is_none(),
        "Failed to read SubnetRecord: {:?}",
        sr_response.error,
    );
    let subnet_record = match sr_response
        .content
        .expect("No content for SubnetRecord")
    {
        Content::Value(bytes) => {
            SubnetRecord::decode(bytes.as_slice()).expect("Failed to decode SubnetRecord")
        }
        Content::LargeValueChunkKeys(_) => panic!("SubnetRecord was chunked; not supported here"),
    };

    assert_eq!(
        subnet_record.subnet_type,
        SubnetTypePb::CloudEngine as i32,
        "Expected CloudEngine ({}), got {}",
        SubnetTypePb::CloudEngine as i32,
        subnet_record.subnet_type,
    );
    println!(
        "Subnet type verified: CloudEngine ({})",
        subnet_record.subnet_type,
    );

    assert_eq!(
        subnet_record.membership.len(),
        4,
        "Expected 4 nodes in the cloud engine subnet, found {}",
        subnet_record.membership.len(),
    );
    println!(
        "Membership verified: {} nodes in the subnet",
        subnet_record.membership.len(),
    );

    println!("All assertions passed: cloud engine subnet was successfully created.");
}

mod sanity_check {
    use super::*;
    use ic_nns_governance::governance::NODE_PROVIDER_REWARD_PERIOD_SECONDS;
    use ic_nns_governance_api::DateUtc;

    /// Metrics fetched from canisters either before or after testing.
    pub struct Metrics {
        governance_prometheus_metrics: prometheus_parse::Scrape,
        governance_most_recent_monthly_node_provider_rewards: MonthlyNodeProviderRewards,
    }

    /// Fetches metrics from canisters.
    pub fn fetch_metrics(state_machine: &StateMachine) -> Metrics {
        let governance_prometheus_metrics = scrape_metrics(state_machine, GOVERNANCE_CANISTER_ID);
        let governance_most_recent_monthly_node_provider_rewards =
            nns_get_most_recent_monthly_node_provider_rewards(state_machine).unwrap();

        Metrics {
            governance_prometheus_metrics,
            governance_most_recent_monthly_node_provider_rewards,
        }
    }

    /// Fetches metrics from canisters after advancing time and checks that they are as expected,
    /// comparing them to the metrics fetched before the upgrade.
    pub fn fetch_and_check_metrics_after_advancing_time(
        state_machine: &StateMachine,
        before: Metrics,
    ) {
        let before_timestamp = before
            .governance_most_recent_monthly_node_provider_rewards
            .timestamp;
        advance_time_to_allow_for_voting_and_node_rewards(state_machine, before_timestamp);
        let after = fetch_metrics(state_machine);
        let after_start_date = after
            .governance_most_recent_monthly_node_provider_rewards
            .start_date
            .clone()
            .unwrap();
        let after_end_date = after
            .governance_most_recent_monthly_node_provider_rewards
            .end_date
            .clone()
            .unwrap();

        println!("node provider rewards start_date {:?}", after_start_date);
        println!("node provider rewards end_date {:?}", after_end_date);
        MetricsBeforeAndAfter { before, after }.check_all();
    }

    fn advance_time_to_allow_for_voting_and_node_rewards(
        state_machine: &StateMachine,
        before_timestamp: u64,
    ) {
        // Advance time in the state machine to just before the next node provider
        // rewards distribution time.
        // Important to reach the exact moment when node provider rewards are distributed!
        let seconds_to_node_provider_reward_distribution = before_timestamp
            + NODE_PROVIDER_REWARD_PERIOD_SECONDS
            - state_machine.get_time().as_secs_since_unix_epoch();
        state_machine.advance_time(std::time::Duration::from_secs(
            seconds_to_node_provider_reward_distribution - 1,
        ));
        for _ in 0..100 {
            state_machine.advance_time(std::time::Duration::from_secs(1));
            state_machine.tick();
        }

        // Advance time in the state machine by one month to ensure that voting rewards
        // are also distributed.
        state_machine.advance_time(std::time::Duration::from_secs(
            ONE_MONTH_SECONDS - seconds_to_node_provider_reward_distribution,
        ));
        for _ in 0..100 {
            state_machine.advance_time(std::time::Duration::from_secs(1));
            state_machine.tick();
        }
    }

    struct MetricsBeforeAndAfter {
        before: Metrics,
        after: Metrics,
    }

    impl MetricsBeforeAndAfter {
        /// Checks a list of metrics:
        /// - The stable/wasm memory size should not double or halve.
        /// - The number of proposals should not decrease by more than 50%.
        /// - The number of neurons should be within 5% of the before value.
        /// - The latest reward event timestamp should have increased.
        /// - The total minted node provider rewards should be +-20% of the before value.
        /// - The node provider rewards timestamp should have increased.
        fn check_all(&self) {
            self.check_metric(
                |metrics| governance_gauge_value(metrics, "governance_stable_memory_size_bytes"),
                |before, after| {
                    assert_not_increased_too_much(before, after, "stable memory size", 0.1);
                },
            );

            self.check_metric(
                |metrics| governance_gauge_value(metrics, "governance_total_memory_size_bytes"),
                |before, after| {
                    assert_not_increased_too_much(before, after, "wasm memory size", 0.5);
                    assert_not_decreased_too_much(before, after, "wasm memory size", 0.8);
                },
            );

            self.check_metric(
                |metrics| {
                    governance_gauge_value(
                        metrics,
                        "governance_latest_reward_event_timestamp_seconds",
                    )
                },
                |before, after| {
                    assert_increased(before, after, "latest voting reward event timestamp");
                },
            );
            self.check_metric(
                |metrics| governance_gauge_value(metrics, "governance_proposals_total"),
                |before, after| {
                    assert_not_decreased_too_much(before, after, "number of proposals", 0.5);
                },
            );
            self.check_metric(
                |metrics| governance_gauge_value(metrics, "governance_neurons_total"),
                |before, after| {
                    assert_not_decreased_too_much(before, after, "number of neurons", 0.05);
                    assert_not_increased_too_much(before, after, "number of neurons", 0.05);
                },
            );
            self.check_metric(
                |metrics| {
                    total_minted_node_rewards_value(
                        &metrics.governance_most_recent_monthly_node_provider_rewards,
                    )
                },
                |before, after| {
                    assert_not_increased_too_much(
                        before,
                        after,
                        "total minted node provider rewards",
                        0.30,
                    );
                    assert_not_decreased_too_much(
                        before,
                        after,
                        "total minted node provider rewards",
                        0.30,
                    );
                },
            );

            self.check_metric(
                |metrics| {
                    metrics
                        .governance_most_recent_monthly_node_provider_rewards
                        .timestamp
                },
                |before, after| {
                    assert_increased(before, after, "node provider rewards timestamp");
                },
            );

            // Check node provider rewards cover contiguous periods.
            let before_end_date = self
                .before
                .governance_most_recent_monthly_node_provider_rewards
                .end_date
                .clone()
                .unwrap();
            let expected_after_start_date = DateUtc {
                year: before_end_date.year,
                month: before_end_date.month,
                day: before_end_date.day + 1,
            };
            assert_eq!(
                self.after
                    .governance_most_recent_monthly_node_provider_rewards
                    .start_date,
                Some(expected_after_start_date)
            );
        }

        fn check_metric<T>(&self, transform: impl Fn(&Metrics) -> T, assertion: impl Fn(T, T)) {
            let before_value = transform(&self.before);
            let after_value = transform(&self.after);
            assertion(before_value, after_value);
        }
    }

    fn governance_gauge_value(metrics: &Metrics, name: &str) -> f64 {
        let metric = metrics
            .governance_prometheus_metrics
            .samples
            .iter()
            .find(|sample| sample.metric == name)
            .unwrap();
        if let prometheus_parse::Value::Gauge(value) = &metric.value {
            *value
        } else {
            panic!("{name} is not a gauge");
        }
    }

    fn total_minted_node_rewards_value(
        most_recent_monthly_node_provider_rewards: &MonthlyNodeProviderRewards,
    ) -> f64 {
        let total_rewards = most_recent_monthly_node_provider_rewards
            .rewards
            .iter()
            .map(|reward| reward.amount_e8s as f64)
            .sum::<f64>();
        let xdr_permyriad_per_icp = *most_recent_monthly_node_provider_rewards
            .xdr_conversion_rate
            .as_ref()
            .unwrap()
            .xdr_permyriad_per_icp
            .as_ref()
            .unwrap();
        total_rewards * (xdr_permyriad_per_icp as f64) / 10_000_f64
    }

    #[track_caller]
    fn assert_not_increased_too_much(before: f64, after: f64, name: &str, diff: f64) {
        assert!(
            after < before * (1.0 + diff),
            "After upgrading and advancing time, {name} increased too much. Before: {before}, After: {after}"
        );
    }

    #[track_caller]
    fn assert_not_decreased_too_much(before: f64, after: f64, name: &str, diff: f64) {
        assert!(
            after > before * (1.0 - diff),
            "After upgrading and advancing time, {name} decreased too much. Before: {before}, After: {after}"
        );
    }

    #[track_caller]
    fn assert_increased<T>(before: T, after: T, name: &str)
    where
        T: PartialOrd + std::fmt::Display,
    {
        assert!(
            after > before,
            "After upgrading and advancing time, {name} did not increase. Before: {before}, After: {after}"
        );
    }
}
