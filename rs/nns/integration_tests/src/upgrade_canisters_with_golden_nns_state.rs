use candid::{CandidType, Decode, Encode, Principal};
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID,
    NNS_UI_CANISTER_ID, NODE_REWARDS_CANISTER_ID, PROTOCOL_CANISTER_IDS, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::{
    ExecuteNnsFunction, MakeProposalRequest, MonthlyNodeProviderRewards, NnsFunction,
    ProposalActionRequest, Vote, manage_neuron_response::Command as CommandResponse,
};
use ic_nns_test_utils::state_test_helpers::{
    nns_get_most_recent_monthly_node_provider_rewards, nns_governance_make_proposal,
    nns_wait_for_proposal_execution, query, registry_get_value, scrape_metrics,
};
use ic_nns_test_utils::{
    common::modify_wasm_bytes,
    state_test_helpers::{
        get_canister_status, nns_cast_vote, nns_create_super_powerful_neuron,
        nns_propose_upgrade_nns_canister, wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    DailyNodeRewards, DailyResults, GetNodeProvidersRewardsCalculationRequest,
    GetNodeProvidersRewardsCalculationResponse,
};
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content;
use ic_state_machine_tests::StateMachine;
use icp_ledger::Tokens;
use maplit::btreemap;
use prost::Message;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
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

fn get_node_rewards_table(state_machine: &StateMachine) -> NodeRewardsTable {
    let response = registry_get_value(state_machine, NODE_REWARDS_TABLE_KEY.as_bytes());
    assert!(response.error.is_none(), "Registry error: {:?}", response.error);
    match response.content.expect("No content in registry response") {
        Content::Value(bytes) => NodeRewardsTable::decode(bytes.as_slice())
            .expect("Failed to decode NodeRewardsTable"),
        Content::LargeValueChunkKeys(_) => panic!("NodeRewardsTable was chunked; not supported here"),
    }
}

fn print_node_rewards_table(table: &NodeRewardsTable, label: &str) {
    println!("\n=== Node Rewards Table ({label}) ===");
    for (region, reward_rates) in &table.table {
        for (node_type, rate) in &reward_rates.rates {
            println!(
                "  {region} / {node_type}: xdr_permyriad={}, coeff={:?}",
                rate.xdr_permyriad_per_node_per_month, rate.reward_coefficient_percent,
            );
        }
    }
    println!("=== End Node Rewards Table ({label}) ===\n");
}

fn call_get_node_providers_rewards_calculation(
    state_machine: &StateMachine,
    day: DateUtc,
) -> GetNodeProvidersRewardsCalculationResponse {
    let request = GetNodeProvidersRewardsCalculationRequest {
        day,
        algorithm_version: None,
    };
    query(
        state_machine,
        NODE_REWARDS_CANISTER_ID,
        "get_node_providers_rewards_calculation",
        Encode!(&request).unwrap(),
    )
    .map(|result| Decode!(&result, GetNodeProvidersRewardsCalculationResponse).unwrap())
    .unwrap()
}

fn print_daily_results(results: &DailyResults, label: &str) {
    println!("\n=== Node Providers Rewards Calculation ({label}) ===");
    for (provider, provider_rewards) in &results.provider_results {
        let type1_nodes: Vec<&DailyNodeRewards> = provider_rewards
            .daily_nodes_rewards
            .iter()
            .filter(|n| {
                n.node_reward_type
                    .as_deref()
                    .map_or(false, |t| t.starts_with("type1"))
            })
            .collect();
        if type1_nodes.is_empty() {
            continue;
        }
        println!("  Provider {provider}:");
        for node in &type1_nodes {
            println!(
                "    node={:?} type={:?} region={:?} base_xdr={:?} adjusted_xdr={:?}",
                node.node_id,
                node.node_reward_type,
                node.region,
                node.base_rewards_xdr_permyriad,
                node.adjusted_rewards_xdr_permyriad,
            );
        }
    }
    println!("=== End Rewards Calculation ({label}) ===\n");
}

fn submit_update_node_rewards_table_proposal(
    state_machine: &StateMachine,
    neuron_controller: PrincipalId,
    neuron_id: NeuronId,
    payload: UpdateNodeRewardsTableProposalPayload,
) {
    let response = nns_governance_make_proposal(
        state_machine,
        neuron_controller,
        neuron_id,
        &MakeProposalRequest {
            title: Some("Update node rewards table".to_string()),
            summary: "Test: update node rewards table values".to_string(),
            action: Some(ProposalActionRequest::ExecuteNnsFunction(
                ExecuteNnsFunction {
                    nns_function: NnsFunction::UpdateNodeRewardsTable as i32,
                    payload: Encode!(&payload).unwrap(),
                },
            )),
            ..Default::default()
        },
    );

    let proposal_id = match response.command.unwrap() {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        other => panic!("Unexpected response: {other:?}"),
    };

    vote_yes_with_well_known_public_neurons(state_machine, proposal_id.id);
    nns_wait_for_proposal_execution(state_machine, proposal_id.id);
}

/// Simulates the execution of a real proposal to reduce Gen-1 node rewards (type1.1)
/// by 40% across multiple regions. Prints the full node rewards table before and after,
/// and verifies the affected entries match the expected new values.
#[test]
fn test_print_and_update_node_rewards_table() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(
        &state_machine,
        neuron_controller,
        Tokens::from_tokens(100_000_000).unwrap(),
    );

    // 0. Upgrade the node-rewards canister to the test WASM.
    //    The test WASM simulates management canister calls for blockmaker statistics,
    //    which are not available in state_machine tests (only NNS subnet is present).
    {
        let nrc = NnsCanisterUpgrade::new("node-rewards");
        println!("Upgrading node-rewards canister to test WASM...");
        let proposal_id = nns_propose_upgrade_nns_canister(
            &state_machine,
            neuron_controller,
            neuron_id,
            nrc.canister_id,
            nrc.wasm_content.clone(),
            nrc.module_arg.clone(),
        );
        vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);
        wait_for_canister_upgrade_to_succeed(
            &state_machine,
            nrc.canister_id,
            &nrc.wasm_hash,
            nrc.controller_principal_id(),
            true,
        );
        println!("Node-rewards canister upgraded successfully.");
    }

    // 1. Print the registry rewards table before the proposal.
    let table_before = get_node_rewards_table(&state_machine);
    print_node_rewards_table(&table_before, "BEFORE proposal");

    // 1b. Call get_node_providers_rewards_calculation BEFORE the proposal.
    let yesterday_secs =
        state_machine.get_time().as_secs_since_unix_epoch() - ONE_DAY_SECONDS;
    let query_day = DateUtc::from_unix_timestamp_seconds(yesterday_secs);
    println!("Querying NRC for rewards calculation on {query_day} (before proposal)...");
    let nrc_before = call_get_node_providers_rewards_calculation(&state_machine, query_day);
    match &nrc_before {
        Ok(results) => print_daily_results(results, "BEFORE proposal"),
        Err(e) => println!("NRC query before proposal returned error: {e}"),
    }

    // 2. Build the exact payload from the proposal:
    //    "Adjust Gen-1 node rewards: reduce XDR permyriad rates for type1.1 by 40%"
    let type1_1 = "type1.1".to_string();
    let coeff_100 = Some(100);

    let update_payload = UpdateNodeRewardsTableProposalPayload {
        new_entries: btreemap! {
            "Asia,JP".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 7_128_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "Asia,SG".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 7_404_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "Europe".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_366_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "Europe,CH".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_816_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "Europe,IM".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 8_142_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "Europe,SI".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_912_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "North America,CA".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_528_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "North America,US".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_024_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "North America,US,California".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_432_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "North America,US,Florida".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_432_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
            "North America,US,Georgia".to_string() => NodeRewardRates {
                rates: btreemap! {
                    type1_1.clone() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 6_432_000,
                        reward_coefficient_percent: coeff_100,
                    },
                },
            },
        },
    };

    // Record expected values for verification.
    let expected: BTreeMap<&str, u64> = btreemap! {
        "Asia,JP" => 7_128_000,
        "Asia,SG" => 7_404_000,
        "Europe" => 6_366_000,
        "Europe,CH" => 6_816_000,
        "Europe,IM" => 8_142_000,
        "Europe,SI" => 6_912_000,
        "North America,CA" => 6_528_000,
        "North America,US" => 6_024_000,
        "North America,US,California" => 6_432_000,
        "North America,US,Florida" => 6_432_000,
        "North America,US,Georgia" => 6_432_000,
    };

    println!("Submitting UpdateNodeRewardsTable proposal (Gen-1 -40% reduction)...");
    submit_update_node_rewards_table_proposal(
        &state_machine,
        neuron_controller,
        neuron_id,
        update_payload,
    );
    println!("Proposal executed successfully.");

    // 3. Print the registry table after the proposal.
    let table_after = get_node_rewards_table(&state_machine);
    print_node_rewards_table(&table_after, "AFTER proposal");

    // 3b. Advance 1 day and call get_node_providers_rewards_calculation again.
    //     The new "yesterday" is the day the proposal took effect, so the NRC
    //     should pick up the updated registry version with the reduced rewards.
    println!("Advancing time by 1 day...");
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
    for _ in 0..20 {
        state_machine.tick();
    }

    let new_yesterday_secs =
        state_machine.get_time().as_secs_since_unix_epoch() - ONE_DAY_SECONDS;
    let query_day_after = DateUtc::from_unix_timestamp_seconds(new_yesterday_secs);
    println!(
        "Querying NRC for rewards calculation on {query_day_after} (after proposal, day before)..."
    );
    let nrc_after =
        call_get_node_providers_rewards_calculation(&state_machine, query_day_after);
    match &nrc_after {
        Ok(results) => print_daily_results(results, "AFTER proposal (day before)"),
        Err(e) => println!("NRC query after proposal returned error: {e}"),
    }

    // 3c. Compare type1 base rewards between before and after.
    if let (Ok(before_results), Ok(after_results)) = (&nrc_before, &nrc_after) {
        println!("\n=== type1 Rewards Comparison ===");
        for (provider, after_provider) in &after_results.provider_results {
            let before_provider = before_results.provider_results.get(provider);
            for node in &after_provider.daily_nodes_rewards {
                let is_type1 = node
                    .node_reward_type
                    .as_deref()
                    .map_or(false, |t| t.starts_with("type1"));
                if !is_type1 {
                    continue;
                }
                let before_base = before_provider.and_then(|bp| {
                    bp.daily_nodes_rewards
                        .iter()
                        .find(|n| n.node_id == node.node_id)
                        .and_then(|n| n.base_rewards_xdr_permyriad)
                });
                println!(
                    "  node={:?} type={:?} region={:?}: base_before={:?} base_after={:?}",
                    node.node_id,
                    node.node_reward_type,
                    node.region,
                    before_base,
                    node.base_rewards_xdr_permyriad,
                );
                if let (Some(before_val), Some(after_val)) =
                    (before_base, node.base_rewards_xdr_permyriad)
                {
                    assert!(
                        after_val < before_val,
                        "Expected type1 base rewards to decrease: before={before_val}, after={after_val} for node {:?}",
                        node.node_id,
                    );
                }
            }
        }
        println!("=== End type1 Rewards Comparison ===\n");
    }

    // 4. Verify every updated entry in the registry table.
    for (region, expected_xdr) in &expected {
        let region_rates = table_after
            .table
            .get(*region)
            .unwrap_or_else(|| panic!("Region '{region}' missing after update"));
        let rate = region_rates
            .rates
            .get("type1.1")
            .unwrap_or_else(|| panic!("type1.1 missing in '{region}' after update"));

        assert_eq!(
            rate.xdr_permyriad_per_node_per_month, *expected_xdr,
            "Mismatch for {region}/type1.1: expected {expected_xdr}, got {}",
            rate.xdr_permyriad_per_node_per_month,
        );
        assert_eq!(
            rate.reward_coefficient_percent,
            Some(100),
            "Mismatch for {region}/type1.1 coefficient",
        );

        // Print before vs after for this specific entry.
        let before_rate = table_before
            .table
            .get(*region)
            .and_then(|r| r.rates.get("type1.1"));
        println!(
            "  {region}/type1.1: before={:?} => after={}",
            before_rate.map(|r| r.xdr_permyriad_per_node_per_month),
            rate.xdr_permyriad_per_node_per_month,
        );
    }

    // 5. Verify regions NOT in the proposal still have their original values.
    for (region, original_rates) in &table_before.table {
        if expected.contains_key(region.as_str()) {
            continue;
        }
        let after_rates = table_after
            .table
            .get(region)
            .unwrap_or_else(|| panic!("Region '{region}' disappeared after update"));
        assert_eq!(
            original_rates, after_rates,
            "Region '{region}' was modified but should not have been",
        );
    }

    println!("All assertions passed.");
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
