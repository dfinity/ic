use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, NODE_REWARDS_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    MonthlyNodeProviderRewards, NetworkEconomics, Vote, VotingPowerEconomics,
};
use ic_nns_test_utils::state_test_helpers::{
    get_canister_status, manage_network_economics, nns_cast_vote, nns_create_super_powerful_neuron,
    nns_propose_upgrade_nns_canister, wait_for_canister_upgrade_to_succeed,
};
use ic_nns_test_utils::state_test_helpers::{
    nns_get_most_recent_monthly_node_provider_rewards, nns_wait_for_proposal_execution,
    scrape_metrics,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_state_machine_tests::StateMachine;
use icp_ledger::Tokens;
use serde::Deserialize;
use std::{
    env,
    fmt::{Debug, Formatter},
    fs,
    str::FromStr,
};

struct NnsCanisterUpgradePBREnabled {
    nns_canister_name: String,
    canister_id: CanisterId,
    environment_variable_name: &'static str,
    wasm_path: String,
    wasm_content: Vec<u8>,
    wasm_hash: [u8; 32],
}

impl NnsCanisterUpgradePBREnabled {
    fn new(nns_canister_name: &str) -> Self {
        #[rustfmt::skip]
        let (canister_id, environment_variable_name) = match nns_canister_name {
            // Using test canister for Governance because PBR is enabled there.
            "governance"     => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_WASM_PATH"),

            // Using test canister for Node Rewards because state-machine does not support
            // multiple subnets yet, and Node Rewards PBR depends on multiple subnets to daily
            // update node metrics.
            "node-rewards"   => (NODE_REWARDS_CANISTER_ID, "NODE_REWARDS_CANISTER_TEST_WASM_PATH"),
            _ => panic!("Not a known NNS canister type: {nns_canister_name}",),
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
            wasm_hash,
        }
    }

    pub fn update(
        &self,
        state_machine: &StateMachine,
        neuron_controller: PrincipalId,
        neuron_id: NeuronId,
    ) {
        println!("\nCurrent canister: {}", self.nns_canister_name);

        let controller = PrincipalId::from(ROOT_CANISTER_ID);

        // Step 1.3: Assert that the upgrade we are about to perform would
        // actually change the code in the canister. (This is "just" a
        // pre-flight check).
        let status_result = get_canister_status(
            &state_machine,
            controller,
            self.canister_id,
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
            &self.wasm_hash,
            "Current code is the same as what is running in mainnet?!\n{status_result:#?}",
        );

        // Step 2: Call code under test: Upgrade the (current) canister.
        println!("Proposing to upgrade NNS {}", self.nns_canister_name);

        let proposal_id = nns_propose_upgrade_nns_canister(
            &state_machine,
            neuron_controller,
            neuron_id,
            self.canister_id,
            self.wasm_content.clone(),
            vec![],
        );

        // Impersonate some public neurons to vote on the proposal. Note that we do not
        // check whether votes succeed, as the governance upgrade can start at any point
        // which will make the canister unresponsive.
        vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);

        // Step 3: Verify result(s): In a short while, the canister should
        // be running the new code.
        wait_for_canister_upgrade_to_succeed(
            &state_machine,
            self.canister_id,
            &self.wasm_hash,
            controller,
        );
        println!(
            "Attempt to upgrade {} was successful.",
            self.nns_canister_name
        );
    }
}

impl Debug for NnsCanisterUpgradePBREnabled {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_hash,
            wasm_content: _,
        } = self;

        let wasm_hash = wasm_hash.map(|element| format!("{element:02X}")).join("");
        let wasm_hash = &wasm_hash;

        formatter
            .debug_struct("NnsCanisterUpgrade")
            .field("nns_canister_name", nns_canister_name)
            .field("wasm_path", wasm_path)
            .field("wasm_hash", wasm_hash)
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
fn test_performance_based_rewards_remuneration() {
    let nns_canister_upgrade_sequence: Vec<NnsCanisterUpgradePBREnabled> = vec![
        NnsCanisterUpgradePBREnabled::new("governance"),
        NnsCanisterUpgradePBREnabled::new("node-rewards"),
    ];

    // Step 1: Prepare the world

    // Step 1.1: Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

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

    // Step 1.3: Modify Network Economics so that the new neuron can vote.
    let proposal_id = manage_network_economics(
        &state_machine,
        NetworkEconomics {
            voting_power_economics: Some(VotingPowerEconomics {
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(
                    VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
                ),
                ..Default::default()
            }),
            ..Default::default()
        },
        neuron_controller,
        neuron_id,
    );
    vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    let metrics_before = sanity_check::fetch_metrics(&state_machine);

    nns_canister_upgrade_sequence.iter().for_each(|canisters| {
        canisters.update(&state_machine, neuron_controller, neuron_id);
    });

    sanity_check::fetch_and_check_metrics_after_advancing_time(&state_machine, metrics_before);
}

mod sanity_check {
    use super::*;
    use ic_nns_governance::governance::NODE_PROVIDER_REWARD_PERIOD_SECONDS;

    /// Metrics fetched from canisters either before or after testing.
    pub struct Metrics {
        pub governance_prometheus_metrics: prometheus_parse::Scrape,
        pub governance_most_recent_monthly_node_provider_rewards: MonthlyNodeProviderRewards,
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
        let target_rewards_distribution_timestamp_seconds = before
            .governance_most_recent_monthly_node_provider_rewards
            .timestamp
            + NODE_PROVIDER_REWARD_PERIOD_SECONDS;

        let now = state_machine.get_time().as_secs_since_unix_epoch();

        state_machine.advance_time(std::time::Duration::from_secs(
            target_rewards_distribution_timestamp_seconds - now - 1,
        ));
        for _ in 0..100 {
            state_machine.advance_time(std::time::Duration::from_secs(1));
            state_machine.tick();
        }

        let after = fetch_metrics(state_machine);
        let current_rewards_timestamp_seconds = after
            .governance_most_recent_monthly_node_provider_rewards
            .timestamp;

        assert_eq!(
            target_rewards_distribution_timestamp_seconds,
            current_rewards_timestamp_seconds
        );
        MetricsBeforeAndAfter { before, after }.check_all();
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
                    assert_increased(before, after, "latest reward event timestamp");
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
                        0.2,
                    );
                    assert_not_decreased_too_much(
                        before,
                        after,
                        "total minted node provider rewards",
                        0.2,
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
        total_rewards * (xdr_permyriad_per_icp as f64) / 10_000f64
    }

    fn assert_not_increased_too_much(before: f64, after: f64, name: &str, diff: f64) {
        assert!(
            after < before * (1.0 + diff),
            "After upgrading and advancing time, {name} increased too much. Before: {before}, After: {after}"
        );
    }

    fn assert_not_decreased_too_much(before: f64, after: f64, name: &str, diff: f64) {
        assert!(
            after > before * (1.0 - diff),
            "After upgrading and advancing time, {name} decreased too much. Before: {before}, After: {after}"
        );
    }

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
