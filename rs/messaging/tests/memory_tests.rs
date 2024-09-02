use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
use ic_types::{messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, Cycles};
use proptest::prelude::*;
use random_traffic_test::{
    extract_metrics, Config as CanisterConfig, Metrics as CanisterMetrics, Record,
};
use std::collections::BTreeMap;
use std::sync::Arc;

const LOCAL_SUBNET_ID: SubnetId = SUBNET_0;
const REMOTE_SUBNET_ID: SubnetId = SUBNET_1;

const KB: u64 = 1024;
const MB: u64 = KB * KB;

const MAX_PAYLOAD_BYTES: u32 = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]
    #[test]
    fn check_guaranteed_response_message_memory_limits_are_respected(
        seeds in proptest::collection::vec(any::<u64>().no_shrink(), 3),
        max_payload_bytes in (MAX_PAYLOAD_BYTES / 4)..=MAX_PAYLOAD_BYTES,
        calls_per_round in 3..=10,
    ) {
        // The number of rounds to execute while chatter is on.
        const CHATTER_PHASE_ROUND_COUNT: u64 = 30;
        // The maximum number of rounds to execute after chatter is turned off. It it takes more than
        // this number of rounds until there are no more hanging calls, the test fails.
        const SHUTDOWN_PHASE_MAX_ROUNDS: u64 = 300;
        // The amount of memory available for guaranteed response message memory on `local_env`.
        const LOCAL_MESSAGE_MEMORY_CAPACITY: u64 = 100 * MB;
        // The amount of memory available for guaranteed response message memory on `remote_env`.
        const REMOTE_MESSAGE_MEMORY_CAPACITY: u64 = 50 * MB;

        let fixture = Fixture::new(FixtureConfig {
            local_canisters_count: 2,
            local_max_instructions_per_round: 100_000_000,
            local_message_memory_capacity: LOCAL_MESSAGE_MEMORY_CAPACITY,
            remote_canisters_count: 1,
            remote_max_instructions_per_round: 100_000_000,
            remote_message_memory_capacity: REMOTE_MESSAGE_MEMORY_CAPACITY,
        });

        let config = CanisterConfig::try_new(
            fixture.canisters(),    // receivers
            0..=max_payload_bytes,  // call_bytes
            0..=max_payload_bytes,  // reply_bytes
            0..=0,                  // instructions_count
            1,                      // downstream_call_weight
            2,                      // reply_weight
        )
        .unwrap();

        // Send configs to canisters, seed the rng.
        for (index, canister) in fixture.canisters().into_iter().enumerate() {
            fixture.replace_config(canister, config.clone()).unwrap();
            fixture.seed_rng(canister, seeds[index]);
        }

        // Start chatter on all canisters.
        fixture.start_chatter(calls_per_round as u32).unwrap();

        // Build up backlog and keep up chatter for while.
        for _ in 0..CHATTER_PHASE_ROUND_COUNT {
            fixture.tick();

            // Check message memory limits are respected.
            let (local_memory, remote_memory) = fixture.guaranteed_response_message_memory_taken();
            prop_assert!(local_memory <= LOCAL_MESSAGE_MEMORY_CAPACITY.into());
            prop_assert!(remote_memory <= REMOTE_MESSAGE_MEMORY_CAPACITY.into());
        }

        // Stop chatter on all canisters.
        fixture.stop_chatter().unwrap();

        // Keep ticking until all calls are answered.
        for counter in 0.. {
            fixture.tick();

            // Check message memory limits are respected.
            let (local_memory, remote_memory) = fixture.guaranteed_response_message_memory_taken();
            prop_assert!(local_memory <= LOCAL_MESSAGE_MEMORY_CAPACITY.into());
            prop_assert!(remote_memory <= REMOTE_MESSAGE_MEMORY_CAPACITY.into());

            if fixture
                .collect_metrics()
                .into_iter()
                .all(|(_canister, metrics)| metrics.hanging_calls == 0)
            {
                break;
            }

            prop_assert!(counter <= SHUTDOWN_PHASE_MAX_ROUNDS);
        }

        // One extra tick to make sure everything is gc'ed.
        fixture.tick();

        // Check the system agrees on 'no hanging calls'.
        for (canisters, env) in [
            (&fixture.local_canisters, &fixture.local_env),
            (&fixture.remote_canisters, &fixture.remote_env),
        ] {
            for canister in canisters.iter() {
                let state = env.get_latest_state();
                let call_context_manager = state
                    .canister_states
                    .get(canister)
                    .unwrap()
                    .system_state
                    .call_context_manager()
                    .unwrap();
                prop_assert!(call_context_manager.call_contexts().is_empty());
            }
        }

        // All memory is freed without hanging calls.
        prop_assert_eq!(
            (NumBytes::new(0), NumBytes::new(0)),
            fixture.guaranteed_response_message_memory_taken()
        );
    }

}

#[derive(Debug)]
struct FixtureConfig {
    local_canisters_count: u64,
    local_max_instructions_per_round: u64,
    local_message_memory_capacity: u64,
    remote_canisters_count: u64,
    remote_max_instructions_per_round: u64,
    remote_message_memory_capacity: u64,
}

impl Default for FixtureConfig {
    fn default() -> Self {
        Self {
            local_canisters_count: 2,
            local_max_instructions_per_round: 100_000_000,
            local_message_memory_capacity: 100 * MB,
            remote_canisters_count: 1,
            remote_max_instructions_per_round: 100_000_000,
            remote_message_memory_capacity: 50 * MB,
        }
    }
}

impl FixtureConfig {
    /// Generates a `StateMachineConfig` using defaults for an application subnet, except for the
    /// subnet message memory capacity and the maximum number of instructions per round.
    fn state_machine_config(
        subnet_message_memory_capacity: u64,
        max_instructions_per_round: u64,
    ) -> StateMachineConfig {
        StateMachineConfig::new(
            SubnetConfig {
                scheduler_config: SchedulerConfig {
                    scheduler_cores: 4,
                    max_instructions_per_round: max_instructions_per_round.into(),
                    max_instructions_per_message_without_dts: max_instructions_per_round.into(),
                    max_instructions_per_slice: max_instructions_per_round.into(),
                    ..SchedulerConfig::application_subnet()
                },
                cycles_account_manager_config: CyclesAccountManagerConfig::application_subnet(),
            },
            HypervisorConfig {
                subnet_message_memory_capacity: subnet_message_memory_capacity.into(),
                ..HypervisorConfig::default()
            },
        )
    }

    /// Generates a `StateMachineConfig` for the `local_env`.
    fn local_state_machine_config(&self) -> StateMachineConfig {
        Self::state_machine_config(
            self.local_message_memory_capacity,
            self.local_max_instructions_per_round,
        )
    }

    /// Generates a `StateMachineConfig` for the `remote_env`.
    fn remote_state_machine_config(&self) -> StateMachineConfig {
        Self::state_machine_config(
            self.remote_message_memory_capacity,
            self.remote_max_instructions_per_round,
        )
    }
}

#[derive(Debug, Clone)]
struct Fixture {
    pub local_env: Arc<StateMachine>,
    pub local_canisters: Vec<CanisterId>,
    pub remote_env: Arc<StateMachine>,
    pub remote_canisters: Vec<CanisterId>,
}

impl Fixture {
    /// Generates a local environment with `local_canisters_count` canisters installed;
    /// and a remote environment with `remote_canisters_count` canisters installed.
    fn new(config: FixtureConfig) -> Self {
        let mut routing_table = RoutingTable::new();
        routing_table_insert_subnet(&mut routing_table, LOCAL_SUBNET_ID).unwrap();
        routing_table_insert_subnet(&mut routing_table, REMOTE_SUBNET_ID).unwrap();
        let wasm = Project::cargo_bin_maybe_from_env("random-traffic-test-canister", &[]).bytes();

        // Generate local environment and install canisters.
        let local_env = StateMachineBuilder::new()
            .with_subnet_id(LOCAL_SUBNET_ID)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table.clone())
            .with_config(Some(config.local_state_machine_config()))
            .build();
        let local_canisters = (0..config.local_canisters_count)
            .map(|_| install_canister(&local_env, wasm.clone()))
            .collect();

        // Generate remote environment and install canisters.
        let remote_env = StateMachineBuilder::new()
            .with_subnet_id(REMOTE_SUBNET_ID)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table(routing_table.clone())
            .with_config(Some(config.remote_state_machine_config()))
            .build();
        let remote_canisters = (0..config.remote_canisters_count)
            .map(|_| install_canister(&remote_env, wasm.clone()))
            .collect();

        Self {
            local_env: local_env.into(),
            local_canisters,
            remote_env: remote_env.into(),
            remote_canisters,
        }
    }

    /// Returns all canisters installed in the fixture, local canisters first.
    pub fn canisters(&self) -> Vec<CanisterId> {
        self.local_canisters
            .iter()
            .cloned()
            .chain(self.remote_canisters.iter().cloned())
            .collect()
    }

    /// Returns a reference to `self.local_env` if `canister` is installed on it.
    /// Else a reference to `self.remote_env` if `canister` is installed on it.
    ///
    /// Panics if `canister` is not installed on either env.
    pub fn get_env(&self, canister: &CanisterId) -> &StateMachine {
        if self.local_canisters.contains(canister) {
            return &self.local_env;
        }
        if self.remote_canisters.contains(canister) {
            return &self.remote_env;
        }
        unreachable!();
    }

    /// Helper function for replacing canister state elements.
    ///
    /// Panics if `canister` is not installed in `Self`.
    fn replace_canister_state<T>(
        &self,
        method: &str,
        canister: CanisterId,
        item: T,
    ) -> Result<T, ()>
    where
        T: candid::CandidType + for<'a> candid::Deserialize<'a>,
    {
        let msg = candid::Encode!(&item).unwrap();
        let reply = self
            .get_env(&canister)
            .execute_ingress(canister, method, msg)
            .unwrap();
        candid::Decode!(&reply.bytes(), Result<T, ()>).unwrap()
    }

    /// Replaces the `CanisterConfig` in `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn replace_config(
        &self,
        canister: CanisterId,
        config: CanisterConfig,
    ) -> Result<CanisterConfig, ()> {
        self.replace_canister_state("replace_config", canister, config)
    }

    /// Replaces the `calls_per_round` in `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn replace_calls_per_round(&self, canister: CanisterId, count: u32) -> Result<u32, ()> {
        self.replace_canister_state("replace_calls_per_round", canister, count)
    }

    /// Sets the `Rng` in `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn seed_rng(&self, canister: CanisterId, seed: u64) {
        let msg = candid::Encode!(&seed).unwrap();
        self.get_env(&canister)
            .execute_ingress(canister, "seed_rng", msg)
            .unwrap();
    }

    /// Sets `calls_per_round` on all canisters to the same value.
    pub fn start_chatter(&self, calls_per_round: u32) -> Result<(), ()> {
        for canister in self.canisters() {
            self.replace_calls_per_round(canister, calls_per_round)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Sets `call_per_round` on all canisters to 0.
    pub fn stop_chatter(&self) -> Result<(), ()> {
        self.start_chatter(0)
    }

    /// Queries the records from `canister` on the subnet `env`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn query_records(&self, canister: CanisterId) -> Vec<Record> {
        let reply = self
            .get_env(&canister)
            .query(canister, "records", vec![])
            .unwrap();
        candid::Decode!(&reply.bytes(), Vec<Record>).unwrap()
    }

    /// Collects the metrics for all installed canisters on the fixture.
    pub fn collect_metrics(&self) -> BTreeMap<CanisterId, CanisterMetrics> {
        self.canisters()
            .into_iter()
            .map(|canister| (canister, extract_metrics(&self.query_records(canister))))
            .collect()
    }

    /// Return the number of bytes take by guaranteed response memory (`local_env`, `remote_env`).
    pub fn guaranteed_response_message_memory_taken(&self) -> (NumBytes, NumBytes) {
        (
            self.local_env
                .get_latest_state()
                .guaranteed_response_message_memory_taken(),
            self.remote_env
                .get_latest_state()
                .guaranteed_response_message_memory_taken(),
        )
    }

    /// Executes one round on both the `local_env` and the `remote_env` by generating a XNet
    /// payload on one and inducting it into the other, and vice versa.
    pub fn tick(&self) {
        if let Ok(xnet_payload) = self.local_env.generate_xnet_payload(
            self.remote_env.get_subnet_id(),
            None,
            None,
            None,
            None,
        ) {
            self.remote_env
                .execute_block_with_xnet_payload(xnet_payload);
        } else {
            self.remote_env.tick();
        }

        if let Ok(xnet_payload) = self.remote_env.generate_xnet_payload(
            self.local_env.get_subnet_id(),
            None,
            None,
            None,
            None,
        ) {
            self.local_env.execute_block_with_xnet_payload(xnet_payload);
        } else {
            self.local_env.tick();
        }
    }
}

/// Installs a 'random-traffic-test-canister' in `env`.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing random-traffic-test-canister failed")
}
