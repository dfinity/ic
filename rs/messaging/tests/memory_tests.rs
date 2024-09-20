use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
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
        calls_per_round in 1..=10,
        reply_weight in 1..=2,
        call_weight in 0..=2,
        // Note: both weights zero defaults to only replies.
    ) {
        prop_assert!(check_guaranteed_response_message_memory_limits_are_respected_impl(
            seeds.as_slice(),
            max_payload_bytes,
            calls_per_round as u32,
            reply_weight as u32,
            call_weight as u32,
        ).is_ok());
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 1 canister installed.
///
/// In the first phase a number of rounds are executed on both subnets, including XNet traffic with
/// 'chatter' enabled, i.e. the installed canisters are making random calls (including downstream calls).
///
/// For the second phase, the 'chatter' is disabled and additional rounds are executed until all
/// calls have received a reply.
///
/// Checks that the guaranteed response message memory never exceeds the limit; that all calls eventually
/// receive a reply (or were rejected synchronously when issued); and that the message memory goes
/// back to 0 after all in-flight messages have been dealt with.
fn check_guaranteed_response_message_memory_limits_are_respected_impl(
    seeds: &[u64],
    max_payload_bytes: u32,
    calls_per_round: u32,
    reply_weight: u32,
    call_weight: u32,
) -> Result<(), (String, DebugInfo)> {
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
        fixture.canisters(),   // receivers
        0..=max_payload_bytes, // call_bytes
        0..=max_payload_bytes, // reply_bytes
        0..=0,                 // instructions_count
    )
    .unwrap();

    // Send configs to canisters, seed the rng.
    for (index, canister) in fixture.canisters().into_iter().enumerate() {
        fixture.set_config(canister, config.clone()).unwrap();
        fixture.seed_rng(canister, seeds[index]);
        fixture.set_reply_weight(canister, reply_weight).unwrap();
        fixture.set_call_weight(canister, call_weight).unwrap();
    }

    // Start chatter on all canisters.
    fixture.start_chatter(calls_per_round).unwrap();

    // Build up backlog and keep up chatter for while.
    for _ in 0..CHATTER_PHASE_ROUND_COUNT {
        fixture.tick();

        // Check message memory limits are respected.
        fixture.expect_guaranteed_response_message_memory_taken_at_most(
            "Chatter",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;
    }

    // Stop chatter on all canisters.
    fixture.stop_chatter().unwrap();

    // Keep ticking until all calls are answered.
    for counter in 0.. {
        fixture.tick();

        // Check message memory limits are respected.
        fixture.expect_guaranteed_response_message_memory_taken_at_most(
            "Shutdown",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;

        if fixture
            .collect_metrics()
            .into_iter()
            .all(|(_canister, metrics)| metrics.hanging_calls == 0)
        {
            break;
        }

        if counter > SHUTDOWN_PHASE_MAX_ROUNDS {
            return fixture.failed_with_reason("shutdown phase hanging");
        }
    }

    // One extra tick to make sure everything is gc'ed.
    fixture.tick();

    // Check the system agrees on 'no hanging calls'.
    if fixture.open_call_contexts_count().values().sum::<usize>() != 0 {
        return fixture.failed_with_reason("found call contexts after shutdown phase");
    }

    // After the fact, all memory is freed and back to 0.
    fixture.expect_guaranteed_response_message_memory_taken_at_most("Final check", 0, 0)
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

    /// Helper function for setting canister state elements; returns the current element before
    /// setting it.
    ///
    /// Panics if `canister` is not installed in `Self`.
    fn set_canister_state<T>(&self, canister: CanisterId, method: &str, item: T) -> Result<T, ()>
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

    /// Sets the `CanisterConfig` in `canister`; returns the current config.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn set_config(
        &self,
        canister: CanisterId,
        config: CanisterConfig,
    ) -> Result<CanisterConfig, ()> {
        self.set_canister_state(canister, "set_config", config)
    }

    /// Sets the `max_calls_per_heartbeat` in `canister`; returns the current value.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn set_max_calls_per_heartbeat(&self, canister: CanisterId, count: u32) -> Result<u32, ()> {
        self.set_canister_state(canister, "set_max_calls_per_heartbeat", count)
    }

    /// Sets the `reply_weight` in `canister`; returns the current weight.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn set_reply_weight(&self, canister: CanisterId, weight: u32) -> Result<u32, ()> {
        self.set_canister_state(canister, "set_reply_weight", weight)
    }

    /// Sets the `call_weight` in `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn set_call_weight(&self, canister: CanisterId, weight: u32) -> Result<u32, ()> {
        self.set_canister_state(canister, "set_call_weight", weight)
    }

    /// Seeds the `Rng` in `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn seed_rng(&self, canister: CanisterId, seed: u64) {
        let msg = candid::Encode!(&seed).unwrap();
        self.get_env(&canister)
            .execute_ingress(canister, "seed_rng", msg)
            .unwrap();
    }

    /// Sets `max_calls_per_heartbeat` on all canisters to the same value.
    pub fn start_chatter(&self, max_calls_per_heartbeat: u32) -> Result<(), ()> {
        for canister in self.canisters() {
            self.set_max_calls_per_heartbeat(canister, max_calls_per_heartbeat)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Sets `call_per_round` on all canisters to 0; sets all call weights to 0.
    ///
    /// This sets the total new calls made on `Self` to 0 whether they are made from the heartbeat
    /// or recursively as a downstream call.
    pub fn stop_chatter(&self) -> Result<(), ()> {
        self.start_chatter(0)?;
        for canister in self.canisters() {
            self.set_call_weight(canister, 0)?;
        }
        Ok(())
    }

    /// Queries the records from `canister`.
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

    /// Return the number of bytes taken by guaranteed response memory (`local_env`, `remote_env`).
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

    /// Checks the local and remote guaranteed response message memory taken and compares it to an
    /// upper limit.
    pub fn expect_guaranteed_response_message_memory_taken_at_most(
        &self,
        label: &str,
        local_memory_upper_limit: u64,
        remote_memory_upper_limit: u64,
    ) -> Result<(), (String, DebugInfo)> {
        let (local_memory, remote_memory) = self.guaranteed_response_message_memory_taken();
        if local_memory > local_memory_upper_limit.into() {
            return self.failed_with_reason(format!("{label}: local memory exceeds limit"));
        }
        if remote_memory > remote_memory_upper_limit.into() {
            return self.failed_with_reason(format!("{label}: remote memory exceeds limit"));
        }
        Ok(())
    }

    /// Returns the number of open call contexts for each `canister` installed on `self`.
    ///
    /// Panics if no such canister exists.
    pub fn open_call_contexts_count(&self) -> BTreeMap<CanisterId, usize> {
        self.canisters()
            .into_iter()
            .map(|canister| {
                let count = self
                    .get_env(&canister)
                    .get_latest_state()
                    .canister_states
                    .get(&canister)
                    .unwrap()
                    .system_state
                    .call_context_manager()
                    .map_or(0, |manager| manager.call_contexts().len());
                (canister, count)
            })
            .collect()
    }

    /// Executes one round on both the `local_env` and the `remote_env` by generating a XNet
    /// payload on one and inducting it into the other, and vice versa; if there are no XNet
    /// messages either way, performs a normal `tick()` on the receiving subnet.
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

    /// Returns the canister records, the latest local state and the latest remote state.
    pub fn failed_with_reason(&self, reason: impl Into<String>) -> Result<(), (String, DebugInfo)> {
        Err((
            reason.into(),
            DebugInfo {
                records: self
                    .canisters()
                    .into_iter()
                    .map(|canister| (canister, self.query_records(canister)))
                    .collect(),
                latest_local_state: self.local_env.get_latest_state(),
                latest_remote_state: self.remote_env.get_latest_state(),
            },
        ))
    }
}

/// Returned by `Fixture::failed_with_reason()`.
#[allow(dead_code)]
struct DebugInfo {
    pub records: BTreeMap<CanisterId, Vec<Record>>,
    pub latest_local_state: Arc<ReplicatedState>,
    pub latest_remote_state: Arc<ReplicatedState>,
}

/// Installs a 'random-traffic-test-canister' in `env`.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing random-traffic-test-canister failed")
}
