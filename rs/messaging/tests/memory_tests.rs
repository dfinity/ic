use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{
    embedders::{Config as EmbeddersConfig, FeatureFlags},
    execution_environment::Config as HypervisorConfig,
    flag_status::FlagStatus,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, UserError};
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::{MessageId, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64},
    Cycles,
};
use proptest::prelude::*;
use random_traffic_test::{extract_metrics, Config as CanisterConfig, Record as CanisterRecord};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const LOCAL_SUBNET_ID: SubnetId = SUBNET_0;
const REMOTE_SUBNET_ID: SubnetId = SUBNET_1;

const KB: u64 = 1024;
const MB: u64 = KB * KB;

const MAX_PAYLOAD_BYTES: u32 = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32;

prop_compose! {
    /// Generates a random `CanisterConfig` using reasonable ranges of values; receivers is empty
    /// and assumed to be populated manually.
    fn arb_canister_config(max_payload_bytes: u32, max_calls_per_heartbeat: u32)(
        max_call_bytes in 0..=max_payload_bytes,
        max_reply_bytes in 0..=max_payload_bytes,
        calls_per_heartbeat in 0..=max_calls_per_heartbeat,
        max_timeout_secs in 10..=100_u32,
        downstream_call_percentage in 0..=100_u32,
        best_effort_call_percentage in 0..=100_u32,
    ) -> CanisterConfig {
        CanisterConfig::try_new(
            vec![],
            0..=max_call_bytes,
            0..=max_reply_bytes,
            0..=0, // instructions_count
            0..=max_timeout_secs,
            calls_per_heartbeat,
            downstream_call_percentage,
            best_effort_call_percentage,
        )
        .expect("bad config inputs")
    }
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_guaranteed_response_message_memory_limits_are_respected(
    #[strategy(proptest::collection::vec(any::<u64>().no_shrink(), 3))] seeds: Vec<u64>,
    #[strategy(arb_canister_config(MAX_PAYLOAD_BYTES, 5))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_guaranteed_response_message_memory_limits_are_respected_impl(
        30,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seeds.as_slice(),
        config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 1 canister installed.
///
/// In the first phase `chatter_phase_round_count` rounds are executed on both subnets, including XNet
/// traffic with 'chatter' enabled, i.e. the installed canisters are making random calls (including
/// downstream calls depending on `config`).
///
/// For the second phase, the 'chatter' is disabled by putting a canister into `Stopping` state
/// every 10 rounds. In addition to shutting down traffic altogether from that canister (including
/// downstream calls) this will also induce a lot asynchronous rejections for requests. If any
/// canister fails to reach `Stopped` state (i.e. no pending calls), something went wrong in
/// message routing, most likely a bug connected to reject signals for requests.
///
/// In the final phase, up to `shutdown_phase_max_rounds` additional rounds are executed after
/// 'chatter' has been turned off to conclude all calls (or else return `Err(_)` if any call fails
/// to do so).
///
/// During all these phases, a check ensures that guaranteed response message memory never exceeds
/// the limit specified in the `FixtureConfig` used to generate the fixture used in this test.
fn check_guaranteed_response_message_memory_limits_are_respected_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seeds: &[u64],
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
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

    config.receivers = fixture.canisters();

    // Send configs to canisters, seed the rng.
    for (index, canister) in fixture.canisters().into_iter().enumerate() {
        fixture.set_config(canister, config.clone());
        fixture.seed_rng(canister, seeds[index]);
    }

    // Build up backlog and keep up chatter for while.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();

        // Check message memory limits are respected.
        fixture.expect_guaranteed_response_message_memory_taken_at_most(
            "Chatter",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;
    }

    // Shut down chatter by putting a canister into `Stopping` state every 10 ticks until they are
    // all `Stopping` or `Stopped`.
    for canister in fixture.canisters().into_iter() {
        fixture.stop_chatter(canister);
        fixture.stop_canister_non_blocking(canister);
        for _ in 0..10 {
            fixture.tick();

            // Check message memory limits are respected.
            fixture.expect_guaranteed_response_message_memory_taken_at_most(
                "Shutdown",
                LOCAL_MESSAGE_MEMORY_CAPACITY,
                REMOTE_MESSAGE_MEMORY_CAPACITY,
            )?;
        }
    }

    // Tick until all calls have concluded; or else fail the test.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |fixture| {
        fixture.expect_guaranteed_response_message_memory_taken_at_most(
            "Wrap up",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )
    })
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_calls_conclude_with_migrating_canister(
    #[strategy(any::<u64>().no_shrink())] seed: u64,
    #[strategy(arb_canister_config(KB as u32, 10))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_calls_conclude_with_migrating_canister_impl(
        10,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seed, config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 5 canisters installed. All canisters, except one local canister referred to
/// as `migrating_canister`, are stopped.
///
/// In the first phase a number of rounds are executed on both subnets, including XNet traffic with
/// the `migrating_canister` making random calls to all installed canisters (since all calls are
/// rejected except those to self).
///
/// For the second phase, `migrating_canister` stops making calls and is then migrated to the
/// remote subnet. Since all other canisters are stopped, there are bound to be a number of reject
/// signals for requests in the stream to the local_subnet. But since we migrated the `migrating_canister`
/// to the remote subnet, the locally generated reject responses fail to induct and are rerouted into the
/// stream to the remote subnet. The remote subnet eventually picks them up and inducts them into
/// `migrating_canister` leaving no pending calls after some more rounds.
///
/// If there are pending calls after a threshold number of rounds, there is most likely a bug
/// connected to reject signals for requests, specifically with the corresponding exceptions due to
/// canister migration.
fn check_calls_conclude_with_migrating_canister_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seed: u64,
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    let mut fixture = Fixture::new(FixtureConfig {
        local_canisters_count: 2,
        remote_canisters_count: 5,
        ..FixtureConfig::default()
    });

    config.receivers = fixture.canisters();

    let migrating_canister = *fixture.local_canisters.first().unwrap();

    // Send config to `migrating_canister` and seed its rng.
    fixture.set_config(migrating_canister, config);
    fixture.seed_rng(migrating_canister, seed);

    // Stop all canisters except `migrating_canister`.
    for canister in fixture.canisters() {
        if canister != migrating_canister {
            // Make sure the canister doesn't make calls when it is
            // put into running state to read its records.
            fixture.stop_chatter(canister);
            fixture.stop_canister_non_blocking(canister);
        }
    }
    // Make calls on `migrating_canister`.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();
    }

    // Stop making calls and migrate `migrating_canister`.
    fixture.stop_chatter(migrating_canister);
    fixture.migrate_canister(migrating_canister);

    // Tick until all calls have concluded; or else fail the test.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |_| Ok(()))
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_canister_can_be_stopped_with_remote_subnet_stalling(
    #[strategy(proptest::collection::vec(any::<u64>().no_shrink(), 2))] seeds: Vec<u64>,
    #[strategy(arb_canister_config(MAX_PAYLOAD_BYTES, 5))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_canister_can_be_stopped_with_remote_subnet_stalling_impl(
        30,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seeds.as_slice(),
        config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with one canister installed that
/// only makes best-effort calls and a remote subnet with one canister installed that makes random
/// calls of all kinds.
///
/// In the first phase a number of rounds are executed on both subnet, including XNet traffic
/// between both canisters.
///
/// For the second phase the local canister is put into `Stopping` state and the remote subnet
/// stalls, i.e. no more ticks are made on it. The local canister should reject any incoming calls
/// and since it made only best-effort calls, all pending calls should be rejected or timed out
/// eventually making the transition to `Stopped` state possible even with the remote subnet stalling.
///
/// If the local canister fails to reach `Stopped` state, there is most likely a bug with timing
/// out best-effort messages.
fn check_canister_can_be_stopped_with_remote_subnet_stalling_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seeds: &[u64],
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    let fixture = Fixture::new(FixtureConfig {
        local_canisters_count: 1,
        remote_canisters_count: 1,
        ..FixtureConfig::default()
    });

    config.receivers = fixture.canisters();

    let local_canister = *fixture.local_canisters.first().unwrap();
    let remote_canister = *fixture.remote_canisters.first().unwrap();

    fixture.seed_rng(local_canister, seeds[0]);
    fixture.seed_rng(remote_canister, seeds[1]);

    // Set the local `config` adapted such that only best-effort calls are made.
    fixture.set_config(
        local_canister,
        CanisterConfig {
            best_effort_call_percentage: 100,
            ..config.clone()
        },
    );
    // Set the remote `config` as is.
    fixture.set_config(remote_canister, config);

    // Make calls on both canisters.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();
    }
    // Stop chatter on the local canister.
    fixture.stop_chatter(local_canister);

    // Put local canister into `Stopping` state.
    let msg_id = fixture.stop_canister_non_blocking(local_canister);

    // Tick for up to `shutdown_phase_max_rounds` times on the local subnet only
    // or until the local canister has stopped.
    for _ in 0..shutdown_phase_max_rounds {
        match fixture.local_env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            } => return Ok(()),
            _ => {
                fixture.local_env.tick();
                fixture
                    .local_env
                    .advance_time(std::time::Duration::from_secs(1));
            }
        }
    }

    fixture.failed_with_reason(format!(
        "failed to stop local canister after {shutdown_phase_max_rounds} ticks"
    ))
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
                embedders_config: EmbeddersConfig {
                    feature_flags: FeatureFlags {
                        best_effort_responses: FlagStatus::Enabled,
                        ..FeatureFlags::default()
                    },
                    ..EmbeddersConfig::default()
                },
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
    pub local_canisters: BTreeSet<CanisterId>,
    pub remote_env: Arc<StateMachine>,
    pub remote_canisters: BTreeSet<CanisterId>,
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

    /// Helper function for update calls to `canister`; returns the current `T` as it was before
    /// this call.
    ///
    /// Panics if `canister` is not installed in `self`.
    fn set_canister_state<T>(&self, canister: CanisterId, method: &str, item: T) -> T
    where
        T: candid::CandidType + for<'a> candid::Deserialize<'a>,
    {
        let msg = candid::Encode!(&item).unwrap();
        let reply = self
            .get_env(&canister)
            .execute_ingress(canister, method, msg)
            .unwrap();
        candid::Decode!(&reply.bytes(), T).unwrap()
    }

    /// Sets the `CanisterConfig` in `canister`; returns the current config.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn set_config(&self, canister: CanisterId, config: CanisterConfig) -> CanisterConfig {
        self.set_canister_state(canister, "set_config", config)
    }

    /// Seeds the `Rng` in `canister`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn seed_rng(&self, canister: CanisterId, seed: u64) {
        let msg = candid::Encode!(&seed).unwrap();
        self.get_env(&canister)
            .execute_ingress(canister, "seed_rng", msg)
            .unwrap();
    }

    /// Starts `canister`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn start_canister(&self, canister: CanisterId) {
        self.get_env(&canister).start_canister(canister).unwrap();
    }

    /// Puts `canister` into `Stopping` state.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn stop_canister_non_blocking(&self, canister: CanisterId) -> MessageId {
        self.get_env(&canister).stop_canister_non_blocking(canister)
    }

    /// Calls the `stop_chatter()` function on `canister`.
    ///
    /// This stops the canister from making calls, downstream and from the heartbeat.
    pub fn stop_chatter(&self, canister: CanisterId) -> CanisterConfig {
        let reply = self
            .get_env(&canister)
            .execute_ingress(canister, "stop_chatter", candid::Encode!().unwrap())
            .unwrap();
        candid::Decode!(&reply.bytes(), CanisterConfig).unwrap()
    }

    /// Queries `canister` for `method`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn query<T: candid::CandidType + for<'a> candid::Deserialize<'a>>(
        &self,
        canister: CanisterId,
        method: &str,
    ) -> Result<T, UserError> {
        let reply = self
            .get_env(&canister)
            .query(canister, method, candid::Encode!().unwrap())?;
        Ok(candid::Decode!(&reply.bytes(), T).unwrap())
    }

    /// Force queries `canister` for `method` by first attempting to a normal query; if it fails, start
    /// the canister and try again.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn force_query<T: candid::CandidType + for<'a> candid::Deserialize<'a>>(
        &self,
        canister: CanisterId,
        method: &str,
    ) -> T {
        match self.query::<T>(canister, method) {
            Err(_) => {
                self.start_canister(canister);
                self.query::<T>(canister, method).unwrap()
            }
            Ok(records) => records,
        }
    }

    /// Returns the latest state `canister` is located on.
    ///
    /// Panics if `canister` is not installed on either env.
    pub fn get_latest_state(&self, canister: &CanisterId) -> Arc<ReplicatedState> {
        self.get_env(canister).get_latest_state()
    }

    /// Returns the number of bytes taken by guaranteed response memory (`local_env`, `remote_env`).
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
        label: impl std::fmt::Display,
        local_memory_upper_limit: u64,
        remote_memory_upper_limit: u64,
    ) -> Result<(), (String, DebugInfo)> {
        let (local_memory, remote_memory) = self.guaranteed_response_message_memory_taken();
        if local_memory > local_memory_upper_limit.into() {
            return self.failed_with_reason(format!("{}: local memory exceeds limit", label));
        }
        if remote_memory > remote_memory_upper_limit.into() {
            return self.failed_with_reason(format!("{}: remote memory exceeds limit", label));
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
                    .get_latest_state(&canister)
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
    ///
    /// Advances time on each env by 1 second.
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
        self.remote_env
            .advance_time(std::time::Duration::from_secs(1));

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
        self.local_env
            .advance_time(std::time::Duration::from_secs(1));
    }

    /// Ticks until all calls have concluded; i.e. there are no more open call contexts.
    ///
    /// Returns `Err(_)` if
    /// - `perform_checks()` fails.
    /// - any call fails to conclude after `max_ticks` ticks.
    /// - there is still memory reserved after all calls have concluded.
    pub fn tick_to_conclusion<F>(
        &self,
        max_ticks: usize,
        perform_checks: F,
    ) -> Result<(), (String, DebugInfo)>
    where
        F: Fn(&Self) -> Result<(), (String, DebugInfo)>,
    {
        // Keep ticking until all calls are answered.
        for _ in 0..max_ticks {
            self.tick();

            perform_checks(self)?;

            // Check for open call contexts.
            if self.open_call_contexts_count().values().sum::<usize>() == 0 {
                // Check the records agree on 'no pending calls'.
                if self
                    .canisters()
                    .into_iter()
                    .map(|canister| extract_metrics(&self.force_query(canister, "records")))
                    .any(|metrics| metrics.pending_calls != 0)
                {
                    return self.failed_with_reason(
                        "no open call contexts but found pending calls in the records",
                    );
                }

                // One extra tick to make sure everything is gc'ed.
                self.tick();

                // After the fact, all memory is freed and back to 0.
                return self.expect_guaranteed_response_message_memory_taken_at_most(
                    "Message memory used despite no open call contexts",
                    0,
                    0,
                );
            }
        }

        self.failed_with_reason(format!(
            "failed to conclude calls after {} ticks",
            max_ticks
        ))
    }

    /// Migrates `canister` between `local_env` and `remote_env` (either direction).
    ///
    /// Panics if no such canister exists.
    pub fn migrate_canister(&mut self, canister: CanisterId) {
        fn move_canister(
            canister: CanisterId,
            from_env: &StateMachine,
            from_subnet: SubnetId,
            to_env: &StateMachine,
            to_subnet: SubnetId,
        ) {
            for env in [from_env, to_env] {
                env.prepare_canister_migrations(canister..=canister, from_subnet, to_subnet);
                env.reroute_canister_range(canister..=canister, to_subnet);
            }
            from_env.move_canister_state_to(to_env, canister).unwrap();
        }

        if self.local_canisters.remove(&canister) {
            move_canister(
                canister,
                &self.local_env,
                LOCAL_SUBNET_ID,
                &self.remote_env,
                REMOTE_SUBNET_ID,
            );
            self.remote_canisters.insert(canister);
        } else {
            move_canister(
                canister,
                &self.remote_env,
                REMOTE_SUBNET_ID,
                &self.local_env,
                LOCAL_SUBNET_ID,
            );
            assert!(self.remote_canisters.remove(&canister));
            self.local_canisters.insert(canister);
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
                    .map(|canister| (canister, self.force_query(canister, "records")))
                    .collect(),
                fixture: self.clone(),
            },
        ))
    }
}

/// Returned by `Fixture::failed_with_reason()`.
#[allow(dead_code)]
struct DebugInfo {
    pub records: BTreeMap<CanisterId, BTreeMap<u32, CanisterRecord>>,
    pub fixture: Fixture,
}

/// Installs a 'random-traffic-test-canister' in `env`.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing random-traffic-test-canister failed")
}
