use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, UserError};
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
use ic_types::{
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
/*
#[test]
fn playground() {
    let seed = vec![17374506990209185531; 3];
    let config = CanisterConfig {
        receivers: vec![],
        call_bytes: (0, 131),
        reply_bytes: (0, 0),
        instructions_count: (0, 0),
        timeout_secs: (0, 37),
        calls_per_heartbeat: 2,
        reply_weight: 3,
        downstream_call_weight: 0,
        best_effort_weight: 0,
        guaranteed_response_weight: 3,
    };

    if let Err((error_msg, mut nfo)) = check_guaranteed_response_message_memory_limits_are_respected_impl(
        10,     // chatter_phase_round_count
        300,    // shutdown_phase_max_rounds
        &seed,
        config,
    ) {
        assert!(false, "{}\n\n{:#?}", error_msg, nfo.records.pop_first().unwrap());
    }
    else {
        unreachable!();
    }
}
*/
prop_compose! {
    /// Generates an arbitrary pair of weights such that w1 + w2 = total > 0.
    fn arb_weights(total: u32)(
        w1 in 0..=total
    ) -> (u32, u32)
    {
        (w1, total - w1)
    }
}

prop_compose! {
    /// Generates a random `CanisterConfig` using reasonable ranges of values; receivers is empty
    /// and assumed to be populated manually.
    fn arb_canister_config(max_payload_bytes: u32, max_calls_per_heartbeat: u32)(
        max_call_bytes in 0..=max_payload_bytes,
        max_reply_bytes in 0..=max_payload_bytes,
        calls_per_heartbeat in 0..=max_calls_per_heartbeat,
        max_timeout_secs in 10..=100_u32,
        (reply_weight, downstream_call_weight) in arb_weights(3),
        (best_effort_weight, guaranteed_response_weight) in arb_weights(3),
    ) -> CanisterConfig {
        CanisterConfig::try_new(
            vec![],
            0..=max_call_bytes,
            0..=max_reply_bytes,
            0..=0, // instructions_count
            0..=max_timeout_secs,
            calls_per_heartbeat,
            reply_weight,
            downstream_call_weight,
            best_effort_weight,
            guaranteed_response_weight,
        )
        .expect("bad config inputs")
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]
    #[test]
    fn check_guaranteed_response_message_memory_limits_are_respected(
        seeds in proptest::collection::vec(any::<u64>().no_shrink(), 3),
        config in arb_canister_config(MAX_PAYLOAD_BYTES, 5),
    ) {
        prop_assert!(check_guaranteed_response_message_memory_limits_are_respected_impl(
            30,     // chatter_phase_round_count
            300,    // shutdown_phase_max_rounds
            seeds.as_slice(),
            config,
        ).is_ok());
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
/// downstream calls) this will also induce a lot asychnronous rejections for requests. If any
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

    // Tick until all calls have concluded.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |fixture| {
        fixture.expect_guaranteed_response_message_memory_taken_at_most(
            "Wrap up",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]
    #[test]
    fn check_calls_conclude_with_migrating_canister(
        seed in any::<u64>().no_shrink(),
        config in arb_canister_config(KB as u32, 10),
    ) {
        prop_assert!(check_calls_conclude_with_migrating_canister_impl(
            10,     // chatter_phase_round_count
            300,    // shutdown_phase_max_rounds
            seed,
            config,
        ).is_ok());
    }
}
/*
#[test]
fn playground2() {
    let seed = 17374506990209185531;
    let config = CanisterConfig {
        receivers: vec![],
        call_bytes: (0, 131),
        reply_bytes: (0, 0),
        instructions_count: (0, 0),
        timeout_secs: (0, 37),
        calls_per_heartbeat: 2,
        reply_weight: 3,
        downstream_call_weight: 0,
        best_effort_weight: 0,
        guaranteed_response_weight: 3,
    };

    if let Err((error_msg, mut nfo)) = check_calls_conclude_with_migrating_canister_impl(
        10,     // chatter_phase_round_count
        300,    // shutdown_phase_max_rounds
        seed,
        config,
    ) {
        assert!(
            false,
            "{}\n\n{:#?}\n\n{:#?}",
            error_msg,
            nfo.records.pop_first().unwrap(),
            nfo
                //.local_env
                .remote_env
                .get_latest_state()
                .canister_states
                .iter()
                .filter_map(|(canister_id, canister_state)| Some(
                    (canister_id, (canister_state.system_state.get_status(), canister_state.system_state.queues()))
                ))

                //.filter_map(|(canister_id, canister_state)| canister_state.has_input().then_some(
                //    (canister_id, canister_state.system_state.queues())
                //))
                //.map(|(canister_id, canister_state)| (canister_id, canister_state.has_input()))
                .collect::<BTreeMap<_, _>>(),
        );
//        assert!(false, "{}\n\n{:#?}", error_msg, nfo.remote_env.get_latest_state().canister_states);
    }
    else {
        unreachable!();
    }
}
*/
/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 5 canisters installed. All canisters, except one local canister referred to
/// as `migrating_canister`, are stopped.
///
/// In the first phase a number of rounds are executed on both subnets, including XNet traffic with
/// the `migrating_canister` making random calls to all installed canisters (since all calls are
/// rejected except those to self, downstream calls are disabled).
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

    // Tick until all calls have concluded.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |_| Ok(()))
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

    /// Helper function for setting canister state elements; returns the current element before
    /// setting it.
    ///
    /// Panics if `canister` is not installed in `Self`.
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
    /// Panics if `canister` is not installed in `Self`.
    pub fn set_config(&self, canister: CanisterId, config: CanisterConfig) -> CanisterConfig {
        self.set_canister_state(canister, "set_config", config)
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

    /// Starts `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn start_canister(&self, canister: CanisterId) {
        self.get_env(&canister).start_canister(canister).unwrap();
    }

    /// Puts `canister` into `Stopping` state.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn stop_canister_non_blocking(&self, canister: CanisterId) -> MessageId {
        self.get_env(&canister).stop_canister_non_blocking(canister)
    }

    /// Calls the `stop_chatter()` function on `canister`.
    ///
    /// This stops the canister from making calls, downstream and from the heartbeat.
    pub fn stop_chatter(&self, canister: CanisterId) {
        self.get_env(&canister)
            .execute_ingress(canister, "stop_chatter", candid::Encode!().unwrap())
            .unwrap();
    }

    /// Queries the records from `canister`.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn query_records(
        &self,
        canister: CanisterId,
    ) -> Result<BTreeMap<u32, CanisterRecord>, UserError> {
        let dummy_msg = candid::Encode!().unwrap();
        let reply = self
            .get_env(&canister)
            .query(canister, "records", dummy_msg)?;
        Ok(candid::Decode!(&reply.bytes(), BTreeMap<u32, CanisterRecord>).unwrap())
    }

    /// Force queries the records from `canister` by first attempting to query them; if it fails, start
    /// the canister and try querying them again.
    ///
    /// Note: If the canister is configured to make calls, starting it will trigger calls before
    ///       the records are returned.
    ///
    /// Panics if `canister` is not installed in `Self`.
    pub fn force_query_records(&self, canister: CanisterId) -> BTreeMap<u32, CanisterRecord> {
        match self.query_records(canister) {
            Err(_) => {
                self.start_canister(canister);
                self.query_records(canister).unwrap()
            }
            Ok(records) => records,
        }
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
                    .map(|canister| extract_metrics(&self.force_query_records(canister)))
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
                    .map(|canister| (canister, self.force_query_records(canister)))
                    .collect(),
                local_env: self.local_env.clone(),
                remote_env: self.remote_env.clone(),
            },
        ))
    }
}

/// Returned by `Fixture::failed_with_reason()`.
#[allow(dead_code)]
struct DebugInfo {
    pub records: BTreeMap<CanisterId, BTreeMap<u32, CanisterRecord>>,
    pub local_env: Arc<StateMachine>,
    pub remote_env: Arc<StateMachine>,
}

/// Installs a 'random-traffic-test-canister' in `env`.
fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing random-traffic-test-canister failed")
}
