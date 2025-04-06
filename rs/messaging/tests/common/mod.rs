use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{
    embedders::{BestEffortResponsesFeature, Config as EmbeddersConfig, FeatureFlags},
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig},
};
use ic_interfaces_certified_stream_store::EncodeStreamError;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, UserError};
use ic_types::{
    messages::{MessageId, RequestOrResponse},
    xnet::StreamHeader,
    Cycles,
};
use proptest::prop_compose;
use random_traffic_test::{extract_metrics, Config as CanisterConfig, Record as CanisterRecord};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const LOCAL_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_0;
const REMOTE_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_1;

pub const KB: u64 = 1024;
pub const MB: u64 = KB * KB;

prop_compose! {
    /// Generates a random `Config` using reasonable ranges of values; receivers is empty
    /// and assumed to be populated manually.
    pub fn arb_canister_config(max_payload_bytes: u32, max_calls_per_heartbeat: u32)(
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

/// Config for `SubnetPair` including message memory limits
/// and number of canisters for each subnet.
#[derive(Debug)]
pub struct SubnetPairConfig {
    pub local_canisters_count: u64,
    pub local_max_instructions_per_round: u64,
    pub local_message_memory_capacity: u64,
    pub remote_canisters_count: u64,
    pub remote_max_instructions_per_round: u64,
    pub remote_message_memory_capacity: u64,
}

impl Default for SubnetPairConfig {
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

impl SubnetPairConfig {
    /// Generates a `StateMachineConfig` using defaults for an application subnet, except for the
    /// subnet message memory capacity and the maximum number of instructions per round.
    pub fn state_machine_config(
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
                guaranteed_response_message_memory_capacity: subnet_message_memory_capacity.into(),
                best_effort_message_memory_capacity: subnet_message_memory_capacity.into(),
                embedders_config: EmbeddersConfig {
                    feature_flags: FeatureFlags {
                        best_effort_responses: BestEffortResponsesFeature::Enabled,
                        ..FeatureFlags::default()
                    },
                    ..EmbeddersConfig::default()
                },
                ..HypervisorConfig::default()
            },
        )
    }

    /// Generates a `StateMachineConfig` for the `local_env`.
    pub fn local_state_machine_config(&self) -> StateMachineConfig {
        Self::state_machine_config(
            self.local_message_memory_capacity,
            self.local_max_instructions_per_round,
        )
    }

    /// Generates a `StateMachineConfig` for the `remote_env`.
    pub fn remote_state_machine_config(&self) -> StateMachineConfig {
        Self::state_machine_config(
            self.remote_message_memory_capacity,
            self.remote_max_instructions_per_round,
        )
    }
}

/// Wrapper for two references to state machines, one considered the `local subnet` and the
/// other the `remote subnet`, each subnet can have an arbitrary amount of
/// 'random-traffic-canisters' installed.
///
/// The purpose of this struct is to simulate bidirectional XNet traffic between canisters
/// installed on different subnets.
#[derive(Debug, Clone)]
pub struct SubnetPair {
    pub local_env: Arc<StateMachine>,
    pub local_canisters: BTreeSet<CanisterId>,
    pub remote_env: Arc<StateMachine>,
    pub remote_canisters: BTreeSet<CanisterId>,
}

impl SubnetPair {
    /// Generates a local environment with `local_canisters_count` canisters installed;
    /// and a remote environment with `remote_canisters_count` canisters installed.
    pub fn new(config: SubnetPairConfig) -> Self {
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

    /// Returns a `SubnetPair` with exactly one local canister and one remote canister installed;
    /// using default settings.
    ///
    /// Returns the local canister ID, the remote canister ID and the subnets.
    pub fn with_local_and_remote_canister() -> (CanisterId, CanisterId, Self) {
        let subnets = Self::new(SubnetPairConfig {
            local_canisters_count: 1,
            remote_canisters_count: 1,
            ..SubnetPairConfig::default()
        });
        (
            *subnets.local_canister(),
            *subnets.remote_canister(),
            subnets,
        )
    }

    /// Returns all canisters installed in the fixture, local canisters first.
    pub fn canisters(&self) -> Vec<CanisterId> {
        self.local_canisters
            .iter()
            .cloned()
            .chain(self.remote_canisters.iter().cloned())
            .collect()
    }

    /// Returns a reference to the first local canister ID. Note: Even though more complex
    /// traffic can be simulated with multiple canisters installed on `Self`, it is enough
    /// for most purposes to look at the first local canister.
    ///
    /// # Panics
    ///
    /// This function panics of no canisters exist on the `local_env`.
    pub fn local_canister(&self) -> &CanisterId {
        self.local_canisters.first().unwrap()
    }

    /// Returns a reference to the first remote canister ID. Note: Even though more complex
    /// traffic can be simulated with multiple canisters installed on `Self`, it is enough
    /// for most purposes to look at the first remote canister.
    ///
    /// # Panics
    ///
    /// This function panics of no canisters exist on the `remote_env`.
    pub fn remote_canister(&self) -> &CanisterId {
        self.remote_canisters.first().unwrap()
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
    fn set_canister_state<T>(&self, canister: &CanisterId, method: &str, item: T) -> T
    where
        T: candid::CandidType + for<'a> candid::Deserialize<'a>,
    {
        let msg = candid::Encode!(&item).unwrap();
        let reply = self
            .get_env(canister)
            .execute_ingress(*canister, method, msg)
            .unwrap();
        candid::Decode!(&reply.bytes(), T).unwrap()
    }

    /// Sets the `CanisterConfig` in `canister`; returns the current config.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn set_config(&self, canister: &CanisterId, config: CanisterConfig) -> CanisterConfig {
        self.set_canister_state(canister, "set_config", config)
    }

    /// Seeds the `Rng` in `canister`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn seed_rng(&self, canister: &CanisterId, seed: u64) {
        let msg = candid::Encode!(&seed).unwrap();
        self.get_env(canister)
            .execute_ingress(*canister, "seed_rng", msg)
            .unwrap();
    }

    /// Starts `canister`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn start_canister(&self, canister: &CanisterId) {
        self.get_env(canister).start_canister(*canister).unwrap();
    }

    /// Puts `canister` into `Stopping` state.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn stop_canister_non_blocking(&self, canister: &CanisterId) -> MessageId {
        self.get_env(canister).stop_canister_non_blocking(*canister)
    }

    /// Calls the `stop_chatter()` function on `canister`.
    ///
    /// This stops the canister from making calls, downstream and from the heartbeat.
    pub fn stop_chatter(&self, canister: &CanisterId) -> CanisterConfig {
        let reply = self
            .get_env(canister)
            .execute_ingress(*canister, "stop_chatter", candid::Encode!().unwrap())
            .unwrap();
        candid::Decode!(&reply.bytes(), CanisterConfig).unwrap()
    }

    /// Queries `canister` for `method`.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn query<T: candid::CandidType + for<'a> candid::Deserialize<'a>>(
        &self,
        canister: &CanisterId,
        method: &str,
    ) -> Result<T, UserError> {
        let reply = self
            .get_env(canister)
            .query(*canister, method, candid::Encode!().unwrap())?;
        Ok(candid::Decode!(&reply.bytes(), T).unwrap())
    }

    /// Force queries `canister` for `method` by first attempting to a normal query; if it fails, start
    /// the canister and try again.
    ///
    /// Panics if `canister` is not installed in `self`.
    pub fn force_query<T: candid::CandidType + for<'a> candid::Deserialize<'a>>(
        &self,
        canister: &CanisterId,
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

    /// Returns the bytes consumed by guaranteed response messages: `(local_env, remote_env)`.
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

    /// Returns the bytes consumed by best-effort messages: `(local_env, remote_env)`.
    pub fn best_effort_message_memory_taken(&self) -> (NumBytes, NumBytes) {
        (
            self.local_env
                .get_latest_state()
                .best_effort_message_memory_taken(),
            self.remote_env
                .get_latest_state()
                .best_effort_message_memory_taken(),
        )
    }

    /// Tests the local and remote guaranteed response and best-effort message
    /// memory usage against the provided upper limits.
    pub fn expect_message_memory_taken_at_most(
        &self,
        label: impl std::fmt::Display,
        local_memory_upper_limit: u64,
        remote_memory_upper_limit: u64,
    ) -> Result<(), (String, DebugInfo)> {
        let (local_memory, remote_memory) = self.guaranteed_response_message_memory_taken();
        if local_memory > local_memory_upper_limit.into() {
            return self.failed_with_reason(format!(
                "{}: local guaranteed response message memory exceeds limit",
                label
            ));
        }
        if remote_memory > remote_memory_upper_limit.into() {
            return self.failed_with_reason(format!(
                "{}: remote guaranteed response message memory exceeds limit",
                label
            ));
        }

        let (local_memory, remote_memory) = self.best_effort_message_memory_taken();
        if local_memory > local_memory_upper_limit.into() {
            return self.failed_with_reason(format!(
                "{}: local best-effort message memory exceeds limit",
                label
            ));
        }
        if remote_memory > remote_memory_upper_limit.into() {
            return self.failed_with_reason(format!(
                "{}: remote best-effort message memory exceeds limit",
                label
            ));
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
        for (from_env, into_env) in [
            (&self.local_env, &self.remote_env),
            (&self.remote_env, &self.local_env),
        ] {
            if induct_from_head_of_stream(from_env, into_env, None).is_err() {
                into_env.tick();
            }
            into_env.advance_time(std::time::Duration::from_secs(1));
        }
    }

    /// Repeatedly calls `f()` until it returns `Ok(true)` indicating 'job done' or else
    /// the job is considered failed after `max_ticks` iterations.
    pub fn repeat<F>(&self, max_ticks: usize, f: F) -> Result<(), (String, DebugInfo)>
    where
        F: Fn() -> Result<bool, (String, DebugInfo)>,
    {
        for _ in 0..max_ticks {
            if let Ok(true) = f() {
                return Ok(());
            }
        }
        self.failed_with_reason(format!("no exit condition in {max_ticks} ticks"))
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
        F: Fn() -> Result<(), (String, DebugInfo)>,
    {
        // Tick until no more call contexts are observed.
        self.repeat(max_ticks, || {
            self.tick();

            perform_checks()?;

            Ok(self.open_call_contexts_count().values().sum::<usize>() == 0)
        })?;

        // Check the records agree on 'no pending calls'.
        if self
            .canisters()
            .iter()
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
        self.expect_message_memory_taken_at_most(
            "Message memory used despite no open call contexts",
            0,
            0,
        )
    }

    /// Migrates `canister` from `local_env` to `remote_env`.
    ///
    /// # Panics if `canister` does not exist on `local_env`.
    pub fn migrate_local_canister_to_remote_env(&mut self, canister: &CanisterId) {
        for env in [&self.local_env, &self.remote_env] {
            env.prepare_canister_migrations(
                *canister..=*canister,
                LOCAL_SUBNET_ID,
                REMOTE_SUBNET_ID,
            );
            env.reroute_canister_range(*canister..=*canister, REMOTE_SUBNET_ID);
        }
        self.local_env
            .move_canister_state_to(&self.remote_env, *canister)
            .unwrap();

        assert!(self.local_canisters.remove(canister));
        assert!(self.remote_canisters.insert(*canister));
    }

    /// Returns the canister records, the latest local state and the latest remote state.
    pub fn failed_with_reason(&self, reason: impl Into<String>) -> Result<(), (String, DebugInfo)> {
        Err((
            reason.into(),
            DebugInfo {
                traps: self.gather_canister_trap_messages(),
                records: self
                    .canisters()
                    .iter()
                    .map(|canister| (*canister, self.force_query(canister, "records")))
                    .collect(),
                subnets: self.clone(),
            },
        ))
    }

    /// Returns a vector of non-empty canister trap error messages
    /// together with the corresponding canister ID.
    pub fn gather_canister_trap_messages(&self) -> Vec<(CanisterId, String)> {
        self.canisters()
            .iter()
            .filter_map(|canister| {
                let err_msg: String = self.force_query(canister, "heartbeat_trap_msg");
                (!err_msg.is_empty()).then_some((*canister, err_msg))
            })
            .collect()
    }
}

/// Returned by `SubnetPair::failed_with_reason()`.
#[allow(dead_code)]
pub struct DebugInfo {
    pub traps: Vec<(CanisterId, String)>,
    pub records: BTreeMap<CanisterId, BTreeMap<u32, CanisterRecord>>,
    pub subnets: SubnetPair,
}

/// Installs a 'random-traffic-test-canister' in `env`.
pub fn install_canister(env: &StateMachine, wasm: Vec<u8>) -> CanisterId {
    env.install_canister_with_cycles(wasm, Vec::new(), None, Cycles::new(u128::MAX / 2))
        .expect("Installing random-traffic-test-canister failed")
}

/// Returns a snapshot of an XNet stream as stream header and a vec of messages.
pub fn stream_snapshot(
    from_subnet: &StateMachine,
    to_subnet: &StateMachine,
) -> Option<(StreamHeader, Vec<RequestOrResponse>)> {
    from_subnet
        .get_latest_state()
        .get_stream(&to_subnet.get_subnet_id())
        .map(|stream| {
            (
                stream.header(),
                stream
                    .messages()
                    .iter()
                    .map(|(_, msg)| msg.clone())
                    .collect::<Vec<_>>(),
            )
        })
}

/// Inducts data from the head of the stream on `from_env` into `into_env`.
pub fn induct_from_head_of_stream(
    from_env: &StateMachine,
    into_env: &StateMachine,
    msg_limit: Option<usize>,
) -> Result<(), EncodeStreamError> {
    let xnet_payload = from_env.generate_xnet_payload(
        into_env.get_subnet_id(),
        None, // witness_begin
        None, // msg_begin
        msg_limit,
        None, // byte_limit,
    )?;
    into_env.execute_block_with_xnet_payload(xnet_payload);
    Ok(())
}
