use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_config::subnet_config::{CyclesAccountManagerConfig, SchedulerConfig, SubnetConfig};
use ic_management_canister_types_private::CanisterStatusType;
use ic_replicated_state::testing::CanisterQueuesTesting;
use ic_state_machine_tests::{StateMachine, StateMachineConfig, SubmitIngressError, UserError};
use ic_types::{
    Cycles, SubnetId,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{MessageId, RequestOrResponse},
};
use messaging_test::{Call, Reply};
use messaging_test_utils::{from_blob, to_encoded_ingress};
use proptest::prelude::*;
use std::sync::Arc;

pub const KB: u32 = 1024;
pub const MB: u32 = KB * KB;

#[derive(Debug, Clone)]
pub struct TestSubnet {
    pub env: Arc<StateMachine>,
}

/// The status a `Call` submitted as an ingress can have. For documentation see `IngressStatus`
/// and then `IngressState`, except `CallStatus::Rejected` which is mapped to
/// `IngressState::Completed(WasmResult::Reject(_))`.
#[derive(Clone, Debug)]
pub enum CallStatus {
    Unknown,
    Rejected(String),
    Received,
    Failed(UserError),
    Processing,
    Done,
}

impl TestSubnet {
    pub fn new(env: Arc<StateMachine>, canisters_count: u64) -> Self {
        let wasm = Project::new()
            .cargo_bin_with_package(Some("messaging-test"), "messaging-test-canister", &[])
            .bytes();
        for _ in 0..canisters_count {
            env.install_canister_with_cycles(
                wasm.clone(),
                Vec::new(),
                None,
                // Give each subnet `u128::MAX / 10` cycles, to avoid overflows.
                Cycles::new(u128::MAX / 10 / canisters_count as u128),
            )
            .expect("Installing messaging-test-canister failed");
        }
        Self { env }
    }

    /// Executes a round on this state machine and advances time by one second.
    pub fn execute_round(&self) {
        self.env.execute_round();
        self.advance_time_by_secs(1);
    }

    /// Advances time on the `StateMachine` by `duration` seconds.
    pub fn advance_time_by_secs(&self, duration: u64) {
        self.env
            .advance_time(std::time::Duration::from_secs(duration));
    }

    /// Attempts to subnet a new `Call` as ingress.
    pub fn submit_call_as_ingress(&self, call: Call) -> Result<MessageId, SubmitIngressError> {
        let (receiver, payload) = to_encoded_ingress(call);
        self.env.submit_ingress_as(
            PrincipalId::new_anonymous(),
            receiver,
            "handle_call",
            payload,
        )
    }

    /// Same as `submit_call_as_ingress` but from just `receiver` and `downstream_calls`;
    /// this is more convenient to use when spelling out calls manually.
    pub fn submit_ingress(
        &self,
        receiver: CanisterId,
        downstream_calls: Vec<Call>,
    ) -> Result<MessageId, SubmitIngressError> {
        self.submit_call_as_ingress(Call {
            receiver: receiver.into(),
            downstream_calls,
            ..Call::default()
        })
    }

    /// Attempts to get the `Reply` for a `Call` submitted with `id`.
    pub fn try_get_reply(&self, id: &MessageId) -> Result<Reply, CallStatus> {
        match self.env.ingress_status(id) {
            IngressStatus::Unknown => Err(CallStatus::Unknown),
            IngressStatus::Known {
                receiver, state, ..
            } => match state {
                IngressState::Received => Err(CallStatus::Received),
                IngressState::Completed(WasmResult::Reply(blob)) => Ok(from_blob(
                    CanisterId::unchecked_from_principal(receiver),
                    blob,
                )),
                IngressState::Completed(WasmResult::Reject(err)) => Err(CallStatus::Rejected(err)),
                IngressState::Failed(err) => Err(CallStatus::Failed(err)),
                IngressState::Processing => Err(CallStatus::Processing),
                IngressState::Done => Err(CallStatus::Done),
            },
        }
    }

    /// Returns the subnet ID of this `TestSubnet`.
    pub fn id(&self) -> SubnetId {
        self.env.get_subnet_id()
    }

    /// Returns the IDs of the canisters installed at the latest state height.
    pub fn canisters(&self) -> Vec<CanisterId> {
        self.env
            .get_latest_state()
            .canister_states
            .keys()
            .cloned()
            .collect()
    }

    /// Returns the canister first installed on this subnet.
    pub fn principal_canister(&self) -> CanisterId {
        *self
            .env
            .get_latest_state()
            .canister_states
            .keys()
            .next()
            .unwrap()
    }

    /// Returns the status of the canister if any, e.g. running, stopping, stopped.
    pub fn canister_status(&self, id: &CanisterId) -> Option<CanisterStatusType> {
        self.env
            .get_latest_state()
            .canister_states
            .get(id)
            .map(|state| state.status())
    }

    /// Returns a snapshot of an output queue of from_canister` to `to_canister`.
    pub fn output_queue_snapshot(
        &self,
        from_canister: CanisterId,
        to_canister: CanisterId,
    ) -> Option<Vec<RequestOrResponse>> {
        Some(
            self.env
                .get_latest_state()
                .canister_states
                .get(&from_canister)?
                .system_state
                .queues()
                .output_queue_iter_for_testing(&to_canister)?
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    /// Checks whether the subnet has any in-flight messages (in ingress queues,
    /// canister queues, streams or refund pool).
    pub fn has_inflight_messages(&self) -> bool {
        self.env.has_inflight_messages()
    }

    /// Retains only calls that have not yet completed, according to the ingress
    /// history; and runs `f` recursively on the reply of every completed call.
    pub fn check_and_drop_completed<F>(&self, msg_ids: Vec<MessageId>, f: &F) -> Vec<MessageId>
    where
        F: Fn(&Reply, usize) + Clone,
    {
        msg_ids
            .into_iter()
            .filter(|msg_id| {
                self.try_get_reply(msg_id).map_or(true, |reply| {
                    reply.for_each_depth_first(f);
                    false
                })
            })
            .collect()
    }

    /// Attempts to split `self` and returns the split off `Self`.
    pub fn split(&self, seed: [u8; 32]) -> Result<Self, String> {
        self.env.split(seed).map(|env| Self { env })
    }
}

/// Checks for an async rejection in the `Reply` that indicates the canister trapped.
///
/// Intended for use as `f` in `check_and_drop_completed`.
pub fn check_for_traps(reply: &Reply, _call_depth: usize) {
    if let Reply::AsyncReject { reject_message, .. } = reply {
        assert!(!reject_message.contains("trapped"));
    }
}

#[derive(Clone, Debug)]
pub struct TestSubnetConfig {
    pub canisters_count: u64,
    pub max_instructions_per_round: u64,
    pub guaranteed_response_message_memory_capacity: u64,
    pub best_effort_message_memory_capacity: u64,
}

impl Default for TestSubnetConfig {
    fn default() -> Self {
        Self {
            canisters_count: 1,
            max_instructions_per_round: 3_000_000_000,
            guaranteed_response_message_memory_capacity: 50 * MB as u64,
            best_effort_message_memory_capacity: 50 * MB as u64,
        }
    }
}

impl TestSubnetConfig {
    fn state_machine_config(&self) -> StateMachineConfig {
        StateMachineConfig::new(
            SubnetConfig {
                scheduler_config: SchedulerConfig {
                    scheduler_cores: 4,
                    max_instructions_per_round: self.max_instructions_per_round.into(),
                    max_instructions_per_query_message: self.max_instructions_per_round.into(),
                    max_instructions_per_slice: self.max_instructions_per_round.into(),
                    ..SchedulerConfig::application_subnet()
                },
                cycles_account_manager_config: CyclesAccountManagerConfig::application_subnet(),
            },
            HypervisorConfig {
                guaranteed_response_message_memory_capacity: self
                    .guaranteed_response_message_memory_capacity
                    .into(),
                best_effort_message_memory_capacity: self
                    .best_effort_message_memory_capacity
                    .into(),
                ..HypervisorConfig::default()
            },
        )
    }
}

/// Generates two `TestSubnet` from configs.
pub fn two_test_subnets(
    config1: TestSubnetConfig,
    config2: TestSubnetConfig,
) -> (TestSubnet, TestSubnet) {
    let (env1, env2) = ic_state_machine_tests::two_subnets_with_config(
        config1.state_machine_config(),
        config2.state_machine_config(),
    );
    (
        TestSubnet::new(env1, config1.canisters_count),
        TestSubnet::new(env2, config2.canisters_count),
    )
}

#[derive(Clone, Debug)]
pub struct TestSubnetSetup {
    pub subnet1: TestSubnet,
    pub subnet2: TestSubnet,
    pub canisters: Vec<CanisterId>,
}

impl TestSubnetSetup {
    pub fn into_parts(self) -> (TestSubnet, TestSubnet, Vec<CanisterId>) {
        (self.subnet1, self.subnet2, self.canisters)
    }
}

/// A mock arbitrary generator for two `TestSubnet`.
///
/// This is to allow generating two `TestSubnet` in the proptest input generator clause. This is
/// useful because canister IDs are generated when installing canisters, hence to use the IDs in
/// random input generation, the subnets must be created first.
pub fn arb_test_subnets(
    config1: TestSubnetConfig,
    config2: TestSubnetConfig,
) -> impl Strategy<Value = TestSubnetSetup> {
    Just((config1, config2)).prop_map(|(config1, config2)| {
        let (subnet1, subnet2) = two_test_subnets(config1, config2);
        let mut canisters = subnet1.canisters();
        canisters.append(&mut subnet2.canisters());

        TestSubnetSetup {
            subnet1,
            subnet2,
            canisters,
        }
    })
}
