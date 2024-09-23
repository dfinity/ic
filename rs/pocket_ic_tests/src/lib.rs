pub use ic_state_machine_tests::{
    CanisterId, Cycles, ErrorCode, PrincipalId, StateMachineConfig, StateMachineNode,
    StateMachineStateDir, SubmitIngressError, Time, UserError, WasmResult,
};

use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterStatusResultV2, MessageId, SubnetId,
};
use std::time::{Duration, SystemTime};

#[derive(Default)]
pub struct StateMachine {
    sm: ic_state_machine_tests::StateMachine,
}

#[derive(Default)]
pub struct StateMachineBuilder {
    sm_builder: ic_state_machine_tests::StateMachineBuilder,
}

impl StateMachineBuilder {
    // Tricky!!!
    // subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE
    // rate_limiting_of_instructions: FlagStatus::Disabled
    pub fn with_config(self, config: Option<StateMachineConfig>) -> Self {
        Self {
            sm_builder: self.sm_builder.with_config(config),
        }
    }
    // need to make subnet IDs configurable for all subnet kinds in PocketIC
    pub fn with_routing_table(self, routing_table: RoutingTable) -> Self {
        Self {
            sm_builder: self.sm_builder.with_routing_table(routing_table),
        }
    }

    // can be refactored into specifying the desired PocketIC subnet kind, e.g., II or fiduciary
    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            sm_builder: self.sm_builder.with_subnet_type(subnet_type),
        }
    }
    pub fn with_subnet_size(self, subnet_size: usize) -> Self {
        Self {
            sm_builder: self.sm_builder.with_subnet_size(subnet_size),
        }
    }
    pub fn with_extra_canister_range(self, id_range: std::ops::RangeInclusive<CanisterId>) -> Self {
        Self {
            sm_builder: self.sm_builder.with_extra_canister_range(id_range),
        }
    }

    pub fn new() -> Self {
        Self {
            sm_builder: ic_state_machine_tests::StateMachineBuilder::new(),
        }
    }

    pub fn with_state_machine_state_dir(self, state_dir: Box<dyn StateMachineStateDir>) -> Self {
        Self {
            sm_builder: self.sm_builder.with_state_machine_state_dir(state_dir),
        }
    }

    pub fn with_time(self, time: Time) -> Self {
        Self {
            sm_builder: self.sm_builder.with_time(time),
        }
    }

    pub fn with_current_time(self) -> Self {
        let time = Time::try_from(SystemTime::now()).expect("Current time conversion failed");
        self.with_time(time)
    }

    pub fn with_nns_subnet_id(self, nns_subnet_id: SubnetId) -> Self {
        Self {
            sm_builder: self.sm_builder.with_nns_subnet_id(nns_subnet_id),
        }
    }

    pub fn build(self) -> StateMachine {
        StateMachine {
            sm: self.sm_builder.build(),
        }
    }
}

impl StateMachine {
    // tricky!!!
    pub fn run_until_completion(&self, max_ticks: usize) {
        self.sm.run_until_completion(max_ticks)
    }
    // tricky!!!
    pub fn num_running_canisters(&self) -> u64 {
        self.sm.num_running_canisters()
    }
    // tricky!!
    pub fn canister_memory_usage_bytes(&self) -> u64 {
        self.sm.canister_memory_usage_bytes()
    }

    pub fn new() -> Self {
        StateMachineBuilder::new().build()
    }

    pub fn get_subnet_id(&self) -> SubnetId {
        self.sm.get_subnet_id()
    }

    pub fn get_subnet_ids(&self) -> Vec<SubnetId> {
        let res = self.sm.get_subnet_ids();
        assert_eq!(res, vec![self.sm.get_subnet_id()]);
        res
    }

    pub fn tick(&self) {
        self.sm.tick();
    }

    pub fn set_time(&self, time: SystemTime) {
        self.sm.set_time(time)
    }

    pub fn time(&self) -> SystemTime {
        self.sm.time()
    }

    pub fn time_of_next_round(&self) -> SystemTime {
        self.sm.time_of_next_round()
    }

    pub fn get_time(&self) -> Time {
        self.sm.get_time()
    }

    pub fn get_time_of_next_round(&self) -> Time {
        self.sm.get_time_of_next_round()
    }

    pub fn advance_time(&self, amount: Duration) {
        self.sm.advance_time(amount)
    }

    pub fn root_key_der(&self) -> Vec<u8> {
        self.sm.root_key_der()
    }

    pub fn await_ingress(
        &self,
        msg_id: MessageId,
        max_ticks: usize,
    ) -> Result<WasmResult, UserError> {
        self.sm.await_ingress(msg_id, max_ticks)
    }

    pub fn install_wasm_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.sm
            .install_wasm_in_mode(canister_id, mode, wasm, payload)
    }

    pub fn create_canister(&self, settings: Option<CanisterSettingsArgs>) -> CanisterId {
        self.sm.create_canister(settings)
    }

    pub fn create_canister_with_cycles(
        &self,
        specified_id: Option<PrincipalId>,
        cycles: Cycles,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        self.sm
            .create_canister_with_cycles(specified_id, cycles, settings)
    }

    pub fn install_canister(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> Result<CanisterId, UserError> {
        self.sm.install_canister(module, payload, settings)
    }

    pub fn install_existing_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.sm
            .install_existing_canister(canister_id, module, payload)
    }

    pub fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.sm.reinstall_canister(canister_id, module, payload)
    }

    pub fn install_canister_with_cycles(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
        cycles: Cycles,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister_with_cycles(None, cycles, settings);
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)?;
        Ok(canister_id)
    }

    pub fn upgrade_canister(
        &self,
        canister_id: CanisterId,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Upgrade, wasm, payload)
    }

    pub fn update_settings(
        &self,
        canister_id: &CanisterId,
        settings: CanisterSettingsArgs,
    ) -> Result<(), UserError> {
        self.sm.update_settings(canister_id, settings)
    }

    pub fn canister_exists(&self, canister: CanisterId) -> bool {
        self.sm.canister_exists(canister)
    }

    pub fn query(
        &self,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.query_as(
            PrincipalId::new_anonymous(),
            receiver,
            method,
            method_payload,
        )
    }

    pub fn query_as(
        &self,
        sender: PrincipalId,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.sm
            .query_as_with_delegation(sender, receiver, method, method_payload, None)
    }

    pub fn execute_ingress(
        &self,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress_as(PrincipalId::new_anonymous(), canister_id, method, payload)
    }

    pub fn execute_ingress_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.sm
            .execute_ingress_as(sender, canister_id, method, payload)
    }

    pub fn start_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.start_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    pub fn start_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<WasmResult, UserError> {
        self.sm.start_canister_as(sender, canister_id)
    }

    pub fn stop_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.stop_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    pub fn stop_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<WasmResult, UserError> {
        self.sm.stop_canister_as(sender, canister_id)
    }

    pub fn canister_status(
        &self,
        canister_id: CanisterId,
    ) -> Result<Result<CanisterStatusResultV2, String>, UserError> {
        self.canister_status_as(PrincipalId::new_anonymous(), canister_id)
    }

    pub fn canister_status_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<Result<CanisterStatusResultV2, String>, UserError> {
        self.sm.canister_status_as(sender, canister_id)
    }

    pub fn delete_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.sm.delete_canister(canister_id)
    }

    pub fn uninstall_code(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.sm.uninstall_code(canister_id)
    }

    pub fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        self.sm.cycle_balance(canister_id)
    }

    pub fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
        self.sm.add_cycles(canister_id, amount)
    }
}
