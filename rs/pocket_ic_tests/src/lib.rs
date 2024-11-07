pub use ic_error_types::{ErrorCode, UserError};
pub use ic_types::ingress::WasmResult;

use candid::Principal;
use ic_management_canister_types::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterStatusResultV2, InstallCodeArgs,
    ProvisionalCreateCanisterWithCyclesArgs, UpdateSettingsArgs,
};
use ic_protobuf::state::ingress::v1::ErrorCode as ErrorCodeProto;
use ic_types::messages::MessageId;
use ic_types::time::Time;
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use pocket_ic::call_candid_as;
use pocket_ic::common::rest::SubnetKind;
use pocket_ic::common::rest::{RawEffectivePrincipal, RawMessageId};
use pocket_ic::management_canister::CanisterIdRecord;
use pocket_ic::{CallError, PocketIc, PocketIcBuilder};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

pub struct StateMachine {
    sm: PocketIc,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self {
            sm: PocketIc::new(),
        }
    }
}

pub struct StateMachineBuilder {
    sm_builder: PocketIcBuilder,
    has_subnet: bool,
    time: Option<SystemTime>,
}

impl Default for StateMachineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachineBuilder {
    pub fn new() -> Self {
        Self {
            sm_builder: PocketIcBuilder::new(),
            has_subnet: false,
            time: None,
        }
    }

    pub fn with_nns_subnet(self) -> Self {
        Self {
            sm_builder: self.sm_builder.with_nns_subnet(),
            has_subnet: true,
            ..self
        }
    }

    pub fn with_ii_subnet(self) -> Self {
        Self {
            sm_builder: self.sm_builder.with_ii_subnet(),
            has_subnet: true,
            ..self
        }
    }

    pub fn with_bitcoin_subnet(self) -> Self {
        Self {
            sm_builder: self.sm_builder.with_bitcoin_subnet(),
            has_subnet: true,
            ..self
        }
    }

    pub fn with_fiduciary_subnet(self) -> Self {
        Self {
            sm_builder: self.sm_builder.with_fiduciary_subnet(),
            has_subnet: true,
            ..self
        }
    }

    pub fn with_state_machine_state_dir(
        self,
        subnet_kind: SubnetKind,
        subnet_id: SubnetId,
        state_dir: PathBuf,
        nonmainnet_features: bool,
    ) -> Self {
        Self {
            sm_builder: self
                .sm_builder
                .with_subnet_state(subnet_kind, subnet_id.get().0, state_dir)
                .with_nonmainnet_features(nonmainnet_features),
            has_subnet: true,
            ..self
        }
    }

    pub fn with_time(self, time: Time) -> Self {
        Self {
            time: Some(time.into()),
            ..self
        }
    }

    pub fn with_current_time(self) -> Self {
        Self {
            time: Some(SystemTime::now()),
            ..self
        }
    }

    pub fn build(self) -> StateMachine {
        let mut sm_builder = self.sm_builder;
        if !self.has_subnet {
            sm_builder = sm_builder.with_application_subnet();
        }
        let sm = sm_builder.build();
        if let Some(time) = self.time {
            sm.set_time(time);
        }
        StateMachine { sm }
    }
}

fn wasm_result(wasm_result: pocket_ic::WasmResult) -> WasmResult {
    match wasm_result {
        pocket_ic::WasmResult::Reply(bytes) => WasmResult::Reply(bytes),
        pocket_ic::WasmResult::Reject(msg) => WasmResult::Reject(msg),
    }
}

fn user_error(user_error: pocket_ic::UserError) -> UserError {
    let error_code = ErrorCodeProto::try_from(user_error.code as i32)
        .unwrap()
        .try_into()
        .unwrap();
    UserError::new(error_code, user_error.description)
}

impl StateMachine {
    pub fn num_running_canisters(&self) -> u64 {
        let metrics = self
            .sm
            .get_subnet_metrics(self.get_subnet_id().get().0)
            .unwrap();
        metrics.num_canisters
    }

    pub fn new() -> Self {
        StateMachineBuilder::new().build()
    }

    pub fn canister_memory_usage_bytes(&self) -> u64 {
        let metrics = self
            .sm
            .get_subnet_metrics(self.get_subnet_id().get().0)
            .unwrap();
        metrics.canister_state_bytes
    }

    pub fn get_subnet_id(&self) -> SubnetId {
        let topology = self.sm.topology();
        SubnetId::from(PrincipalId(
            topology
                .get_subnet(self.get_default_effective_canister_id())
                .unwrap(),
        ))
    }

    pub fn get_default_effective_canister_id(&self) -> Principal {
        self.sm.topology().default_effective_canister_id.into()
    }

    pub fn get_subnet_ids(&self) -> Vec<SubnetId> {
        vec![self.get_subnet_id()]
    }

    pub fn tick(&self) {
        self.sm.tick();
    }

    pub fn set_time(&self, time: SystemTime) {
        self.sm.set_time(time)
    }

    pub fn time(&self) -> SystemTime {
        self.sm.get_time()
    }

    pub fn get_time(&self) -> Time {
        self.time().try_into().unwrap()
    }

    pub fn advance_time(&self, amount: Duration) {
        self.sm.advance_time(amount)
    }

    pub fn root_key_der(&self) -> Vec<u8> {
        self.sm.root_key().unwrap()
    }

    pub fn await_ingress(
        &self,
        msg_id: MessageId,
        _max_ticks: usize,
    ) -> Result<WasmResult, UserError> {
        let raw_msg_id = RawMessageId {
            message_id: msg_id.as_bytes().to_vec(),
            effective_principal: RawEffectivePrincipal::CanisterId(
                self.sm.topology().default_effective_canister_id.canister_id,
            ),
        };
        self.sm
            .await_call(raw_msg_id)
            .map(wasm_result)
            .map_err(user_error)
    }

    pub fn install_wasm_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        post_process(call_candid_as(
            &self.sm,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.get().to_vec()),
            Principal::anonymous(),
            "install_code",
            (InstallCodeArgs {
                mode,
                canister_id: canister_id.into(),
                wasm_module: wasm,
                arg: payload,
                sender_canister_version: None,
                compute_allocation: None,
                memory_allocation: None,
            },),
        ))
    }

    pub fn create_canister(&self, settings: Option<CanisterSettingsArgs>) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            &self.sm,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            Principal::anonymous(),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterWithCyclesArgs {
                amount: None,
                settings,
                specified_id: None,
                sender_canister_version: None,
            },),
        )
        .map(|(x,)| x)
        .unwrap();
        CanisterId::unchecked_from_principal(PrincipalId(canister_id))
    }

    pub fn create_canister_with_cycles(
        &self,
        specified_id: Option<PrincipalId>,
        cycles: Cycles,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            &self.sm,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            Principal::anonymous(),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(cycles.into()),
                settings,
                specified_id,
                sender_canister_version: None,
            },),
        )
        .map(|(x,)| x)
        .unwrap();
        CanisterId::unchecked_from_principal(PrincipalId(canister_id))
    }

    pub fn install_canister(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister(settings);
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)?;
        Ok(canister_id)
    }

    pub fn install_canister_wat(
        &self,
        wat: &str,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        self.install_canister(wat::parse_str(wat).expect("invalid WAT"), payload, settings)
            .unwrap()
    }

    pub fn install_existing_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)
    }

    pub fn install_existing_canister_wat(
        &self,
        canister_id: CanisterId,
        wat: &str,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_existing_canister(
            canister_id,
            wat::parse_str(wat).expect("invalid WAT"),
            payload,
        )
    }

    pub fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        post_process(
            self.sm
                .reinstall_canister(canister_id.into(), module, payload, None),
        )
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

    pub fn upgrade_canister_wat(&self, canister_id: CanisterId, wat: &str, payload: Vec<u8>) {
        self.install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Upgrade,
            wat::parse_str(wat).expect("invalid WAT"),
            payload,
        )
        .unwrap();
    }

    pub fn update_settings(
        &self,
        canister_id: &CanisterId,
        settings: CanisterSettingsArgs,
    ) -> Result<(), UserError> {
        let update_settings_args = UpdateSettingsArgs {
            canister_id: canister_id.get(),
            settings,
            sender_canister_version: None,
        };
        post_process(call_candid_as::<_, ()>(
            &self.sm,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.get().to_vec()),
            Principal::anonymous(),
            "update_settings",
            (update_settings_args,),
        ))
    }

    pub fn canister_exists(&self, canister: CanisterId) -> bool {
        self.sm.canister_exists(canister.into())
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
            .query_call(
                receiver.get().0,
                sender.0,
                &method.to_string(),
                method_payload,
            )
            .map(wasm_result)
            .map_err(user_error)
    }

    pub fn execute_ingress_as_with_effective_canister_id(
        &self,
        effective_canister_id: PrincipalId,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.sm
            .update_call_with_effective_principal(
                canister_id.into(),
                RawEffectivePrincipal::CanisterId(effective_canister_id.to_vec()),
                sender.into(),
                &method.to_string(),
                payload,
            )
            .map(wasm_result)
            .map_err(user_error)
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
            .update_call(canister_id.get().0, sender.0, &method.to_string(), payload)
            .map(wasm_result)
            .map_err(user_error)
    }

    pub fn start_canister(&self, canister_id: CanisterId) -> Result<(), UserError> {
        self.start_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    pub fn start_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<(), UserError> {
        post_process(
            self.sm
                .start_canister(canister_id.into(), Some(sender.into())),
        )
    }

    pub fn stop_canister(&self, canister_id: CanisterId) -> Result<(), UserError> {
        self.stop_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    pub fn stop_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<(), UserError> {
        post_process(
            self.sm
                .stop_canister(canister_id.into(), Some(sender.into())),
        )
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
        let res = call_candid_as::<_, (CanisterStatusResultV2,)>(
            &self.sm,
            sender.0,
            RawEffectivePrincipal::CanisterId(canister_id.get().to_vec()),
            Principal::anonymous(),
            "canister_status",
            (CanisterIdRecord {
                canister_id: canister_id.into(),
            },),
        );
        match res {
            Ok(res) => Ok(Ok(res.0)),
            Err(CallError::Reject(msg)) => Ok(Err(msg)),
            Err(CallError::UserError(err)) => Err(user_error(err)),
        }
    }

    pub fn delete_canister(&self, canister_id: CanisterId) -> Result<(), UserError> {
        post_process(self.sm.delete_canister(canister_id.into(), None))
    }

    pub fn uninstall_code(&self, canister_id: CanisterId) -> Result<(), UserError> {
        post_process(self.sm.uninstall_canister(canister_id.into(), None))
    }

    pub fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        self.sm.cycle_balance(canister_id.into())
    }

    pub fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
        self.sm.add_cycles(canister_id.into(), amount)
    }
}

fn post_process(res: Result<(), CallError>) -> Result<(), UserError> {
    match res {
        Ok(()) => Ok(()),
        Err(CallError::Reject(msg)) => panic!("Unexpected reject with message {}", msg),
        Err(CallError::UserError(err)) => Err(user_error(err)),
    }
}
