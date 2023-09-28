//! Temporary client library implementing the V2-version of the REST-API which will eventually
//! replace the existing PocketIc struct.

use crate::{
    common::rest::{
        ApiResponse, CreateInstanceResponse, InstanceId, RawAddCycles, RawCanisterCall,
        RawCanisterId, RawCanisterResult, RawCycles, RawTime, RawWasmResult,
    },
    CallError, UserError, WasmResult,
};
use candid::{
    decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
    Principal,
};
use ic_cdk::api::management_canister::{
    main::{CanisterInstallMode, CreateCanisterArgument, InstallCodeArgument},
    provisional::{CanisterId, CanisterIdRecord, CanisterSettings},
};
use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use std::time::{Duration, SystemTime};

const PROCESSING_TIME_HEADER: &str = "processing-timeout-ms";
const PROCESSING_TIME_VALUE_MS: u64 = 30_000;

pub struct PocketIcV2 {
    pub instance_id: InstanceId,
    server_url: Url,
    reqwest_client: reqwest::blocking::Client,
}

impl PocketIcV2 {
    pub fn new() -> Self {
        let server_url = crate::start_or_reuse_server();
        let reqwest_client = reqwest::blocking::Client::new();
        use CreateInstanceResponse::*;
        let instance_id = match reqwest_client
            .post(server_url.join("v2/instances").unwrap())
            .send()
            .expect("Failed to get result")
            .json::<CreateInstanceResponse>()
            .expect("Could not parse response for create instance request")
        {
            Created { instance_id } => instance_id,
            Error { message } => panic!("{}", message),
        };

        Self {
            instance_id,
            server_url,
            reqwest_client,
        }
    }

    pub fn list_instances() -> Vec<String> {
        let url = crate::start_or_reuse_server().join("v2/instances").unwrap();
        let instances: Vec<String> = reqwest::blocking::Client::new()
            .get(url)
            .send()
            .expect("Failed to get result")
            .json()
            .expect("Failed to get json");
        instances
    }

    pub fn tick(&self) {
        let endpoint = "update/tick";
        self.post::<(), _>(endpoint, "");
    }

    pub fn get_time(&self) -> SystemTime {
        let endpoint = "read/get_time";
        let result: RawTime = self.get(endpoint);
        SystemTime::UNIX_EPOCH + Duration::from_nanos(result.nanos_since_epoch)
    }

    pub fn set_time(&self, time: SystemTime) {
        let endpoint = "update/set_time";
        self.post::<(), _>(
            endpoint,
            RawTime {
                nanos_since_epoch: time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_nanos() as u64,
            },
        );
    }

    pub fn advance_time(&self, duration: Duration) {
        let now = self.get_time();
        self.set_time(now + duration);
    }

    pub fn cycle_balance(&self, canister_id: Principal) -> u128 {
        let endpoint = "read/get_cycles";
        let result: RawCycles = self.post(
            endpoint,
            RawCanisterId {
                canister_id: canister_id.as_slice().to_vec(),
            },
        );
        result.cycles
    }

    pub fn add_cycles(&self, canister_id: Principal, amount: u128) -> u128 {
        let endpoint = "update/add_cycles";
        let result: RawCycles = self.post(
            endpoint,
            RawAddCycles {
                canister_id: canister_id.as_slice().to_vec(),
                amount,
            },
        );
        result.cycles
    }

    pub fn update_call(
        &self,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "update/execute_ingress_message";
        self.canister_call(endpoint, canister_id, sender, method, payload)
    }

    pub fn query_call(
        &self,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "read/query";
        self.canister_call(endpoint, canister_id, sender, method, payload)
    }

    pub fn create_canister(&self, sender: Option<Principal>) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (CreateCanisterArgument { settings: None },),
        )
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    pub fn create_canister_with_settings(
        &self,
        settings: Option<CanisterSettings>,
        sender: Option<Principal>,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (CreateCanisterArgument { settings },),
        )
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    pub fn install_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) {
        call_candid_as::<(InstallCodeArgument,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "install_code",
            (InstallCodeArgument {
                mode: CanisterInstallMode::Install,
                canister_id,
                wasm_module,
                arg,
            },),
        )
        .unwrap();
    }

    pub fn upgrade_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(InstallCodeArgument,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "install_code",
            (InstallCodeArgument {
                mode: CanisterInstallMode::Upgrade,
                canister_id,
                wasm_module,
                arg,
            },),
        )
    }

    pub fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(InstallCodeArgument,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "install_code",
            (InstallCodeArgument {
                mode: CanisterInstallMode::Reinstall,
                canister_id,
                wasm_module,
                arg,
            },),
        )
    }

    pub fn start_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "start_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    pub fn stop_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "stop_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    pub fn delete_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "delete_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    pub fn create_checkpoint(&self) {
        let endpoint = "update/create_checkpoint";
        self.post::<(), &str>(endpoint, "");
    }

    fn instance_url(&self) -> Url {
        let instance_id = self.instance_id;
        self.server_url
            .join("/v2/instances/")
            .unwrap()
            .join(&format!("{instance_id}/"))
            .unwrap()
    }

    fn get<T: DeserializeOwned>(&self, endpoint: &str) -> T {
        let result = self
            .reqwest_client
            .get(self.instance_url().join(endpoint).unwrap())
            .header(PROCESSING_TIME_HEADER, PROCESSING_TIME_VALUE_MS)
            .send()
            .expect("HTTP failure")
            .into();

        match result {
            ApiResponse::Success(t) => t,
            ApiResponse::Error { message } => panic!("{}", message),
            ApiResponse::Busy { state_label, op_id } => {
                panic!("Busy: state_label: {}, op_id: {}", state_label, op_id)
            }
            ApiResponse::Started { state_label, op_id } => {
                panic!("Started: state_label: {}, op_id: {}", state_label, op_id)
            }
        }
    }

    fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: B) -> T {
        let result = self
            .reqwest_client
            .post(self.instance_url().join(endpoint).unwrap())
            .header(PROCESSING_TIME_HEADER, PROCESSING_TIME_VALUE_MS)
            .json(&body)
            .send()
            .expect("HTTP failure");
        match result.into() {
            ApiResponse::Success(t) => t,
            ApiResponse::Error { message } => panic!("{}", message),
            ApiResponse::Busy { state_label, op_id } => {
                panic!("Busy: state_label: {}, op_id: {}", state_label, op_id)
            }
            ApiResponse::Started { state_label, op_id } => {
                panic!("Started: state_label: {}, op_id: {}", state_label, op_id)
            }
        }
    }

    fn canister_call(
        &self,
        endpoint: &str,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
        };

        let result: RawCanisterResult = self.post(endpoint, raw_canister_call);
        match result {
            RawCanisterResult::Ok(raw_wasm_result) => match raw_wasm_result {
                RawWasmResult::Reply(data) => Ok(WasmResult::Reply(data)),
                RawWasmResult::Reject(text) => Ok(WasmResult::Reject(text)),
            },
            RawCanisterResult::Err(user_error) => Err(user_error),
        }
    }
}

impl Default for PocketIcV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PocketIcV2 {
    fn drop(&mut self) {
        self.reqwest_client
            .delete(self.instance_url())
            .send()
            .expect("Failed to send delete request");
    }
}

/// Call a canister candid method, authenticated.
/// The state machine executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid_as<Input, Output>(
    env: &PocketIcV2,
    canister_id: Principal,
    sender: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    with_candid(input, |bytes| {
        env.update_call(canister_id, sender, method, bytes)
    })
}

/// A helper function that we use to implement both [`call_candid`] and
/// [`query_candid`].
pub fn with_candid<Input, Output>(
    input: Input,
    f: impl FnOnce(Vec<u8>) -> Result<WasmResult, UserError>,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    let in_bytes = encode_args(input).expect("failed to encode args");
    match f(in_bytes) {
        Ok(WasmResult::Reply(out_bytes)) => Ok(decode_args(&out_bytes).unwrap_or_else(|e| {
            panic!(
                "Failed to decode response as candid type {}:\nerror: {}\nbytes: {:?}\nutf8: {}",
                std::any::type_name::<Output>(),
                e,
                out_bytes,
                String::from_utf8_lossy(&out_bytes),
            )
        })),
        Ok(WasmResult::Reject(message)) => Err(CallError::Reject(message)),
        Err(user_error) => Err(CallError::UserError(user_error)),
    }
}
