use crate::common::{
    blob::{BlobCompression, BlobId},
    rest::{
        ApiResponse, CreateInstanceResponse, InstanceId, RawAddCycles, RawCanisterCall,
        RawCanisterId, RawCanisterResult, RawCycles, RawSetStableMemory, RawStableMemory, RawTime,
        RawWasmResult,
    },
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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime},
};
pub mod common;

const PROCESSING_TIME_HEADER: &str = "processing-timeout-ms";
const PROCESSING_TIME_VALUE_MS: u64 = 30_000;
const LOCALHOST: &str = "127.0.0.1";

pub struct PocketIc {
    pub instance_id: InstanceId,
    server_url: Url,
    reqwest_client: reqwest::blocking::Client,
}

impl PocketIc {
    pub fn new() -> Self {
        let server_url = crate::start_or_reuse_server();
        let reqwest_client = reqwest::blocking::Client::new();
        use CreateInstanceResponse::*;
        let instance_id = match reqwest_client
            .post(server_url.join("instances").unwrap())
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

    pub fn upload_blob(&self, blob: Vec<u8>, compression: BlobCompression) -> BlobId {
        // TODO: check if the hash of the blob already exists and if yes, don't upload.
        let mut request = self
            .reqwest_client
            .post(self.server_url.join("blobstore/").unwrap())
            .body(blob);
        if compression == BlobCompression::Gzip {
            request = request.header(reqwest::header::CONTENT_ENCODING, "gzip");
        }
        let blob_id = request
            .send()
            .expect("Failed to get response")
            .text()
            .expect("Failed to get text");

        let hash_vec = hex::decode(blob_id).expect("Failed to decode hex");
        let hash: Result<[u8; 32], Vec<u8>> = hash_vec.try_into();
        BlobId(hash.expect("Invalid hash"))
    }

    pub fn set_stable_memory(
        &self,
        canister_id: Principal,
        data: Vec<u8>,
        compression: BlobCompression,
    ) {
        let blob_id = self.upload_blob(data, compression);
        let endpoint = "update/set_stable_memory";
        self.post::<(), _>(
            endpoint,
            RawSetStableMemory {
                canister_id: canister_id.as_slice().to_vec(),
                blob_id,
            },
        );
    }

    pub fn get_stable_memory(&self, canister_id: Principal) -> Vec<u8> {
        let endpoint = "read/get_stable_memory";
        let RawStableMemory { blob } = self.post(
            endpoint,
            RawCanisterId {
                canister_id: canister_id.as_slice().to_vec(),
            },
        );
        blob
    }

    pub fn list_instances() -> Vec<String> {
        let url = crate::start_or_reuse_server().join("instances").unwrap();
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
            .join("/instances/")
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

impl Default for PocketIc {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PocketIc {
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
    env: &PocketIc,
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

/// Call a canister candid method, anonymous.
/// The state machine executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid<Input, Output>(
    env: &PocketIc,
    canister_id: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    call_candid_as(env, canister_id, Principal::anonymous(), method, input)
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

#[derive(Clone, Copy, Debug)]
pub enum TryFromError {
    ValueOutOfRange(u64),
}

/// User-facing error codes.
///
/// The error codes are currently assigned using an HTTP-like
/// convention: the most significant digit is the corresponding reject
/// code and the rest is just a sequentially assigned two-digit
/// number.
#[derive(PartialOrd, Ord, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    CanisterOutputQueueFull = 201,
    IngressMessageTimeout = 202,
    CanisterQueueNotEmpty = 203,
    IngressHistoryFull = 204,
    CanisterNotFound = 301,
    CanisterMethodNotFound = 302,
    CanisterAlreadyInstalled = 303,
    CanisterWasmModuleNotFound = 304,
    InsufficientMemoryAllocation = 402,
    InsufficientCyclesForCreateCanister = 403,
    SubnetNotFound = 404,
    CanisterNotHostedBySubnet = 405,
    CanisterOutOfCycles = 501,
    CanisterTrapped = 502,
    CanisterCalledTrap = 503,
    CanisterContractViolation = 504,
    CanisterInvalidWasm = 505,
    CanisterDidNotReply = 506,
    CanisterOutOfMemory = 507,
    CanisterStopped = 508,
    CanisterStopping = 509,
    CanisterNotStopped = 510,
    CanisterStoppingCancelled = 511,
    CanisterInvalidController = 512,
    CanisterFunctionNotFound = 513,
    CanisterNonEmpty = 514,
    CertifiedStateUnavailable = 515,
    CanisterRejectedMessage = 516,
    QueryCallGraphLoopDetected = 517,
    UnknownManagementMessage = 518,
    InvalidManagementPayload = 519,
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    CanisterInstallCodeRateLimited = 523,
    CanisterMemoryAccessLimitExceeded = 524,
    QueryCallGraphTooDeep = 525,
    QueryCallGraphTotalInstructionLimitExceeded = 526,
    CompositeQueryCalledInReplicatedMode = 527,
    QueryTimeLimitExceeded = 528,
    QueryCallGraphInternal = 529,
    InsufficientCyclesInComputeAllocation = 530,
    InsufficientCyclesInMemoryAllocation = 531,
    InsufficientCyclesInMemoryGrow = 532,
    ReservedCyclesLimitExceededInMemoryAllocation = 533,
    ReservedCyclesLimitExceededInMemoryGrow = 534,
}

impl TryFrom<u64> for ErrorCode {
    type Error = TryFromError;
    fn try_from(err: u64) -> Result<ErrorCode, Self::Error> {
        match err {
            101 => Ok(ErrorCode::SubnetOversubscribed),
            102 => Ok(ErrorCode::MaxNumberOfCanistersReached),
            201 => Ok(ErrorCode::CanisterOutputQueueFull),
            202 => Ok(ErrorCode::IngressMessageTimeout),
            203 => Ok(ErrorCode::CanisterQueueNotEmpty),
            204 => Ok(ErrorCode::IngressHistoryFull),
            301 => Ok(ErrorCode::CanisterNotFound),
            302 => Ok(ErrorCode::CanisterMethodNotFound),
            303 => Ok(ErrorCode::CanisterAlreadyInstalled),
            304 => Ok(ErrorCode::CanisterWasmModuleNotFound),
            402 => Ok(ErrorCode::InsufficientMemoryAllocation),
            403 => Ok(ErrorCode::InsufficientCyclesForCreateCanister),
            404 => Ok(ErrorCode::SubnetNotFound),
            405 => Ok(ErrorCode::CanisterNotHostedBySubnet),
            501 => Ok(ErrorCode::CanisterOutOfCycles),
            502 => Ok(ErrorCode::CanisterTrapped),
            503 => Ok(ErrorCode::CanisterCalledTrap),
            504 => Ok(ErrorCode::CanisterContractViolation),
            505 => Ok(ErrorCode::CanisterInvalidWasm),
            506 => Ok(ErrorCode::CanisterDidNotReply),
            507 => Ok(ErrorCode::CanisterOutOfMemory),
            508 => Ok(ErrorCode::CanisterStopped),
            509 => Ok(ErrorCode::CanisterStopping),
            510 => Ok(ErrorCode::CanisterNotStopped),
            511 => Ok(ErrorCode::CanisterStoppingCancelled),
            512 => Ok(ErrorCode::CanisterInvalidController),
            513 => Ok(ErrorCode::CanisterFunctionNotFound),
            514 => Ok(ErrorCode::CanisterNonEmpty),
            515 => Ok(ErrorCode::CertifiedStateUnavailable),
            516 => Ok(ErrorCode::CanisterRejectedMessage),
            517 => Ok(ErrorCode::QueryCallGraphLoopDetected),
            518 => Ok(ErrorCode::UnknownManagementMessage),
            519 => Ok(ErrorCode::InvalidManagementPayload),
            520 => Ok(ErrorCode::InsufficientCyclesInCall),
            521 => Ok(ErrorCode::CanisterWasmEngineError),
            522 => Ok(ErrorCode::CanisterInstructionLimitExceeded),
            523 => Ok(ErrorCode::CanisterInstallCodeRateLimited),
            524 => Ok(ErrorCode::CanisterMemoryAccessLimitExceeded),
            525 => Ok(ErrorCode::QueryCallGraphTooDeep),
            526 => Ok(ErrorCode::QueryCallGraphTotalInstructionLimitExceeded),
            527 => Ok(ErrorCode::CompositeQueryCalledInReplicatedMode),
            528 => Ok(ErrorCode::QueryTimeLimitExceeded),
            529 => Ok(ErrorCode::QueryCallGraphInternal),
            530 => Ok(ErrorCode::InsufficientCyclesInComputeAllocation),
            531 => Ok(ErrorCode::InsufficientCyclesInMemoryAllocation),
            532 => Ok(ErrorCode::InsufficientCyclesInMemoryGrow),
            533 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation),
            534 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryGrow),
            _ => Err(TryFromError::ValueOutOfRange(err)),
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // E.g. "IC0301"
        write!(f, "IC{:04}", *self as i32)
    }
}

/// The error that is sent back to users of IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in ingress history.
#[derive(PartialOrd, Ord, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserError {
    pub code: ErrorCode,
    pub description: String,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // E.g. "IC0301: Canister 42 not found"
        write!(f, "{}: {}", self.code, self.description)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CallError {
    Reject(String),
    UserError(UserError),
}

/// This struct describes the different types that executing a Wasm function in
/// a canister can produce
#[derive(PartialOrd, Ord, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmResult {
    /// Raw response, returned in a "happy" case
    Reply(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Returned with an error message when the canister decides to reject the
    /// message
    Reject(String),
}

/// Attempt to start a new PocketIC server if it's not already running.
pub fn start_or_reuse_server() -> Url {
    // Use the parent process ID to find the PocketIC server port for this `cargo test` run.
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let parent_pid = std::os::unix::process::parent_id();
    Command::new(PathBuf::from(bin_path))
        .arg("--pid")
        .arg(parent_pid.to_string())
        .spawn()
        .expect("Failed to start PocketIC binary");

    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
    let start = Instant::now();
    loop {
        match ready_file_path.try_exists() {
            Ok(true) => {
                let port_string = std::fs::read_to_string(port_file_path)
                    .expect("Failed to read port from port file");
                let port: u16 = port_string.parse().expect("Failed to parse port to number");
                return Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    }
}
