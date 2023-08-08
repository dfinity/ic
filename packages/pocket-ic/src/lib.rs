use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::{decode_args, encode_args, Principal};
use ic_cdk::api::management_canister::main::{
    CanisterId, CanisterIdRecord, CanisterInstallMode, CanisterSettings, CreateCanisterArgument,
    InstallCodeArgument,
};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

const LOCALHOST: &str = "127.0.0.1";
const POCKET_IC_BIN_PATH: &str = "../../target/debug/pocket-ic-backend";

type InstanceId = String;

// ======================================================================================================
// Code borrowed from https://github.com/dfinity/test-state-machine-client/blob/main/src/lib.rs
// The StateMachine struct is renamed to `PocketIc` and given new interface.
pub struct PocketIc {
    pub instance_id: InstanceId,
    // The PocketIC server's base address.
    daemon_url: Url,
    // The PocketIC server's base address plus "/instance/<instance_id>".
    // All communication with this IC instance goes through this endpoint.
    instance_url: Url,
    reqwest_client: reqwest::blocking::Client,
}

impl PocketIc {
    pub fn new() -> Self {
        // Attempt to start new PocketIC backend if it's not already running.
        let parent_pid = std::os::unix::process::parent_id();
        Command::new(PathBuf::from(POCKET_IC_BIN_PATH))
            .arg("--pid")
            .arg(parent_pid.to_string())
            .spawn()
            .expect("Failed to start PocketIC binary");
        // Use the parent process ID to find the PocketIC backend port for this `cargo test` run.
        let daemon_url = Self::get_daemon_url(parent_pid);
        let reqwest_client = reqwest::blocking::Client::new();
        let instance_id = reqwest_client
            .post(daemon_url.join("instance").unwrap())
            .send()
            .expect("Failed to get result")
            .text()
            .expect("Failed to get text");
        println!("Created new instance with id {}", instance_id);
        let instance_url = daemon_url
            .join("instance/")
            .unwrap()
            .join(&instance_id)
            .unwrap();

        Self {
            instance_id,
            daemon_url,
            instance_url,
            reqwest_client,
        }
    }

    fn get_daemon_url(parent_pid: u32) -> Url {
        let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
        let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
        let start = Instant::now();
        loop {
            match ready_file_path.try_exists() {
                Ok(true) => {
                    let port_string = std::fs::read_to_string(port_file_path)
                        .expect("Failed to read port from port file");
                    let port: u16 = port_string.parse().expect("Failed to parse port to number");
                    let daemon_url =
                        Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
                    println!("Found PocketIC running at {}", daemon_url);
                    return daemon_url;
                }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
            if start.elapsed() > Duration::from_secs(5) {
                panic!("Failed to start PocketIC service in time");
            }
        }
    }

    pub fn list_instances(&self) -> Vec<InstanceId> {
        let url = self.daemon_url.join("instance").unwrap();
        let response = reqwest::blocking::Client::new()
            .get(url)
            .send()
            .expect("Failed to get result")
            .text()
            .expect("Failed to get text");
        response.split(", ").map(String::from).collect()
    }

    pub fn send_request(&self, request: Request) -> String {
        self.reqwest_client
            .post(self.instance_url.clone())
            .json(&request)
            .send()
            .expect("Failed to get result")
            .text()
            .expect("Failed to get text")
    }
    // ------------------------------------------------------------------

    pub fn update_call(
        &self,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.call_state_machine(Request::CanisterUpdateCall(CanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            arg,
        }))
    }

    pub fn query_call(
        &self,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.call_state_machine(Request::CanisterQueryCall(CanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            arg,
        }))
    }

    pub fn root_key(&self) -> Vec<u8> {
        self.call_state_machine(Request::RootKey)
    }

    pub fn create_canister(&self, sender: Option<Principal>) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            sender.unwrap_or(Principal::anonymous()),
            "create_canister",
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
            "create_canister",
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

    pub fn canister_exists(&self, canister_id: Principal) -> bool {
        self.call_state_machine(Request::CanisterExists(RawCanisterId::from(canister_id)))
    }

    pub fn time(&self) -> SystemTime {
        self.call_state_machine(Request::Time)
    }

    pub fn set_time(&self, time: SystemTime) {
        self.call_state_machine(Request::SetTime(time))
    }

    pub fn advance_time(&self, duration: Duration) {
        self.call_state_machine(Request::AdvanceTime(duration))
    }

    pub fn tick(&self) {
        self.call_state_machine(Request::Tick)
    }

    pub fn run_until_completion(&self, max_ticks: u64) {
        self.call_state_machine(Request::RunUntilCompletion(RunUntilCompletionArg {
            max_ticks,
        }))
    }

    pub fn stable_memory(&self, canister_id: Principal) -> Vec<u8> {
        self.call_state_machine(Request::ReadStableMemory(RawCanisterId::from(canister_id)))
    }

    pub fn set_stable_memory(&self, canister_id: Principal, data: ByteBuf) {
        self.call_state_machine(Request::SetStableMemory(SetStableMemoryArg {
            canister_id: canister_id.as_slice().to_vec(),
            data,
        }))
    }

    pub fn cycle_balance(&self, canister_id: Principal) -> u128 {
        self.call_state_machine(Request::CyclesBalance(RawCanisterId::from(canister_id)))
    }

    pub fn add_cycles(&self, canister_id: Principal, amount: u128) -> u128 {
        self.call_state_machine(Request::AddCycles(AddCyclesArg {
            canister_id: canister_id.as_slice().to_vec(),
            amount,
        }))
    }

    /// Verifies a canister signature. Returns Ok(()) if the signature is valid.
    /// On error, returns a string describing the error.
    pub fn verify_canister_signature(
        &self,
        msg: Vec<u8>,
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        root_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        self.call_state_machine(Request::VerifyCanisterSig(VerifyCanisterSigArg {
            msg,
            sig,
            pubkey,
            root_pubkey,
        }))
    }

    fn call_state_machine<T: DeserializeOwned>(&self, request: Request) -> T {
        let res = self.send_request(request);
        serde_json::from_str(&res).expect("Failed to decode json")
    }
}

impl Default for PocketIc {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    RootKey,
    Time,
    SetTime(SystemTime),
    AdvanceTime(Duration),
    CanisterUpdateCall(CanisterCall),
    CanisterQueryCall(CanisterCall),
    CanisterExists(RawCanisterId),
    CyclesBalance(RawCanisterId),
    AddCycles(AddCyclesArg),
    SetStableMemory(SetStableMemoryArg),
    ReadStableMemory(RawCanisterId),
    Tick,
    RunUntilCompletion(RunUntilCompletionArg),
    VerifyCanisterSig(VerifyCanisterSigArg),
}

#[derive(Serialize, Deserialize)]
pub struct VerifyCanisterSigArg {
    #[serde(with = "base64")]
    pub msg: Vec<u8>,
    #[serde(with = "base64")]
    pub sig: Vec<u8>,
    #[serde(with = "base64")]
    pub pubkey: Vec<u8>,
    #[serde(with = "base64")]
    pub root_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RunUntilCompletionArg {
    // max_ticks until completion must be reached
    pub max_ticks: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AddCyclesArg {
    // raw bytes of the principal
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub amount: u128,
}

#[derive(Serialize, Deserialize)]
pub struct SetStableMemoryArg {
    // raw bytes of the principal
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub data: ByteBuf,
}

#[derive(Serialize, Deserialize)]
pub struct RawCanisterId {
    // raw bytes of the principal
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
}

impl From<Principal> for RawCanisterId {
    fn from(principal: Principal) -> Self {
        Self {
            canister_id: principal.as_slice().to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CanisterCall {
    #[serde(with = "base64")]
    pub sender: Vec<u8>,
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub method: String,
    #[serde(with = "base64")]
    pub arg: Vec<u8>,
}

/// Call a canister candid query method, anonymous.
pub fn query_candid<Input, Output>(
    env: &PocketIc,
    canister_id: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    query_candid_as(env, canister_id, Principal::anonymous(), method, input)
}

/// Call a canister candid query method, authenticated.
pub fn query_candid_as<Input, Output>(
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
        env.query_call(canister_id, sender, method, bytes)
    })
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

/// User-facing error codes.
///
/// The error codes are currently assigned using an HTTP-like
/// convention: the most significant digit is the corresponding reject
/// code and the rest is just a sequentially assigned two-digit
/// number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    CanisterOutputQueueFull = 201,
    IngressMessageTimeout = 202,
    CanisterQueueNotEmpty = 203,
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
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // E.g. "IC0301"
        write!(f, "IC{:04}", *self as i32)
    }
}

/// The error that is sent back to users of IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in ingress history.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserError {
    pub code: ErrorCode,
    pub description: String,
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // E.g. "IC0301: Canister 42 not found"
        write!(f, "{}: {}", self.code, self.description)
    }
}

#[derive(Debug)]
pub enum CallError {
    Reject(String),
    UserError(UserError),
}

/// This struct describes the different types that executing a Wasm function in
/// a canister can produce
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmResult {
    /// Raw response, returned in a "happy" case
    Reply(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Returned with an error message when the canister decides to reject the
    /// message
    Reject(String),
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

// ===================================

// By default, serde serializes Vec<u8> to a list of numbers, which is inefficient.
// This enables serializing Vec<u8> to a compact base64 representation.
#[allow(deprecated)]
pub mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e))
    }
}
