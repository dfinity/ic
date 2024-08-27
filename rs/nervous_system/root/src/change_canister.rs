use crate::LOG_PREFIX;
use candid::{CandidType, Deserialize, Encode, Principal};
use dfn_core::api::CanisterId;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_crypto_sha2::Sha256;
use ic_management_canister_types::{CanisterInstallMode, InstallCodeArgs, IC_00};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{
        canister_status, CanisterStatusResultFromManagementCanister, CanisterStatusType,
    },
};
use ic_nervous_system_runtime::Runtime;
use serde::Serialize;

/// Argument to the similarly-named methods on the NNS and SNS root canisters.
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChangeCanisterRequest {
    /// Whether the canister should first be stopped before the install_code
    /// method is called.
    ///
    /// The value depend on the canister. For instance:
    /// * Canisters that don't emit any inter-canister call, such as the
    ///   registry canister, have no reason to be stopped before being upgraded.
    /// * Canisters that emit inter-canister call are at risk of undefined
    ///   behavior if a callback is delivered to them after the upgrade.
    pub stop_before_installing: bool,

    // -------------------------------------------------------------------- //

    // The fields below are copied from ic_types::ic00::InstallCodeArgs.
    /// Whether to Reinstall or Upgrade a canister.
    ///
    /// Using mode `Reinstall` on a stateful canister is very dangerous;
    /// however, this field is provided so that repairing a nervous system
    /// (e.g. NNS) is possible even under extreme circumstances.
    pub mode: CanisterInstallMode,

    /// The id of the canister to change.
    pub canister_id: CanisterId,

    /// The new wasm module to ship.
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,

    /// The new canister args
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,

    #[serde(serialize_with = "serialize_optional_nat")]
    pub compute_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub memory_allocation: Option<candid::Nat>,
}

impl ChangeCanisterRequest {
    fn format(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("ChangeCanisterRequest")
            .field("stop_before_installing", &self.stop_before_installing)
            .field("mode", &self.mode)
            .field("canister_id", &self.canister_id)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("arg_sha256", &format!("{:x?}", arg_sha))
            .field("compute_allocation", &self.compute_allocation)
            .field("memory_allocation", &self.memory_allocation)
            .finish()
    }
}

impl std::fmt::Debug for ChangeCanisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl std::fmt::Display for ChangeCanisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl ChangeCanisterRequest {
    pub fn new(
        stop_before_installing: bool,
        mode: CanisterInstallMode,
        canister_id: CanisterId,
    ) -> Self {
        Self {
            stop_before_installing,
            mode,
            canister_id,
            wasm_module: Vec::new(),
            arg: Encode!().unwrap(),
            compute_allocation: None,
            memory_allocation: None,
        }
    }

    pub fn with_memory_allocation(mut self, n: u64) -> Self {
        self.memory_allocation = Some(candid::Nat::from(n));
        self
    }

    pub fn with_wasm(mut self, wasm_module: Vec<u8>) -> Self {
        self.wasm_module = wasm_module;
        self
    }

    pub fn with_arg(mut self, arg: Vec<u8>) -> Self {
        self.arg = arg;
        self
    }

    pub fn with_mode(mut self, mode: CanisterInstallMode) -> Self {
        self.mode = mode;
        self
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct AddCanisterRequest {
    /// A unique name for this canister.
    pub name: String,

    // The field belows are copied from ic_types::ic00::InstallCodeArgs.
    /// The new wasm module to ship.
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,

    #[serde(serialize_with = "serialize_optional_nat")]
    pub compute_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub memory_allocation: Option<candid::Nat>,

    pub initial_cycles: u64,
}

impl AddCanisterRequest {
    fn format(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("AddCanisterRequest")
            .field("name", &self.name)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("arg_sha256", &format!("{:x?}", arg_sha))
            .field("compute_allocation", &self.compute_allocation)
            .field("memory_allocation", &self.memory_allocation)
            .field("initial_cycles", &self.initial_cycles)
            .finish()
    }
}

impl std::fmt::Debug for AddCanisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl std::fmt::Display for AddCanisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

// The action to take on the canister.
#[derive(candid::CandidType, Serialize, candid::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanisterAction {
    Stop,
    Start,
}

/// Argument to the similarly-named methods on the NNS and SNS root canisters.
#[derive(candid::CandidType, Serialize, candid::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopOrStartCanisterRequest {
    pub canister_id: CanisterId,
    pub action: CanisterAction,
}

pub async fn change_canister<Rt>(request: ChangeCanisterRequest) -> Result<(), String>
where
    Rt: Runtime,
{
    let canister_id = request.canister_id;
    let stop_before_installing = request.stop_before_installing;

    if stop_before_installing {
        let stop_result = stop_canister::<Rt>(canister_id).await;
        if stop_result.is_err() {
            println!(
                "{}change_canister: Failed to stop canister, trying to restart...",
                LOG_PREFIX
            );
            return match start_canister::<Rt>(canister_id).await {
                Ok(_) => {
                    Err(format!("Failed to stop canister {canister_id:?}. After failing to stop, attempted to start it, and succeeded in that."))
                }
                Err(_) => {
                    println!("{}change_canister: Failed to restart canister.", LOG_PREFIX);
                    Err(format!("Failed to stop canister {canister_id:?}. After failing to stop, attempted to start it, and failed in that."))
                }
            };
        }
    }

    // Ship code to the canister.
    //
    // Note that there's no guarantee that the canister to install/reinstall/upgrade
    // is actually stopped here, even if stop_before_installing is true. This is
    // because there could be a concurrent request to restart it. This could be
    // guaranteed with a "stopped precondition" in the management canister, or
    // with some locking here.
    let res = install_code(request.clone()).await;
    // For once, we don't want to unwrap the result here. The reason is that, if the
    // installation failed (e.g., the wasm was rejected because it's invalid),
    // then we want to restart the canister. So we just keep the res to be
    // unwrapped later.

    // Restart the canister, if needed
    if stop_before_installing {
        start_canister::<Rt>(canister_id).await.unwrap();
    }

    // Check the result of the install_code
    res.map_err(|(rejection_code, message)| format!("Attempt to call install_code with request {request:?} failed with code {rejection_code:?}: {message}"))
}

/// Calls the "install_code" method of the management canister.
async fn install_code(request: ChangeCanisterRequest) -> ic_cdk::api::call::CallResult<()> {
    let ChangeCanisterRequest {
        mode,
        canister_id,
        wasm_module,
        arg,
        compute_allocation,
        memory_allocation,

        stop_before_installing: _,
    } = request;

    let canister_id = canister_id.get();
    let sender_canister_version = Some(ic_cdk::api::canister_version());

    let install_code_args = InstallCodeArgs {
        mode,
        canister_id,
        wasm_module,
        arg,
        compute_allocation,
        memory_allocation,
        sender_canister_version,
    };
    // Warning: despite dfn_core::call returning a Result, it actually traps when
    // the callee traps! Use the public cdk instead, which does not have this
    // issue.
    ic_cdk::api::call::call(
        Principal::try_from(IC_00.get().as_slice()).unwrap(),
        "install_code",
        (&install_code_args,),
    )
    .await
}

pub async fn start_canister<Rt>(canister_id: CanisterId) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    // start_canister returns the candid empty type, which cannot be parsed using
    // dfn_candid::candid
    let res: Result<(), (i32, String)> = Rt::call_with_cleanup(
        CanisterId::ic_00(),
        "start_canister",
        (CanisterIdRecord::from(canister_id),),
    )
    .await;

    if res.is_ok() {
        println!("{}start_canister call successful. {res:?}", LOG_PREFIX);
    }
    res
}

/// Stops the given canister, and polls until the `Stopped` state is reached.
///
/// Warning: there's no guarantee that this ever finishes!
/// TODO(IC-1099)
pub async fn stop_canister<Rt>(canister_id: CanisterId) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    // stop_canister returns the candid empty type, which cannot be parsed using
    // dfn_candid::candid
    Rt::call_with_cleanup(
        CanisterId::ic_00(),
        "stop_canister",
        (CanisterIdRecord::from(canister_id),),
    )
    .await?;

    loop {
        let status: CanisterStatusResultFromManagementCanister =
            canister_status::<Rt>(CanisterIdRecord::from(canister_id))
                .await
                .unwrap();

        if status.status == CanisterStatusType::Stopped {
            return Ok(());
        }

        println!(
            "{}Waiting for {:?} to stop. Current status: {}",
            LOG_PREFIX, canister_id, status.status
        );
    }
}

// Use a serde field attribute to custom serialize the Nat candid type.
fn serialize_optional_nat<S>(nat: &Option<candid::Nat>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match nat.as_ref() {
        Some(num) => serializer.serialize_str(&num.to_string()),
        None => serializer.serialize_none(),
    }
}
