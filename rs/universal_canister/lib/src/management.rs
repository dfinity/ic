use crate::Call;
use crate::CallInterface;
use candid::{CandidType, Deserialize, Encode, Principal};
use std::convert::TryFrom;

/// Creates a new canister.
///
/// Example usage:
///
/// ```
/// use ic_universal_canister::{wasm, management, CallInterface};
/// use ic_types::Cycles;
///
/// // Create a new canister with some cycles.
/// wasm().call(management::create_canister(Cycles::from(2_000_000_000_000u64).into_parts()));
///
/// // Create a new canister with a specific freezing threshold.
/// wasm().call(
///   management::create_canister(Cycles::from(2_000_000_000_000u64).into_parts())
///      .with_freezing_threshold(1234)
/// );
///
/// // Create a new canister with custom callbacks.
/// wasm().call(management::create_canister(Cycles::from(2_000_000_000_000u64).into_parts())
///   .on_reply(wasm().noop()) // custom on_reply
///   .on_reject(wasm().noop()) // custom on_reject
///   .on_cleanup(wasm().noop())); // custom on_cleanup
/// ```
pub fn create_canister(cycles: (u64, u64)) -> CandidCallBuilder<CreateCanisterArgs> {
    CandidCallBuilder {
        args: CreateCanisterArgs { settings: None },
        call: Call::new(Principal::management_canister(), "create_canister").cycles(cycles),
    }
}

/// Installs code onto a canister.
///
/// Example usage:
///
/// ```
/// use ic_universal_canister::{wasm, management, CallInterface};
///
/// let wasm_module = &[1, 2, 3]; // Some wasm module.
/// let canister_id = &[1, 2, 3]; // Some canister ID.
///
/// // Install a wasm_module on the canister.
/// wasm().call(management::install_code(canister_id, wasm_module));
///
/// // Reinstall a wasm_module on the canister.
/// wasm().call(
///   management::install_code(canister_id, wasm_module)
///      .with_mode(management::InstallMode::Reinstall)
/// );
///
/// // Reinstall a wasm_module with a new memory allocation.
/// wasm().call(
///   management::install_code(canister_id, wasm_module)
///      .with_mode(management::InstallMode::Reinstall)
///      .with_memory_allocation(1000)
/// );
///
/// // Upgrade a canister with custom callbacks
/// wasm().call(
///   management::install_code(canister_id, wasm_module)
///      .with_mode(management::InstallMode::Upgrade)
///      .on_reply(wasm().noop()) // custom on_reply
///      .on_reject(wasm().noop()) // custom on_reject
///      .on_cleanup(wasm().noop())); // custom on_cleanup
/// ```
pub fn install_code<C: AsRef<[u8]>, M: AsRef<[u8]>>(
    canister_id: C,
    wasm_module: M,
) -> CandidCallBuilder<InstallCodeArgs> {
    CandidCallBuilder {
        args: InstallCodeArgs::new(
            Principal::try_from(canister_id.as_ref()).unwrap(),
            wasm_module,
        ),
        call: Call::new(Principal::management_canister(), "install_code"),
    }
}

pub fn uninstall_code<C: AsRef<[u8]>>(canister_id: C) -> Call {
    call_with_canister_id("uninstall_code", canister_id)
}

pub fn canister_status<C: AsRef<[u8]>>(canister_id: C) -> Call {
    call_with_canister_id("canister_status", canister_id)
}

pub fn stop_canister<C: AsRef<[u8]>>(canister_id: C) -> Call {
    call_with_canister_id("stop_canister", canister_id)
}

pub fn start_canister<C: AsRef<[u8]>>(canister_id: C) -> Call {
    call_with_canister_id("start_canister", canister_id)
}

pub fn delete_canister<C: AsRef<[u8]>>(canister_id: C) -> Call {
    call_with_canister_id("delete_canister", canister_id)
}

/// Updates a canister's settings.
///
/// Example usage:
///
/// ```
/// use ic_universal_canister::{wasm, management, CallInterface};
///
/// let canister_id = &[1, 2, 3]; // Some canister ID.
///
/// wasm().call(
///   management::update_settings(canister_id)
///      .with_controllers(vec![canister_id, canister_id])
///      .with_freezing_threshold(1234)
/// );
/// ```
pub fn update_settings<C: AsRef<[u8]>>(canister_id: C) -> CandidCallBuilder<UpdateSettings> {
    CandidCallBuilder {
        args: UpdateSettings {
            canister_id: Principal::try_from(canister_id.as_ref()).unwrap(),
            settings: CanisterSettings::default(),
        },
        call: Call::new(Principal::management_canister(), "update_settings"),
    }
}

/// A builder for calls with candid payloads.
pub struct CandidCallBuilder<Args: CandidType> {
    args: Args,
    call: Call,
}

impl<Args: CandidType> CallInterface for CandidCallBuilder<Args> {
    fn call(&mut self) -> &mut Call {
        &mut self.call
    }
}

impl CandidCallBuilder<CreateCanisterArgs> {
    pub fn with_freezing_threshold<T: Into<candid::Nat>>(mut self, threshold: T) -> Self {
        let mut settings = self.args.settings.unwrap_or_default();
        settings.freezing_threshold = Some(threshold.into());
        self.args.settings = Some(settings);
        self
    }

    pub fn with_compute_allocation<T: Into<candid::Nat>>(mut self, allocation: T) -> Self {
        let mut settings = self.args.settings.unwrap_or_default();
        settings.compute_allocation = Some(allocation.into());
        self.args.settings = Some(settings);
        self
    }

    pub fn with_memory_allocation<T: Into<candid::Nat>>(mut self, allocation: T) -> Self {
        let mut settings = self.args.settings.unwrap_or_default();
        settings.memory_allocation = Some(allocation.into());
        self.args.settings = Some(settings);
        self
    }

    pub fn with_controller<P: AsRef<[u8]>>(mut self, controller: P) -> Self {
        let mut settings = self.args.settings.unwrap_or_default();
        settings.controller = Some(Principal::try_from(controller.as_ref()).unwrap());
        self.args.settings = Some(settings);
        self
    }

    pub fn with_controllers<P: AsRef<[u8]>>(mut self, controllers: Vec<P>) -> Self {
        let mut settings = self.args.settings.unwrap_or_default();
        settings.controllers = Some(
            controllers
                .iter()
                .map(|controller| Principal::try_from(controller.as_ref()).unwrap())
                .collect(),
        );
        self.args.settings = Some(settings);
        self
    }
}

impl CandidCallBuilder<InstallCodeArgs> {
    pub fn with_mode(mut self, mode: InstallMode) -> Self {
        self.args.mode = mode;
        self
    }

    pub fn with_compute_allocation(mut self, allocation: u64) -> Self {
        self.args.compute_allocation = Some(candid::Nat::from(allocation));
        self
    }

    pub fn with_memory_allocation(mut self, allocation: u64) -> Self {
        self.args.memory_allocation = Some(candid::Nat::from(allocation));
        self
    }
}

// NOTE: This code is copied from above. Need to figure out a way to avoid the
// duplication.
impl CandidCallBuilder<UpdateSettings> {
    pub fn with_freezing_threshold<T: Into<candid::Nat>>(mut self, threshold: T) -> Self {
        let mut settings = self.args.settings;
        settings.freezing_threshold = Some(threshold.into());
        self.args.settings = settings;
        self
    }

    pub fn with_compute_allocation<T: Into<candid::Nat>>(mut self, allocation: T) -> Self {
        let mut settings = self.args.settings;
        settings.compute_allocation = Some(allocation.into());
        self.args.settings = settings;
        self
    }

    pub fn with_memory_allocation<T: Into<candid::Nat>>(mut self, allocation: T) -> Self {
        let mut settings = self.args.settings;
        settings.memory_allocation = Some(allocation.into());
        self.args.settings = settings;
        self
    }

    pub fn with_controller<P: AsRef<[u8]>>(mut self, controller: P) -> Self {
        let mut settings = self.args.settings;
        settings.controller = Some(Principal::try_from(controller.as_ref()).unwrap());
        self.args.settings = settings;
        self
    }

    pub fn with_controllers<P: AsRef<[u8]>>(mut self, controllers: Vec<P>) -> Self {
        let mut settings = self.args.settings;
        settings.controller = None;
        settings.controllers = Some(
            controllers
                .iter()
                .map(|controller| Principal::try_from(controller.as_ref()).unwrap())
                .collect(),
        );
        self.args.settings = settings;
        self
    }
}

impl<Args: CandidType> From<CandidCallBuilder<Args>> for Call {
    fn from(val: CandidCallBuilder<Args>) -> Self {
        val.call.with_payload(Encode!(&val.args).unwrap())
    }
}

#[derive(CandidType, Deserialize)]
pub enum InstallMode {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade,
}

#[derive(CandidType)]
pub struct InstallCodeArgs {
    mode: InstallMode,
    canister_id: Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
    compute_allocation: Option<candid::Nat>,
    memory_allocation: Option<candid::Nat>,
}

impl InstallCodeArgs {
    fn new<M: AsRef<[u8]>>(canister_id: Principal, wasm_module: M) -> Self {
        let mut wasm_module_vec = vec![];
        wasm_module_vec.extend_from_slice(wasm_module.as_ref());
        Self {
            mode: InstallMode::Install,
            canister_id,
            wasm_module: wasm_module_vec,
            arg: Vec::new(),
            compute_allocation: None,
            memory_allocation: None,
        }
    }
}

#[derive(CandidType)]
pub struct CreateCanisterArgs {
    settings: Option<CanisterSettings>,
}

#[derive(CandidType)]
pub struct UpdateSettings {
    canister_id: Principal,
    settings: CanisterSettings,
}

#[derive(CandidType, Default)]
pub struct CanisterSettings {
    pub controller: Option<Principal>,
    pub controllers: Option<Vec<Principal>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
}

// A call to the management canister with the following candid args:
//   (record {canister_id : canister_id})
fn call_with_canister_id<C: AsRef<[u8]>>(method_name: &str, canister_id: C) -> Call {
    #[derive(CandidType)]
    struct Args {
        canister_id: Principal,
    }

    Call::new(Principal::management_canister(), method_name).with_payload(
        Encode!(&Args {
            canister_id: Principal::try_from(canister_id.as_ref()).unwrap(),
        })
        .unwrap(),
    )
}
