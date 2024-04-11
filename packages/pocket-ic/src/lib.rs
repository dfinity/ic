//! # PocketIC: A Canister Testing Platform
//!
//! PocketIC is the local canister smart contract testing platform for the [Internet Computer](https://internetcomputer.org/).
//!
//! It consists of the PocketIC server, which can run many independent IC instances, and a client library (this crate), which provides an interface to your IC instances.
//!
//! With PocketIC, testing canisters is as simple as calling rust functions. Here is a minimal example:
//!
//! ```rust,no_run
//! use candid::encode_one;
//! use pocket_ic::PocketIc;
//!
//!  #[test]
//!  fn test_counter_canister() {
//!     let pic = PocketIc::new();
//!     // Create an empty canister as the anonymous principal and add cycles.
//!     let canister_id = pic.create_canister();
//!     pic.add_cycles(canister_id, 2_000_000_000_000);
//!  
//!     let wasm_bytes = load_counter_wasm(...);
//!     pic.install_canister(canister_id, wasm_bytes, vec![], None);
//!     // 'inc' is a counter canister method.
//!     call_counter_canister(&pic, canister_id, "inc");
//!     // Check if it had the desired effect.
//!     let reply = call_counter_canister(&pic, canister_id, "read");
//!     assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 1]));
//!  }
//!
//! fn call_counter_canister(pic: &PocketIc, canister_id: CanisterId, method: &str) -> WasmResult {
//!     pic.update_call(canister_id, Principal::anonymous(), method, encode_one(()).unwrap())
//!         .expect("Failed to call counter canister")
//! }
//! ```
//! For more information, see the [README](https://crates.io/crates/pocket-ic).
//!
use crate::common::rest::{
    ApiResponse, BlobCompression, BlobId, CreateInstanceResponse, DtsFlag, ExtendedSubnetConfigSet,
    InstanceId, RawAddCycles, RawCanisterCall, RawCanisterId, RawCanisterResult, RawCycles,
    RawEffectivePrincipal, RawSetStableMemory, RawStableMemory, RawSubnetId, RawTime,
    RawVerifyCanisterSigArg, RawWasmResult, SubnetId, SubnetSpec, Topology,
};
use candid::{
    decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
    CandidType, Nat, Principal,
};
pub use ic_cdk::api::management_canister::main::CanisterSettings;
use ic_cdk::api::management_canister::main::{
    CanisterId, CanisterIdRecord, CanisterInstallMode, CanisterStatusResponse, InstallCodeArgument,
    UpdateSettingsArgument,
};
use reqwest::Url;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime},
};
use tracing::{debug, instrument, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
pub mod common;

// how long a get/post request may retry or poll
const MAX_REQUEST_TIME_MS: u64 = 300_000;
// wait time between polling requests
const POLLING_PERIOD_MS: u64 = 10;

const LOCALHOST: &str = "127.0.0.1";

const LOG_DIR_PATH_ENV_NAME: &str = "POCKET_IC_LOG_DIR";
const LOG_DIR_LEVELS_ENV_NAME: &str = "POCKET_IC_LOG_DIR_LEVELS";

pub struct PocketIcBuilder {
    config: ExtendedSubnetConfigSet,
}

#[allow(clippy::new_without_default)]
impl PocketIcBuilder {
    pub fn new() -> Self {
        Self {
            config: ExtendedSubnetConfigSet::default(),
        }
    }

    pub fn build(self) -> PocketIc {
        PocketIc::from_config(self.config)
    }

    /// Add an empty NNS subnet
    pub fn with_nns_subnet(self) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                nns: Some(SubnetSpec::default()),
                ..self.config
            },
        }
    }

    /// Add an NNS subnet loaded form the given state directory. Note that the provided path must
    /// be accessible for the PocketIC server process.
    ///
    /// `path_to_nns_state` should lead to the `ic_state` directory which is expected to have
    /// the following structure:
    ///
    /// ic_state/
    ///  |-- backups
    ///  |-- checkpoints
    ///  |-- diverged_checkpoints
    ///  |-- diverged_state_markers
    ///  |-- fs_tmp
    ///  |-- page_deltas
    ///  |-- states_metadata.pbuf
    ///  |-- tip
    ///  `-- tmp
    ///
    /// `nns_subnet_id` should be the subnet ID of the NNS subnet in the state under
    /// `path_to_state`, e.g.:
    /// ```rust
    /// PrincipalId(
    ///     candid::Principal::from_text(
    ///         "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
    ///     )
    ///     .unwrap(),
    /// )
    /// .into();
    /// ```
    ///
    /// The value can be obtained, e.g., via the following command:
    /// ```sh
    /// ic-regedit snapshot <path-to-ic_registry_local_store> | jq -r ".nns_subnet_id"
    /// ```
    pub fn with_nns_state(self, nns_subnet_id: SubnetId, path_to_state: PathBuf) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                nns: Some(SubnetSpec::default().with_state_dir(path_to_state, nns_subnet_id)),
                ..self.config
            },
        }
    }

    /// Add an empty sns subnet
    pub fn with_sns_subnet(self) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                sns: Some(SubnetSpec::default()),
                ..self.config
            },
        }
    }
    /// Add an empty internet identity subnet
    pub fn with_ii_subnet(self) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                ii: Some(SubnetSpec::default()),
                ..self.config
            },
        }
    }

    /// Add an empty fiduciary subnet
    pub fn with_fiduciary_subnet(self) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                fiduciary: Some(SubnetSpec::default()),
                ..self.config
            },
        }
    }

    /// Add an empty bitcoin subnet
    pub fn with_bitcoin_subnet(self) -> Self {
        Self {
            config: ExtendedSubnetConfigSet {
                bitcoin: Some(SubnetSpec::default()),
                ..self.config
            },
        }
    }

    /// Add an empty generic system subnet
    pub fn with_system_subnet(mut self) -> Self {
        self.config.system.push(SubnetSpec::default());
        self
    }

    /// Add an empty generic application subnet
    pub fn with_application_subnet(mut self) -> Self {
        self.config.application.push(SubnetSpec::default());
        self
    }

    pub fn with_benchmarking_application_subnet(mut self) -> Self {
        self.config
            .application
            .push(SubnetSpec::default().with_benchmarking_instruction_config());
        self
    }

    pub fn with_dts_flag(mut self, dts_flag: DtsFlag) -> Self {
        self.config = self.config.with_dts_flag(dts_flag);
        self
    }
}
/// Main entry point for interacting with PocketIC.
pub struct PocketIc {
    /// The unique ID of this PocketIC instance.
    pub instance_id: InstanceId,
    topology: Topology,
    server_url: Url,
    reqwest_client: reqwest::blocking::Client,
    _log_guard: Option<WorkerGuard>,
}

impl PocketIc {
    /// Creates a new PocketIC instance with a single application subnet on the server.
    /// The server is started if it's not already running.
    pub fn new() -> Self {
        PocketIcBuilder::new().with_application_subnet().build()
    }

    /// Creates a new PocketIC instance with the specified subnet config.
    /// The server is started if it's not already running.
    pub fn from_config(config: impl Into<ExtendedSubnetConfigSet>) -> Self {
        let server_url = crate::start_or_reuse_server();
        Self::from_config_and_server_url(config, server_url)
    }

    /// Creates a new PocketIC instance with the specified subnet config and server url.
    /// This function is intended for advanced users who start the server manually.
    pub fn from_config_and_server_url(
        config: impl Into<ExtendedSubnetConfigSet>,
        server_url: Url,
    ) -> Self {
        let config = config.into();
        config.validate().unwrap();

        let parent_pid = std::os::unix::process::parent_id();
        let log_guard = setup_tracing(parent_pid);

        let reqwest_client = reqwest::blocking::Client::new();
        let (instance_id, topology) = match reqwest_client
            .post(server_url.join("instances").unwrap())
            .json(&config)
            .send()
            .expect("Failed to get result")
            .json::<CreateInstanceResponse>()
            .expect("Could not parse response for create instance request")
        {
            CreateInstanceResponse::Created {
                instance_id,
                topology,
            } => (instance_id, topology),
            CreateInstanceResponse::Error { message } => panic!("{}", message),
        };
        debug!("instance_id={} New instance created.", instance_id);

        Self {
            instance_id,
            topology,
            server_url,
            reqwest_client,
            _log_guard: log_guard,
        }
    }

    /// Returns the topology of the different subnets of this PocketIC instance.
    pub fn topology(&self) -> Topology {
        self.topology.clone()
    }

    /// Upload and store a binary blob to the PocketIC server.
    #[instrument(ret(Display), skip(self, blob), fields(instance_id=self.instance_id, blob_len = %blob.len(), compression = ?compression))]
    pub fn upload_blob(&self, blob: Vec<u8>, compression: BlobCompression) -> BlobId {
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
        BlobId(hash_vec)
    }

    /// Set stable memory of a canister. Optional GZIP compression can be used for reduced
    /// data traffic.
    #[instrument(skip(self, data), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), data_len = %data.len(), compression = ?compression))]
    pub fn set_stable_memory(
        &self,
        canister_id: CanisterId,
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

    /// Get stable memory of a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub fn get_stable_memory(&self, canister_id: CanisterId) -> Vec<u8> {
        let endpoint = "read/get_stable_memory";
        let RawStableMemory { blob } = self.post(
            endpoint,
            RawCanisterId {
                canister_id: canister_id.as_slice().to_vec(),
            },
        );
        blob
    }

    /// List all instances and their status.
    #[instrument(ret)]
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

    /// Verify a canister signature.
    #[instrument(skip_all, fields(instance_id=self.instance_id))]
    pub fn verify_canister_signature(
        &self,
        msg: Vec<u8>,
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        root_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        let url = self.server_url.join("verify_signature").unwrap();
        reqwest::blocking::Client::new()
            .post(url)
            .json(&RawVerifyCanisterSigArg {
                msg,
                sig,
                pubkey,
                root_pubkey,
            })
            .send()
            .expect("Failed to get result")
            .json()
            .expect("Failed to get json")
    }

    /// Make the IC produce and progress by one block.
    /// Note that multiple ticks might be necessary to observe
    /// an expected effect, e.g., if the effect depends on
    /// inter-canister calls or heartbeats.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub fn tick(&self) {
        let endpoint = "update/tick";
        self.post::<(), _>(endpoint, "");
    }

    /// Configures the IC to make progress automatically,
    /// i.e., periodically update the time of the IC
    /// to the real time and execute rounds on the subnets.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub fn auto_progress(&self) {
        let endpoint = "auto_progress";
        self.post::<(), _>(endpoint, "");
    }

    /// Stops automatic progress (see `auto_progress`) on the IC.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub fn stop_progress(&self) {
        let endpoint = "stop_progress";
        self.post::<(), _>(endpoint, "");
    }

    /// Get the root key of this IC instance. Returns `None` if the IC has no NNS subnet.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub fn root_key(&self) -> Option<Vec<u8>> {
        let subnet_id = self.topology.get_nns()?;
        let subnet_id: RawSubnetId = subnet_id.into();
        let endpoint = "read/pub_key";
        let res = self.post::<Vec<u8>, _>(endpoint, subnet_id);
        Some(res)
    }

    /// Get the current time of the IC.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub fn get_time(&self) -> SystemTime {
        let endpoint = "read/get_time";
        let result: RawTime = self.get(endpoint);
        SystemTime::UNIX_EPOCH + Duration::from_nanos(result.nanos_since_epoch)
    }

    /// Set the current time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.instance_id, time = ?time))]
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

    /// Advance the time on the IC on all subnets by some nanoseconds.
    #[instrument(skip(self), fields(instance_id=self.instance_id, duration = ?duration))]
    pub fn advance_time(&self, duration: Duration) {
        let now = self.get_time();
        self.set_time(now + duration);
    }

    /// Get the current cycles balance of a canister.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        let endpoint = "read/get_cycles";
        let result: RawCycles = self.post(
            endpoint,
            RawCanisterId {
                canister_id: canister_id.as_slice().to_vec(),
            },
        );
        result.cycles
    }

    /// Add cycles to a canister. Returns the new balance.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), amount = %amount))]
    pub fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
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

    /// Execute an update call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub fn update_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "update/execute_ingress_message";
        self.canister_call(
            endpoint,
            RawEffectivePrincipal::None,
            canister_id,
            sender,
            method,
            payload,
        )
    }

    /// Execute a query call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub fn query_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "read/query";
        self.canister_call(
            endpoint,
            RawEffectivePrincipal::None,
            canister_id,
            sender,
            method,
            payload,
        )
    }

    /// Request a canister's status.
    #[instrument(skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn canister_status(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<CanisterStatusResponse, CallError> {
        call_candid_as::<(CanisterIdRecord,), (CanisterStatusResponse,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "canister_status",
            (CanisterIdRecord { canister_id },),
        )
        .map(|responses| responses.0)
    }

    /// Create a canister with default settings as the anonymous principal.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id))]
    pub fn create_canister(&self) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            Principal::anonymous(),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings: None,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Create a canister with optional custom settings and a sender.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, settings = ?settings, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn create_canister_with_settings(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Creates a canister with a specific canister ID and optional custom settings.
    /// Returns an error if the canister ID is already in use.
    /// Panics if the canister ID is not contained in any of the subnets.
    ///
    /// The canister ID must be contained in the Bitcoin, Fiduciary, II, SNS or NNS
    /// subnet range, it is not intended to be used on regular app or system subnets,
    /// where it can lead to conflicts on which the function panics.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, canister_id = %canister_id.to_string()))]
    pub fn create_canister_with_id(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        canister_id: CanisterId,
    ) -> Result<CanisterId, String> {
        let res = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                specified_id: Some(canister_id),
                amount: Some(0_u64.into()),
            },),
        )
        .map(|(x,)| x);
        match res {
            Ok(CanisterIdRecord {
                canister_id: actual_canister_id,
            }) => Ok(actual_canister_id),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    /// Create a canister on a specific subnet with optional custom settings.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, subnet_id = %subnet_id.to_string()))]
    pub fn create_canister_on_subnet(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        subnet_id: SubnetId,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::SubnetId(subnet_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Install a WASM module on an existing canister.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
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
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
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

    /// Upgrade a canister with a new WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
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
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
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

    /// Reinstall a canister WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
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
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
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

    /// Set canister's controllers.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn set_controllers(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        new_controllers: Vec<Principal>,
    ) -> Result<(), CallError> {
        let settings = CanisterSettings {
            controllers: Some(new_controllers),
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
        };
        call_candid_as::<(UpdateSettingsArgument,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "update_settings",
            (UpdateSettingsArgument {
                canister_id,
                settings,
            },),
        )
    }

    /// Start a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn start_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "start_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    /// Stop a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn stop_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "stop_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    /// Delete a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn delete_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "delete_canister",
            (CanisterIdRecord { canister_id },),
        )
    }

    /// Checks whether the provided canister exists.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub fn canister_exists(&self, canister_id: CanisterId) -> bool {
        self.get_subnet(canister_id).is_some()
    }

    /// Returns the subnet ID of the canister if the canister exists.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub fn get_subnet(&self, canister_id: CanisterId) -> Option<SubnetId> {
        let endpoint = "read/get_subnet";
        let result: Option<RawSubnetId> = self.post(
            endpoint,
            RawCanisterId {
                canister_id: canister_id.as_slice().to_vec(),
            },
        );
        result.map(|RawSubnetId { subnet_id }| SubnetId::from_slice(&subnet_id))
    }

    fn instance_url(&self) -> Url {
        self.server_url
            .join("/instances/")
            .unwrap()
            .join(&format!("{}/", self.instance_id))
            .unwrap()
    }

    fn get<T: DeserializeOwned>(&self, endpoint: &str) -> T {
        // we may have to try several times if the instance is busy
        let start = std::time::SystemTime::now();
        loop {
            let result = self
                .reqwest_client
                .get(self.instance_url().join(endpoint).unwrap())
                .send()
                .expect("HTTP failure");
            match result.into() {
                ApiResponse::Success(t) => break t,
                ApiResponse::Error { message } => panic!("{}", message),
                ApiResponse::Busy { state_label, op_id } => {
                    debug!(
                        "instance_id={} Instance is busy: state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                }
                ApiResponse::Started { state_label, op_id } => {
                    panic!(
                        "Error: A 'get' should not return Started: state_label: {}, op_id: {}",
                        state_label, op_id
                    )
                }
            }
            if start.elapsed().unwrap() > Duration::from_millis(MAX_REQUEST_TIME_MS) {
                panic!("'get' request to PocketIC server timed out.");
            }
            std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
        }
    }

    fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: B) -> T {
        // we may have to try several times if the instance is busy
        let start = std::time::SystemTime::now();
        loop {
            let result = self
                .reqwest_client
                .post(self.instance_url().join(endpoint).unwrap())
                .json(&body)
                .send()
                .expect("HTTP failure");
            match result.into() {
                ApiResponse::Success(t) => break t,
                ApiResponse::Error { message } => panic!("{}", message),
                ApiResponse::Busy { state_label, op_id } => {
                    debug!(
                        "instance_id={} Instance is busy (with a different computation): state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                }
                ApiResponse::Started { state_label, op_id } => {
                    // once we have a Started reply, we only want to query the result to that computation
                    debug!(
                        "instance_id={} Instance has Started: state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                    loop {
                        std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
                        let result = self
                            .reqwest_client
                            .get(
                                self.server_url
                                    .join(&format!("/read_graph/{}/{}", state_label, op_id))
                                    .unwrap(),
                            )
                            .send()
                            .expect("HTTP failure");
                        match result.into() {
                            ApiResponse::Error { message } => {
                                debug!("Polling has not succeeded yet: {}", message)
                            }
                            ApiResponse::Success(t) => {
                                return t;
                            }
                            ApiResponse::Started { state_label, op_id } => {
                                warn!(
                                    "instance_id={} unexpected Started({} {})",
                                    self.instance_id, state_label, op_id
                                );
                            }
                            ApiResponse::Busy { state_label, op_id } => {
                                warn!(
                                    "instance_id={} unexpected Busy({} {})",
                                    self.instance_id, state_label, op_id
                                );
                            }
                        }
                        if start.elapsed().unwrap() > Duration::from_millis(MAX_REQUEST_TIME_MS) {
                            panic!("'post' request to PocketIC server timed out.");
                        }
                    }
                }
            }
            if start.elapsed().unwrap() > Duration::from_millis(MAX_REQUEST_TIME_MS) {
                panic!("'post' request to PocketIC server timed out.");
            }
            std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
        }
    }

    fn canister_call(
        &self,
        endpoint: &str,
        effective_principal: RawEffectivePrincipal,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
            effective_principal,
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

    fn update_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "update/execute_ingress_message";
        self.canister_call(
            endpoint,
            effective_principal,
            canister_id,
            sender,
            method,
            payload,
        )
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

/// Call a canister candid method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    effective_principal: RawEffectivePrincipal,
    sender: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    with_candid(input, |payload| {
        env.update_call_with_effective_principal(
            canister_id,
            effective_principal,
            sender,
            method,
            payload,
        )
    })
}

/// Call a canister candid method, anonymous.
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    effective_principal: RawEffectivePrincipal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    call_candid_as(
        env,
        canister_id,
        effective_principal,
        Principal::anonymous(),
        method,
        input,
    )
}

/// Call a canister candid query method, anonymous.
pub fn query_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    query_candid_as(env, canister_id, Principal::anonymous(), method, input)
}

/// Call a canister candid query method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub fn query_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
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

/// Call a canister candid update method, anonymous.
pub fn update_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    update_candid_as(env, canister_id, Principal::anonymous(), method, input)
}

/// Call a canister candid update method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub fn update_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
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

fn setup_tracing(pid: u32) -> Option<WorkerGuard> {
    use tracing_subscriber::prelude::*;
    match std::env::var(LOG_DIR_PATH_ENV_NAME).map(std::path::PathBuf::from) {
        Ok(p) => {
            std::fs::create_dir_all(&p).expect("Could not create directory");

            let file_name = format!("pocket_ic_client_{pid}.log");
            let appender = tracing_appender::rolling::never(&p, file_name);
            let (non_blocking_appender, guard) = tracing_appender::non_blocking(appender);
            let log_dir_filter: EnvFilter =
                tracing_subscriber::EnvFilter::try_from_env(LOG_DIR_LEVELS_ENV_NAME)
                    .unwrap_or_else(|_| "trace".parse().unwrap());

            let layers = vec![tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_appender)
                // disable color escape codes in files
                .with_ansi(false)
                .with_filter(log_dir_filter)
                .boxed()];
            let _ = tracing_subscriber::registry().with(layers).try_init();
            Some(guard)
        }
        _ => None,
    }
}

#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
struct ProvisionalCreateCanisterArgument {
    pub settings: Option<CanisterSettings>,
    pub specified_id: Option<Principal>,
    pub amount: Option<Nat>,
}

/// Error type for [`TryFrom<u64>`].
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
#[derive(
    PartialOrd, Ord, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum ErrorCode {
    // 1xx -- `RejectCode::SysFatal`
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    // 2xx -- `RejectCode::SysTransient`
    CanisterQueueFull = 201,
    IngressMessageTimeout = 202,
    CanisterQueueNotEmpty = 203,
    IngressHistoryFull = 204,
    CanisterIdAlreadyExists = 205,
    StopCanisterRequestTimeout = 206,
    CanisterOutOfCycles = 207,
    CertifiedStateUnavailable = 208,
    CanisterInstallCodeRateLimited = 209,
    // 3xx -- `RejectCode::DestinationInvalid`
    CanisterNotFound = 301,
    // 302 (previously `CanisterMethodNotFound`)
    // 303 (previously `CanisterAlreadyInstalled`)
    // 304 (previously `CanisterWasmModuleNotFound`)
    // 4xx -- `RejectCode::CanisterReject`
    // 401
    InsufficientMemoryAllocation = 402,
    InsufficientCyclesForCreateCanister = 403,
    SubnetNotFound = 404,
    CanisterNotHostedBySubnet = 405,
    CanisterRejectedMessage = 406,
    UnknownManagementMessage = 407,
    InvalidManagementPayload = 408,
    // 5xx -- `RejectCode::CanisterError`
    // 501 (previously `CanisterOutOfCycles`)
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
    // 515 (previously `CertifiedStateUnavailable`)
    // 516 (previously `CanisterRejectedMessage`)
    QueryCallGraphLoopDetected = 517,
    // 518 (previously `UnknownManagementMessage`)
    // 519 (previously `InvalidManagementPayload`)
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    // 523 (previously `CanisterInstallCodeRateLimited`)
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
    InsufficientCyclesInMessageMemoryGrow = 535,
    CanisterMethodNotFound = 536,
    CanisterWasmModuleNotFound = 537,
    CanisterAlreadyInstalled = 538,
}

impl TryFrom<u64> for ErrorCode {
    type Error = TryFromError;
    fn try_from(err: u64) -> Result<ErrorCode, Self::Error> {
        match err {
            // 1xx -- `RejectCode::SysFatal`
            101 => Ok(ErrorCode::SubnetOversubscribed),
            102 => Ok(ErrorCode::MaxNumberOfCanistersReached),
            // 2xx -- `RejectCode::SysTransient`
            201 => Ok(ErrorCode::CanisterQueueFull),
            202 => Ok(ErrorCode::IngressMessageTimeout),
            203 => Ok(ErrorCode::CanisterQueueNotEmpty),
            204 => Ok(ErrorCode::IngressHistoryFull),
            205 => Ok(ErrorCode::CanisterIdAlreadyExists),
            206 => Ok(ErrorCode::StopCanisterRequestTimeout),
            207 => Ok(ErrorCode::CanisterOutOfCycles),
            208 => Ok(ErrorCode::CertifiedStateUnavailable),
            209 => Ok(ErrorCode::CanisterInstallCodeRateLimited),
            // 3xx -- `RejectCode::DestinationInvalid`
            301 => Ok(ErrorCode::CanisterNotFound),
            // TODO: RUN-948: Backward compatibility
            302 => Ok(ErrorCode::CanisterMethodNotFound),
            303 => Ok(ErrorCode::CanisterAlreadyInstalled),
            304 => Ok(ErrorCode::CanisterWasmModuleNotFound),
            // 4xx -- `RejectCode::CanisterReject`
            // 401
            402 => Ok(ErrorCode::InsufficientMemoryAllocation),
            403 => Ok(ErrorCode::InsufficientCyclesForCreateCanister),
            404 => Ok(ErrorCode::SubnetNotFound),
            405 => Ok(ErrorCode::CanisterNotHostedBySubnet),
            406 => Ok(ErrorCode::CanisterRejectedMessage),
            407 => Ok(ErrorCode::UnknownManagementMessage),
            408 => Ok(ErrorCode::InvalidManagementPayload),
            // 5xx -- `RejectCode::CanisterError`
            // 501 (previously `CanisterOutOfCycles`)
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
            // TODO: RUN-948: Backward compatibility
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
            535 => Ok(ErrorCode::InsufficientCyclesInMessageMemoryGrow),
            536 => Ok(ErrorCode::CanisterMethodNotFound),
            537 => Ok(ErrorCode::CanisterWasmModuleNotFound),
            538 => Ok(ErrorCode::CanisterAlreadyInstalled),
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

/// The error that is sent back to users from the IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in the ingress history.
#[derive(
    PartialOrd, Ord, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct UserError {
    /// The error code.
    pub code: ErrorCode,
    /// A human-readable description of the error.
    pub description: String,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // E.g. "IC0301: Canister 42 not found"
        write!(f, "{}: {}", self.code, self.description)
    }
}

/// This enum describes the different error types when invoking a canister.
#[derive(Debug, Serialize, Deserialize)]
pub enum CallError {
    Reject(String),
    UserError(UserError),
}

/// This struct describes the different types that executing a WASM function in
/// a canister can produce.
#[derive(PartialOrd, Ord, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmResult {
    /// Raw response, returned in a successful case.
    Reply(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Returned with an error message when the canister decides to reject the
    /// message.
    Reject(String),
}

/// Attempt to start a new PocketIC server if it's not already running.
pub fn start_or_reuse_server() -> Url {
    let bin_path = match std::env::var_os("POCKET_IC_BIN") {
        None => "./pocket-ic".to_string(),
        Some(path) => path
            .clone()
            .into_string()
            .unwrap_or_else(|_| panic!("Invalid string path for {path:?}")),
    };

    if !Path::new(&bin_path).exists() {
        panic!("
Could not find the PocketIC binary.

The PocketIC binary could not be found at {:?}. Please specify the path to the binary with the POCKET_IC_BIN environment variable, \
or place it in your current working directory (you are running PocketIC from {:?}).

To download the binary, please visit https://github.com/dfinity/pocketic."
, &bin_path, &std::env::current_dir().map(|x| x.display().to_string()).unwrap_or_else(|_| "an unknown directory".to_string()));
    }

    // Use the parent process ID to find the PocketIC server port for this `cargo test` run.
    let parent_pid = std::os::unix::process::parent_id();
    let mut cmd = Command::new(PathBuf::from(bin_path));
    cmd.arg("--pid").arg(parent_pid.to_string());
    if std::env::var("POCKET_IC_MUTE_SERVER").is_ok() {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }
    cmd.spawn().expect("Failed to start PocketIC binary");

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
