use backoff::backoff::Backoff;
use core::future::Future;
use dfn_candid::{candid, candid_multi_arity};
use ic_canister_client::{Agent, Sender};
use ic_config::{subnet_config::SubnetConfig, Config};
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_replica_tests::*;
pub use ic_test_utilities::assert_utils::assert_balance_equals;
use ic_types::CanisterStatusType::Stopped;
pub use ic_types::{
    ic00,
    ic00::{
        CanisterIdRecord, CanisterStatusResult, InstallCodeArgs,
        ProvisionalCreateCanisterWithCyclesArgs, SetControllerArgs, IC_00,
    },
    ingress::WasmResult,
    messages::CanisterInstallMode,
    CanisterId, Cycles, PrincipalId,
};
use on_wire::{FromWire, IntoWire, NewType};

use std::convert::TryFrom;
use std::env;
use std::fmt;
use std::time::Duration;
use std::{convert::AsRef, fs::File, io::Read, path::Path};
use wabt::wasm2wat;

const MIN_BACKOFF_INTERVAL: Duration = Duration::from_millis(250);
// The value must be smaller than `ic_http_handler::MAX_TCP_PEEK_TIMEOUT_SECS`.
// See VER-1060 for details.
const MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(10);
// The multiplier is chosen such that the sum of all intervals is about 100
// seconds: `sum ~= (1.1^25 - 1) / (1.1 - 1) ~= 98`.
const BACKOFF_INTERVAL_MULTIPLIER: f64 = 1.1;

pub fn get_backoff_policy() -> backoff::ExponentialBackoff {
    backoff::ExponentialBackoff {
        initial_interval: MIN_BACKOFF_INTERVAL,
        current_interval: MIN_BACKOFF_INTERVAL,
        randomization_factor: 0.1,
        multiplier: BACKOFF_INTERVAL_MULTIPLIER,
        start_time: std::time::Instant::now(),
        max_interval: MAX_BACKOFF_INTERVAL,
        max_elapsed_time: None,
        clock: backoff::SystemClock::default(),
    }
}

#[derive(Clone)]
pub struct Wasm(Vec<u8>);

impl Wasm {
    /// Constructs the name of the env variable that will be checked to see if a
    /// pre-compiled binary exists on the filesystem.
    pub fn env_var_name(bin_name: &str, features: &[&str]) -> String {
        let features_part = if features.is_empty() {
            "".into()
        } else {
            format!("_{}", features.join("_"))
        };
        format!("{}{}_WASM_PATH", bin_name, features_part)
            .replace("-", "_")
            .to_uppercase()
    }

    /// If an environment variable with a specific name derived from the binary
    /// name exists, then assumes it is the location of a wasm file and
    /// reads it.
    pub fn from_location_specified_by_env_var(bin_name: &str, features: &[&str]) -> Option<Wasm> {
        let var_name = Wasm::env_var_name(bin_name, features);
        match env::var(&var_name) {
            Ok(path) => {
                eprintln!("Using pre-built binary for {}", bin_name);
                Some(Wasm::from_file(path))
            }
            Err(env::VarError::NotPresent) => {
                if env::var("CI").is_ok() {
                    panic!(
                        "Running on CI and expected canister env var {0}\n\
                         Please add {1} to the following locations:\n\
                        \tgitlab-ci/tools/cargo-build-canisters\n\
                        \tgitlab-ci/src/canisters/wasm-build-functions.sh",
                        var_name, bin_name
                    )
                }
                None
            }
            Err(e) => panic!("When trying to access var {}, got error {}.", var_name, e),
        }
    }

    /// This read's WASM from a file path
    /// This function is very partial and should only be used for testing
    pub fn from_file<P: AsRef<Path>>(f: P) -> Wasm {
        let mut wasm_data = Vec::new();
        let mut wasm_file = File::open(&f).unwrap_or_else(|e| {
            panic!(
                "Could not open wasm file: {} - Error: {}",
                f.as_ref().display(),
                e
            )
        });
        wasm_file
            .read_to_end(&mut wasm_data)
            .unwrap_or_else(|e| panic!("{}", e.to_string()));

        // It's not very consistent with the other `from_xx` functions to
        // optimize wasms here. This is because canisters are not optimized
        // on CI; see OPS-178.
        Wasm::from_bytes(wasm_data).strip_debug_info()
    }

    pub fn from_wat(content: &str) -> Wasm {
        let wasm = wabt::wat2wasm(content).expect("couldn't convert wat to wasm");
        Wasm(wasm)
    }

    pub fn from_bytes<B: Into<Vec<u8>>>(bytes: B) -> Self {
        Self { 0: bytes.into() }
    }

    /// Strip the debug info out of the wasm binaries.
    fn strip_debug_info(self) -> Self {
        // The WAT format does not have any support for custom sections. So they are
        // removed (including any debug info) when converting a WASM to a WAT.
        let bytes =
            wabt::wat2wasm(wasm2wat(self.0).expect("wasm2wat failed")).expect("wat2wasm failed.");
        println!("Compiled canister size: {:?}", bytes.len());
        Self::from_bytes(bytes)
    }

    /// For simple cases, use `install_` instead.
    pub fn install(self, runtime: &Runtime) -> Install<'_> {
        Install {
            runtime,
            mode: CanisterInstallMode::Install,
            wasm: self,
            compute_allocation: None,
            memory_allocation: None,
            query_allocation: None,
            // By default, give the max amount of cycles to the created canister.
            num_cycles: Some(std::u64::MAX),
        }
    }

    pub async fn install_<P: IntoWire>(
        self,
        runtime: &Runtime,
        payload: P,
    ) -> Result<Canister<'_>, String> {
        self.install(runtime).bytes(payload.into_bytes()?).await
    }

    pub fn map(self, f: impl FnOnce(Vec<u8>) -> Vec<u8>) -> Self {
        Wasm(f(self.0))
    }

    /// Extract the wasm bytes.
    pub fn bytes(self) -> Vec<u8> {
        self.0
    }

    /// Installs this wasm onto a pre-existing canister.
    pub async fn install_onto_canister(
        self,
        mut canister: &mut Canister<'_>,
        canister_init_payload: Option<Vec<u8>>,
    ) -> Result<(), String> {
        self.install(canister.runtime)
            .install(&mut canister, canister_init_payload.unwrap_or_default())
            .await
    }

    /// Installs this wasm onto the given pre-existing canister, with
    /// retries.This is especially useful when the runtime is remote, and
    /// for which transient errors may happen.
    pub async fn install_with_retries_onto_canister(
        self,
        mut canister: &mut Canister<'_>,
        canister_init_payload: Option<Vec<u8>>,
        memory_allocation: Option<u64>,
    ) -> Result<(), String> {
        let init_payload = canister_init_payload.unwrap_or_default();
        let runtime = canister.runtime;
        let mut backoff = get_backoff_policy();
        loop {
            let mut install = self
                .clone()
                .install(runtime)
                .with_mode(CanisterInstallMode::Reinstall);

            if let Some(memory_allocation) = memory_allocation {
                install = install.with_memory_allocation(memory_allocation);
            }

            let canister_id = canister.canister_id;
            println!(
                "Attempting to install wasm into canister with ID: {}",
                canister_id
            );
            match install.install(&mut canister, init_payload.clone()).await {
                Ok(()) => {
                    println!(
                        "Successfully installed wasm into canister with ID: {}",
                        canister_id
                    );
                    return Ok(());
                }
                Err(e) => {
                    eprintln!(
                        "Installation of wasm into cansiter with ID: {} failed with: {}",
                        canister_id, e
                    );
                    match backoff.next_backoff() {
                        Some(interval) => {
                            std::thread::sleep(interval);
                        }
                        None => {
                            return Err(format!(
                                "Canister installation timed out. Last error was: {}",
                                e
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// Tries calling function `f` a few times with exponential backoff until it
/// results an `Ok`. If after a while `f` has returned only `Err`s, gives up and
/// returns the last error.
async fn execute_with_retries<F, T, E, Fut>(f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut backoff = get_backoff_policy();
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => match backoff.next_backoff() {
                Some(interval) => {
                    eprintln!("Retrying due to: {}", &e);
                    std::thread::sleep(interval);
                }
                None => {
                    eprintln!("Failed due to: {}", &e);
                    return Err(e);
                }
            },
        }
    }
}

pub enum Runtime {
    Remote(RemoteTestRuntime),
    Local(LocalTestRuntime),
}

impl<'a> Runtime {
    /// Returns a client-side view of the management canister.
    pub fn get_management_canister(&'a self) -> Canister<'a> {
        Canister {
            runtime: self,
            canister_id: IC_00,
            wasm: None,
        }
    }

    /// Creates a new canister with the maximum allowed cycles balance.
    ///
    /// Note that this calls ic00::Method::ProvisionalCreateCanisterWithCycles,
    /// which is protected by a whitelist of callers. Depending on the
    /// runtime, and depending on the replica configuration, this may not be
    /// authorized.
    pub async fn create_canister_with_max_cycles(&'a self) -> Result<Canister<'a>, String> {
        self.create_canister(None).await
    }

    /// Creates an empty canister.
    ///
    /// Note that this calls ic00::Method::ProvisionalCreateCanisterWithCycles,
    /// which is protected by a whitelist of callers. Depending on the
    /// runtime, and depending on the replica configuration, this may not be
    /// authorized.
    pub async fn create_canister(
        &'a self,
        num_cycles: Option<u64>,
    ) -> Result<Canister<'a>, String> {
        let canister_id_record: Result<CanisterIdRecord, String> = self
            .get_management_canister()
            .update_(
                ic00::Method::ProvisionalCreateCanisterWithCycles.to_string(),
                candid,
                (ProvisionalCreateCanisterWithCyclesArgs::new(num_cycles),),
            )
            .await;
        Ok(Canister {
            runtime: self,
            canister_id: canister_id_record?.get_canister_id(),
            wasm: None,
        })
    }

    /// Creates an empty canister, with retries. This is especially useful when
    /// the runtime is remote, and for which transient errors may happen.
    ///
    /// Note that this calls ic00::Method::ProvisionalCreateCanisterWithCycles,
    /// which is protected by a whitelist of callers. Depending on the
    /// runtime, and depending on the replica configuration, this may not be
    /// authorized.
    pub async fn create_canister_max_cycles_with_retries(&'a self) -> Result<Canister<'a>, String> {
        execute_with_retries(|| self.create_canister_with_max_cycles())
            .await
            .map_err(|e| format!("Creation of a canister timed out. Last error was: {}", e))
    }

    /// Clean up the run times (if any clean up is needed)
    pub fn stop(&self) {
        if let Runtime::Local(r) = self {
            r.stop();
        }
    }
}

/// An Internet Computer test runtime that talks to the IC using http
/// connections, through public endpoints. This is as close to the real thing as
/// it gets, depending on how the target was set up.
pub struct RemoteTestRuntime {
    pub agent: Agent,
}

impl RemoteTestRuntime {
    /// This will provide you with a random 8 byte nonce each time you call
    /// it
    fn get_nonce_vec(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..8).map(move |_| rng.gen::<u8>()).collect()
    }
}

/// This runs the testing DSL over 'canister_test' which is our internal testing
/// tool
pub fn local_test<Fut, Out, F>(run: F) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    canister_test_async(|t| run(Runtime::Local(t)))
}

/// This is a convenience method that gives sensible defaults for types and
/// error handling for type inference
pub fn local_test_e<Fut, Out, F>(run: F) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    local_test(run).expect("local_test_e failed")
}

/// Same as local_test but running a custom Config.
pub fn local_test_with_config<Fut, Out, F>(
    config: Config,
    subnet_config: SubnetConfig,
    run: F,
) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let ic_config = get_ic_config();
    canister_test_with_config_async(config, subnet_config, ic_config, |t| run(Runtime::Local(t)))
}

/// Same as local_test but running a custom Config and applying initial Registry
/// mutations
pub fn local_test_with_config_with_mutations<Fut, Out, F>(
    config: Config,
    mutations: Vec<RegistryMutation>,
    run: F,
) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let mut ic_config = get_ic_config();
    ic_config.initial_mutations = mutations;
    canister_test_with_config_async(
        config,
        SubnetConfig::default_application_subnet(),
        ic_config,
        |t| run(Runtime::Local(t)),
    )
}

/// Same as local_test but running a custom Config
pub fn local_test_with_config_e<Fut, Out, F>(
    config: Config,
    subnet_config: SubnetConfig,
    run: F,
) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    local_test_with_config(config, subnet_config, run).expect("local_test_with_config_e failed")
}

/// A representation of a canister on the IC, with or without code installed,
/// from a caller's point of view outside of the IC.
///
/// This can be used to test a canister as an end-user would -- e.g., installing
/// it, sending it updates and queries, and upgrading it.
#[derive(Clone)]
pub struct Canister<'a> {
    runtime: &'a Runtime,
    canister_id: CanisterId,

    // If the canister has been installed, then this is the code that was used.
    // If the canister is reinstalled or upgraded, it is possible that this no longer
    // matches the actual wasm module inside the canister.
    wasm: Option<Wasm>,
}

impl<'a> fmt::Debug for Canister<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client-side view of canister {}", self.canister_id)
    }
}

impl<'a> Canister<'a> {
    pub fn new(runtime: &'a Runtime, canister_id: CanisterId) -> Self {
        Self {
            runtime,
            canister_id,
            wasm: None,
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn canister_id_vec8(&self) -> Vec<u8> {
        self.canister_id().get().into_vec()
    }

    pub fn from_vec8(runtime: &'a Runtime, canister_id_vec8: Vec<u8>) -> Canister<'a> {
        Self {
            runtime,
            canister_id: CanisterId::new(
                PrincipalId::try_from(&canister_id_vec8[..])
                    .expect("failed to decode principal id"),
            )
            .unwrap(),
            wasm: None,
        }
    }

    /// This is depreciated and will be removed soon use query_
    pub fn query<S: Into<String>>(&'a self, method_name: S) -> Query<'a> {
        Query {
            canister: self,
            method_name: method_name.into(),
        }
    }

    pub async fn query_<S, Input, ReturnType, Witness>(
        &'a self,
        method_name: S,
        _: Witness,
        input: Input::Inner,
    ) -> Result<ReturnType::Inner, String>
    where
        S: Into<String>,
        Input: IntoWire + NewType,
        Witness: FnOnce(ReturnType, Input::Inner) -> (ReturnType::Inner, Input),
        ReturnType: FromWire + NewType,
    {
        let res = Query {
            canister: self,
            method_name: method_name.into(),
        }
        .bytes(Input::from_inner(input).into_bytes()?)
        .await?;
        match ReturnType::from_bytes(res) {
            Ok(r) => Ok(r.into_inner()),
            Err(e) => Err(e),
        }
    }

    pub fn update<S: Into<String>>(&'a self, method_name: S) -> Update<'a> {
        Update {
            canister: self,
            method_name: method_name.into(),
        }
    }

    pub async fn update_<S, Input, ReturnType, Witness>(
        &'a self,
        method_name: S,
        _: Witness,
        input: Input::Inner,
    ) -> Result<ReturnType::Inner, String>
    where
        S: Into<String>,
        Input: IntoWire + NewType,
        Witness: FnOnce(ReturnType, Input::Inner) -> (ReturnType::Inner, Input),
        ReturnType: FromWire + NewType,
    {
        let res = Update {
            canister: self,
            method_name: method_name.into(),
        }
        .bytes(Input::from_inner(input).into_bytes()?)
        .await?;
        FromWire::from_bytes(res)
            .map_err(|e| e)
            .map(|r: ReturnType| r.into_inner())
    }

    pub async fn update_from_sender<S, Input, ReturnType, Witness>(
        &'a self,
        method_name: S,
        _: Witness,
        input: Input::Inner,
        sender: &Sender,
    ) -> Result<ReturnType::Inner, String>
    where
        S: Into<String>,
        Input: IntoWire + NewType,
        Witness: FnOnce(ReturnType, Input::Inner) -> (ReturnType::Inner, Input),
        ReturnType: FromWire + NewType,
    {
        let res = Update {
            canister: self,
            method_name: method_name.into(),
        }
        .bytes_with_sender(Input::from_inner(input).into_bytes()?, sender)
        .await?;
        FromWire::from_bytes(res)
            .map_err(|e| e)
            .map(|r: ReturnType| r.into_inner())
    }

    pub async fn query_from_sender<S, Input, ReturnType, Witness>(
        &'a self,
        method_name: S,
        _: Witness,
        input: Input::Inner,
        sender: &Sender,
    ) -> Result<ReturnType::Inner, String>
    where
        S: Into<String>,
        Input: IntoWire + NewType,
        Witness: FnOnce(ReturnType, Input::Inner) -> (ReturnType::Inner, Input),
        ReturnType: FromWire + NewType,
    {
        let res = Query {
            canister: self,
            method_name: method_name.into(),
        }
        .bytes_with_sender(Input::from_inner(input).into_bytes()?, sender)
        .await?;
        FromWire::from_bytes(res)
            .map_err(|e| e)
            .map(|r: ReturnType| r.into_inner())
    }

    /// Runs the upgrade process, but with the new binary being identical to the
    /// previous one.
    ///
    /// payload: the argument to `canister_post_upgrade`
    pub async fn upgrade_to_self_binary(&mut self, payload: Vec<u8>) -> Result<(), String> {
        self.take_wasm()?
            .install(self.runtime)
            .with_mode(CanisterInstallMode::Upgrade)
            .install(self, payload)
            .await
    }

    /// Runs the re-install process, with the new binary being identical to the
    /// previous one.
    ///
    ///  payload: the argument to `canister_init`
    pub async fn reinstall_with_self_binary(&mut self, payload: Vec<u8>) -> Result<(), String> {
        self.take_wasm()?
            .install(self.runtime)
            .with_mode(CanisterInstallMode::Reinstall)
            .install(self, payload)
            .await
    }

    /// Steals the wasm out of this canister.
    fn take_wasm(&mut self) -> Result<Wasm, String> {
        self.wasm.take().ok_or(format!(
            "Canister {} does not have a known wasm.",
            self.canister_id
        ))
    }

    pub fn wasm(&self) -> Result<&Wasm, String> {
        self.wasm.as_ref().ok_or(format!(
            "Canister {} does not have a known wasm.",
            self.canister_id
        ))
    }

    /// Records the wasm module associated with this canister.
    ///
    /// Callers can call this, for instance, after upgrading a canister.
    ///
    /// Use with care: this function could be used to make the wasm stored here
    /// out of date.
    pub fn set_wasm(&mut self, wasm: Vec<u8>) {
        self.wasm = Some(Wasm::from_bytes(wasm));
    }

    pub async fn set_controller(&self, new_controller: PrincipalId) -> Result<(), String> {
        self.runtime
            .get_management_canister()
            .update_(
                ic00::Method::SetController.to_string(),
                dfn_candid::candid_multi_arity,
                (SetControllerArgs::new(self.canister_id, new_controller),),
            )
            .await
    }

    pub async fn set_controller_with_retries(
        &self,
        new_controller: PrincipalId,
    ) -> Result<(), String> {
        execute_with_retries(|| self.set_controller(new_controller)).await
    }

    /// Returns an ic00::CanisterIdRecord representing this canister. Useful
    /// to communicate with the management canister.
    pub fn as_record(&self) -> CanisterIdRecord {
        CanisterIdRecord::from(self.canister_id())
    }

    /// Tries to stop this canister, waits for it to reach the Stopped state.
    pub async fn stop(&self) -> Result<(), String> {
        let stop_res: Result<(), String> = self
            .runtime
            .get_management_canister()
            .update_("stop_canister", candid_multi_arity, (self.as_record(),))
            .await;
        stop_res?;
        loop {
            let status_res: Result<CanisterStatusResult, String> = self
                .runtime
                .get_management_canister()
                .update_("canister_status", candid, (self.as_record(),))
                .await;
            let status = status_res?;
            if status.status() == Stopped {
                break;
            }
        }
        Ok(())
    }

    /// Tries to delete this canister.
    pub async fn delete(&self) -> Result<(), String> {
        self.runtime
            .get_management_canister()
            .update_("delete_canister", candid_multi_arity, (self.as_record(),))
            .await?;
        Ok(())
    }

    /// Tries to stop this canister, waits for it to reach the Stopped state,
    /// then restarts it.
    ///
    /// This is expected to work only when the canister's controller is the
    /// anonymous user.
    ///
    /// TODO(EXE-59): Provide some IC-wide "wait for empty queues" function to
    /// replace this in tests.
    pub async fn stop_then_restart(&self) -> Result<(), String> {
        self.stop().await?;
        let start_res: Result<(), String> = self
            .runtime
            .get_management_canister()
            .update_("start_canister", candid_multi_arity, (self.as_record(),))
            .await;
        start_res?;
        Ok(())
    }
}

/// When extending this you should implement
/// pub fn serialization_name(&self, payload) -> result
#[must_use]
pub struct Query<'a> {
    pub canister: &'a Canister<'a>,
    pub method_name: String,
}

/// When extending this you should implement
/// pub fn serialization_name(&self, payload) -> result
#[must_use]
pub struct Update<'a> {
    pub canister: &'a Canister<'a>,
    pub method_name: String,
}

/// A wrapper around a Wasm binary that provides a builder-pattern for
/// installation arguments.
// The main function is called "bytes" because it takes the payload as bytes.
// This is designed to be able to support serialization of the argument to
// the ic00::Method::InstallCode using other format (e.g., candid).
// When extending this you should implement
// pub fn serialization_name(&self, payload) -> Canister<'a>
#[must_use]
pub struct Install<'a> {
    pub mode: CanisterInstallMode,
    pub runtime: &'a Runtime,
    pub wasm: Wasm,
    pub compute_allocation: Option<u64>,
    pub memory_allocation: Option<u64>,
    pub query_allocation: Option<u64>,
    pub num_cycles: Option<u64>,
}

impl<'a> Query<'a> {
    pub async fn bytes(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let canister = self.canister;
        match canister.runtime {
            Runtime::Local(t) => {
                let result = t
                    .query(canister.canister_id, &self.method_name, payload)
                    .map_err(|e| e.to_string())?;
                match result {
                    WasmResult::Reply(v) => Ok(v),
                    WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
                }
            }
            Runtime::Remote(c) => {
                let ingress_result = c
                    .agent
                    .execute_query(&canister.canister_id(), &self.method_name, payload)
                    .await?;
                ingress_result.ok_or_else(|| "Request timed out after 120 seconds".to_string())
            }
        }
    }

    pub async fn bytes_with_sender(
        &self,
        payload: Vec<u8>,
        sender: &Sender,
    ) -> Result<Vec<u8>, String> {
        let canister = self.canister;
        match canister.runtime {
            Runtime::Local(t) => {
                let result = t
                    .ingress_with_sender(canister.canister_id, &self.method_name, payload, sender)
                    .map_err(|e| e.to_string())?;
                match result {
                    WasmResult::Reply(v) => Ok(v),
                    WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
                }
            }
            Runtime::Remote(r) => {
                // We make a "shallow" copy of the agent in order to pass in a sender. We
                // retain the reqwest client which contains the bulk of the runtime state, so
                // this should not incur too much overhead even if used in loops.
                let agent_with_sender = r.agent.new_for_test(sender.clone());
                let ingress_result = agent_with_sender
                    .execute_query(&canister.canister_id(), &self.method_name, payload)
                    .await?;
                ingress_result.ok_or_else(|| "RemoteTestRuntime: Request timed out".to_string())
            }
        }
    }
}

impl<'a> Update<'a> {
    pub async fn bytes(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let canister = self.canister;
        match canister.runtime {
            Runtime::Local(t) => {
                let result = t
                    .ingress(canister.canister_id, &self.method_name, payload)
                    .map_err(|e| e.to_string())?;
                match result {
                    WasmResult::Reply(v) => Ok(v),
                    WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
                }
            }
            Runtime::Remote(c) => {
                let ingress_result = c
                    .agent
                    .execute_update(
                        &canister.canister_id(),
                        &self.method_name,
                        payload,
                        c.get_nonce_vec(),
                    )
                    .await?;
                ingress_result.ok_or_else(|| "RemoteTestRuntime: Request timed out".to_string())
            }
        }
    }

    pub async fn bytes_with_sender(
        &self,
        payload: Vec<u8>,
        sender: &Sender,
    ) -> Result<Vec<u8>, String> {
        let canister = self.canister;
        match canister.runtime {
            Runtime::Local(t) => {
                let result = t
                    .ingress_with_sender(canister.canister_id, &self.method_name, payload, sender)
                    .map_err(|e| e.to_string())?;
                match result {
                    WasmResult::Reply(v) => Ok(v),
                    WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
                }
            }
            Runtime::Remote(r) => {
                // We make a "shallow" copy of the agent in order to pass in a sender. We
                // retain the reqwest client which contains the bulk of the runtime state, so
                // this should not incur too much overhead even if used in loops.
                let agent_with_sender = r.agent.new_for_test(sender.clone());
                let ingress_result = agent_with_sender
                    .execute_update(
                        &canister.canister_id(),
                        &self.method_name,
                        payload,
                        r.get_nonce_vec(),
                    )
                    .await?;
                ingress_result.ok_or_else(|| "RemoteTestRuntime: Request timed out".to_string())
            }
        }
    }
}

impl<'a> Install<'a> {
    /// Creates and installs the canister.
    ///
    /// `payload` is the the canister init payload, as raw bytes.
    pub async fn bytes(self, payload: Vec<u8>) -> Result<Canister<'a>, String> {
        let mut canister = self.runtime.create_canister(self.num_cycles).await?;
        self.install(&mut canister, payload).await?;
        Ok(canister)
    }

    /// Ships the wasm code to the given canister.
    pub async fn install(
        self,
        canister: &mut Canister<'a>,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        let install_args = InstallCodeArgs::new(
            self.mode,
            canister.canister_id,
            self.wasm.0.clone(),
            payload,
            self.compute_allocation,
            self.memory_allocation,
            self.query_allocation,
        );
        eprintln!("Install args: {}", &install_args);
        match self.runtime {
            Runtime::Local(local_runtime) => local_runtime
                .install_canister_helper(install_args)
                .map_err(|e| e.to_string())
                .map(|_| {}),
            Runtime::Remote(c) => c.agent.install_canister(install_args).await,
        }?;
        canister.wasm = Some(self.wasm);
        Ok(())
    }

    pub fn with_compute_allocation(mut self, compute_allocation: u64) -> Install<'a> {
        self.compute_allocation = Some(compute_allocation);
        self
    }

    pub fn with_memory_allocation(mut self, memory_allocation: u64) -> Install<'a> {
        self.memory_allocation = Some(memory_allocation);
        self
    }

    pub fn with_query_allocation(mut self, query_allocation: u64) -> Install<'a> {
        self.query_allocation = Some(query_allocation);
        self
    }

    pub fn with_cycles(mut self, num_cycles: Option<u64>) -> Install<'a> {
        self.num_cycles = num_cycles;
        self
    }

    pub fn with_mode(mut self, mode: CanisterInstallMode) -> Install<'a> {
        self.mode = mode;
        self
    }
}
