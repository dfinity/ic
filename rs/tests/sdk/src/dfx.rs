use candid::Principal;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::get_dependency_path_from_env;
use slog::{Logger, info};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone)]
pub struct DfxCommandContext {
    path: PathBuf,
    log: Logger,
    working_dir: PathBuf,
    home_dir: PathBuf,
    wallet_wasm: Option<PathBuf>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FrontendType {
    SvelteKit,
    Vanilla,
    Vue,
    React,
    SimpleAssets,
    None,
}

impl FrontendType {
    fn to_argument(self) -> &'static str {
        match self {
            FrontendType::SvelteKit => "sveltekit",
            FrontendType::Vanilla => "vanilla",
            FrontendType::Vue => "vue",
            FrontendType::React => "react",
            FrontendType::SimpleAssets => "simple-assets",
            FrontendType::None => "none",
        }
    }
}

impl BackendType {
    fn to_argument(self) -> &'static str {
        match self {
            BackendType::Motoko => "motoko",
            BackendType::Rust => "rust",
            BackendType::Azle => "azle",
            BackendType::Kybra => "kybra",
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BackendType {
    Motoko,
    Rust,
    Azle,
    Kybra,
}

impl DfxCommandContext {
    pub fn new(env: &TestEnv) -> Self {
        let log = env.logger();
        let path = fs::canonicalize(get_dependency_path_from_env("DFX_PATH")).unwrap();
        let home_dir = fs::canonicalize(env.base_path()).unwrap();
        let working_dir = home_dir.clone();
        Self {
            path,
            log,
            working_dir,
            home_dir,
            wallet_wasm: None,
        }
    }

    pub fn with_wallet_wasm(&self, path: &Path) -> Self {
        let clone = self.clone();
        Self {
            wallet_wasm: Some(path.to_path_buf()),
            ..clone
        }
    }
    pub fn with_working_dir<P: AsRef<Path>>(&self, path: P) -> Self {
        let clone = self.clone();
        Self {
            working_dir: path.as_ref().to_path_buf(),
            ..clone
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(self.path.clone());
        command
            .current_dir(self.working_dir.clone())
            .env("HOME", self.home_dir.clone());
        if let Some(wallet_wasm) = &self.wallet_wasm {
            command.env("DFX_WALLET_WASM", wallet_wasm);
        }
        command
    }

    pub fn canister_call(&self, canister_name: &str, method: &str, param: &str) -> String {
        info!(
            self.log,
            "dfx canister call {canister_name} {method} {param}"
        );
        let mut cmd = self.command();
        cmd.args(["canister", "call", canister_name, method, param]);
        let response = self.execute_and_return_stdout(cmd);
        info!(self.log, "dfx canister call response: {response}");
        response
    }

    pub fn canister_id(&self, canister_name: &str) -> Principal {
        info!(self.log, "dfx canister id {canister_name}");
        let mut cmd = self.command();
        cmd.args(["canister", "id", canister_name]);
        let s = self.execute_and_return_stdout(cmd);
        let id = Principal::from_text(s.trim()).unwrap();
        info!(self.log, "canister id of {canister_name} is {id}");
        id
    }

    pub fn deploy(&self) {
        info!(self.log, "dfx deploy");
        let mut cmd = self.command();
        cmd.arg("deploy");
        self.execute(cmd);
    }

    pub fn identity_get_wallet(&self) -> Principal {
        info!(self.log, "dfx identity get-wallet");
        let mut cmd = self.command();
        cmd.args(["identity", "get-wallet"]);
        let s = self.execute_and_return_stdout(cmd);
        let id = Principal::from_text(s.trim()).unwrap();
        info!(self.log, "wallet principal is {id}");
        id
    }

    pub fn ping(&self) {
        info!(self.log, "dfx ping");
        let mut cmd = self.command();
        cmd.arg("ping");
        self.execute(cmd);
    }

    pub fn new_project(&self, project_name: &str, frontend: FrontendType, backend: BackendType) {
        info!(self.log, "dfx new {project_name}");
        let mut cmd = self.command();
        cmd.args([
            "new",
            project_name,
            "--frontend",
            frontend.to_argument(),
            "--type",
            backend.to_argument(),
        ]);
        self.execute(cmd);
    }

    pub fn version(&self) -> String {
        info!(self.log, "dfx --version");
        let mut cmd = self.command();
        cmd.arg("--version");
        let version = self.execute_and_return_stdout(cmd);
        info!(self.log, "dfx --version reported: {version}");
        version
    }

    pub fn wallet_balance(&self) -> String {
        info!(self.log, "dfx wallet balance");
        let mut cmd = self.command();
        cmd.args(["wallet", "balance"]);
        let balance = self.execute_and_return_stdout(cmd);
        info!(self.log, "wallet balance: {balance}");
        balance
    }

    pub fn execute(&self, mut cmd: Command) -> Output {
        info!(self.log, "Executing command {:?} ...", &cmd);
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("Could not run '{cmd:?}' because {e:?}"));
        std::io::stdout().write_all(&out.stdout).unwrap();
        std::io::stderr().write_all(&out.stderr).unwrap();

        if !out.status.success() {
            panic!("Failed to run '{cmd:?}'");
        }
        out
    }

    pub fn execute_and_return_stdout(&self, cmd: Command) -> String {
        let output = self.execute(cmd);
        String::from_utf8(output.stdout).expect("failed to convert stdout to String")
    }
}
