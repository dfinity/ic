//! Functions for determining the executable and args to use when creating
//! sandbox and launcher processes. In production use cases the executable can
//! always be found in the current folder, but this won't be the case when
//! running unit tests or running within tools such as `drun` or `ic-replay`.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use once_cell::sync::OnceCell;

use ic_canister_sandbox_common::{RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_SANDBOX_LAUNCHER_FLAG};

const SANDBOX_EXECUTABLE_NAME: &str = "canister_sandbox";
const LAUNCHER_EXECUTABLE_NAME: &str = "sandbox_launcher";

// These binaries support running in the canister sandbox mode.
const RUNNABLE_AS_SANDBOX: &[&str] = &["drun", "ic-replay"];

enum SandboxCrate {
    SandboxLauncher,
    CanisterSandbox,
}

impl SandboxCrate {
    fn executable_name(&self) -> &'static str {
        match self {
            Self::SandboxLauncher => LAUNCHER_EXECUTABLE_NAME,
            Self::CanisterSandbox => SANDBOX_EXECUTABLE_NAME,
        }
    }

    fn env_binary(&self) -> Option<String> {
        match self {
            Self::SandboxLauncher => std::env::var("LAUNCHER_BINARY").ok(),
            Self::CanisterSandbox => std::env::var("SANDBOX_BINARY").ok(),
        }
    }

    fn run_as_flag(&self) -> &'static str {
        match self {
            Self::SandboxLauncher => RUN_AS_SANDBOX_LAUNCHER_FLAG,
            Self::CanisterSandbox => RUN_AS_CANISTER_SANDBOX_FLAG,
        }
    }
}

/// Gets the executable and arguments for spawning a canister sandbox.
pub(super) fn create_sandbox_argv() -> Option<Vec<String>> {
    create_child_process_argv(SandboxCrate::CanisterSandbox)
}

/// Gets the executable and arguments for spawning the sandbox launcher.
pub(super) fn create_launcher_argv() -> Option<Vec<String>> {
    create_child_process_argv(SandboxCrate::SandboxLauncher)
}

/// Gets the executable and arguments for spawning a canister sandbox.
fn create_child_process_argv(krate: SandboxCrate) -> Option<Vec<String>> {
    let current_binary_path = current_binary_path()?;
    let current_binary_name = current_binary_path.file_name()?.to_str()?;

    // The order of checks performed in this function is important.
    // Please do not reorder.
    //
    // 1. If the current binary supports running the sandbox mode, then use it.
    // This is important for `ic-replay` and `drun` where we do not control
    // the location of the sandbox binary.
    if RUNNABLE_AS_SANDBOX.contains(&current_binary_name) {
        let exec_path = current_binary_path.to_str()?.to_string();
        return Some(vec![exec_path, krate.run_as_flag().to_string()]);
    }

    // 2. If the sandbox binary is in the same folder as the current binary, then
    // use it.
    let current_binary_folder = current_binary_path.parent()?;
    let sandbox_executable_path = current_binary_folder.join(krate.executable_name());
    if Path::exists(&sandbox_executable_path) {
        let exec_path = sandbox_executable_path.to_str()?.to_string();
        return Some(vec![exec_path]);
    }

    // 3. The two checks above cover all production use cases.
    // Find the sandbox binary for testing and local development.
    create_sandbox_argv_for_testing(krate)
}

/// Get the path of the current running binary.
fn current_binary_path() -> Option<PathBuf> {
    std::env::args().next().map(PathBuf::from)
}

/// Only for testing purposes.
/// Gets executable and arguments when running in CI or in a dev environment.
fn create_sandbox_argv_for_testing(krate: SandboxCrate) -> Option<Vec<String>> {
    // Try environment variables first.
    if let Some(env_binary) = krate.env_binary() {
        return Some(vec![env_binary]);
    }
    let executable_name = krate.executable_name();
    // In CI we expect the sandbox executable to be in our path so this should
    // succeed.
    if let Ok(exec_path) = which::which(executable_name) {
        println!("Running sandbox with executable {:?}", exec_path);
        return Some(vec![exec_path.to_str().unwrap().to_string()]);
    }

    static SANDBOX_COMPILED: OnceCell<()> = OnceCell::new();
    static LAUNCHER_COMPILED: OnceCell<()> = OnceCell::new();

    // When running in a dev environment we expect `cargo` to be in our path and
    // we should be able to find the `canister_sandbox` or `sandbox_launcher`
    // cargo manifest so this should succeed.
    match (which::which("cargo"), cargo_manifest_for_testing(&krate)) {
        (Ok(path), Some(manifest_path)) => {
            println!(
                "Building {} with cargo {:?} and manifest {:?}",
                executable_name, path, manifest_path
            );
            let path = path.to_str().unwrap().to_string();
            let cell = match krate {
                SandboxCrate::CanisterSandbox => &SANDBOX_COMPILED,
                SandboxCrate::SandboxLauncher => &LAUNCHER_COMPILED,
            };
            cell.get_or_init(|| {
                build_sandbox_with_cargo_for_testing(executable_name, &path, &manifest_path)
            });
            // Run `canister_sandbox` using `cargo run` so that we don't need to find the
            // executable in the target folder.
            Some(make_cargo_argv_for_testing(
                executable_name,
                &path,
                &manifest_path,
                CargoCommandType::Run,
            ))
        }
        _ => None,
    }
}

/// Only for testing purposes.
/// Finds the cargo manifest of the `canister_sandbox` or `sandbox_launcher`
/// crate in the directory path of the current manifest.
fn cargo_manifest_for_testing(krate: &SandboxCrate) -> Option<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok();
    let mut next_parent = manifest_dir.as_ref().map(Path::new);
    let mut current_manifest = None;
    while let Some(parent) = next_parent {
        let next: PathBuf = [parent, Path::new("Cargo.toml")].iter().collect();
        if next.exists() {
            current_manifest = Some(next);
        }
        next_parent = parent.parent();
    }
    // At this point `current_manifest` points to the top-level workspace
    // manifest. Try to get the manifest of the `canister_sandbox` crate
    // relative to it.
    //
    // Using the top-level cargo manifest would also be correct, but that would
    // ignore the `dev-dependencies` resulting in a different metadata hash,
    // which causes rebuilding of all dependencies that have already been
    // built by `cargo test`.
    let canister_sandbox: PathBuf = [
        current_manifest.as_ref()?.parent()?,
        &match krate {
            SandboxCrate::SandboxLauncher => Path::new("canister_sandbox").join("sandbox_launcher"),
            SandboxCrate::CanisterSandbox => PathBuf::from("canister_sandbox"),
        },
        Path::new("Cargo.toml"),
    ]
    .iter()
    .collect();
    if canister_sandbox.exists() {
        Some(canister_sandbox)
    } else {
        None
    }
}

/// Only for testing purposes.
fn build_sandbox_with_cargo_for_testing(
    executable_name: &str,
    cargo_path: &str,
    manifest_path: &Path,
) {
    let argv = make_cargo_argv_for_testing(
        executable_name,
        cargo_path,
        manifest_path,
        CargoCommandType::Build,
    );
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .expect("Failed to build canister_sandbox with cargo");
    if !output.status.success() {
        panic!(
            "Failed to build canister_sandbox with cargo\nError: {:?}\nstderr: {:?}",
            output.status, output.stderr
        )
    }
}

enum CargoCommandType {
    Build,
    Run,
}

/// Only for testing purposes.
fn make_cargo_argv_for_testing(
    executable_name: &str,
    cargo_path: &str,
    manifest_path: &Path,
    cargo_command_type: CargoCommandType,
) -> Vec<String> {
    let common_args = vec![
        "--quiet",
        "--manifest-path",
        manifest_path.to_str().unwrap(),
        "--bin",
        executable_name,
    ];
    let argv = match cargo_command_type {
        CargoCommandType::Run => vec![vec![cargo_path, "run"], common_args, vec!["--"]],
        CargoCommandType::Build => vec![vec![cargo_path, "build"], common_args],
    };
    argv.into_iter()
        .map(|s| s.into_iter().map(|s| s.to_string()))
        .flatten()
        .collect()
}
