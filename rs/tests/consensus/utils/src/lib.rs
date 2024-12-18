use std::path::PathBuf;

use ic_system_test_driver::driver::test_env_api::set_var_to_path;

pub mod node;
pub mod performance;
pub mod rw_message;
pub mod ssh_access;
pub mod subnet;
pub mod upgrade;

pub fn set_sandbox_env_vars(dir: PathBuf) {
    set_var_to_path("SANDBOX_BINARY", dir.join("canister_sandbox"));
    set_var_to_path("LAUNCHER_BINARY", dir.join("sandbox_launcher"));
    set_var_to_path("COMPILER_BINARY", dir.join("compiler_sandbox"));
}
