use crate::error::config::ConfigError;
use crate::error::config::ConfigError::{
    DetermineConfigDirectoryFailed, EnsureConfigDirectoryExistsFailed,
};
use crate::error::get_user_home::GetUserHomeError;
use crate::error::get_user_home::GetUserHomeError::NoHomeInEnvironment;
#[cfg(not(windows))]
use crate::foundation::get_user_home;
use crate::fs::composite::ensure_dir_exists;
use directories_next::ProjectDirs;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub fn project_dirs() -> Result<&'static ProjectDirs, GetUserHomeError> {
    lazy_static::lazy_static! {
        static ref DIRS: Option<ProjectDirs> = ProjectDirs::from("org", "dfinity", "dfx");
    }
    DIRS.as_ref().ok_or(NoHomeInEnvironment())
}

pub fn get_shared_network_data_directory(network: &str) -> Result<PathBuf, GetUserHomeError> {
    Ok(project_dirs()?
        .data_local_dir()
        .join("network")
        .join(network))
}

/// Returns the user's dfx config directory. Usually `~/.config/dfx`: see
/// `get_user_dfx_config_dir_with_override` for the exact rule, including the
/// `DFX_CONFIG_ROOT` override and the Windows-specific location.
pub fn get_user_dfx_config_dir() -> Result<PathBuf, ConfigError> {
    let config_root = DFX_CONFIG_ROOT.lock().unwrap().clone();
    get_user_dfx_config_dir_with_override(config_root.as_deref().map(Path::new))
}

/// Like [`get_user_dfx_config_dir`], but the config root override is passed in
/// explicitly instead of being read from the process-global [`DFX_CONFIG_ROOT`].
/// This lets a caller (in particular, a test) supply a value directly, instead
/// of mutating shared global state that would otherwise race across parallel
/// test threads.
pub(crate) fn get_user_dfx_config_dir_with_override(
    config_root_override: Option<&Path>,
) -> Result<PathBuf, ConfigError> {
    // dirs-next is not used for *nix to preserve existing paths
    #[cfg(not(windows))]
    let p = {
        let home = get_user_home().map_err(DetermineConfigDirectoryFailed)?;
        let root = config_root_override
            .map(|root| root.as_os_str().to_owned())
            .unwrap_or(home);
        PathBuf::from(root).join(".config").join("dfx")
    };
    #[cfg(windows)]
    let p = match config_root_override {
        Some(var) => var.to_owned(),
        None => project_dirs()
            .map_err(DetermineConfigDirectoryFailed)?
            .config_dir()
            .to_owned(),
    };
    ensure_dir_exists(&p).map_err(EnsureConfigDirectoryExistsFailed)?;
    Ok(p)
}

// tests want to be able to call set_var. set_var is unsafe. So, the env-var check is replaced
// with a global that the tests can modify.
pub(crate) static DFX_CONFIG_ROOT: LazyLock<Mutex<Option<OsString>>> =
    LazyLock::new(|| Mutex::new(std::env::var_os("DFX_CONFIG_ROOT")));
