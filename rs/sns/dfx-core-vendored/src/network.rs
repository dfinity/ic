//! Minimal network resolution.
//!
//! Replaces `dfx_core`'s full `network` + `config` machinery with just the cases
//! SNS needs: the built-in `ic` (mainnet) network, the `local` network (shared
//! or project, honouring a running replica's `webserver-port`), and an explicit
//! IC HTTP endpoint URL. Playground and arbitrary named networks defined in
//! `networks.json` are intentionally not supported.
//!
//! For `local`, resolution mirrors dfx's
//! `LocalBindDetermination::ApplyRunningWebserverPort`. Walk up from the working
//! directory to find the nearest `dfx.json`. If that file declares its own
//! `networks.local` entry, read the address from there, defaulting to
//! `127.0.0.1:8000` when the entry has no `bind`. Otherwise, read the address
//! from the shared `local` network in `networks.json`, defaulting to
//! `127.0.0.1:4943` when that file has no `local` entry either. This
//! "otherwise" case covers both not finding any `dfx.json`, and finding one
//! that doesn't declare `local`. Either address is overridden by the port
//! recorded in the network's `webserver-port` file when a replica is running.
use crate::config::directories::{
    DFX_CONFIG_ROOT, get_shared_network_data_directory, get_user_dfx_config_dir_with_override,
};
use crate::error::config::ConfigError;
use crate::error::get_user_home::GetUserHomeError;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;

// Kept identical to the corresponding constants in dfx-core.
const DEFAULT_IC_GATEWAY: &str = "https://icp0.io";
const DEFAULT_IC_GATEWAY_TRAILING_SLASH: &str = "https://icp0.io/";
const DEFAULT_SHARED_LOCAL_ADDRESS: &str = "127.0.0.1:4943"; // hex for "IC"
const DEFAULT_PROJECT_LOCAL_ADDRESS: &str = "127.0.0.1:8000";

/// The subset of dfx's `NetworkDescriptor` that SNS actually consumes. Named
/// after the upstream `dfx_core::config::model::network_descriptor::NetworkDescriptor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDescriptor {
    pub providers: Vec<String>,
    pub is_ic: bool,
}

#[derive(Error, Debug)]
pub enum NetworkResolutionError {
    #[error(
        "ComputeNetworkNotFound: Network '{0}' does not coincide with any known network. This vendored dfx subset only supports 'ic', 'local', and an IC HTTP endpoint URL."
    )]
    NetworkNotFound(String),

    // dfx-core's `Config::from_current_dir` propagates a `std::env::current_dir`
    // failure as an Err (`LoadDfxConfigError::DetermineCurrentWorkingDirFailed`),
    // rather than treating it the same as no project root being found.
    #[error("Failed to determine current working dir")]
    DetermineCurrentWorkingDirFailed(#[source] std::io::Error),

    #[error("Failed to determine the shared local network data directory")]
    DetermineSharedNetworkDirectoryFailed(#[source] GetUserHomeError),

    #[error("Failed to determine the shared dfx config directory")]
    DetermineSharedConfigDirectoryFailed(#[source] ConfigError),

    // dfx-core's `Config::from_file` propagates a read failure on an existing
    // dfx.json as an Err (via `crate::fs::read(path)?`), rather than treating
    // it the same as dfx.json being absent.
    #[error("Failed to read {0}")]
    ReadProjectDfxJsonFailed(PathBuf, #[source] std::io::Error),

    // dfx-core's `Config::from_slice` deserializes dfx.json into a typed
    // `ConfigInterface` and propagates any resulting serde error as an Err.
    #[error("Failed to parse {0} as JSON")]
    ParseProjectDfxJsonFailed(PathBuf, #[source] serde_json::Error),

    // Same fidelity note as `ParseProjectDfxJsonFailed`: dfx-core's
    // `ConfigLocalProvider::bind` is a typed `Option<String>` field, so a
    // non-string "bind" fails that same `Config::from_slice` deserialization.
    #[error("{path}'s local network has a \"bind\" value that is not a string: {value}")]
    InvalidProjectLocalNetworkBind {
        path: PathBuf,
        value: serde_json::Value,
    },

    // dfx-core's `NetworksConfig::new` only defaults when networks.json does
    // not exist. If it exists but can't be read, `NetworksConfig::from_file`
    // propagates the error (via `crate::fs::read(path)?`) instead of
    // defaulting.
    #[error("Failed to read {0}")]
    ReadSharedNetworksJsonFailed(PathBuf, #[source] std::io::Error),

    // Mirrors dfx-core's `NetworksConfig::from_file`, which propagates a
    // deserialization error as an Err.
    #[error("Failed to parse {0} as JSON")]
    ParseSharedNetworksJsonFailed(PathBuf, #[source] serde_json::Error),

    // Same fidelity note as `InvalidProjectLocalNetworkBind`.
    #[error("{path}'s local network has a \"bind\" value that is not a string: {value}")]
    InvalidSharedLocalNetworkBind {
        path: PathBuf,
        value: serde_json::Value,
    },

    #[error("Failed to read webserver port from {0}")]
    ReadWebserverPortFailed(PathBuf, #[source] std::io::Error),

    #[error("Failed to parse port value in {0}")]
    ParsePortValueFailed(PathBuf, #[source] std::num::ParseIntError),
}

/// Determines whether the provided connection is the official IC.
/// Mirrors `dfx_core::config::model::network_descriptor::NetworkDescriptor::is_ic`.
fn is_ic(network_name: &str, providers: &[String]) -> bool {
    let name_match = matches!(
        network_name,
        "ic" | DEFAULT_IC_GATEWAY | DEFAULT_IC_GATEWAY_TRAILING_SLASH
    );
    let provider_match = {
        providers.len() == 1
            && matches!(
                providers.first().unwrap().as_str(),
                DEFAULT_IC_GATEWAY | DEFAULT_IC_GATEWAY_TRAILING_SLASH
            )
    };
    name_match || provider_match
}

/// Resolves a network identifier (`ic`, `local`, or an IC HTTP endpoint URL) to
/// the provider URLs and mainnet flag needed to build an agent.
pub fn resolve_network(network_name: &str) -> Result<NetworkDescriptor, NetworkResolutionError> {
    if network_name == "ic" {
        return Ok(NetworkDescriptor {
            providers: vec![DEFAULT_IC_GATEWAY.to_string()],
            is_ic: true,
        });
    }

    if network_name == "local" {
        return resolve_local_network();
    }

    // Fall back to interpreting the identifier as an IC HTTP endpoint URL.
    // Like dfx-core's `create_url_based_network_descriptor`, any parseable URL is
    // accepted as-is (a non-HTTP scheme fails later at agent construction, as it
    // does in dfx), and an unparseable identifier falls through to `NetworkNotFound`.
    if Url::parse(network_name).is_ok() {
        let providers = vec![network_name.to_string()];
        let is_ic = is_ic(network_name, &providers);
        return Ok(NetworkDescriptor { providers, is_ic });
    }

    Err(NetworkResolutionError::NetworkNotFound(
        network_name.to_string(),
    ))
}

/// Resolves the `local` network, mirroring dfx's default bind determination.
fn resolve_local_network() -> Result<NetworkDescriptor, NetworkResolutionError> {
    let start_dir = std::env::current_dir()
        .map_err(NetworkResolutionError::DetermineCurrentWorkingDirFailed)?;
    let config_root_override = DFX_CONFIG_ROOT.lock().unwrap().clone();
    resolve_local_network_with(&start_dir, config_root_override.as_deref().map(Path::new))
}

/// Does the actual work of [`resolve_local_network`], but takes the working
/// directory and the `DFX_CONFIG_ROOT` override as explicit parameters
/// instead of reading them from process-global state (`std::env::current_dir`,
/// and the `DFX_CONFIG_ROOT` mutex). This lets tests supply both directly,
/// instead of mutating that global state, which would otherwise race across
/// parallel test threads.
///
/// `start_dir` plays the role of the working directory (see
/// `find_project_local_network`). `config_root_override` plays the role of
/// the `DFX_CONFIG_ROOT` environment variable (see `shared_local_address`):
/// `None` means it is not set, `Some` means it is set to that path.
fn resolve_local_network_with(
    start_dir: &Path,
    config_root_override: Option<&Path>,
) -> Result<NetworkDescriptor, NetworkResolutionError> {
    let project_local_network = find_project_local_network(start_dir)?;

    let (data_directory, default_address) = match project_local_network {
        Some((project_root, bind)) => (
            project_root.join(".dfx").join("network").join("local"),
            bind,
        ),
        None => (
            get_shared_network_data_directory("local")
                .map_err(NetworkResolutionError::DetermineSharedNetworkDirectoryFailed)?,
            shared_local_address(config_root_override)?,
        ),
    };

    let address = get_running_webserver_address(&data_directory, &default_address)?;
    let provider = format!("http://{address}");
    Ok(NetworkDescriptor {
        providers: vec![provider],
        is_ic: false,
    })
}

/// Walks up from `start_dir` looking for a `dfx.json`. The directory
/// containing `dfx.json` is the "project root". If `dfx.json` has "network" > "local",
/// then, we return 2 things:
///
/// 1. the project root
/// 2. the "bind" value within the local network, or DEFAULT_PROJECT_LOCAL_ADDRESS.
///
/// Otherwise, returns None. In this case, dfx falls back to the shared
/// network.
///
/// Mirrors dfx's `create_project_network_descriptor`, which only produces a project
/// network descriptor for networks actually present in the project's `dfx.json`.
///
/// Returns `Err` if the nearest `dfx.json` exists, but cannot be read, cannot
/// be parsed as JSON, or its local network's "bind" value is present, but is
/// not a string. Unlike "no dfx.json" or "dfx.json has no local network"
/// (both legitimate, and treated as `None`), these are all real problems with
/// the user's project, and dfx-core itself surfaces them as errors too (see
/// `Config::from_file` and `Config::from_slice` in dfx-core's
/// `config/model/dfinity.rs`), so they must not be swept under the rug here
/// either.
fn find_project_local_network(
    start_dir: &Path,
) -> Result<Option<(PathBuf, String)>, NetworkResolutionError> {
    let mut dir = start_dir.to_path_buf();

    loop {
        let dfx_json = dir.join("dfx.json");

        if !dfx_json.is_file() {
            // Try the parent directory.
            if !dir.pop() {
                // Give up, because no parent directory.
                return Ok(None);
            }
            continue;
        }

        // Found the nearest dfx.json! Read it.
        let content = std::fs::read(&dfx_json).map_err(|err| {
            NetworkResolutionError::ReadProjectDfxJsonFailed(dfx_json.clone(), err)
        })?;

        // Parse dfx.json.
        let dfx_json_value: serde_json::Value =
            serde_json::from_slice(&content).map_err(|err| {
                NetworkResolutionError::ParseProjectDfxJsonFailed(dfx_json.clone(), err)
            })?;

        // Get networks.local out of dfx.json. If it doesn't exist, return None.
        let Some(local) = dfx_json_value
            .get("networks")
            .and_then(|networks| networks.get("local"))
        else {
            // dfx.json exists and parses, but does not declare its own "local"
            // network. This is a legitimate "not found": fall back to the
            // shared network.
            return Ok(None);
        };

        let bind = local.get("bind");
        // Fall back to default. If it's not a string, return Err.
        let bind = match bind {
            None => DEFAULT_PROJECT_LOCAL_ADDRESS.to_string(),
            Some(bind) => match bind.as_str() {
                Some(bind) => bind.to_string(),
                None => {
                    return Err(NetworkResolutionError::InvalidProjectLocalNetworkBind {
                        path: dfx_json,
                        value: bind.clone(),
                    });
                }
            },
        };

        return Ok(Some((dir, bind)));
    }
}

/// Looks for `networks.json` in the shared dfx config directory (normally
/// `~/.config/dfx`, but see `config_root_override`). Within that, looks for
/// `"local"`. Within the `"local"` Object, looks for `"bind"`:
///
/// * If there is a value, returns it (assuming it is a string).
/// * Otherwise, returns DEFAULT_SHARED_LOCAL_ADDRESS
///
/// (Otherwise, Err is returned.)
///
/// Mirrors dfx's `create_shared_network_descriptor`.
///
/// `config_root_override` plays the role of the real `DFX_CONFIG_ROOT`
/// environment variable, read by the caller (`resolve_local_network`) and
/// passed in explicitly, rather than being read from process-global state
/// here. This lets a caller (in particular, a test) supply a value directly.
/// When `None`, `DFX_CONFIG_ROOT` is not set, and the shared dfx config
/// directory falls back to its real default location (see
/// `get_user_dfx_config_dir_with_override`).
fn shared_local_address(
    config_root_override: Option<&Path>,
) -> Result<String, NetworkResolutionError> {
    let networks_json = get_user_dfx_config_dir_with_override(config_root_override)
        .map_err(NetworkResolutionError::DetermineSharedConfigDirectoryFailed)?
        .join("networks.json");

    if !networks_json.is_file() {
        // No networks.json: use the default. Mirrors dfx-core's
        // `NetworksConfig::new`, which only defaults when the file doesn't
        // exist -- if it exists but can't be read, that's an Err instead (see
        // `ReadSharedNetworksJsonFailed` below).
        return Ok(DEFAULT_SHARED_LOCAL_ADDRESS.to_string());
    }

    // Read it.
    let content = std::fs::read(&networks_json).map_err(|err| {
        NetworkResolutionError::ReadSharedNetworksJsonFailed(networks_json.clone(), err)
    })?;

    // Parse networks.json.
    let networks_json_value: serde_json::Value =
        serde_json::from_slice(&content).map_err(|err| {
            NetworkResolutionError::ParseSharedNetworksJsonFailed(networks_json.clone(), err)
        })?;

    let Some(local) = networks_json_value.get("local") else {
        // No "local" entry: use the default.
        return Ok(DEFAULT_SHARED_LOCAL_ADDRESS.to_string());
    };

    let bind = local.get("bind");
    // Fall back to default. If it's not a string, return Err.
    let bind = match bind {
        None => DEFAULT_SHARED_LOCAL_ADDRESS.to_string(),
        Some(bind) => match bind.as_str() {
            Some(bind) => bind.to_string(),
            None => {
                return Err(NetworkResolutionError::InvalidSharedLocalNetworkBind {
                    path: networks_json,
                    value: bind.clone(),
                });
            }
        },
    };

    Ok(bind)
}

/// Applies a running replica's webserver port (if any) to the default address.
/// Mirrors `dfx_core::network::provider::get_running_webserver_bind_address`.
fn get_running_webserver_address(
    data_directory: &Path,
    default_local_address: &str,
) -> Result<String, NetworkResolutionError> {
    let local_address = default_local_address.to_string();
    let path = data_directory.join("webserver-port");
    if path.exists() {
        let s = std::fs::read_to_string(&path)
            .map_err(|e| NetworkResolutionError::ReadWebserverPortFailed(path.clone(), e))?;
        let s = s.trim();
        if s.is_empty() {
            Ok(local_address)
        } else {
            let port = s
                .parse::<u16>()
                .map_err(|e| NetworkResolutionError::ParsePortValueFailed(path.clone(), e))?;
            // converting to a socket address, and then setting the port,
            // will unfortunately transform "localhost:port" to "[::1]:{port}",
            // which the agent fails to connect with.
            let host = match local_address.rfind(':') {
                None => local_address.clone(),
                Some(index) => local_address[0..index].to_string(),
            };
            Ok(format!("{host}:{port}"))
        }
    } else {
        Ok(local_address)
    }
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
