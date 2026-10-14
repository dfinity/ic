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
use crate::error::fs::ReadToStringError;
use crate::error::get_user_home::GetUserHomeError;
use crate::error::load_dfx_config::LoadDfxConfigError;
use crate::error::load_networks_config::LoadNetworksConfigError;
use crate::json::load_json_file;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;

// Kept identical to the corresponding constants in dfx-core.
const DEFAULT_IC_GATEWAY: &str = "https://icp0.io";
const DEFAULT_IC_GATEWAY_TRAILING_SLASH: &str = "https://icp0.io/";
const DEFAULT_SHARED_LOCAL_ADDRESS: &str = "127.0.0.1:4943"; // hex for "IC"
const DEFAULT_PROJECT_LOCAL_ADDRESS: &str = "127.0.0.1:8000";

/// The subset of dfx-core's `NetworkDescriptor` that SNS actually consumes. Named
/// after the upstream `dfx_core::config::model::network_descriptor::NetworkDescriptor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDescriptor {
    pub providers: Vec<String>,
    pub is_ic: bool,
}

/// The subset of dfx-core's `ConfigNetwork::ConfigLocalProvider`
/// (`config/model/dfinity.rs`) this crate needs: just a "bind" address. Used
/// to deserialize the "local" entry of both a project's `dfx.json`
/// (`networks.local`) and the shared `networks.json` (`local`). Unknown
/// fields on the network object (e.g. "bitcoin", "replica") are ignored.
#[derive(Deserialize)]
struct LocalNetworkBind {
    bind: Option<String>,
}

/// The subset of dfx-core's `ConfigInterface` this crate needs: a project's
/// `dfx.json` "networks" map, from which only the "local" entry, if any, is
/// read.
#[derive(Deserialize)]
struct ProjectDfxJson {
    #[serde(default)]
    networks: BTreeMap<String, LocalNetworkBind>,
}

/// The shared `networks.json`'s top-level shape: a map from network name to
/// its configuration, from which only the "local" entry, if any, is read.
/// Named after dfx-core's `NetworksConfigInterface::networks` field, which has
/// the same type (`config/model/dfinity.rs`).
type SharedNetworksJson = BTreeMap<String, LocalNetworkBind>;

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

    // Copied (name + shape) from dfx-core's `LoadDfxConfigError`: mirrors
    // `Config::from_file`/`Config::from_slice` reading and parsing dfx.json,
    // including a non-string "bind" value, which fails the same typed
    // deserialization as any other malformed field.
    #[error(transparent)]
    LoadProjectDfxJsonFailed(#[from] LoadDfxConfigError),

    // Copied (name + shape) from dfx-core's `LoadNetworksConfigError`: mirrors
    // `NetworksConfig::new`/`from_file` reading and parsing networks.json,
    // with the same non-string-"bind" fidelity note as `LoadProjectDfxJsonFailed`.
    #[error(transparent)]
    LoadSharedNetworksConfigFailed(#[from] LoadNetworksConfigError),

    // Copied (name + shape) from dfx-core's `NetworkConfigError::ReadWebserverPortFailed`
    // (`error/network_config.rs`), which wraps `ReadToStringError` rather than
    // an unadorned `std::io::Error` -- the path is carried by `ReadToStringError`
    // itself, not duplicated onto this variant.
    #[error("Failed to read webserver port")]
    ReadWebserverPortFailed(#[source] ReadToStringError),

    // Copied (name, shape, and message) from dfx-core's
    // `NetworkConfigError::ParsePortValueFailed` (`error/network_config.rs`),
    // including its boxing of both fields.
    #[error("Failed to parse contents of {0} as a port value")]
    ParsePortValueFailed(Box<PathBuf>, #[source] Box<std::num::ParseIntError>),
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
    let working_directory = std::env::current_dir()
        .map_err(NetworkResolutionError::DetermineCurrentWorkingDirFailed)?;
    let dfx_config_root = DFX_CONFIG_ROOT.lock().unwrap().clone().map(PathBuf::from);
    resolve_local_network_with(&working_directory, dfx_config_root.as_deref())
}

/// Does the actual work of [`resolve_local_network`], but takes the working
/// directory and the `DFX_CONFIG_ROOT` environment variable override as
/// explicit parameters instead of reading them, making this more testable.
///
/// `dfx_config_root` is the value of the `DFX_CONFIG_ROOT` environment
/// variable: `None` means it is not set, `Some` means it is set to that path.
fn resolve_local_network_with(
    working_directory: &Path,
    dfx_config_root: Option<&Path>,
) -> Result<NetworkDescriptor, NetworkResolutionError> {
    let project_local_network = find_project_local_network(working_directory)?;

    let (data_directory, default_address) = match project_local_network {
        Some((project_root, bind)) => (
            project_root.join(".dfx").join("network").join("local"),
            bind,
        ),
        None => (
            get_shared_network_data_directory("local")
                .map_err(NetworkResolutionError::DetermineSharedNetworkDirectoryFailed)?,
            shared_local_address(dfx_config_root)?,
        ),
    };

    let address = get_running_webserver_address(&data_directory, &default_address)?;
    let provider = format!("http://{address}");
    Ok(NetworkDescriptor {
        providers: vec![provider],
        is_ic: false,
    })
}

/// Walks up from `working_directory` looking for a `dfx.json`. The directory
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
/// Returns `Err` if the nearest `dfx.json` exists, but cannot be read or
/// parsed as JSON. A "bind" value that is present but not a string fails
/// that same parse, so it returns `Err` too. Unlike "no dfx.json" or
/// "dfx.json has no local network" (both legitimate, and treated as
/// `None`), these are all real problems with the user's project.
fn find_project_local_network(
    working_directory: &Path,
) -> Result<Option<(PathBuf, String)>, NetworkResolutionError> {
    let mut dir = working_directory.to_path_buf();

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

        // Found the nearest dfx.json! Read and parse it.
        let project_dfx_json: ProjectDfxJson = load_dfx_json(&dfx_json)?;

        // Get networks.local out of dfx.json. If it doesn't exist, return None.
        let Some(local) = project_dfx_json.networks.get("local") else {
            // dfx.json exists and parses, but does not declare its own "local"
            // network. This is a legitimate "not found": fall back to the
            // shared network.
            return Ok(None);
        };

        // Fall back to default.
        let bind = local
            .bind
            .clone()
            .unwrap_or_else(|| DEFAULT_PROJECT_LOCAL_ADDRESS.to_string());

        return Ok(Some((dir, bind)));
    }
}

/// Reads and parses `path` (a project's `dfx.json`) into the subset of its
/// schema this crate needs. Mirrors dfx-core's `Config::from_file` +
/// `Config::from_slice`.
fn load_dfx_json(path: &Path) -> Result<ProjectDfxJson, LoadDfxConfigError> {
    let content = crate::fs::read(path)?;
    serde_json::from_slice(&content).map_err(|err| {
        LoadDfxConfigError::DeserializeValueFailed(Box::new(path.to_path_buf()), err)
    })
}

/// Looks for `networks.json` in the shared dfx config directory (normally
/// `~/.config/dfx`, but see `dfx_config_root`). Within that, looks for
/// `"local"`. Within the `"local"` Object, looks for `"bind"`:
///
/// * If there is a value, returns it (assuming it is a string).
/// * Otherwise, returns DEFAULT_SHARED_LOCAL_ADDRESS
///
/// (Otherwise, Err is returned.)
///
/// Mirrors dfx's `create_shared_network_descriptor`.
///
/// `dfx_config_root` is the value of the `DFX_CONFIG_ROOT` environment
/// variable, read by the caller (`resolve_local_network`) and passed in
/// explicitly. When `None`, `DFX_CONFIG_ROOT` is not set, and the shared dfx
/// config directory falls back to its real default location (see
/// `get_user_dfx_config_dir_with_override`).
fn shared_local_address(dfx_config_root: Option<&Path>) -> Result<String, NetworkResolutionError> {
    let networks = load_shared_networks_config(dfx_config_root)?;

    let Some(local) = networks.get("local") else {
        // No "local" entry: use the default.
        return Ok(DEFAULT_SHARED_LOCAL_ADDRESS.to_string());
    };

    // Fall back to default.
    Ok(local
        .bind
        .clone()
        .unwrap_or_else(|| DEFAULT_SHARED_LOCAL_ADDRESS.to_string()))
}

/// Reads and parses the shared `networks.json`, defaulting to an empty map
/// when the file doesn't exist. Mirrors dfx-core's `NetworksConfig::new` +
/// `NetworksConfig::from_file`.
fn load_shared_networks_config(
    dfx_config_root: Option<&Path>,
) -> Result<SharedNetworksJson, LoadNetworksConfigError> {
    let networks_json = get_user_dfx_config_dir_with_override(dfx_config_root)
        .map_err(LoadNetworksConfigError::GetConfigPathFailed)?
        .join("networks.json");

    if !networks_json.is_file() {
        // No networks.json: use the default. Mirrors dfx-core's
        // `NetworksConfig::new`, which only defaults when the file doesn't
        // exist. If it exists but can't be read or parsed, that's an Err
        // instead (see `LoadConfigFromFileFailed` below).
        return Ok(SharedNetworksJson::new());
    }

    load_json_file(&networks_json).map_err(LoadNetworksConfigError::LoadConfigFromFileFailed)
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
        let s = crate::fs::read_to_string(&path)
            .map_err(NetworkResolutionError::ReadWebserverPortFailed)?;
        let s = s.trim();
        if s.is_empty() {
            Ok(local_address)
        } else {
            let port = s.parse::<u16>().map_err(|e| {
                NetworkResolutionError::ParsePortValueFailed(Box::new(path), Box::new(e))
            })?;
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
