//! Minimal network resolution.
//!
//! Replaces `dfx_core`'s full `network` + `config` machinery with just the cases
//! SNS needs: the built-in `ic` (mainnet) network, the `local` network (shared
//! or project, honouring a running replica's `webserver-port`), and an explicit
//! IC HTTP endpoint URL. Playground and arbitrary named networks defined in
//! `networks.json` are intentionally not supported.
//!
//! For `local`, resolution mirrors dfx's `LocalBindDetermination::ApplyRunning
//! WebserverPort`: the address to connect to defaults to `127.0.0.1:8000` inside
//! a dfx project (a `dfx.json` found by walking up from the working directory) or
//! `127.0.0.1:4943` for the shared network, and is overridden by the port
//! recorded in the network's `webserver-port` file when a replica is running.
use crate::config::directories::get_shared_network_data_directory;
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

    #[error("Failed to determine the shared local network data directory")]
    DetermineSharedNetworkDirectoryFailed(#[source] GetUserHomeError),

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
    let (data_directory, default_address) = match find_project_root() {
        Some(project_root) => (
            project_root.join(".dfx").join("network").join("local"),
            project_local_address(&project_root),
        ),
        None => (
            get_shared_network_data_directory("local")
                .map_err(NetworkResolutionError::DetermineSharedNetworkDirectoryFailed)?,
            DEFAULT_SHARED_LOCAL_ADDRESS.to_string(),
        ),
    };

    let address = get_running_webserver_address(&data_directory, &default_address)?;
    let provider = format!("http://{address}");
    Ok(NetworkDescriptor {
        providers: vec![provider],
        is_ic: false,
    })
}

/// Walks up from the working directory looking for a `dfx.json`, returning the
/// directory that contains it (the project root), if any.
fn find_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("dfx.json").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Returns the configured address for the project's `local` network, falling
/// back to dfx's project default. Only the `bind` field is honoured; when a
/// replica is running its `webserver-port` takes precedence regardless.
fn project_local_address(project_root: &Path) -> String {
    let dfx_json = project_root.join("dfx.json");
    let bind = std::fs::read(&dfx_json)
        .ok()
        .and_then(|content| serde_json::from_slice::<serde_json::Value>(&content).ok())
        .and_then(|value| {
            value
                .get("networks")?
                .get("local")?
                .get("bind")?
                .as_str()
                .map(str::to_string)
        });
    bind.unwrap_or_else(|| DEFAULT_PROJECT_LOCAL_ADDRESS.to_string())
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
