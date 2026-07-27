//! Minimal network resolution.
//!
//! Replaces `dfx_core`'s full `network` + `config` machinery with just the cases
//! SNS needs: the built-in `ic` (mainnet) network, the `local` network (shared
//! or project, honouring a running replica's `webserver-port`), and an explicit
//! IC HTTP endpoint URL. Playground and arbitrary named networks defined in
//! `networks.json` are intentionally not supported.
//!
//! For `local`, resolution mirrors dfx's `LocalBindDetermination::ApplyRunning
//! WebserverPort`: the address to connect to is read from the nearest `dfx.json`
//! (found by walking up from the working directory) *only if that file declares
//! its own `networks.local` entry* -- falling back to `127.0.0.1:8000` when the
//! entry has no `bind` -- and otherwise (including when no `dfx.json` is found,
//! or the one that is found doesn't declare `local`) comes from the shared
//! `local` network in `networks.json`, defaulting to `127.0.0.1:4943` when that
//! file has no `local` entry either. Either address is overridden by the port
//! recorded in the network's `webserver-port` file when a replica is running.
use crate::config::directories::{get_shared_network_data_directory, get_user_dfx_config_dir};
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

    #[error("Failed to determine the shared local network data directory")]
    DetermineSharedNetworkDirectoryFailed(#[source] GetUserHomeError),

    #[error("Failed to determine the shared dfx config directory")]
    DetermineSharedConfigDirectoryFailed(#[source] ConfigError),

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
    let (data_directory, default_address) = match find_project_local_network() {
        Some((project_root, bind)) => (
            project_root.join(".dfx").join("network").join("local"),
            bind,
        ),
        None => (
            get_shared_network_data_directory("local")
                .map_err(NetworkResolutionError::DetermineSharedNetworkDirectoryFailed)?,
            shared_local_address()?,
        ),
    };

    let address = get_running_webserver_address(&data_directory, &default_address)?;
    let provider = format!("http://{address}");
    Ok(NetworkDescriptor {
        providers: vec![provider],
        is_ic: false,
    })
}

/// Walks up from the working directory looking for a `dfx.json`, and, if one is
/// found *and it declares its own `networks.local` entry*, returns the project
/// root together with the configured `bind` address (or dfx's project-local
/// default, when the entry has no `bind`).
///
/// Returns `None` both when no `dfx.json` is found and when the nearest one
/// doesn't declare `local` -- in both cases dfx falls back to the shared
/// network, even from inside a dfx project directory. Mirrors dfx's
/// `create_project_network_descriptor`, which only produces a project network
/// descriptor for networks actually present in the project's `dfx.json`.
fn find_project_local_network() -> Option<(PathBuf, String)> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let dfx_json = dir.join("dfx.json");
        if dfx_json.is_file() {
            let local_network = std::fs::read(&dfx_json)
                .ok()
                .and_then(|content| serde_json::from_slice::<serde_json::Value>(&content).ok())
                .and_then(|value| value.get("networks")?.get("local").cloned());
            return local_network.map(|local| {
                let bind = local
                    .get("bind")
                    .and_then(|b| b.as_str())
                    .unwrap_or(DEFAULT_PROJECT_LOCAL_ADDRESS)
                    .to_string();
                (dir, bind)
            });
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Returns the shared network's configured address for `local`, read from
/// `networks.json` in the shared dfx config directory, falling back to dfx's
/// shared-network default when that file doesn't exist, doesn't declare
/// `local`, or the entry has no `bind`. Unlike a project's `dfx.json`, the
/// shared `networks.json` has no top-level `networks` key: it is itself the
/// map from network name to configuration.
/// Mirrors dfx's `create_shared_network_descriptor`.
fn shared_local_address() -> Result<String, NetworkResolutionError> {
    let networks_json = get_user_dfx_config_dir()
        .map_err(NetworkResolutionError::DetermineSharedConfigDirectoryFailed)?
        .join("networks.json");
    let bind = std::fs::read(&networks_json)
        .ok()
        .and_then(|content| serde_json::from_slice::<serde_json::Value>(&content).ok())
        .and_then(|value| {
            value
                .get("local")?
                .get("bind")?
                .as_str()
                .map(str::to_string)
        });
    Ok(bind.unwrap_or_else(|| DEFAULT_SHARED_LOCAL_ADDRESS.to_string()))
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
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `find_project_local_network` and `shared_local_address` inspect global
    // process state (the working directory and, via `DFX_CONFIG_ROOT`, the
    // shared config directory), so tests that touch either must not run
    // concurrently with one another.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn unique_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dfx-core-vendored-network-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn with_current_dir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = f();
        std::env::set_current_dir(original).unwrap();
        result
    }

    /// Points the shared dfx config directory (normally `~/.config/dfx`) at
    /// `<root>/.config/dfx` for the duration of `f`, matching how the real
    /// `DFX_CONFIG_ROOT` environment variable overrides dfx's notion of "home".
    fn with_dfx_config_root<T>(root: &Path, f: impl FnOnce() -> T) -> T {
        let mut config_root = crate::config::directories::DFX_CONFIG_ROOT.lock().unwrap();
        let original = config_root.take();
        *config_root = Some(root.as_os_str().to_owned());
        drop(config_root);
        let result = f();
        *crate::config::directories::DFX_CONFIG_ROOT.lock().unwrap() = original;
        result
    }

    fn write_shared_networks_json(config_root: &Path, contents: &str) {
        let dfx_dir = config_root.join(".config").join("dfx");
        std::fs::create_dir_all(&dfx_dir).unwrap();
        std::fs::write(dfx_dir.join("networks.json"), contents).unwrap();
    }

    #[test]
    fn project_dfx_json_without_networks_falls_back_to_shared_network() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project_dir = unique_temp_dir("project-no-networks-key");
        std::fs::write(project_dir.join("dfx.json"), r#"{"canisters": {}}"#).unwrap();

        let config_root = unique_temp_dir("shared-config");
        write_shared_networks_json(&config_root, r#"{"local": {"bind": "127.0.0.1:8080"}}"#);

        let result = with_current_dir(&project_dir, || {
            with_dfx_config_root(&config_root, resolve_local_network)
        })
        .unwrap();

        // Regression test for the vendored resolver hardcoding the
        // project-local default (127.0.0.1:8000) instead of reading the
        // shared network's actually configured bind address.
        assert_eq!(result.providers, vec!["http://127.0.0.1:8080".to_string()]);

        std::fs::remove_dir_all(&project_dir).ok();
        std::fs::remove_dir_all(&config_root).ok();
    }

    #[test]
    fn project_dfx_json_with_its_own_local_network_takes_precedence() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project_dir = unique_temp_dir("project-with-local");
        std::fs::write(
            project_dir.join("dfx.json"),
            r#"{"networks": {"local": {"bind": "127.0.0.1:9999"}}}"#,
        )
        .unwrap();

        let result = with_current_dir(&project_dir, resolve_local_network).unwrap();

        assert_eq!(result.providers, vec!["http://127.0.0.1:9999".to_string()]);

        std::fs::remove_dir_all(&project_dir).ok();
    }

    #[test]
    fn shared_network_without_local_entry_uses_default_shared_address() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project_dir = unique_temp_dir("no-project");
        let config_root = unique_temp_dir("empty-shared-config");

        let result = with_current_dir(&project_dir, || {
            with_dfx_config_root(&config_root, resolve_local_network)
        })
        .unwrap();

        assert_eq!(
            result.providers,
            vec![format!("http://{DEFAULT_SHARED_LOCAL_ADDRESS}")]
        );

        std::fs::remove_dir_all(&project_dir).ok();
        std::fs::remove_dir_all(&config_root).ok();
    }
}
