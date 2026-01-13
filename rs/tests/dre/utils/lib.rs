use anyhow::bail;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_http_utils::file_downloader::FileDownloader;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::util::block_on;
use ic_types::ReplicaVersion;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use url::Url;

pub mod defs;
pub mod steps;

const GUESTOS_DISK_IMG_VERSION: &str = "ENV_DEPS__GUESTOS_DISK_IMG_VERSION";
const GUESTOS_DISK_IMG_URL: &str = "ENV_DEPS__GUESTOS_DISK_IMG_URL";
const GUESTOS_DISK_IMG_HASH: &str = "ENV_DEPS__GUESTOS_DISK_IMG_HASH";
const GUESTOS_INITIAL_UPDATE_IMG_URL: &str = "ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL";
const GUESTOS_INITIAL_UPDATE_IMG_HASH: &str = "ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH";
const GUESTOS_INITIAL_UPDATE_IMG_MEASUREMENTS_FILE: &str =
    "ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE";
const GUESTOS_UPDATE_IMG_VERSION: &str = "ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION";
const GUESTOS_UPDATE_IMG_URL: &str = "ENV_DEPS__GUESTOS_UPDATE_IMG_URL";
const GUESTOS_UPDATE_IMG_HASH: &str = "ENV_DEPS__GUESTOS_UPDATE_IMG_HASH";
const GUESTOS_UPDATE_IMG_MEASUREMENTS_FILE: &str = "ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE";

pub const IC_CONFIG: &str = "IC_CONFIG";

pub fn setup(env: TestEnv, config: IcConfig) {
    let mut ic = InternetComputer::new();

    if let Some(v) = config.initial_version {
        ic = ic.with_initial_replica(NodeSoftwareVersion {
            replica_version: v.clone(),
            replica_url: Url::parse("https://unimportant.com").unwrap(),
            replica_hash: "".to_string(),
            orchestrator_url: Url::parse("https://unimportant.com").unwrap(),
            orchestrator_hash: "".to_string(),
        });
    }

    if let Some(subnets) = config.subnets {
        subnets.iter().for_each(|s| {
            let su = match s {
                ConfigurableSubnet::Simple(s) => Subnet::new(s.subnet_type).add_nodes(s.num_nodes),
                ConfigurableSubnet::Complex(s) => *s.to_owned(),
            };
            ic = ic.clone().add_subnet(su)
        })
    }
    if let Some(u) = config.unassigned_nodes {
        match u {
            ConfigurableUnassignedNodes::Simple(un) => ic = ic.clone().with_unassigned_nodes(un),
            ConfigurableUnassignedNodes::Complex(uns) => uns
                .into_iter()
                .for_each(|un| ic = ic.clone().with_unassigned_node(un)),
        }
    }
    if let Some(u) = config.api_boundary_nodes {
        match u {
            ConfigurableApiBoundaryNodes::Simple(un) => ic = ic.clone().with_api_boundary_nodes(un),
            ConfigurableApiBoundaryNodes::Complex(uns) => uns
                .into_iter()
                .for_each(|un| ic = ic.clone().with_api_boundary_node(un)),
        }
    }
    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
}

#[derive(Deserialize, Debug)]
pub struct IcConfig {
    pub subnets: Option<Vec<ConfigurableSubnet>>,
    pub unassigned_nodes: Option<ConfigurableUnassignedNodes>,
    pub api_boundary_nodes: Option<ConfigurableApiBoundaryNodes>,
    pub initial_version: Option<ReplicaVersion>,
    pub target_version: ReplicaVersion,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableSubnet {
    Simple(SubnetSimple),
    Complex(Box<Subnet>),
}

#[derive(Deserialize, Debug)]
pub struct SubnetSimple {
    pub subnet_type: SubnetType,
    pub num_nodes: usize,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableApiBoundaryNodes {
    Simple(usize),
    Complex(Vec<Node>),
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ConfigurableUnassignedNodes {
    Simple(usize),
    Complex(Vec<Node>),
}

pub fn mock_env_variables(config: &IcConfig) {
    if let Some(v) = &config.initial_version {
        update_env_variables(
            vec![
                (
                    v.to_string(),
                    GUESTOS_DISK_IMG_VERSION,
                ),
                (
                    "Note this is currently not supported, as we do not publish GuestOS disk images directly.".to_string(),
                    GUESTOS_DISK_IMG_URL,
                ),
                (
                    "Note this is currently not supported, as we do not publish GuestOS disk images directly.".to_string(),
                    GUESTOS_DISK_IMG_HASH,
                ),
                (
                    format!("http://download.proxy-global.dfinity.network:8080/ic/{v}/guest-os/update-img/update-img.tar.zst"),
                    GUESTOS_INITIAL_UPDATE_IMG_URL,
                ),
                (
                    block_on(fetch_update_file_sha256_with_retry(v)),
                    GUESTOS_INITIAL_UPDATE_IMG_HASH,
                ),
                (
                    block_on(fetch_update_file_measurements_with_retry(v)).display().to_string(),
                    GUESTOS_INITIAL_UPDATE_IMG_MEASUREMENTS_FILE,
                ),
            ],
        );
    }

    update_env_variables(vec![
        (
            config.target_version.to_string(),
            GUESTOS_UPDATE_IMG_VERSION,
        ),
        (
            format!(
                "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/update-img.tar.zst",
                config.target_version
            ),
            GUESTOS_UPDATE_IMG_URL,
        ),
        (
            block_on(fetch_update_file_sha256_with_retry(&config.target_version)),
            GUESTOS_UPDATE_IMG_HASH,
        ),
        (
            block_on(fetch_update_file_measurements_with_retry(
                &config.target_version,
            ))
            .display()
            .to_string(),
            GUESTOS_UPDATE_IMG_MEASUREMENTS_FILE,
        ),
    ]);
}

fn update_env_variables(pairs: Vec<(String, &str)>) {
    for (value, env_variable) in pairs {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var(env_variable, &value) };
        eprintln!("Overriden env variable `{env_variable}` to value: {value}")
    }
}

// The following are used to fetch artifact metadata from public URLs

fn get_public_update_image_sha_url(git_revision: &ReplicaVersion) -> String {
    format!(
        "http://download.proxy-global.dfinity.network:8080/ic/{git_revision}/guest-os/update-img/SHA256SUMS"
    )
}

pub fn get_public_update_image_guest_launch_measurements(git_revision: &ReplicaVersion) -> String {
    format!(
        "http://download.proxy-global.dfinity.network:8080/ic/{git_revision}/guest-os/update-img/launch-measurements.json"
    )
}

async fn fetch_update_file_sha256_with_retry(version: &ReplicaVersion) -> String {
    // NOTE: Throw away internal logs here, as we don't yet have a logger and
    // don't bother making a new one.
    let log_null = slog::Logger::root(slog::Discard, slog::o!());

    ic_system_test_driver::retry_with_msg_async!(
        format!("fetch update file sha256 of version {}", version),
        &log_null,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match fetch_update_file_sha256(version).await {
                Err(err) => bail!(err),
                Ok(sha) => Ok(sha),
            }
        }
    )
    .await
    .expect("Failed to fetch sha256 file.")
}

async fn fetch_update_file_sha256(version: &ReplicaVersion) -> Result<String, String> {
    let sha_url = get_public_update_image_sha_url(version);
    let tmpfile =
        tempfile::NamedTempFile::new().map_err(|err| format!("Unable to create tmpfile: {err}"))?;
    FileDownloader::new(None)
        .download_file(&sha_url, tmpfile.path(), None)
        .await
        .map_err(|err| format!("Download of SHA256SUMS file failed: {err}"))?;
    let contents = fs::read_to_string(tmpfile)
        .map_err(|err| format!("Something went wrong reading the file: {err}"))?;
    for line in contents.lines() {
        let words: Vec<&str> = line.split(char::is_whitespace).collect();
        let suffix = "update-img.tar.zst";
        if words.len() == 2 && words[1].ends_with(suffix) {
            return Ok(words[0].to_string());
        }
    }

    Err(format!("SHA256 hash is not found in {sha_url}"))
}

async fn fetch_update_file_measurements_with_retry(version: &ReplicaVersion) -> PathBuf {
    // NOTE: Throw away internal logs here, as we don't yet have a logger and
    // don't bother making a new one.
    let log_null = slog::Logger::root(slog::Discard, slog::o!());

    ic_system_test_driver::retry_with_msg_async!(
        format!("fetch update file measurements of version {}", version),
        &log_null,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match fetch_update_file_measurements(version).await {
                Err(err) => bail!(err),
                Ok(measurements) => Ok(measurements),
            }
        }
    )
    .await
    .expect("Failed to fetch measurements file.")
}

async fn fetch_update_file_measurements(version: &ReplicaVersion) -> Result<PathBuf, String> {
    let tmpfile =
        tempfile::NamedTempFile::new().map_err(|err| format!("Unable to create tmpfile: {err}"))?;
    FileDownloader::new(None)
        .download_file(
            &get_public_update_image_guest_launch_measurements(version),
            tmpfile.path(),
            None,
        )
        .await
        .map_err(|err| format!("Download of measurements file failed: {err}"))?;

    // NOTE: We must keep the tmpfile, as the path sits in an env variable.
    let (_file, path) = tmpfile
        .keep()
        .map_err(|err| format!("Unable to persist tmpfile: {err}"))?;

    Ok(path)
}
