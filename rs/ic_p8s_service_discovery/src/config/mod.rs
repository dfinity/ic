use std::{
    fs::File,
    io::{self, BufReader},
    net::{AddrParseError, SocketAddr},
    num::ParseIntError,
    path::Path,
};

use anyhow::Result;
use gflags_derive::GFlags;
use humantime::parse_duration;
use parse_int::parse;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;

pub(crate) mod nns;

#[derive(Error, Debug)]
pub(crate) enum ConfigError {
    #[error(transparent)]
    LogConfigurationFailed {
        #[from]
        source: ic_p8s_service_discovery_log::ConfigError,
    },

    #[error(transparent)]
    NnsConfigurationFailed {
        #[from]
        source: nns::ConfigError,
    },

    #[error(transparent)]
    ConfigFileFailed {
        #[from]
        source: ConfigFileError,
    },

    #[error("--nns_urls is required")]
    NnsUrlMissing,

    #[error("invalid IP address: {source}")]
    InvalidIpAddr {
        #[from]
        source: AddrParseError,
    },

    #[error("no --ic_name provided")]
    MissingIcName,

    #[error("no --service_discovery_file provided")]
    MissingServiceDiscoveryFile,

    #[error("could not parse duration {duration}: {source}")]
    InvalidDuration {
        duration: String,
        source: humantime::DurationError,
    },

    #[error("could not parse mode {mode}: {source}")]
    InvalidPermissionsMode { mode: String, source: ParseIntError },
}

/// External configuration -- from a config file and/or flags.
#[derive(Clone, Debug, Deserialize, Serialize, GFlags)]
#[serde(default)]
#[gflags(prefix = "_")]
pub(crate) struct Config {
    /// Path to configuration file to load
    #[gflags(placeholder = "PATH")]
    config_file: String,

    /// Path to the output service discovery file
    #[gflags(placeholder = "PATH")]
    pub(crate) service_discovery_file: String,

    /// path to NNS public key file
    #[gflags(placeholder = "NNS_PUBLIC_KEY_PATH")]
    pub(crate) nns_public_key_path: String,

    /// Final permissions for the service discovery file (e.g., 0o644)
    #[gflags(type = "&str", placeholder = "MODE")]
    pub(crate) service_discovery_file_mode: u32,

    /// Value to use as generated "ic" label. "sodium", "topochange", etc
    #[gflags(placeholder = "IC_NAME")]
    pub(crate) ic_name: String,

    /// ip:port to serve metrics on
    #[gflags(type = "&str", placeholder = "ADDR")]
    pub(crate) metrics_addr: SocketAddr,

    /// Count of seconds to elapse between service refreshes
    #[gflags(type = "&str")]
    #[serde(with = "humantime_serde")]
    pub(crate) discover_every: time::Duration,

    /// The log configuration
    #[gflags(skip)]
    pub(crate) log: ic_p8s_service_discovery_log::Config,

    /// The registry client configuration
    #[gflags(skip)]
    pub(crate) nns: nns::Config,
}

/// Configuration if nothing is provided
impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: "".to_string(),
            service_discovery_file: "".to_string(),
            nns_public_key_path: "".to_string(),
            service_discovery_file_mode: 0o640,
            ic_name: "".to_string(),
            discover_every: time::Duration::from_secs(30),
            metrics_addr: "127.0.0.1:8006".parse::<SocketAddr>().unwrap(),
            log: ic_p8s_service_discovery_log::Config::default(),
            nns: nns::Config::default(),
        }
    }
}

impl Config {
    /// Load config from `--config_file` arg (if present) and then override
    /// with any values provided on the command line.
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = if CONFIG_FILE.is_present() {
            read_config_from_file(CONFIG_FILE.flag)?
        } else {
            Config::default()
        };

        if DISCOVER_EVERY.is_present() {
            config.discover_every = parse_duration(DISCOVER_EVERY.flag).map_err(|source| {
                ConfigError::InvalidDuration {
                    duration: DISCOVER_EVERY.flag.to_string(),
                    source,
                }
            })?;
        }

        if METRICS_ADDR.is_present() {
            config.metrics_addr = METRICS_ADDR.flag.parse()?;
        }

        config.log = ic_p8s_service_discovery_log::from_flags(config.log)?;
        config.nns = nns::from_flags(config.nns)?;

        if config.nns.urls.is_empty() {
            return Err(ConfigError::NnsUrlMissing);
        }

        if SERVICE_DISCOVERY_FILE.is_present() {
            config.service_discovery_file = SERVICE_DISCOVERY_FILE.flag.to_string();
        }

        if NNS_PUBLIC_KEY_PATH.is_present() {
            config.nns_public_key_path = NNS_PUBLIC_KEY_PATH.flag.to_string();
        }

        if config.service_discovery_file.is_empty() {
            return Err(ConfigError::MissingServiceDiscoveryFile);
        }

        if SERVICE_DISCOVERY_FILE_MODE.is_present() {
            config.service_discovery_file_mode = parse::<u32>(SERVICE_DISCOVERY_FILE_MODE.flag)
                .map_err(|source| ConfigError::InvalidPermissionsMode {
                    mode: SERVICE_DISCOVERY_FILE_MODE.flag.to_string(),
                    source,
                })?;
        }

        if IC_NAME.is_present() && !IC_NAME.flag.to_string().is_empty() {
            config.ic_name = IC_NAME.flag.to_string();
        }

        if config.ic_name.is_empty() {
            return Err(ConfigError::MissingIcName);
        }

        Ok(config)
    }
}

#[derive(Error, Debug)]
pub(crate) enum ConfigFileError {
    #[error("loading configuration failed: {source}")]
    IoError {
        #[from]
        source: io::Error,
    },

    #[error("parsing configuration failed: {source}")]
    SerdeJsonError {
        #[from]
        source: serde_json::error::Error,
    },
}

fn read_config_from_file<P: AsRef<Path>>(path: P) -> Result<Config, ConfigFileError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let c = serde_json::from_reader(reader)?;

    Ok(c)
}
