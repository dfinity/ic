//! A parser for the configuration file.
// Here we can crash as we cannot proceed with an invalid config.
#![allow(clippy::expect_used)]

use crate::config::{Config, OnchainObservabilityAdapterSpecificConfig};
use clap::Parser;
use ic_config::{Config as ReplicaConfig, ConfigSource};
use slog::Level;
use std::{fs::File, io, path::PathBuf};
use tempfile::Builder;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FlagsError {
    #[error("{0}")]
    Io(io::Error),
    #[error("An error occurred while deserialized the provided configuration: {0}")]
    Deserialize(String),
    #[error("An error occurred while validating the provided configuration: {0}")]
    Validation(String),
}

/// This struct is use to provide a command line interface to the adapter.
#[derive(Parser)]
#[clap(version = "0.1.0", author = "DFINITY team <team@dfinity.org>")]
pub struct Flags {
    /// Config specific to the onchain observability adapter. This will be combined with replica config to generate overall config.
    #[clap(long = "adapter-specific-config-file", parse(from_os_str))]
    pub adapter_specific_config: PathBuf,
    /// We also want to stay in sync with replica filepaths for crypto, registry
    #[clap(long = "replica-config-file", parse(from_os_str))]
    pub replica_config: PathBuf,
    /// This field represents if the adapter should run in verbose.
    #[clap(short, long)]
    pub verbose: bool,
}

impl Flags {
    /// Gets the log filter level by checking the verbose field.
    pub fn get_logging_level(&self) -> Level {
        if self.verbose {
            Level::Debug
        } else {
            Level::Info
        }
    }

    /// Loads the adapter specific config and replica config and synthesizes into a final config
    pub fn get_config(&self) -> Result<Config, FlagsError> {
        let adapter_specific_config_file =
            File::open(&self.adapter_specific_config).map_err(FlagsError::Io)?;
        let adapter_specific_config: OnchainObservabilityAdapterSpecificConfig =
            serde_json::from_reader(adapter_specific_config_file)
                .map_err(|err| FlagsError::Deserialize(err.to_string()))?;

        let replica_config = get_replica_config(self.replica_config.clone());

        Ok(Config {
            logger: adapter_specific_config.logger,
            crypto_config: replica_config.crypto,
            registry_config: replica_config.registry_client,
            report_length_sec: adapter_specific_config.report_length_sec,
            sampling_interval_sec: adapter_specific_config.sampling_interval_sec,
            canister_client_url: adapter_specific_config.canister_client_url,
            canister_id: adapter_specific_config.canister_id,
        })
    }
}

fn get_replica_config(replica_config_file: PathBuf) -> ReplicaConfig {
    let tmpdir = Builder::new()
        .prefix("ic_config")
        .tempdir()
        .expect("failed to create temporary directory for replica config")
        .path()
        .to_path_buf();

    ReplicaConfig::load_with_tmpdir(ConfigSource::File(replica_config_file), tmpdir)
}
// TODO add tests
