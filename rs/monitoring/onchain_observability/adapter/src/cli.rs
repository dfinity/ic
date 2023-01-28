//! A parser for the configuration file.
// Here we can crash as we cannot proceed with an invalid config.
#![allow(clippy::expect_used)]

use crate::config::Config;
use clap::Parser;
use slog::Level;
use std::{fs::File, io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
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
pub struct Cli {
    /// This field contains the path to the config file.
    pub config: PathBuf,

    #[clap(short, long)]
    /// This field represents if the adapter should run in verbose.
    pub verbose: bool,
}

impl Cli {
    /// Gets the log filter level by checking the verbose field.
    pub fn get_logging_level(&self) -> Level {
        if self.verbose {
            Level::Debug
        } else {
            Level::Info
        }
    }

    /// Loads the config from the provided `config` argument.
    pub fn get_config(&self) -> Result<Config, CliError> {
        // The expected JSON config.
        let file = File::open(&self.config).map_err(CliError::Io)?;
        let config: Config =
            serde_json::from_reader(file).map_err(|err| CliError::Deserialize(err.to_string()))?;
        // TODO other fields

        Ok(config)
    }
}

//TODO add tests
