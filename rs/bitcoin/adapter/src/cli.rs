//! A parser for the configuration file.
// Here we can crash as we cannot proceed with an invalid config.
#![allow(clippy::expect_used)]

use crate::config::Config;
use bitcoin::Network;
use clap::{AppSettings, Clap};
use serde::Deserialize;
use slog::Level;
use std::net::SocketAddr;
use std::str::FromStr;
use std::{fs::File, io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Io(io::Error),
    #[error("An error occurred while deserialized the provided configuration: {0}")]
    Deserialize(String),
}

pub type CliResult<T> = Result<T, CliError>;

/// This struct is use to provide a command line interface to the adapter.
#[derive(Clap)]
#[clap(version = "0.0.0", author = "DFINITY team <team@dfinity.org>")]
#[clap(setting = AppSettings::ColoredHelp)]
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
    pub fn get_config(&self) -> CliResult<Config> {
        // The expected JSON config.
        //
        // This is similar to `Config`, but additional fields are marked as optional
        // so that they don't need to be specified in config files.
        #[derive(Deserialize)]
        struct CliConfig {
            network: Network,
            additional_seeds: Option<Vec<String>>,
            socks_proxy: Option<SocketAddr>,
            nodes: Option<Vec<String>>,
        }

        let file = File::open(&self.config).map_err(CliError::Io)?;

        let cli_config: CliResult<CliConfig> =
            serde_json::from_reader(file).map_err(|err| CliError::Deserialize(err.to_string()));

        // Convert the `CliConfig` to `Config`, adding default values where necessary.
        cli_config.map(|cli_config| {
            let mut dns_seeds = seeds(cli_config.network);
            if let Some(ref additional_seeds) = cli_config.additional_seeds {
                dns_seeds.extend(additional_seeds.clone());
            }

            Config {
                network: cli_config.network,
                dns_seeds,
                socks_proxy: cli_config.socks_proxy,
                nodes: cli_config
                    .nodes
                    .unwrap_or_else(Vec::new)
                    .iter()
                    .map(|node_addr| SocketAddr::from_str(node_addr).expect("Invalid node address"))
                    .collect(),
            }
        })
    }
}

/// Returns a list of default seed addresses to use based on the Bitcoin network provided.
/// The mainnet addresses were retrieved from [here](https://github.com/bitcoin/bitcoin/blame/master/src/chainparams.cpp#L121),
/// and the testnet addresses were retrieved from [here](https://github.com/bitcoin/bitcoin/blame/master/src/chainparams.cpp#L233).
fn seeds(network: Network) -> Vec<String> {
    match network {
        Network::Bitcoin => vec![
            "seed.bitcoin.sipa.be",          // Pieter Wuille
            "dnsseed.bluematt.me",           // Matt Corallo
            "dnsseed.bitcoin.dashjr.org",    // Luke Dashjr
            "seed.bitcoinstats.com",         // Christian Decker
            "seed.bitcoin.jonasschnelli.ch", // Jonas Schnelli
            "seed.btc.petertodd.org",        // Peter Todd
            "seed.bitcoin.sprovoost.nl",     // Sjors Provoost
            "dnsseed.emzy.de",               // Stephan Oeste
            "seed.bitcoin.wiz.biz",          // Jason Maurice
        ],
        Network::Testnet => vec![
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.org",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me",
        ],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use bitcoin::Network;

    use super::*;

    /// This function tests the `Cli::get_logging_level()` function.
    #[test]
    fn test_cli_get_logging_level() {
        let cli = Cli {
            config: PathBuf::new(),
            verbose: false,
        };

        assert_eq!(cli.get_logging_level(), Level::Info);

        let cli = Cli {
            config: PathBuf::new(),
            verbose: true,
        };

        assert_eq!(cli.get_logging_level(), Level::Debug);
    }

    #[test]
    fn test_cli_get_config_error_opening_file() {
        let cli = Cli {
            config: PathBuf::from_str("/tmp/btc-adapter-test.json").expect("Bad file path string"),
            verbose: true,
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, CliError::Io(_)));
    }

    #[test]
    fn test_cli_get_config_error_invalid_json() {
        let cli = Cli {
            config: PathBuf::from_str("./tests/sample/empty.config.json")
                .expect("Bad file path string"),
            verbose: true,
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        let matches = match error {
            CliError::Deserialize(message) => {
                message == "missing field `network` at line 1 column 2"
            }
            _ => false,
        };
        assert!(matches);
    }

    #[test]
    fn test_cli_get_config_good_baseline_json() {
        let cli = Cli {
            config: PathBuf::from_str("./tests/sample/baseline.config.json")
                .expect("Bad file path string"),
            verbose: true,
        };
        let result = cli.get_config();
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.network, Network::Bitcoin);
    }
}
