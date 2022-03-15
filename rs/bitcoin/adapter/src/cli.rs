//! A parser for the command line flags and configuration file.
use crate::config::Config;
use clap::{AppSettings, Clap};
use slog::Level;
use std::{fs::File, io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Io(io::Error),
    #[error("An error occurred while deserialized the provided configuration: {0}")]
    Deserialize(String),
}
/// This struct is use to provide a command line interface to the adapter.
#[derive(Clap)]
#[clap(version = "0.0.0", author = "DFINITY team <team@dfinity.org>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Cli {
    /// This field contains the path to the config file.
    pub config: PathBuf,

    /// This field represents if the adapter should ignore connecting to IPv4 addresses only.
    #[clap(short, long)]
    pub ipv6_only: bool,

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
        serde_json::from_reader(file).map_err(|err| CliError::Deserialize(err.to_string()))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::IncomingSource;
    use bitcoin::Network;
    use std::path::PathBuf;
    use std::str::FromStr;

    /// This function tests the `Cli::get_logging_level()` function.
    #[test]
    fn test_cli_get_logging_level() {
        let cli = Cli {
            config: PathBuf::new(),
            ipv6_only: false,
            verbose: false,
        };

        assert_eq!(cli.get_logging_level(), Level::Info);

        let cli = Cli {
            config: PathBuf::new(),
            ipv6_only: false,
            verbose: true,
        };

        assert_eq!(cli.get_logging_level(), Level::Debug);
    }

    #[test]
    fn test_cli_get_config_error_opening_file() {
        let cli = Cli {
            config: PathBuf::from_str("/tmp/btc-adapter-test.json").expect("Bad file path string"),
            ipv6_only: false,
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
            config: PathBuf::from_str("./src/json_configs/empty.config.json")
                .expect("Bad file path string"),
            ipv6_only: false,
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
    fn test_cli_get_config_good_mainnet_json() {
        let cli = Cli {
            config: PathBuf::from_str("./src/json_configs/mainnet.config.json")
                .expect("Bad file path string"),
            ipv6_only: false,
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        assert_eq!(config.network, Network::Bitcoin);
        assert_eq!(config.dns_seeds.len(), 9);
        assert_eq!(config.socks_proxy, None);
        assert_eq!(config.incoming_source, IncomingSource::Systemd);
    }

    #[test]
    fn test_cli_get_config_good_testnet_json() {
        let cli = Cli {
            config: PathBuf::from_str("./src/json_configs/testnet.config.json")
                .expect("Bad file path string"),
            ipv6_only: false,
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.dns_seeds.len(), 4);
        assert_eq!(config.socks_proxy, None);
        assert_eq!(
            config.incoming_source,
            IncomingSource::Path(PathBuf::from("/tmp/ic-btc-adapter.socket"))
        );
    }
}
