//! A parser for the configuration file.
// Here we can crash as we cannot proceed with an invalid config.
#![allow(clippy::expect_used)]

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
    use std::io::Write;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tempfile::NamedTempFile;
    use url::Url;

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

    // This function tests opening a config file that does not exist.
    #[test]
    fn test_cli_get_config_error_opening_file() {
        let cli = Cli {
            config: PathBuf::from_str("/tmp/http-adapter-test.json").expect("Bad file path string"),
            verbose: true,
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, CliError::Io(_)));
    }

    // This function tests using a invalid JSON file.
    #[test]
    fn test_cli_get_config_bad_json() {
        let json = r#"{asdf"#;

        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", json).expect("Failed to write to tmp file");

        // should use the default values
        let cli = Cli {
            config: tmpfile.path().to_owned(),
            verbose: true,
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        let matches = match error {
            CliError::Deserialize(message) => message == "key must be a string at line 1 column 2",
            _ => false,
        };
        assert!(matches);
    }

    // This function tests an empty json file. In this case there should be fallback to the default values.
    #[test]
    fn test_cli_get_config_empty_json() {
        let json = r#"{}"#;

        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", json).expect("Failed to write to tmp file");

        // should use the default values
        let cli = Cli {
            config: tmpfile.path().to_owned(),
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        let expected_config = Config::default();
        assert_eq!(config, expected_config);
    }

    // This function tests having an unknown field in the JSON. The unknown field is ignored and it falls back to the defaults.
    #[test]
    fn test_cli_get_config_unknown_field_json() {
        let json = r#"{
            "unknown": "unknown"
        }"#;

        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", json).expect("Failed to write to tmp file");

        let cli = Cli {
            config: tmpfile.path().to_owned(),
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        let expected_config = Config::default();
        assert_eq!(config, expected_config);
    }

    // This function tests a partially specified config file. It overwrites all default values.
    #[test]
    fn test_cli_get_partial_config_json() {
        let json = r#"
        {
            "http_request_timeout_secs": 20,
            "incoming_source": "Systemd",
            "logger": {
                "dc_id": 200,
                "format": "text_full",
                "debug_overrides": [],
                "block_on_overflow": false
            }        
        }       
        "#;

        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", json).expect("Failed to write to tmp file");

        // should use the default values
        let cli = Cli {
            config: tmpfile.path().to_owned(),
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        let expected_config = Config {
            http_request_timeout_secs: 20,
            incoming_source: IncomingSource::Systemd,
            logger: ic_config::logger::Config {
                dc_id: 200,
                format: ic_config::logger::LogFormat::TextFull,
                debug_overrides: Vec::new(),
                block_on_overflow: false,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(config, expected_config);
    }

    // This function tests a fully specified config file. It overwrites all default values.
    #[test]
    fn test_cli_get_full_config_json() {
        let json = r#"
        {
            "http_connect_timeout_secs": 20,
            "http_request_timeout_secs": 50,
            "http_request_size_limit_bytes": 1073741824,
            "incoming_source": {
                    "Path": "/tmp/path.socket"
            },
            "logger": {
                "node_id": 0,
                "dc_id": 200,
                "level": "info",
                "format": "json",
                "debug_overrides": [],
                "enabled_tags": [],
                "block_on_overflow": true
            },
            "socks_proxy": "socks5://notaproxy.com"        
        }       
        "#;

        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", json).expect("Failed to write to tmp file");

        // should use the default values
        let cli = Cli {
            config: tmpfile.path().to_owned(),
            verbose: true,
        };
        let result = cli.get_config();
        let config = result.unwrap();
        let expected_config = Config {
            http_connect_timeout_secs: 20,
            http_request_timeout_secs: 50,
            http_request_size_limit_bytes: 1073741824,
            incoming_source: IncomingSource::Path(PathBuf::from("/tmp/path.socket")),
            logger: ic_config::logger::Config {
                node_id: 0,
                dc_id: 200,
                level: slog::Level::Info,
                format: ic_config::logger::LogFormat::Json,
                debug_overrides: Vec::new(),
                ..Default::default()
            },
            socks_proxy: Some(Url::parse("socks5://notaproxy.com").unwrap()),
        };
        assert_eq!(config, expected_config);
    }
}
