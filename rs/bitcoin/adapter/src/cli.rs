//! A parser for the command line flags and configuration file.
use clap::Parser;
use http::Uri;
use ic_btc_adapter::{address_limits, Config};
use std::{fs::File, io, path::PathBuf};
use thiserror::Error;

#[allow(missing_docs)]
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
#[clap(version = "0.0.0", author = "DFINITY team <team@dfinity.org>")]
pub struct Cli {
    /// This field contains the path to the config file.
    pub config: PathBuf,
}

impl Cli {
    /// Loads the config from the provided `config` argument.
    pub fn get_config(&self) -> Result<Config, CliError> {
        // The expected JSON config.
        let file = File::open(&self.config).map_err(CliError::Io)?;
        let mut config: Config =
            serde_json::from_reader(file).map_err(|err| CliError::Deserialize(err.to_string()))?;

        // Set the address limits based on the specified network.
        config.address_limits = address_limits(config.network);

        // Validate proxy URL.
        // Check for general validation errors.
        if let Some(socks_proxy) = &config.socks_proxy {
            let uri = socks_proxy
                .parse::<Uri>()
                .map_err(|_| CliError::Validation("Failed to parse socks_proxy url".to_string()))?;
            // scheme, host, port should be present. 'socks5://someproxy.com:80'
            if uri.scheme().is_none() || uri.host().is_none() || uri.port().is_none() {
                return Err(CliError::Validation(
                    "Make sure socks proxy url contains (scheme,host,port)".to_string(),
                ));
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::IncomingSource;
    use bitcoin::Network;
    use std::io::Write;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    const EMPTY_CONFIG: &str = r#"{}"#;
    const MAINNET_CONFIG: &str = r#"{
        "network": "bitcoin",
        "dns_seeds": [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr.org",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.org",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz"
        ],
        "logger": {
            "format": "json",
            "level": "info"
        }
    }"#;
    const TESTNET_CONFIG: &str = r#"{
        "network": "testnet",
        "dns_seeds": [
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.org",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me"
        ],
        "incoming_source": {
            "Path": "/tmp/ic-btc-adapter.socket"
        },
        "ipv6_only": true    
    }"#;

    const TESTNET_BAD_SOCKS_CONFIG: &str = r#"{
        "network": "testnet",
        "socks_proxy": "socks5.notaproxy.com"        
    }"#;

    #[test]
    fn test_cli_get_config_error_opening_file() {
        let cli = Cli {
            config: PathBuf::from_str("/tmp/btc-adapter-test.json").expect("Bad file path string"),
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, CliError::Io(_)));
    }

    #[test]
    fn test_cli_get_config_error_invalid_json() {
        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", EMPTY_CONFIG).expect("Failed to write to tmp file");
        let cli = Cli {
            config: tmpfile.path().to_owned(),
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
    fn test_cli_bad_socks_url() {
        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", TESTNET_BAD_SOCKS_CONFIG).expect("Failed to write to tmp file");
        let cli = Cli {
            config: tmpfile.path().to_owned(),
        };
        let result = cli.get_config();
        assert!(result.is_err());
        let error = result.unwrap_err();
        let matches = match error {
            CliError::Validation(message) => message.contains("Make sure socks proxy url contains"),
            _ => false,
        };
        assert!(matches);
    }

    #[test]
    fn test_cli_get_config_good_mainnet_json() {
        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", MAINNET_CONFIG).expect("Failed to write to tmp file");
        let cli = Cli {
            config: tmpfile.path().to_owned(),
        };
        let result = cli.get_config();
        let config = result.unwrap();
        assert_eq!(config.network, Network::Bitcoin);
        assert_eq!(config.address_limits, (500, 2000));
        assert_eq!(config.dns_seeds.len(), 9);
        assert_eq!(config.socks_proxy, None);
        assert_eq!(config.incoming_source, IncomingSource::Systemd);
    }

    #[test]
    fn test_cli_get_config_good_testnet_json() {
        let mut tmpfile = NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(tmpfile, "{}", TESTNET_CONFIG).expect("Failed to write to tmp file");
        let cli = Cli {
            config: tmpfile.path().to_owned(),
        };
        let result = cli.get_config();
        let config = result.unwrap();
        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.address_limits, (100, 1000));
        assert_eq!(config.dns_seeds.len(), 4);
        assert_eq!(config.socks_proxy, None);
        assert_eq!(
            config.incoming_source,
            IncomingSource::Path(PathBuf::from("/tmp/ic-btc-adapter.socket"))
        );
    }
}
