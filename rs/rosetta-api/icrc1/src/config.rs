use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ic_base_types::{CanisterId, PrincipalId};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::Level;
use url::Url;

const MAINNET_DEFAULT_URL: &str = "https://ic0.app";
const TESTNET_DEFAULT_URL: &str = "https://exchanges.testnet.dfinity.network";

#[derive(Clone, Debug, ValueEnum)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

/// Used in args.
#[derive(Clone, Debug, ValueEnum)]
pub enum StoreType {
    InMemory,
    File,
}

/// Used in config.
#[derive(Clone, Debug)]
pub enum Store {
    InMemory,
    File { dir_path: PathBuf },
}

// This struct is used to parse the token definitions from the command line arguments.
// The token definitions are in the format: canister_id[:s=symbol][:d=decimals]
// The symbol and decimals are optional.
#[derive(Clone, Debug)]
pub struct TokenDef {
    pub ledger_id: CanisterId,
    // Below are optional, checked against online values if set.
    pub icrc1_symbol: Option<String>,
    pub icrc1_decimals: Option<u8>,
}

impl TokenDef {
    pub fn from_string(token_description: &str) -> Result<Self> {
        let parts: Vec<&str> = token_description.split(':').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(anyhow::Error::msg(format!(
                "Invalid token description: {token_description}"
            )));
        }

        let principal_id = PrincipalId::from_str(parts[0])
            .context(format!("Failed to parse PrincipalId from {}", parts[0]))?;
        let ledger_id = CanisterId::try_from_principal_id(principal_id)?;

        let mut icrc1_symbol: Option<String> = None;
        let mut icrc1_decimals: Option<u8> = None;

        for part in parts.iter().skip(1) {
            if let Some(symbol) = part.strip_prefix("s=") {
                if icrc1_symbol.is_some() {
                    return Err(anyhow::Error::msg(format!(
                        "Invalid token description: {token_description}. Symbol (s=) can only be specified once"
                    )));
                }
                icrc1_symbol = Some(symbol.to_string());
            } else if let Some(decimals) = part.strip_prefix("d=") {
                if icrc1_decimals.is_some() {
                    return Err(anyhow::Error::msg(format!(
                        "Invalid token description: {token_description}. Decimals (d=) can only be specified once"
                    )));
                }
                icrc1_decimals = Some(
                    decimals
                        .parse()
                        .context(format!("Failed to parse u8 from {part}"))?,
                );
            } else {
                return Err(anyhow::Error::msg(format!(
                    "Invalid token description: {token_description}. It must be canister_id[:s=symbol][:d=decimals]"
                )));
            }
        }

        Ok(Self {
            ledger_id,
            icrc1_symbol,
            icrc1_decimals,
        })
    }

    pub fn are_metadata_args_set(&self) -> bool {
        self.icrc1_symbol.is_some() && self.icrc1_decimals.is_some()
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub ledger_id: Option<CanisterId>,

    /// The token definitions in the format: canister_id[:s=symbol][:d=decimals]
    /// The symbol and decimals are optional.
    /// Can't be used with ledger_id.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub multi_tokens: Vec<String>,

    /// The directory where the databases for the multi-tokens will be stored.
    #[arg(long, default_value = "/data")]
    pub multi_tokens_store_dir: PathBuf,

    /// The symbol of the ICRC-1 token.
    /// If set Rosetta will check the symbol against the ledger it connects to. If the symbol does not match, it will exit.
    #[arg(long)]
    pub icrc1_symbol: Option<String>,

    #[arg(long)]
    pub icrc1_decimals: Option<u8>,

    /// The port to which Rosetta will bind.
    /// If not set then it will be 0.
    #[arg(short, long)]
    pub port: Option<u16>,

    /// The file where the port to which Rosetta will bind
    /// will be written.
    #[arg(short = 'P', long)]
    pub port_file: Option<PathBuf>,

    /// The type of the store to use.
    #[arg(short, long, value_enum, default_value_t = StoreType::File)]
    pub store_type: StoreType,

    /// The file to use for the store if [store_type] is file.
    ///
    /// DEPRECATED: This parameter is not used. Use `multi_tokens_store_dir` instead.
    #[deprecated(
        since = "1.2.6",
        note = "This parameter is deprecated. Use `multi_tokens_store_dir` instead to specify the directory where database files will be stored."
    )]
    #[arg(short = 'f', long, default_value = "/data/db.sqlite")]
    pub store_file: PathBuf,

    /// The network type that rosetta connects to.
    /// DEPRECATED: This argument is deprecated.
    #[arg(short = 'n', long, value_enum)]
    pub network_type: Option<NetworkType>,

    /// URL of the IC to connect to.
    /// Default Mainnet URL is: https://ic0.app,
    /// Default Testnet URL is: https://exchanges.testnet.dfinity.network
    #[arg(long, short = 'u')]
    pub network_url: Option<String>,

    #[arg(short = 'L', long, default_value_t = Level::INFO)]
    pub log_level: Level,

    /// Set this option to only do one full sync of the ledger and then exit rosetta
    #[arg(long = "exit-on-sync")]
    pub exit_on_sync: bool,

    /// Set this option to only run the rosetta server, no block synchronization will be performed and no transactions can be submitted in this mode.
    #[arg(long)]
    pub offline: bool,

    /// The file to use for storing logs.
    #[arg(long = "log-file", default_value = "log/rosetta-api.log")]
    pub log_file: PathBuf,

    /// Timeout in seconds for sync watchdog. If no synchronization is attempted within this time, the sync thread will be restarted.
    #[arg(long = "watchdog-timeout-seconds", default_value = "60")]
    pub watchdog_timeout_seconds: u64,

    /// Maximum cache size for SQLite in KB. This controls the PRAGMA cache_size.
    /// Lower values reduce memory usage but may impact performance.
    #[arg(long = "sqlite-max-cache-kb")]
    pub sqlite_max_cache_kb: Option<i64>,

    /// Flush the cache and shrink the memory after processing account balances.
    /// If enabled, reduces memory usage but may impact performance.
    #[arg(long = "flush-cache-shrink-mem", default_value = "false")]
    pub flush_cache_shrink_mem: bool,

    /// Batch size for account balance synchronization. This controls how many blocks
    /// are loaded into memory at once when updating account balances.
    /// Lower values reduce memory usage but may slow down sync.
    /// Default is 100000 blocks per batch.
    #[arg(long = "balance-sync-batch-size")]
    pub balance_sync_batch_size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub tokens: Vec<TokenDef>,
    pub store: Store,
    pub port: Option<u16>,
    pub port_file: Option<PathBuf>,
    pub network_url: Url,
    pub log_level: Level,
    pub exit_on_sync: bool,
    pub offline: bool,
    pub log_file: PathBuf,
    pub watchdog_timeout_seconds: u64,
    pub sqlite_max_cache_kb: Option<i64>,
    pub flush_cache_shrink_mem: bool,
    pub balance_sync_batch_size: Option<u64>,
}

impl ParsedConfig {
    pub fn from_args(args: Args) -> Result<Self> {
        let tokens = Self::extract_token_defs_from_args(&args)?;

        let network_type = match args.network_type {
            Some(network_type) => {
                eprintln!(
                    "WARNING: The --network-type argument is deprecated and will be removed in a future version."
                );
                network_type
            }
            None => NetworkType::Mainnet,
        };

        // Compute the effective network URL based on network_type and provided URL
        let network_url_str = args.network_url.unwrap_or_else(|| match network_type {
            NetworkType::Mainnet => MAINNET_DEFAULT_URL.to_string(),
            NetworkType::Testnet => TESTNET_DEFAULT_URL.to_string(),
        });

        let network_url = Url::parse(&network_url_str)
            .context(format!("Failed to parse network URL: {network_url_str}"))?;

        // Construct the appropriate store type
        let store = match args.store_type {
            StoreType::InMemory => Store::InMemory,
            StoreType::File => Store::File {
                dir_path: args.multi_tokens_store_dir,
            },
        };

        Ok(Self {
            tokens,
            store,
            port: args.port,
            port_file: args.port_file,
            network_url,
            log_level: args.log_level,
            exit_on_sync: args.exit_on_sync,
            offline: args.offline,
            log_file: args.log_file,
            watchdog_timeout_seconds: args.watchdog_timeout_seconds,
            sqlite_max_cache_kb: args.sqlite_max_cache_kb,
            flush_cache_shrink_mem: args.flush_cache_shrink_mem,
            balance_sync_batch_size: args.balance_sync_batch_size,
        })
    }

    /// Parses TokenDefs from the command line arguments.
    fn extract_token_defs_from_args(args: &Args) -> Result<Vec<TokenDef>> {
        let mut input_tokens = args.multi_tokens.clone();

        // If no tokens are provided, use the legacy arguments
        if input_tokens.is_empty() {
            if args.ledger_id.is_none() {
                return Err(anyhow::Error::msg("No token definitions provided"));
            }

            let mut token_dec = format!("{}", args.ledger_id.unwrap(),);

            if args.icrc1_symbol.is_some() {
                token_dec.push_str(&format!(":s={}", args.icrc1_symbol.clone().unwrap()));
            }

            if args.icrc1_decimals.is_some() {
                token_dec.push_str(&format!(":d={}", args.icrc1_decimals.unwrap()));
            }

            input_tokens.push(token_dec);
        } else {
            if args.ledger_id.is_some() {
                return Err(anyhow::Error::msg(
                    "Cannot provide both multi-tokens and ledger-id",
                ));
            }
            if args.icrc1_symbol.is_some() {
                return Err(anyhow::Error::msg(
                    "Cannot provide both multi-tokens and icrc1-symbol",
                ));
            }
            if args.icrc1_decimals.is_some() {
                return Err(anyhow::Error::msg(
                    "Cannot provide both multi-tokens and icrc1-decimals",
                ));
            }
        }

        let token_defs: Vec<TokenDef> = input_tokens
            .iter()
            .map(|token_description| TokenDef::from_string(token_description))
            .collect::<Result<Vec<TokenDef>>>()?;

        Ok(token_defs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use tracing::Level;

    fn create_test_args() -> Args {
        Args {
            ledger_id: None,
            multi_tokens: vec![],
            multi_tokens_store_dir: PathBuf::from("/test"),
            icrc1_symbol: None,
            icrc1_decimals: None,
            port: None,
            port_file: None,
            store_type: StoreType::InMemory,
            #[allow(deprecated)]
            store_file: PathBuf::from("/test/db.sqlite"),
            network_type: None,
            network_url: None,
            log_level: Level::INFO,
            exit_on_sync: false,
            offline: false,
            log_file: PathBuf::from("/test/log"),
            watchdog_timeout_seconds: 60,
            sqlite_max_cache_kb: None,
            flush_cache_shrink_mem: false,
            balance_sync_batch_size: Some(100000),
        }
    }

    #[test]
    fn test_token_def_from_string_valid_canister_only() {
        let canister_id = "rdmx6-jaaaa-aaaaa-aaadq-cai";
        let token_def = TokenDef::from_string(canister_id).unwrap();

        assert_eq!(token_def.ledger_id.to_string(), canister_id);
        assert_eq!(token_def.icrc1_symbol, None);
        assert_eq!(token_def.icrc1_decimals, None);
    }

    #[test]
    fn test_token_def_from_string_with_symbol() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:s=ICP";
        let token_def = TokenDef::from_string(token_desc).unwrap();

        assert_eq!(
            token_def.ledger_id.to_string(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai"
        );
        assert_eq!(token_def.icrc1_symbol, Some("ICP".to_string()));
        assert_eq!(token_def.icrc1_decimals, None);
    }

    #[test]
    fn test_token_def_from_string_with_decimals() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:d=8";
        let token_def = TokenDef::from_string(token_desc).unwrap();

        assert_eq!(
            token_def.ledger_id.to_string(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai"
        );
        assert_eq!(token_def.icrc1_symbol, None);
        assert_eq!(token_def.icrc1_decimals, Some(8));
    }

    #[test]
    fn test_token_def_from_string_with_symbol_and_decimals() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:s=ICP:d=8";
        let token_def = TokenDef::from_string(token_desc).unwrap();

        assert_eq!(
            token_def.ledger_id.to_string(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai"
        );
        assert_eq!(token_def.icrc1_symbol, Some("ICP".to_string()));
        assert_eq!(token_def.icrc1_decimals, Some(8));
    }

    #[test]
    fn test_token_def_from_string_invalid_empty() {
        let result = TokenDef::from_string("");
        assert!(result.is_err());
        // Empty string gets split into one empty part, so it fails on principal parsing
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse PrincipalId")
        );
    }

    #[test]
    fn test_token_def_from_string_invalid_too_many_parts() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:s=ICP:d=8:extra";
        let result = TokenDef::from_string(token_desc);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid token description")
        );
    }

    #[test]
    fn test_token_def_from_string_invalid_principal() {
        let result = TokenDef::from_string("invalid-principal");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse PrincipalId")
        );
    }

    #[test]
    fn test_token_def_from_string_invalid_format() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:invalid=value";
        let result = TokenDef::from_string(token_desc);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("It must be canister_id[:s=symbol][:d=decimals]")
        );
    }

    #[test]
    fn test_token_def_from_string_invalid_decimals() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:d=invalid";
        let result = TokenDef::from_string(token_desc);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse u8")
        );
    }

    #[test]
    fn test_token_def_from_string_duplicate_symbol() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:s=ICP:s=ckBTC";
        let result = TokenDef::from_string(token_desc);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Symbol (s=) can only be specified once")
        );
    }

    #[test]
    fn test_token_def_from_string_duplicate_decimals() {
        let token_desc = "rdmx6-jaaaa-aaaaa-aaadq-cai:d=8:d=12";
        let result = TokenDef::from_string(token_desc);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Decimals (d=) can only be specified once")
        );
    }

    #[test]
    fn test_token_def_are_metadata_args_set() {
        let mut token_def = TokenDef {
            ledger_id: CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
            icrc1_symbol: None,
            icrc1_decimals: None,
        };

        assert!(!token_def.are_metadata_args_set());

        token_def.icrc1_symbol = Some("ICP".to_string());
        assert!(!token_def.are_metadata_args_set());

        token_def.icrc1_decimals = Some(8);
        assert!(token_def.are_metadata_args_set());
    }

    #[test]
    fn test_parsed_config_from_args_legacy_single_token() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.icrc1_symbol = Some("ICP".to_string());
        args.icrc1_decimals = Some(8);

        let config = ParsedConfig::from_args(args).unwrap();

        assert_eq!(config.tokens.len(), 1);
        assert_eq!(
            config.tokens[0].ledger_id.to_string(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai"
        );
        assert_eq!(config.tokens[0].icrc1_symbol, Some("ICP".to_string()));
        assert_eq!(config.tokens[0].icrc1_decimals, Some(8));
    }

    #[test]
    fn test_parsed_config_from_args_multi_tokens() {
        let mut args = create_test_args();
        args.multi_tokens = vec![
            "rdmx6-jaaaa-aaaaa-aaadq-cai:s=ICP:d=8".to_string(),
            "rrkah-fqaaa-aaaaa-aaaaq-cai".to_string(),
        ];

        let config = ParsedConfig::from_args(args).unwrap();

        assert_eq!(config.tokens.len(), 2);
        assert_eq!(
            config.tokens[0].ledger_id.to_string(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai"
        );
        assert_eq!(config.tokens[0].icrc1_symbol, Some("ICP".to_string()));
        assert_eq!(
            config.tokens[1].ledger_id.to_string(),
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
        assert_eq!(config.tokens[1].icrc1_symbol, None);
    }

    #[test]
    fn test_parsed_config_from_args_no_tokens_error() {
        let args = create_test_args();
        let result = ParsedConfig::from_args(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No token definitions provided")
        );
    }

    #[test]
    fn test_parsed_config_from_args_conflicting_args_ledger_id() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.multi_tokens = vec!["rrkah-fqaaa-aaaaa-aaaaq-cai".to_string()];

        let result = ParsedConfig::from_args(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot provide both multi-tokens and ledger-id")
        );
    }

    #[test]
    fn test_parsed_config_from_args_conflicting_args_symbol() {
        let mut args = create_test_args();
        args.icrc1_symbol = Some("ICP".to_string());
        args.multi_tokens = vec!["rrkah-fqaaa-aaaaa-aaaaq-cai".to_string()];

        let result = ParsedConfig::from_args(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot provide both multi-tokens and icrc1-symbol")
        );
    }

    #[test]
    fn test_parsed_config_from_args_conflicting_args_decimals() {
        let mut args = create_test_args();
        args.icrc1_decimals = Some(8);
        args.multi_tokens = vec!["rrkah-fqaaa-aaaaa-aaaaq-cai".to_string()];

        let result = ParsedConfig::from_args(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot provide both multi-tokens and icrc1-decimals")
        );
    }

    #[test]
    fn test_parsed_config_network_url_mainnet_default() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.network_type = Some(NetworkType::Mainnet);

        let config = ParsedConfig::from_args(args).unwrap();
        assert!(config.network_url.domain() == Some("ic0.app"));
    }

    #[test]
    fn test_parsed_config_network_url_testnet_default() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.network_type = Some(NetworkType::Testnet);

        let config = ParsedConfig::from_args(args).unwrap();

        assert_eq!(
            config.network_url.as_str(),
            "https://exchanges.testnet.dfinity.network/"
        );
    }

    #[test]
    fn test_parsed_config_network_url_none_defaults_to_mainnet() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.network_type = None;

        let config = ParsedConfig::from_args(args).unwrap();
        assert!(config.network_url.domain() == Some("ic0.app"));
    }

    #[test]
    fn test_parsed_config_network_url_custom() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.network_url = Some("https://custom.network.com".to_string());

        let config = ParsedConfig::from_args(args).unwrap();

        assert_eq!(config.network_url.as_str(), "https://custom.network.com/");
    }

    #[test]
    fn test_parsed_config_network_url_invalid() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.network_url = Some("invalid-url".to_string());

        let result = ParsedConfig::from_args(args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse network URL")
        );
    }

    #[test]
    fn test_parsed_config_store_memory() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.store_type = StoreType::InMemory;

        let config = ParsedConfig::from_args(args).unwrap();

        match config.store {
            Store::InMemory => {}
            Store::File { .. } => panic!("Expected InMemory store type"),
        }
    }

    #[test]
    fn test_parsed_config_store_file() {
        let mut args = create_test_args();
        args.ledger_id = Some(CanisterId::from_str("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap());
        args.store_type = StoreType::File;
        args.multi_tokens_store_dir = PathBuf::from("/custom/path");

        let config = ParsedConfig::from_args(args).unwrap();

        match config.store {
            Store::File { dir_path } => {
                assert_eq!(dir_path, PathBuf::from("/custom/path"));
            }
            Store::InMemory => panic!("Expected File store type"),
        }
    }
}
