pub mod convert;
pub mod errors;
pub mod ledger_client;
pub mod models;
pub mod request;
pub mod request_handler;
pub mod request_types;
pub mod rosetta_server;
pub mod transaction_id;

pub const API_VERSION: &str = "1.4.10";
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_TOKEN_SYMBOL: &str = "ICP";
pub const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";
pub const MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST: u64 = 10000;
