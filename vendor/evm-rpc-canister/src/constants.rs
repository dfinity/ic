// The default value of max_resposne_bytes is 2_000_000.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 2_000_000;

// Cycles (per node) which must be passed with each RPC request
// as processing fee.
pub const COLLATERAL_CYCLES_PER_NODE: u128 = 10_000_000;

pub const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000;

pub const API_KEY_MAX_SIZE: u32 = 512;
pub const PROVIDER_MAX_SIZE: u32 = 256;
pub const MESSAGE_FILTER_MAX_SIZE: u32 = 1000;
pub const RPC_SERVICE_MAX_SIZE: u32 = 256;
pub const AUTH_SET_STORABLE_MAX_SIZE: u32 = 1000;
pub const WASM_PAGE_SIZE: u64 = 65536;

pub const NODES_IN_SUBNET: u32 = 34;

pub const API_KEY_REPLACE_STRING: &str = "{API_KEY}";
pub const VALID_API_KEY_CHARS: &str =
    "0123456789ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz$-_.+!*";

pub const CONTENT_TYPE_HEADER_LOWERCASE: &str = "content-type";
pub const CONTENT_TYPE_VALUE: &str = "application/json";

pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_SEPOLIA_CHAIN_ID: u64 = 11155111;
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42161;
pub const BASE_MAINNET_CHAIN_ID: u64 = 8453;
pub const OPTIMISM_MAINNET_CHAIN_ID: u64 = 10;
