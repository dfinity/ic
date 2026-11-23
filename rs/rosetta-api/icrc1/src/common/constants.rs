use std::time::Duration;

pub const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";
pub const ROSETTA_VERSION: &str = "1.2.10";
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const INGRESS_INTERVAL_SECS: u64 = 4 * 60;
pub const BLOCK_SYNC_WAIT_SECS: u64 = 1;
pub const MAX_BLOCK_SYNC_WAIT_SECS: u64 = 60;
pub const MIN_PROGRESS_BAR: u64 = 50;
pub const MINT_OPERATION_IDENTIFIER: u64 = 0;
pub const BURN_OPERATION_IDENTIFIER: u64 = 1;
pub const TRANSFER_TO_OPERATION_IDENTIFIER: u64 = 3;
pub const TRANSFER_FROM_OPERATION_IDENTIFIER: u64 = 4;
pub const FEE_OPERATION_IDENTIFIER: u64 = 5;
pub const APPROVE_OPERATION_IDENTIFIER: u64 = 6;
pub const SPENDER_OPERATION_IDENTIFIER: u64 = 7;
pub const FEE_COLLECTOR_OPERATION_IDENTIFIER: u64 = 8;
pub const MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST: u64 = 10000;
pub const INGRESS_INTERVAL_OVERLAP: Duration = Duration::from_secs(120);
/// Maximum permitted ingress window, mirroring the 24-hour bound documented on
/// `ConstructionPayloadsRequestMetadata`.
pub const MAX_INGRESS_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum permitted memo length in `/construction/payloads`. The memo is copied
/// into every envelope of the unsigned transaction, so its size must be bounded.
/// This is well above the max memo length of any production ICRC-1 ledger.
pub const MAX_MEMO_LENGTH_BYTES: usize = 1024;
/// Maximum permitted size of the Candid-encoded ledger method arguments built in
/// `/construction/payloads`. The arguments are copied into every envelope of the unsigned
/// transaction, so their size must be bounded.
pub const MAX_CANISTER_METHOD_ARGS_BYTES: usize = 4 * 1024;
/// Maximum number of envelopes of a transaction in `/construction/combine`. This is the number of
/// ingress expiries `/construction/payloads` builds for the longest ingress window,
/// `MAX_INGRESS_WINDOW`, with an expiry every 2 minutes.
pub const MAX_ENVELOPES_PER_TRANSACTION: usize = 720;
/// Maximum size of a signature in `/construction/combine`. Signatures are copied into every
/// envelope they sign, so their size must be bounded. Ed25519 and ECDSA secp256k1 signatures
/// are 64 bytes long.
pub const MAX_SIGNATURE_BYTES: usize = 64;
/// Maximum size of a public key in `/construction/combine`, which is copied into every envelope
/// like the signature. This is the size of an uncompressed secp256k1 public key.
pub const MAX_PUBLIC_KEY_BYTES: usize = 65;
pub const STATUS_COMPLETED: &str = "COMPLETED";
pub const MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST: u64 = 10000;
