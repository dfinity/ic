use std::time::Duration;

pub mod address;
pub mod blocklist;
mod cbor;
pub mod checked_amount;
pub mod endpoints;
pub mod eth_logs;
pub mod eth_rpc;
pub mod eth_rpc_client;
pub mod eth_rpc_error;
pub mod guard;
pub mod lifecycle;
pub mod logs;
pub mod management;
pub mod map;
pub mod numeric;
mod serde_data;
pub mod state;
pub mod storage;
pub mod transactions;
pub mod tx;

#[cfg(test)]
mod tests;

use serde_bytes::ByteBuf;

pub const MAIN_DERIVATION_PATH: Vec<ByteBuf> = vec![];
pub const SCRAPPING_ETH_LOGS_INTERVAL: Duration = Duration::from_secs(3 * 60);
pub const PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL: Duration = Duration::from_secs(15);
pub const MINT_RETRY_DELAY: Duration = Duration::from_secs(3 * 60);
