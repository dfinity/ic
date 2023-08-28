pub mod address;
pub mod endpoints;
pub mod eth_logs;
pub mod eth_rpc;
pub mod eth_rpc_client;
pub mod eth_rpc_error;
pub mod guard;
pub mod logs;
pub mod management;
pub mod numeric;
mod serde_data;
pub mod state;
pub mod transactions;
pub mod tx;

#[cfg(test)]
mod tests;

use serde_bytes::ByteBuf;

pub const MAIN_DERIVATION_PATH: Vec<ByteBuf> = vec![];
