pub mod address;
pub mod blocklist;
mod cbor;
pub mod checked_amount;
pub mod deposit;
pub mod endpoints;
pub mod erc20;
pub mod eth_logs;
pub mod eth_rpc;
pub mod eth_rpc_client;
pub mod eth_rpc_error;
pub mod guard;
pub mod ledger_client;
pub mod lifecycle;
pub mod logs;
pub mod management;
pub mod map;
pub mod memo;
pub mod numeric;
pub mod state;
pub mod storage;
pub mod tx;
pub mod withdraw;

#[cfg(test)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;

use candid::Principal;
use serde_bytes::ByteBuf;
use std::time::Duration;

pub const MAIN_DERIVATION_PATH: Vec<ByteBuf> = vec![];
pub const SCRAPING_ETH_LOGS_INTERVAL: Duration = Duration::from_secs(3 * 60);
pub const PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL: Duration = Duration::from_secs(6 * 60);
pub const PROCESS_REIMBURSEMENT: Duration = Duration::from_secs(3 * 60);
pub const PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL: Duration = Duration::from_secs(3 * 60);
pub const MINT_RETRY_DELAY: Duration = Duration::from_secs(3 * 60);
pub const EVM_RPC_ID_MAINNET: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 204, 1, 1]);
pub const EVM_RPC_ID_STAGING: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 161, 1, 1]);

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn test_evm_rpc_id_mainnet_value() {
        assert_eq!(
            EVM_RPC_ID_MAINNET.to_string(),
            "7hfb6-caaaa-aaaar-qadga-cai"
        );
    }

    #[test]
    fn test_evm_rpc_id_staging_value() {
        assert_eq!(
            EVM_RPC_ID_STAGING.to_string(),
            "xhcuo-6yaaa-aaaar-qacqq-cai"
        );
    }
}
