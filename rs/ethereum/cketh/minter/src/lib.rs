pub mod address;
pub mod balance_scan;
pub mod blocklist;
mod cbor;
pub mod checked_amount;
pub mod deposit;
pub mod deposit_address;
pub mod endpoints;
pub mod erc20;
pub mod eth_logs;
pub mod eth_rpc;
pub mod eth_rpc_client;
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
pub mod timed_sized_map;
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
pub const REFRESH_LATEST_BLOCK_HEIGHT_INTERVAL: Duration = Duration::from_secs(30);
pub const BALANCE_SCAN_INTERVAL: Duration = Duration::from_secs(30);
pub const PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL: Duration = Duration::from_secs(6 * 60);
pub const PROCESS_REIMBURSEMENT: Duration = Duration::from_secs(3 * 60);
pub const PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL: Duration = Duration::from_secs(3 * 60);
pub const MINT_RETRY_DELAY: Duration = Duration::from_secs(3 * 60);
pub const EVM_RPC_ID_PRODUCTION: Principal =
    Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 204, 1, 1]);
pub const EVM_RPC_ID_STAGING: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 161, 1, 1]);
pub const CKETH_LEDGER_MEMO_SIZE: u16 = 80;

/// The minter's fee subaccount on the ckETH ledger — `0x…0fee`, the subaccount configured as the
/// ledger's fee collector, where ckETH transaction fees accrue.
///
/// Sweep gas is funded exclusively out of this account, never out of the ETH backing ckETH 1:1.
/// Burning from it needs [`crate::ledger_client::LedgerClient::burn_from_own_subaccount`] rather
/// than the allowance-based `burn_from` used for user withdrawals.
pub const CKETH_FEE_SUBACCOUNT: [u8; 32] = {
    let mut subaccount = [0_u8; 32];
    subaccount[30] = 0x0f;
    subaccount[31] = 0xee;
    subaccount
};
