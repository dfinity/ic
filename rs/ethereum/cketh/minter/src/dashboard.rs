#[cfg(test)]
mod tests;

use askama::Template;
use candid::Principal;
use ic_cketh_minter::endpoints::{EthTransaction, RetrieveEthStatus};
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEthEvent};
use ic_cketh_minter::eth_rpc::Hash;
use ic_cketh_minter::eth_rpc_client::responses::TransactionStatus;
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{BlockNumber, LedgerBurnIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::transactions::{EthWithdrawalRequest, Reimbursed};
use ic_cketh_minter::state::{EthBalance, MintedEvent, State};
use ic_ethereum_types::Address;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

mod filters {
    pub fn timestamp_to_datetime<T: std::fmt::Display>(timestamp: T) -> askama::Result<String> {
        let input = timestamp.to_string();
        let ts: i128 = input
            .parse()
            .map_err(|e| askama::Error::Custom(Box::new(e)))?;
        let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(ts).unwrap();
        // 2020-12-09T17:25:40+00:00
        let format =
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
                .unwrap();
        Ok(dt_offset.format(&format).unwrap())
    }
}

pub struct DashboardPendingTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub transaction_amount: Wei,
    pub status: RetrieveEthStatus,
}

pub struct DashboardFinalizedTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub transaction_amount: Wei,
    pub block_number: BlockNumber,
    pub transaction_hash: Hash,
    pub transaction_fee: Wei,
    pub status: TransactionStatus,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub minter_address: String,
    pub eth_helper_contract_address: String,
    pub next_transaction_nonce: TransactionNonce,
    pub minimum_withdrawal_amount: Wei,
    pub first_synced_block: BlockNumber,
    pub last_synced_block: BlockNumber,
    pub last_observed_block: Option<BlockNumber>,
    pub ledger_id: Principal,
    pub minted_events: Vec<MintedEvent>,
    pub events_to_mint: Vec<ReceivedEthEvent>,
    pub rejected_deposits: BTreeMap<EventSource, String>,
    pub withdrawal_requests: Vec<EthWithdrawalRequest>,
    pub pending_transactions: Vec<DashboardPendingTransaction>,
    pub finalized_transactions: Vec<DashboardFinalizedTransaction>,
    pub reimbursed_transactions: Vec<Reimbursed>,
    pub eth_balance: EthBalance,
    pub skipped_blocks: BTreeSet<BlockNumber>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        let mut minted_events: Vec<_> = state.minted_events.values().cloned().collect();
        minted_events.sort_unstable_by_key(|event| Reverse(event.mint_block_index));
        let mut events_to_mint: Vec<_> = state.eth_events_to_mint();
        events_to_mint.sort_unstable_by_key(|event| Reverse(event.block_number));

        let mut withdrawal_requests: Vec<_> = state
            .eth_transactions
            .withdrawal_requests_iter()
            .cloned()
            .collect();
        withdrawal_requests.sort_unstable_by_key(|req| Reverse(req.ledger_burn_index));

        let mut pending_transactions: Vec<_> = state
            .eth_transactions
            .transactions_to_sign_iter()
            .map(
                |(_nonce, ledger_burn_index, tx)| DashboardPendingTransaction {
                    ledger_burn_index: *ledger_burn_index,
                    destination: tx.destination,
                    transaction_amount: tx.amount,
                    status: RetrieveEthStatus::TxCreated,
                },
            )
            .collect();
        pending_transactions.extend(state.eth_transactions.sent_transactions_iter().flat_map(
            |(_nonce, ledger_burn_index, txs)| {
                txs.iter().map(|tx| DashboardPendingTransaction {
                    ledger_burn_index: *ledger_burn_index,
                    destination: tx.transaction().destination,
                    transaction_amount: tx.transaction().amount,
                    status: RetrieveEthStatus::TxSent(EthTransaction::from(tx)),
                })
            },
        ));
        pending_transactions
            .sort_unstable_by_key(|pending_tx| Reverse(pending_tx.ledger_burn_index));

        let mut finalized_transactions: Vec<_> = state
            .eth_transactions
            .finalized_transactions_iter()
            .map(|(_tx_nonce, index, tx)| DashboardFinalizedTransaction {
                ledger_burn_index: *index,
                destination: *tx.destination(),
                transaction_amount: *tx.transaction_amount(),
                block_number: *tx.block_number(),
                transaction_hash: *tx.transaction_hash(),
                transaction_fee: tx.effective_transaction_fee(),
                status: *tx.transaction_status(),
            })
            .collect();
        finalized_transactions.sort_unstable_by_key(|tx| Reverse(tx.ledger_burn_index));

        let mut reimbursed_transactions = state.eth_transactions.get_reimbursed_transactions();
        reimbursed_transactions
            .sort_unstable_by_key(|reimbursed_tx| std::cmp::Reverse(reimbursed_tx.withdrawal_id));

        DashboardTemplate {
            ethereum_network: state.ethereum_network,
            ecdsa_key_name: state.ecdsa_key_name.clone(),
            minter_address: state
                .minter_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            eth_helper_contract_address: state
                .eth_helper_contract_address
                .map_or("N/A".to_string(), |address| address.to_string()),
            ledger_id: state.ledger_id,
            next_transaction_nonce: state.eth_transactions.next_transaction_nonce(),
            minimum_withdrawal_amount: state.minimum_withdrawal_amount,
            first_synced_block: state.first_scraped_block_number,
            last_synced_block: state.last_scraped_block_number,
            last_observed_block: state.last_observed_block_number,
            minted_events,
            events_to_mint,
            rejected_deposits: state.invalid_events.clone(),
            withdrawal_requests,
            pending_transactions,
            finalized_transactions,
            reimbursed_transactions,
            eth_balance: state.eth_balance.clone(),
            skipped_blocks: state.skipped_blocks.clone(),
        }
    }
}
