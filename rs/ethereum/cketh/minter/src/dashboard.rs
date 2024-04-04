#[cfg(test)]
mod tests;

use crate::erc20::CkErc20Token;
use askama::Template;
use candid::Principal;
use ic_cketh_minter::endpoints::{EthTransaction, RetrieveEthStatus};
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEvent};
use ic_cketh_minter::eth_rpc::Hash;
use ic_cketh_minter::eth_rpc_client::responses::TransactionStatus;
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{BlockNumber, LedgerBurnIndex, LogIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::transactions::{Reimbursed, WithdrawalRequest};
use ic_cketh_minter::state::{EthBalance, MintedEvent, State};
use ic_ethereum_types::Address;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

mod filters {
    use super::*;

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

    //TODO XC-82: also render token symbol
    pub fn withdrawal_amount(request: &WithdrawalRequest) -> askama::Result<String> {
        match request {
            WithdrawalRequest::CkEth(r) => Ok(r.withdrawal_amount.to_string()),
            WithdrawalRequest::CkErc20(r) => Ok(r.withdrawal_amount.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct DashboardPendingDeposit {
    pub tx_hash: Hash,
    pub log_index: LogIndex,
    pub block_number: BlockNumber,
    pub from: Address,
    pub token_symbol: String,
    pub value: candid::Nat,
    pub beneficiary: Principal,
}

#[derive(Clone)]
pub struct DashboardPendingTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub transaction_amount: Wei,
    pub status: RetrieveEthStatus,
}

#[derive(Clone)]
pub struct DashboardFinalizedTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub transaction_amount: Wei,
    pub block_number: BlockNumber,
    pub transaction_hash: Hash,
    pub transaction_fee: Wei,
    pub status: TransactionStatus,
}

fn received_event_token_symbol(
    supported_ckerc20_tokens: &[CkErc20Token],
    event: &ReceivedEvent,
) -> String {
    match event {
        ReceivedEvent::Eth(_) => "ckETH".to_string(),
        ReceivedEvent::Erc20(event) => supported_ckerc20_tokens
            .iter()
            .find_map(|token| {
                if token.erc20_contract_address == event.erc20_contract_address {
                    Some(token.ckerc20_token_symbol.to_string())
                } else {
                    None
                }
            })
            .unwrap_or("N/A".to_string()),
    }
}

impl DashboardPendingDeposit {
    fn new(supported_ckerc20_tokens: &[CkErc20Token], event: &ReceivedEvent) -> Self {
        Self {
            tx_hash: event.transaction_hash(),
            log_index: event.log_index(),
            block_number: event.block_number(),
            from: event.from_address(),
            token_symbol: received_event_token_symbol(supported_ckerc20_tokens, event),
            value: event.value(),
            beneficiary: event.principal(),
        }
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
#[derive(Clone)]
pub struct DashboardTemplate {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub minter_address: String,
    pub eth_helper_contract_address: String,
    pub erc20_helper_contract_address: String,
    pub next_transaction_nonce: TransactionNonce,
    pub minimum_withdrawal_amount: Wei,
    pub first_synced_block: BlockNumber,
    pub last_eth_synced_block: BlockNumber,
    pub last_erc20_synced_block: Option<BlockNumber>,
    pub last_observed_block: Option<BlockNumber>,
    pub ledger_id: Principal,
    pub minted_events: Vec<MintedEvent>,
    pub pending_deposits: Vec<DashboardPendingDeposit>,
    pub rejected_deposits: BTreeMap<EventSource, String>,
    pub withdrawal_requests: Vec<WithdrawalRequest>,
    pub pending_transactions: Vec<DashboardPendingTransaction>,
    pub finalized_transactions: Vec<DashboardFinalizedTransaction>,
    pub reimbursed_transactions: Vec<Reimbursed>,
    pub eth_balance: EthBalance,
    pub skipped_blocks: BTreeSet<BlockNumber>,
    pub supported_ckerc20_tokens: Vec<CkErc20Token>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        let mut minted_events: Vec<_> = state.minted_events.values().cloned().collect();
        minted_events.sort_unstable_by_key(|event| {
            let deposit_event = &event.deposit_event;
            Reverse((deposit_event.block_number(), deposit_event.log_index()))
        });

        let mut supported_ckerc20_tokens: Vec<_> = state.supported_ck_erc20_tokens().collect();
        supported_ckerc20_tokens.sort_unstable_by_key(|token| token.ckerc20_token_symbol.clone());

        let mut events_to_mint = state.events_to_mint();
        events_to_mint
            .sort_unstable_by_key(|event| Reverse((event.block_number(), event.log_index())));
        let pending_deposits = events_to_mint
            .iter()
            .map(|event| DashboardPendingDeposit::new(&supported_ckerc20_tokens, event))
            .collect();

        let mut withdrawal_requests: Vec<_> = state
            .eth_transactions
            .withdrawal_requests_iter()
            .cloned()
            .collect();
        withdrawal_requests.sort_unstable_by_key(|req| Reverse(req.cketh_ledger_burn_index()));

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
                txs.into_iter().map(|tx| DashboardPendingTransaction {
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
            .sort_unstable_by_key(|reimbursed_tx| std::cmp::Reverse(reimbursed_tx.burn_in_block));

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
            erc20_helper_contract_address: state
                .erc20_helper_contract_address
                .map_or("N/A".to_string(), |address| address.to_string()),
            ledger_id: state.ledger_id,
            next_transaction_nonce: state.eth_transactions.next_transaction_nonce(),
            minimum_withdrawal_amount: state.minimum_withdrawal_amount,
            first_synced_block: state.first_scraped_block_number,
            last_eth_synced_block: state.last_scraped_block_number,
            last_erc20_synced_block: state
                .erc20_helper_contract_address
                .map(|_| state.last_erc20_scraped_block_number),
            last_observed_block: state.last_observed_block_number,
            minted_events,
            pending_deposits,
            rejected_deposits: state.invalid_events.clone(),
            withdrawal_requests,
            pending_transactions,
            finalized_transactions,
            reimbursed_transactions,
            eth_balance: state.eth_balance.clone(),
            skipped_blocks: state.skipped_blocks.clone(),
            supported_ckerc20_tokens,
        }
    }
}
