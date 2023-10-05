use askama::Template;
use candid::Principal;
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{EthTransaction, RetrieveEthStatus};
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEthEvent};
use ic_cketh_minter::eth_rpc::Hash;
use ic_cketh_minter::eth_rpc_client::responses::TransactionStatus;
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{BlockNumber, LedgerBurnIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::{MintedEvent, State};
use ic_cketh_minter::transactions::EthWithdrawalRequest;
use std::cmp::Reverse;
use std::collections::BTreeMap;

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
    pub contract_address: String,
    pub next_transaction_nonce: TransactionNonce,
    pub last_synced_block: BlockNumber,
    pub last_observed_block: Option<BlockNumber>,
    pub ledger_id: Principal,
    pub minted_events: Vec<MintedEvent>,
    pub events_to_mint: Vec<ReceivedEthEvent>,
    pub rejected_deposits: BTreeMap<EventSource, String>,
    pub withdrawal_requests: Vec<EthWithdrawalRequest>,
    pub pending_transactions: Vec<DashboardPendingTransaction>,
    pub finalized_transactions: Vec<DashboardFinalizedTransaction>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        let mut minted_events: Vec<_> = state.minted_events.values().cloned().collect();
        minted_events.sort_unstable_by_key(|event| Reverse(event.mint_block_index));
        let mut events_to_mint: Vec<_> = state.events_to_mint.values().cloned().collect();
        events_to_mint.sort_unstable_by_key(|event| Reverse(event.block_number));

        let mut withdrawal_requests: Vec<_> = state
            .eth_transactions
            .withdrawal_requests_iter()
            .cloned()
            .collect();
        withdrawal_requests.sort_unstable_by_key(|req| Reverse(req.ledger_burn_index));

        let mut pending_transactions: Vec<_> = state
            .eth_transactions
            .created_transactions_iter()
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

        DashboardTemplate {
            ethereum_network: state.ethereum_network,
            ecdsa_key_name: state.ecdsa_key_name.clone(),
            minter_address: state
                .minter_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            contract_address: state
                .ethereum_contract_address
                .map_or("N/A".to_string(), |address| address.to_string()),
            ledger_id: state.ledger_id,
            next_transaction_nonce: state.eth_transactions.next_transaction_nonce(),
            last_synced_block: state.last_scraped_block_number,
            last_observed_block: state.last_observed_block_number,
            minted_events,
            events_to_mint,
            rejected_deposits: state.invalid_events.clone(),
            withdrawal_requests,
            pending_transactions,
            finalized_transactions,
        }
    }
}
