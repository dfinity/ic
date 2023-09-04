use askama::Template;
use candid::Principal;
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{EthereumNetwork, RetrieveEthStatus};
use ic_cketh_minter::eth_logs::{EventSource, EventSourceError, SMART_CONTRACT_ADDRESS};
use ic_cketh_minter::eth_rpc::{BlockNumber, Hash};
use ic_cketh_minter::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
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

pub struct DashboardConfirmedTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub transaction_amount: Wei,
    pub block_number: BlockNumber,
    pub transaction_hash: Hash,
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
    pub last_finalized_block: Option<BlockNumber>,
    pub ledger_id: Principal,
    pub minted_events: Vec<MintedEvent>,
    pub rejected_deposits: BTreeMap<EventSource, EventSourceError>,
    pub withdrawal_requests: Vec<EthWithdrawalRequest>,
    pub pending_transaction: Option<DashboardPendingTransaction>,
    pub confirmed_transactions: Vec<DashboardConfirmedTransaction>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        let mut minted_events: Vec<_> = state.minted_events.values().cloned().collect();
        minted_events.sort_unstable_by_key(|event| Reverse(event.mint_block_index));

        DashboardTemplate {
            ethereum_network: state.ethereum_network,
            ecdsa_key_name: state.ecdsa_key_name.clone(),
            minter_address: state
                .minter_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            contract_address: Address::new(SMART_CONTRACT_ADDRESS).to_string(),
            ledger_id: state.ledger_id,
            next_transaction_nonce: state.next_transaction_nonce,
            last_synced_block: state.last_scraped_block_number,
            last_finalized_block: state.last_finalized_block_number,
            minted_events,
            rejected_deposits: state.invalid_events.clone(),
            withdrawal_requests: state
                .eth_transactions
                .withdrawal_requests_iter()
                .cloned()
                .collect(),
            pending_transaction: state.eth_transactions.pending_tx_info().map(
                |(req, tx, status)| DashboardPendingTransaction {
                    ledger_burn_index: req.ledger_burn_index,
                    destination: tx.destination,
                    transaction_amount: tx.amount,
                    status: status.clone(),
                },
            ),
            confirmed_transactions: state
                .eth_transactions
                .confirmed_transactions_by_burn_index()
                .into_iter()
                .map(|(index, tx)| DashboardConfirmedTransaction {
                    ledger_burn_index: index,
                    destination: tx.transaction().destination,
                    transaction_amount: tx.transaction().amount,
                    block_number: tx.block_number(),
                    transaction_hash: tx.signed_transaction().hash(),
                })
                .collect(),
        }
    }
}
