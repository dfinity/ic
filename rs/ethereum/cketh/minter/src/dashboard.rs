#[cfg(test)]
mod tests;

use askama::Template;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::{EthTransaction, RetrieveEthStatus};
use ic_cketh_minter::erc20::CkTokenSymbol;
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEvent};
use ic_cketh_minter::eth_rpc::Hash;
use ic_cketh_minter::eth_rpc_client::responses::TransactionStatus;
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{
    BlockNumber, Erc20Value, LedgerBurnIndex, LedgerMintIndex, LogIndex, TransactionNonce, Wei,
};
use ic_cketh_minter::state::eth_logs_scraping::LogScrapings;
use ic_cketh_minter::state::transactions::{
    ReimbursedError, ReimbursementIndex, TransactionCallData, WithdrawalRequest,
};
use ic_cketh_minter::state::{EthBalance, InvalidEventReason, MintedEvent, State};
use ic_cketh_minter::tx::Eip1559TransactionRequest;
use ic_ethereum_types::Address;
use ic_http_types::HttpRequest;
use icrc_ledger_types::icrc1::account::Account;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

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

    pub fn lower_alphanumeric<T: std::fmt::Display>(input: T) -> askama::Result<String> {
        let mut input = input.to_string();
        input.make_ascii_lowercase();
        input.retain(|c| c.is_ascii_alphanumeric());
        Ok(input)
    }
}

#[derive(Clone)]
pub struct DashboardCkErc20Token {
    pub erc20_contract_address: Address,
    pub ckerc20_token_symbol: CkTokenSymbol,
    pub ckerc20_ledger_id: Principal,
    pub balance: Erc20Value,
}

#[derive(Clone)]
pub struct DashboardPendingDeposit {
    pub tx_hash: Hash,
    pub log_index: LogIndex,
    pub block_number: BlockNumber,
    pub from: Address,
    pub token_symbol: CkTokenSymbol,
    pub value: Nat,
    pub beneficiary: Account,
}

#[derive(Clone)]
pub struct DashboardWithdrawalRequest {
    pub cketh_ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub value: Nat,
    pub token_symbol: CkTokenSymbol,
    pub created_at: Option<u64>,
}

#[derive(Clone)]
pub struct DashboardPendingTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub value: Nat,
    pub token_symbol: CkTokenSymbol,
    pub status: RetrieveEthStatus,
}

#[derive(Clone)]
pub struct DashboardFinalizedTransaction {
    pub ledger_burn_index: LedgerBurnIndex,
    pub destination: Address,
    pub value: Nat,
    pub token_symbol: CkTokenSymbol,
    pub block_number: BlockNumber,
    pub transaction_hash: Hash,
    pub transaction_fee: Wei,
    pub status: TransactionStatus,
}

#[derive(Clone)]
pub enum DashboardReimbursedTransaction {
    Reimbursed {
        cketh_ledger_burn_index: LedgerBurnIndex,
        reimbursed_in_block: LedgerMintIndex,
        reimbursed_amount: Nat,
        token_symbol: CkTokenSymbol,
        transaction_hash: Option<Hash>,
    },
    Quarantined {
        cketh_ledger_burn_index: LedgerBurnIndex,
        token_symbol: CkTokenSymbol,
    },
}

impl DashboardReimbursedTransaction {
    pub fn cketh_ledger_burn_index(&self) -> LedgerBurnIndex {
        match self {
            DashboardReimbursedTransaction::Reimbursed {
                cketh_ledger_burn_index,
                ..
            } => *cketh_ledger_burn_index,
            DashboardReimbursedTransaction::Quarantined {
                cketh_ledger_burn_index,
                ..
            } => *cketh_ledger_burn_index,
        }
    }
}

impl DashboardPendingDeposit {
    fn new(event: &ReceivedEvent, state: &State) -> Self {
        Self {
            tx_hash: event.transaction_hash(),
            log_index: event.log_index(),
            block_number: event.block_number(),
            from: event.from_address(),
            token_symbol: match event {
                ReceivedEvent::Eth(_) => CkTokenSymbol::cketh_symbol_from_state(state),
                ReceivedEvent::Erc20(e) => state
                    .ckerc20_tokens
                    .get_alt(&e.erc20_contract_address)
                    .expect("BUG: unknown ERC-20 token")
                    .clone(),
            },
            value: event.value(),
            beneficiary: event.beneficiary(),
        }
    }
}

// Number of entries per page in dashboard tables (e.g. minted events, finalized transactions).
const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Default, Clone)]
pub struct DashboardPaginationParameters {
    minted_events_start: usize,
    finalized_transactions_start: usize,
    reimbursed_transactions_start: usize,
}

impl DashboardPaginationParameters {
    pub(crate) fn from_query_params(
        req: &HttpRequest,
    ) -> Result<DashboardPaginationParameters, String> {
        fn parse_query_param(req: &HttpRequest, param_name: &str) -> Result<usize, String> {
            Ok(match req.raw_query_param(param_name) {
                Some(arg) => usize::from_str(arg)
                    .map_err(|_| format!("failed to parse the '{param_name}' parameter"))?,
                None => 0,
            })
        }

        Ok(Self {
            minted_events_start: parse_query_param(req, "minted_events_start")?,
            finalized_transactions_start: parse_query_param(req, "finalized_transactions_start")?,
            reimbursed_transactions_start: parse_query_param(req, "reimbursed_transactions_start")?,
        })
    }
}

#[derive(Clone)]
pub struct DashboardPaginatedTable<T> {
    current_page: Vec<T>,
    pagination: DashboardTablePagination,
}

impl<T: Clone> DashboardPaginatedTable<T> {
    pub fn from_items(
        items: &[T],
        current_page_offset: usize,
        page_size: usize,
        num_cols: usize,
        table_reference: &str,
        page_offset_query_param: &str,
    ) -> Self {
        Self {
            current_page: items
                .iter()
                .skip(current_page_offset)
                .take(page_size)
                .cloned()
                .collect(),
            pagination: DashboardTablePagination::pagination(
                items.len(),
                current_page_offset,
                page_size,
                num_cols,
                table_reference,
                page_offset_query_param,
            ),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.current_page.is_empty()
    }

    pub fn has_more_than_one_page(&self) -> bool {
        self.pagination.pages.len() > 1
    }
}

#[derive(Clone)]
pub struct DashboardTablePage {
    index: usize,
    offset: usize,
}

#[derive(Template)]
#[template(path = "pagination.html")]
#[derive(Clone)]
pub struct DashboardTablePagination {
    pub table_id: String,
    pub table_width: usize,
    pub page_offset_query_param: String,
    pub current_page_index: usize,
    pub pages: Vec<DashboardTablePage>,
}

impl DashboardTablePagination {
    fn pagination(
        num_items: usize,
        current_offset: usize,
        page_size: usize,
        table_width: usize,
        table_reference: &str,
        page_offset_query_param: &str,
    ) -> Self {
        let pages = (0..num_items)
            .step_by(page_size)
            .enumerate()
            .map(|(index, offset)| DashboardTablePage {
                index: index + 1,
                offset,
            })
            .collect();
        let current_page_index = current_offset / page_size + 1;
        Self {
            table_id: String::from(table_reference),
            page_offset_query_param: String::from(page_offset_query_param),
            table_width,
            current_page_index,
            pages,
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
    pub log_scrapings: LogScrapings,
    pub next_transaction_nonce: TransactionNonce,
    pub minimum_withdrawal_amount: Wei,
    pub first_synced_block: BlockNumber,
    pub last_observed_block: Option<BlockNumber>,
    pub cketh_ledger_id: Principal,
    pub minted_events_table: DashboardPaginatedTable<MintedEvent>,
    pub pending_deposits: Vec<DashboardPendingDeposit>,
    pub invalid_events: BTreeMap<EventSource, InvalidEventReason>,
    pub withdrawal_requests: Vec<DashboardWithdrawalRequest>,
    pub pending_transactions: Vec<DashboardPendingTransaction>,
    pub finalized_transactions_table: DashboardPaginatedTable<DashboardFinalizedTransaction>,
    pub reimbursed_transactions_table: DashboardPaginatedTable<DashboardReimbursedTransaction>,
    pub eth_balance: EthBalance,
    pub skipped_blocks: BTreeMap<String, BTreeSet<BlockNumber>>,
    pub supported_ckerc20_tokens: Vec<DashboardCkErc20Token>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State, pagination_parameters: DashboardPaginationParameters) -> Self {
        let mut minted_events: Vec<_> = state.minted_events.values().cloned().collect();
        minted_events.sort_unstable_by_key(|event| {
            let deposit_event = &event.deposit_event;
            Reverse((deposit_event.block_number(), deposit_event.log_index()))
        });

        let minted_events_table = DashboardPaginatedTable::from_items(
            &minted_events,
            pagination_parameters.minted_events_start,
            DEFAULT_PAGE_SIZE,
            7,
            "minted-events",
            "minted_events_start",
        );

        let mut supported_ckerc20_tokens: Vec<_> = state
            .supported_ck_erc20_tokens()
            .map(|ckerc20| DashboardCkErc20Token {
                erc20_contract_address: ckerc20.erc20_contract_address,
                ckerc20_token_symbol: ckerc20.ckerc20_token_symbol,
                ckerc20_ledger_id: ckerc20.ckerc20_ledger_id,
                balance: state
                    .erc20_balances
                    .balance_of(&ckerc20.erc20_contract_address),
            })
            .collect();
        supported_ckerc20_tokens.sort_unstable_by_key(|token| token.ckerc20_token_symbol.clone());

        let mut events_to_mint = state.events_to_mint();
        events_to_mint
            .sort_unstable_by_key(|event| Reverse((event.block_number(), event.log_index())));
        let pending_deposits = events_to_mint
            .iter()
            .map(|event| DashboardPendingDeposit::new(event, state))
            .collect();

        let mut withdrawal_requests: Vec<_> = state
            .eth_transactions
            .withdrawal_requests_iter()
            .cloned()
            .map(|request| match request {
                WithdrawalRequest::CkEth(req) => DashboardWithdrawalRequest {
                    cketh_ledger_burn_index: req.ledger_burn_index,
                    destination: req.destination,
                    value: req.withdrawal_amount.into(),
                    token_symbol: CkTokenSymbol::cketh_symbol_from_state(state),
                    created_at: req.created_at,
                },
                WithdrawalRequest::CkErc20(req) => {
                    let erc20_contract_address = &req.erc20_contract_address;
                    DashboardWithdrawalRequest {
                        cketh_ledger_burn_index: req.cketh_ledger_burn_index,
                        destination: req.destination,
                        value: req.withdrawal_amount.into(),
                        token_symbol: state
                            .ckerc20_tokens
                            .get_alt(erc20_contract_address)
                            .expect("BUG: unknown ERC-20 token")
                            .clone(),
                        created_at: Some(req.created_at),
                    }
                }
            })
            .collect();
        withdrawal_requests.sort_unstable_by_key(|req| Reverse(req.cketh_ledger_burn_index));

        let mut pending_transactions: Vec<_> = state
            .eth_transactions
            .transactions_to_sign_iter()
            .map(|(_nonce, ledger_burn_index, tx)| {
                let (destination, value, token_symbol) = to_dashboard_transaction(tx, state);
                DashboardPendingTransaction {
                    ledger_burn_index: *ledger_burn_index,
                    destination,
                    value,
                    token_symbol,
                    status: RetrieveEthStatus::TxCreated,
                }
            })
            .collect();
        pending_transactions.extend(state.eth_transactions.sent_transactions_iter().flat_map(
            |(_nonce, ledger_burn_index, txs)| {
                txs.into_iter().map(|tx| {
                    let (destination, value, token_symbol) = to_dashboard_transaction(tx, state);
                    DashboardPendingTransaction {
                        ledger_burn_index: *ledger_burn_index,
                        destination,
                        value,
                        token_symbol,
                        status: RetrieveEthStatus::TxSent(EthTransaction::from(tx)),
                    }
                })
            },
        ));
        pending_transactions
            .sort_unstable_by_key(|pending_tx| Reverse(pending_tx.ledger_burn_index));

        let mut finalized_transactions: Vec<_> = state
            .eth_transactions
            .finalized_transactions_iter()
            .map(|(_tx_nonce, index, tx)| {
                let (destination, value, token_symbol) = to_dashboard_transaction(tx, state);
                DashboardFinalizedTransaction {
                    ledger_burn_index: *index,
                    destination,
                    value,
                    token_symbol,
                    block_number: *tx.block_number(),
                    transaction_hash: *tx.transaction_hash(),
                    transaction_fee: tx.effective_transaction_fee(),
                    status: *tx.transaction_status(),
                }
            })
            .collect();
        finalized_transactions.sort_unstable_by_key(|tx| Reverse(tx.ledger_burn_index));

        let finalized_transactions_table = DashboardPaginatedTable::from_items(
            &finalized_transactions,
            pagination_parameters.finalized_transactions_start,
            DEFAULT_PAGE_SIZE,
            8,
            "finalized-transactions",
            "finalized_transactions_start",
        );

        let mut reimbursed_transactions: Vec<_> = state
            .eth_transactions
            .reimbursed_transactions_iter()
            .map(|(index, result)| {
                let (cketh_ledger_burn_index, token_symbol) = match index {
                    ReimbursementIndex::CkEth { ledger_burn_index } => (
                        *ledger_burn_index,
                        CkTokenSymbol::cketh_symbol_from_state(state),
                    ),
                    ReimbursementIndex::CkErc20 {
                        cketh_ledger_burn_index,
                        ledger_id,
                        ckerc20_ledger_burn_index: _,
                    } => (
                        *cketh_ledger_burn_index,
                        state
                            .ckerc20_tokens
                            .get(ledger_id)
                            .expect("BUG: unknown ERC-20 token")
                            .clone(),
                    ),
                };
                match result {
                    Ok(reimbursed) => DashboardReimbursedTransaction::Reimbursed {
                        cketh_ledger_burn_index,
                        reimbursed_in_block: reimbursed.reimbursed_in_block,
                        reimbursed_amount: reimbursed.reimbursed_amount.into(),
                        token_symbol,
                        transaction_hash: reimbursed.transaction_hash,
                    },
                    Err(ReimbursedError::Quarantined) => {
                        DashboardReimbursedTransaction::Quarantined {
                            cketh_ledger_burn_index,
                            token_symbol,
                        }
                    }
                }
            })
            .collect();
        reimbursed_transactions
            .sort_unstable_by_key(|reimbursed_tx| Reverse(reimbursed_tx.cketh_ledger_burn_index()));

        let reimbursed_transactions_table = DashboardPaginatedTable::from_items(
            &reimbursed_transactions,
            pagination_parameters.reimbursed_transactions_start,
            DEFAULT_PAGE_SIZE,
            6,
            "reimbursed-transactions",
            "reimbursed_transactions_start",
        );

        DashboardTemplate {
            ethereum_network: state.ethereum_network,
            ecdsa_key_name: state.ecdsa_key_name.clone(),
            minter_address: state
                .minter_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            log_scrapings: state.log_scrapings.clone(),
            cketh_ledger_id: state.cketh_ledger_id,
            next_transaction_nonce: state.eth_transactions.next_transaction_nonce(),
            minimum_withdrawal_amount: state.cketh_minimum_withdrawal_amount,
            first_synced_block: state.first_scraped_block_number,
            last_observed_block: state.last_observed_block_number,
            minted_events_table,
            pending_deposits,
            invalid_events: state.invalid_events.clone(),
            withdrawal_requests,
            pending_transactions,
            finalized_transactions_table,
            reimbursed_transactions_table,
            eth_balance: state.eth_balance.clone(),
            skipped_blocks: state
                .skipped_blocks
                .iter()
                .map(|(contract_address, blocks)| (contract_address.to_string(), blocks.clone()))
                .collect(),
            supported_ckerc20_tokens,
        }
    }
}

fn to_dashboard_transaction<T: AsRef<Eip1559TransactionRequest>>(
    tx: T,
    state: &State,
) -> (Address, Nat, CkTokenSymbol) {
    let tx = tx.as_ref();
    if !tx.data.is_empty() {
        let TransactionCallData::Erc20Transfer { to, value } =
            TransactionCallData::decode(&tx.data)
                .expect("BUG: failed to decode transaction data from transaction issued by minter");
        let destination = to;
        let value = value.into();
        let token_symbol = state
            .ckerc20_tokens
            .get_alt(&tx.destination)
            .expect("BUG: unknown ERC-20 token")
            .clone();
        (destination, value, token_symbol)
    } else {
        let destination = tx.destination;
        let value = tx.amount.into();
        let token_symbol = CkTokenSymbol::cketh_symbol_from_state(state);
        (destination, value, token_symbol)
    }
}
