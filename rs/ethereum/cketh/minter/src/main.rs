#![allow(deprecated)]
use crate::dashboard::DashboardPaginationParameters;
use crate::memo;
use candid::Nat;
use dashboard::DashboardTemplate;
use ic_canister_log::log;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::{AddressValidationError, validate_address_as_destination};
use ic_cketh_minter::deposit::scrape_logs;
use ic_cketh_minter::endpoints::ckerc20::{
    RetrieveErc20Request, WithdrawErc20Arg, WithdrawErc20Error,
};
use ic_cketh_minter::endpoints::events::{
    Event as CandidEvent, EventSource as CandidEventSource, GetEventsArg, GetEventsResult,
};
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, DecodeLedgerMemoArgs, DecodeLedgerMemoResult, Eip1559TransactionPrice,
    Eip1559TransactionPriceArg, Erc20Balance, GasFeeEstimate, MemoType, MinterInfo,
    RetrieveEthRequest, RetrieveEthStatus, WithdrawalArg, WithdrawalDetail, WithdrawalError,
    WithdrawalSearchParameter,
};
use ic_cketh_minter::erc20::CkTokenSymbol;
use ic_cketh_minter::eth_logs::{
    EventSource, LedgerSubaccount, ReceivedErc20Event, ReceivedEthEvent,
};
use ic_cketh_minter::guard::retrieve_withdraw_guard;
use ic_cketh_minter::ledger_client::{LedgerBurnError, LedgerClient};
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::logs::INFO;
use ic_cketh_minter::memo::BurnMemo;
use ic_cketh_minter::numeric::{Erc20Value, LedgerBurnIndex, Wei};
use ic_cketh_minter::state::audit::{Event, EventType, process_event};
use ic_cketh_minter::state::eth_logs_scraping::{LogScrapingId, LogScrapingInfo};
use ic_cketh_minter::state::transactions::{
    Erc20WithdrawalRequest, EthWithdrawalRequest, Reimbursed, ReimbursementIndex,
    ReimbursementRequest,
};
use ic_cketh_minter::state::{
    STATE, State, lazy_call_ecdsa_public_key, mutate_state, read_state, transactions,
};
use ic_cketh_minter::tx::lazy_refresh_gas_fee_estimate;
use ic_cketh_minter::withdraw::{
    CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT, CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
    process_reimbursement, process_retrieve_eth_requests,
};
use ic_cketh_minter::{
    PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_REIMBURSEMENT, SCRAPING_ETH_LOGS_INTERVAL,
    state, storage,
};
use ic_cketh_minter::{endpoints, erc20};
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

mod dashboard;

pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;
pub const CKETH_LEDGER_TRANSACTION_FEE: Wei = Wei::new(2_000_000_000_000_u128);

fn validate_caller_not_anonymous() -> candid::Principal {
    let principal = ic_cdk::caller();
    if principal == candid::Principal::anonymous() {
        panic!("anonymous principal is not allowed");
    }
    principal
}

fn validate_ckerc20_active() {
    if !read_state(State::is_ckerc20_feature_active) {
        ic_cdk::trap("ckERC20 feature is disabled");
    }
}

fn setup_timers() {
    ic_cdk_timers::set_timer(Duration::from_secs(0), async {
        // Initialize the minter's public key to make the address known.
        let _ = lazy_call_ecdsa_public_key().await;
    });
    // Start scraping logs immediately after the install, then repeat with the interval.
    ic_cdk_timers::set_timer(Duration::from_secs(0), async {
        scrape_logs().await;
    });
    ic_cdk_timers::set_timer_interval(SCRAPING_ETH_LOGS_INTERVAL, async || {
        scrape_logs().await;
    });
    ic_cdk_timers::set_timer_interval(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, async || {
        process_retrieve_eth_requests().await;
    });
    ic_cdk_timers::set_timer_interval(PROCESS_REIMBURSEMENT, async || {
        process_reimbursement().await;
    });
}

#[init]
fn init(arg: MinterArg) {
    match arg {
        MinterArg::InitArg(init_arg) => {
            log!(INFO, "[init]: initialized minter with arg: {:?}", init_arg);
            STATE.with(|cell| {
                storage::record_event(EventType::Init(init_arg.clone()));
                *cell.borrow_mut() =
                    Some(State::try_from(init_arg).expect("BUG: failed to initialize minter"))
            });
        }
        MinterArg::UpgradeArg(_) => {
            ic_cdk::trap("cannot init canister state with upgrade args");
        }
    }
    setup_timers();
}

fn emit_preupgrade_events() {
    read_state(|s| {
        for (id, scraping_state) in s.log_scrapings.iter() {
            let block_number = scraping_state.last_scraped_block_number();
            let event = match id {
                LogScrapingId::EthDepositWithoutSubaccount => {
                    EventType::SyncedToBlock { block_number }
                }
                LogScrapingId::Erc20DepositWithoutSubaccount => {
                    EventType::SyncedErc20ToBlock { block_number }
                }
                LogScrapingId::EthOrErc20DepositWithSubaccount => {
                    EventType::SyncedDepositWithSubaccountToBlock { block_number }
                }
            };
            storage::record_event(event);
        }
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    emit_preupgrade_events();
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    use ic_cketh_minter::lifecycle;
    match minter_arg {
        Some(MinterArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        Some(MinterArg::UpgradeArg(upgrade_args)) => lifecycle::post_upgrade(Some(upgrade_args)),
        None => lifecycle::post_upgrade(None),
    }
    setup_timers();
}

#[update]
async fn minter_address() -> String {
    state::minter_address().await.to_string()
}

#[query]
async fn smart_contract_address() -> String {
    read_state(|s| {
        s.log_scrapings
            .contract_address(LogScrapingId::EthDepositWithoutSubaccount)
            .cloned()
    })
    .map(|a| a.to_string())
    .unwrap_or("N/A".to_string())
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
#[query]
async fn eip_1559_transaction_price(
    token: Option<Eip1559TransactionPriceArg>,
) -> Eip1559TransactionPrice {
    let gas_limit = match token {
        None => CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
        Some(Eip1559TransactionPriceArg { ckerc20_ledger_id }) => {
            match read_state(|s| s.find_ck_erc20_token_by_ledger_id(&ckerc20_ledger_id)) {
                Some(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
                None => {
                    if ckerc20_ledger_id == read_state(|s| s.cketh_ledger_id) {
                        CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT
                    } else {
                        ic_cdk::trap(format!(
                            "ERROR: Unsupported ckERC20 token ledger {ckerc20_ledger_id}"
                        ))
                    }
                }
            }
        }
    };
    match read_state(|s| s.last_transaction_price_estimate.clone()) {
        Some((ts, estimate)) => {
            let mut result = Eip1559TransactionPrice::from(estimate.to_price(gas_limit));
            result.timestamp = Some(ts);
            result
        }
        None => ic_cdk::trap("ERROR: last transaction price estimate is not available"),
    }
}

/// Returns the current parameters used by the minter.
/// This includes information that can be retrieved form other endpoints as well.
/// To retain some flexibility in the API all fields in the return value are optional.
#[allow(deprecated)]
#[query]
async fn get_minter_info() -> MinterInfo {
    read_state(|s| {
        let (erc20_balances, supported_ckerc20_tokens) = if s.is_ckerc20_feature_active() {
            let (balances, tokens) = s
                .supported_ck_erc20_tokens()
                .map(|token| {
                    (
                        Erc20Balance {
                            erc20_contract_address: token.erc20_contract_address.to_string(),
                            balance: s
                                .erc20_balances
                                .balance_of(&token.erc20_contract_address)
                                .into(),
                        },
                        endpoints::CkErc20Token::from(token),
                    )
                })
                .unzip();
            (Some(balances), Some(tokens))
        } else {
            (None, None)
        };

        let LogScrapingInfo {
            eth_helper_contract_address,
            last_eth_scraped_block_number,
            erc20_helper_contract_address,
            last_erc20_scraped_block_number,
            deposit_with_subaccount_helper_contract_address,
            last_deposit_with_subaccount_scraped_block_number,
        } = s.log_scrapings.info();

        MinterInfo {
            minter_address: s.minter_address().map(|a| a.to_string()),
            smart_contract_address: eth_helper_contract_address.clone(),
            eth_helper_contract_address,
            erc20_helper_contract_address,
            deposit_with_subaccount_helper_contract_address,
            supported_ckerc20_tokens,
            minimum_withdrawal_amount: Some(s.cketh_minimum_withdrawal_amount.into()),
            ethereum_block_height: Some(s.ethereum_block_height.clone()),
            last_observed_block_number: s.last_observed_block_number.map(|n| n.into()),
            eth_balance: Some(s.eth_balance.eth_balance().into()),
            last_gas_fee_estimate: s.last_transaction_price_estimate.as_ref().map(
                |(timestamp, estimate)| GasFeeEstimate {
                    max_fee_per_gas: estimate.estimate_max_fee_per_gas().into(),
                    max_priority_fee_per_gas: estimate.max_priority_fee_per_gas.into(),
                    timestamp: *timestamp,
                },
            ),
            erc20_balances,
            last_eth_scraped_block_number,
            last_erc20_scraped_block_number,
            last_deposit_with_subaccount_scraped_block_number,
            cketh_ledger_id: Some(s.cketh_ledger_id),
            evm_rpc_id: Some(s.evm_rpc_id),
        }
    })
}

#[update]
async fn withdraw_eth(
    WithdrawalArg {
        amount,
        recipient,
        from_subaccount,
    }: WithdrawalArg,
) -> Result<RetrieveEthRequest, WithdrawalError> {
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_withdraw_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(format!(
            "Failed retrieving guard for principal {caller}: {e:?}"
        ))
    });

    let destination = validate_address_as_destination(&recipient).map_err(|e| match e {
        AddressValidationError::Invalid { .. } | AddressValidationError::NotSupported(_) => {
            ic_cdk::trap(e.to_string())
        }
        AddressValidationError::Blocked(address) => WithdrawalError::RecipientAddressBlocked {
            address: address.to_string(),
        },
    })?;

    let amount = Wei::try_from(amount).expect("failed to convert Nat to u256");

    let minimum_withdrawal_amount = read_state(|s| s.cketh_minimum_withdrawal_amount);
    if amount < minimum_withdrawal_amount {
        return Err(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: minimum_withdrawal_amount.into(),
        });
    }

    let client = read_state(LedgerClient::cketh_ledger_from_state);
    let now = ic_cdk::api::time();
    log!(INFO, "[withdraw]: burning {:?}", amount);
    match client
        .burn_from(
            Account {
                owner: caller,
                subaccount: from_subaccount,
            },
            amount,
            BurnMemo::Convert {
                to_address: destination,
            },
        )
        .await
    {
        Ok(ledger_burn_index) => {
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount: amount,
                destination,
                ledger_burn_index,
                from: caller,
                from_subaccount: from_subaccount.and_then(LedgerSubaccount::from_bytes),
                created_at: Some(now),
            };

            log!(
                INFO,
                "[withdraw]: queuing withdrawal request {:?}",
                withdrawal_request,
            );

            mutate_state(|s| {
                process_event(
                    s,
                    EventType::AcceptedEthWithdrawalRequest(withdrawal_request.clone()),
                );
            });
            Ok(RetrieveEthRequest::from(withdrawal_request))
        }
        Err(e) => Err(WithdrawalError::from(e)),
    }
}

#[update]
async fn retrieve_eth_status(block_index: u64) -> RetrieveEthStatus {
    let ledger_burn_index = LedgerBurnIndex::new(block_index);
    read_state(|s| s.eth_transactions.transaction_status(&ledger_burn_index))
}

#[query]
async fn withdrawal_status(parameter: WithdrawalSearchParameter) -> Vec<WithdrawalDetail> {
    use transactions::WithdrawalRequest::*;
    let parameter = transactions::WithdrawalSearchParameter::try_from(parameter).unwrap();
    read_state(|s| {
        s.eth_transactions
            .withdrawal_status(&parameter)
            .into_iter()
            .map(|(request, status, tx)| WithdrawalDetail {
                withdrawal_id: *request.cketh_ledger_burn_index().as_ref(),
                recipient_address: request.payee().to_string(),
                token_symbol: match request {
                    CkEth(_) => CkTokenSymbol::cketh_symbol_from_state(s).to_string(),
                    CkErc20(r) => s
                        .ckerc20_tokens
                        .get_alt(&r.erc20_contract_address)
                        .unwrap()
                        .to_string(),
                },
                withdrawal_amount: match request {
                    CkEth(r) => r.withdrawal_amount.into(),
                    CkErc20(r) => r.withdrawal_amount.into(),
                },
                max_transaction_fee: match (request, tx) {
                    (CkEth(_), None) => None,
                    (CkEth(r), Some(tx)) => {
                        r.withdrawal_amount.checked_sub(tx.amount).map(|x| x.into())
                    }
                    (CkErc20(r), _) => Some(r.max_transaction_fee.into()),
                },
                from: request.from(),
                from_subaccount: request
                    .from_subaccount()
                    .cloned()
                    .map(LedgerSubaccount::to_bytes),
                status,
            })
            .collect()
    })
}

#[update]
async fn withdraw_erc20(
    WithdrawErc20Arg {
        amount,
        ckerc20_ledger_id,
        recipient,
        from_cketh_subaccount,
        from_ckerc20_subaccount,
    }: WithdrawErc20Arg,
) -> Result<RetrieveErc20Request, WithdrawErc20Error> {
    validate_ckerc20_active();
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_withdraw_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(format!(
            "Failed retrieving guard for principal {caller}: {e:?}"
        ))
    });

    let destination = validate_address_as_destination(&recipient).map_err(|e| match e {
        AddressValidationError::Invalid { .. } | AddressValidationError::NotSupported(_) => {
            ic_cdk::trap(e.to_string())
        }
        AddressValidationError::Blocked(address) => WithdrawErc20Error::RecipientAddressBlocked {
            address: address.to_string(),
        },
    })?;
    let ckerc20_withdrawal_amount =
        Erc20Value::try_from(amount).expect("ERROR: failed to convert Nat to u256");

    let ckerc20_token = read_state(|s| s.find_ck_erc20_token_by_ledger_id(&ckerc20_ledger_id))
        .ok_or_else(|| {
            let supported_ckerc20_tokens: BTreeSet<_> = read_state(|s| {
                s.supported_ck_erc20_tokens()
                    .map(|token| token.into())
                    .collect()
            });
            WithdrawErc20Error::TokenNotSupported {
                supported_tokens: Vec::from_iter(supported_ckerc20_tokens),
            }
        })?;
    let cketh_ledger = read_state(LedgerClient::cketh_ledger_from_state);
    let erc20_tx_fee = estimate_erc20_transaction_fee().await.ok_or_else(|| {
        WithdrawErc20Error::TemporarilyUnavailable("Failed to retrieve current gas fee".to_string())
    })?;
    let cketh_account = Account {
        owner: caller,
        subaccount: from_cketh_subaccount,
    };
    let ckerc20_account = Account {
        owner: caller,
        subaccount: from_ckerc20_subaccount,
    };
    let now = ic_cdk::api::time();
    log!(
        INFO,
        "[withdraw_erc20]: burning {:?} ckETH from account {}",
        erc20_tx_fee,
        cketh_account
    );
    match cketh_ledger
        .burn_from(
            cketh_account,
            erc20_tx_fee,
            BurnMemo::Erc20GasFee {
                ckerc20_token_symbol: ckerc20_token.ckerc20_token_symbol.clone(),
                ckerc20_withdrawal_amount,
                to_address: destination,
            },
        )
        .await
    {
        Ok(cketh_ledger_burn_index) => {
            log!(
                INFO,
                "[withdraw_erc20]: burning {} {} from account {}",
                ckerc20_withdrawal_amount,
                ckerc20_token.ckerc20_token_symbol,
                ckerc20_account
            );
            match LedgerClient::ckerc20_ledger(&ckerc20_token)
                .burn_from(
                    ckerc20_account,
                    ckerc20_withdrawal_amount,
                    BurnMemo::Erc20Convert {
                        ckerc20_withdrawal_id: cketh_ledger_burn_index.get(),
                        to_address: destination,
                    },
                )
                .await
            {
                Ok(ckerc20_ledger_burn_index) => {
                    let withdrawal_request = Erc20WithdrawalRequest {
                        max_transaction_fee: erc20_tx_fee,
                        withdrawal_amount: ckerc20_withdrawal_amount,
                        destination,
                        cketh_ledger_burn_index,
                        ckerc20_ledger_id: ckerc20_token.ckerc20_ledger_id,
                        ckerc20_ledger_burn_index,
                        erc20_contract_address: ckerc20_token.erc20_contract_address,
                        from: caller,
                        from_subaccount: from_ckerc20_subaccount
                            .and_then(LedgerSubaccount::from_bytes),
                        created_at: now,
                    };
                    log!(
                        INFO,
                        "[withdraw_erc20]: queuing withdrawal request {:?}",
                        withdrawal_request
                    );
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::AcceptedErc20WithdrawalRequest(withdrawal_request.clone()),
                        );
                    });
                    Ok(RetrieveErc20Request::from(withdrawal_request))
                }
                Err(ckerc20_burn_error) => {
                    let reimbursed_amount = match &ckerc20_burn_error {
                        LedgerBurnError::TemporarilyUnavailable { .. } => erc20_tx_fee, //don't penalize user in case of an error outside of their control
                        LedgerBurnError::InsufficientFunds { .. }
                        | LedgerBurnError::AmountTooLow { .. }
                        | LedgerBurnError::InsufficientAllowance { .. } => erc20_tx_fee
                            .checked_sub(CKETH_LEDGER_TRANSACTION_FEE)
                            .unwrap_or(Wei::ZERO),
                    };
                    if reimbursed_amount > Wei::ZERO {
                        let reimbursement_request = ReimbursementRequest {
                            ledger_burn_index: cketh_ledger_burn_index,
                            reimbursed_amount: reimbursed_amount.change_units(),
                            to: cketh_account.owner,
                            to_subaccount: cketh_account
                                .subaccount
                                .and_then(LedgerSubaccount::from_bytes),
                            transaction_hash: None,
                        };
                        mutate_state(|s| {
                            process_event(
                                s,
                                EventType::FailedErc20WithdrawalRequest(reimbursement_request),
                            );
                        });
                    }
                    Err(WithdrawErc20Error::CkErc20LedgerError {
                        cketh_block_index: Nat::from(cketh_ledger_burn_index.get()),
                        error: ckerc20_burn_error.into(),
                    })
                }
            }
        }
        Err(cketh_burn_error) => Err(WithdrawErc20Error::CkEthLedgerError {
            error: cketh_burn_error.into(),
        }),
    }
}

async fn estimate_erc20_transaction_fee() -> Option<Wei> {
    lazy_refresh_gas_fee_estimate()
        .await
        .map(|gas_fee_estimate| {
            gas_fee_estimate
                .to_price(CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT)
                .max_transaction_fee()
        })
}

#[query]
fn is_address_blocked(address_string: String) -> bool {
    let address = Address::from_str(&address_string)
        .unwrap_or_else(|e| ic_cdk::trap(format!("invalid recipient address: {e:?}")));
    ic_cketh_minter::blocklist::is_blocked(&address)
}

#[update]
async fn add_ckerc20_token(erc20_token: AddCkErc20Token) {
    let orchestrator_id = read_state(|s| s.ledger_suite_orchestrator_id)
        .unwrap_or_else(|| ic_cdk::trap("ERROR: ERC-20 feature is not activated"));
    if orchestrator_id != ic_cdk::caller() {
        ic_cdk::trap(format!(
            "ERROR: only the orchestrator {orchestrator_id} can add ERC-20 tokens"
        ));
    }
    let ckerc20_token = erc20::CkErc20Token::try_from(erc20_token)
        .unwrap_or_else(|e| ic_cdk::trap(format!("ERROR: {e}")));
    mutate_state(|s| process_event(s, EventType::AddedCkErc20Token(ckerc20_token)));
}

#[update]
async fn get_canister_status() -> ic_cdk::api::management_canister::main::CanisterStatusResponse {
    ic_cdk::api::management_canister::main::canister_status(
        ic_cdk::api::management_canister::main::CanisterIdRecord {
            canister_id: ic_cdk::id(),
        },
    )
    .await
    .expect("failed to fetch canister status")
    .0
}

#[query]
fn get_events(arg: GetEventsArg) -> GetEventsResult {
    use ic_cketh_minter::endpoints::events::{
        AccessListItem, ReimbursementIndex as CandidReimbursementIndex,
        TransactionReceipt as CandidTransactionReceipt,
        TransactionStatus as CandidTransactionStatus, UnsignedTransaction,
    };
    use ic_cketh_minter::eth_rpc_client::responses::TransactionReceipt;
    use ic_cketh_minter::tx::Eip1559TransactionRequest;
    use serde_bytes::ByteBuf;

    const MAX_EVENTS_PER_RESPONSE: u64 = 100;

    fn map_event_source(
        EventSource {
            transaction_hash,
            log_index,
        }: EventSource,
    ) -> CandidEventSource {
        CandidEventSource {
            transaction_hash: transaction_hash.to_string(),
            log_index: log_index.into(),
        }
    }

    fn map_reimbursement_index(index: ReimbursementIndex) -> CandidReimbursementIndex {
        match index {
            ReimbursementIndex::CkEth { ledger_burn_index } => CandidReimbursementIndex::CkEth {
                ledger_burn_index: ledger_burn_index.get().into(),
            },
            ReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index,
                ledger_id,
                ckerc20_ledger_burn_index,
            } => CandidReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index: cketh_ledger_burn_index.get().into(),
                ledger_id,
                ckerc20_ledger_burn_index: ckerc20_ledger_burn_index.get().into(),
            },
        }
    }

    fn map_unsigned_transaction(tx: Eip1559TransactionRequest) -> UnsignedTransaction {
        UnsignedTransaction {
            chain_id: tx.chain_id.into(),
            nonce: tx.nonce.into(),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.into(),
            max_fee_per_gas: tx.max_fee_per_gas.into(),
            gas_limit: tx.gas_limit.into(),
            destination: tx.destination.to_string(),
            value: tx.amount.into(),
            data: ByteBuf::from(tx.data),
            access_list: tx
                .access_list
                .0
                .iter()
                .map(|item| AccessListItem {
                    address: item.address.to_string(),
                    storage_keys: item
                        .storage_keys
                        .iter()
                        .map(|key| ByteBuf::from(key.0.to_vec()))
                        .collect(),
                })
                .collect(),
        }
    }

    fn map_transaction_receipt(receipt: TransactionReceipt) -> CandidTransactionReceipt {
        use ic_cketh_minter::eth_rpc_client::responses::TransactionStatus;
        CandidTransactionReceipt {
            block_hash: receipt.block_hash.to_string(),
            block_number: receipt.block_number.into(),
            effective_gas_price: receipt.effective_gas_price.into(),
            gas_used: receipt.gas_used.into(),
            status: match receipt.status {
                TransactionStatus::Success => CandidTransactionStatus::Success,
                TransactionStatus::Failure => CandidTransactionStatus::Failure,
            },
            transaction_hash: receipt.transaction_hash.to_string(),
        }
    }

    fn map_event(Event { timestamp, payload }: Event) -> CandidEvent {
        use ic_cketh_minter::endpoints::events::EventPayload as EP;
        CandidEvent {
            timestamp,
            payload: match payload {
                EventType::Init(args) => EP::Init(args),
                EventType::Upgrade(args) => EP::Upgrade(args),
                EventType::AcceptedDeposit(ReceivedEthEvent {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    subaccount,
                }) => EP::AcceptedDeposit {
                    transaction_hash: transaction_hash.to_string(),
                    block_number: block_number.into(),
                    log_index: log_index.into(),
                    from_address: from_address.to_string(),
                    value: value.into(),
                    principal,
                    subaccount: subaccount.map(|s| s.to_bytes()),
                },
                EventType::AcceptedErc20Deposit(ReceivedErc20Event {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    erc20_contract_address,
                    subaccount,
                }) => EP::AcceptedErc20Deposit {
                    transaction_hash: transaction_hash.to_string(),
                    block_number: block_number.into(),
                    log_index: log_index.into(),
                    from_address: from_address.to_string(),
                    value: value.into(),
                    principal,
                    erc20_contract_address: erc20_contract_address.to_string(),
                    subaccount: subaccount.map(|s| s.to_bytes()),
                },
                EventType::InvalidDeposit {
                    event_source,
                    reason,
                } => EP::InvalidDeposit {
                    event_source: map_event_source(event_source),
                    reason,
                },
                EventType::MintedCkEth {
                    event_source,
                    mint_block_index,
                } => EP::MintedCkEth {
                    event_source: map_event_source(event_source),
                    mint_block_index: mint_block_index.get().into(),
                },
                EventType::SyncedToBlock { block_number } => EP::SyncedToBlock {
                    block_number: block_number.into(),
                },
                EventType::SyncedErc20ToBlock { block_number } => EP::SyncedErc20ToBlock {
                    block_number: block_number.into(),
                },
                EventType::SyncedDepositWithSubaccountToBlock { block_number } => {
                    EP::SyncedDepositWithSubaccountToBlock {
                        block_number: block_number.into(),
                    }
                }
                EventType::AcceptedEthWithdrawalRequest(EthWithdrawalRequest {
                    withdrawal_amount,
                    destination,
                    ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                }) => EP::AcceptedEthWithdrawalRequest {
                    withdrawal_amount: withdrawal_amount.into(),
                    destination: destination.to_string(),
                    ledger_burn_index: ledger_burn_index.get().into(),
                    from,
                    from_subaccount: from_subaccount.map(LedgerSubaccount::to_bytes),
                    created_at,
                },
                EventType::CreatedTransaction {
                    withdrawal_id,
                    transaction,
                } => EP::CreatedTransaction {
                    withdrawal_id: withdrawal_id.get().into(),
                    transaction: map_unsigned_transaction(transaction),
                },
                EventType::SignedTransaction {
                    withdrawal_id,
                    transaction,
                } => EP::SignedTransaction {
                    withdrawal_id: withdrawal_id.get().into(),
                    raw_transaction: transaction.raw_transaction_hex_string(),
                },
                EventType::ReplacedTransaction {
                    withdrawal_id,
                    transaction,
                } => EP::ReplacedTransaction {
                    withdrawal_id: withdrawal_id.get().into(),
                    transaction: map_unsigned_transaction(transaction),
                },
                EventType::FinalizedTransaction {
                    withdrawal_id,
                    transaction_receipt,
                } => EP::FinalizedTransaction {
                    withdrawal_id: withdrawal_id.get().into(),
                    transaction_receipt: map_transaction_receipt(transaction_receipt),
                },
                EventType::ReimbursedEthWithdrawal(Reimbursed {
                    burn_in_block: withdrawal_id,
                    reimbursed_in_block,
                    reimbursed_amount,
                    transaction_hash,
                }) => EP::ReimbursedEthWithdrawal {
                    withdrawal_id: withdrawal_id.get().into(),
                    reimbursed_in_block: reimbursed_in_block.get().into(),
                    reimbursed_amount: reimbursed_amount.into(),
                    transaction_hash: transaction_hash.map(|h| h.to_string()),
                },
                EventType::ReimbursedErc20Withdrawal {
                    cketh_ledger_burn_index,
                    ckerc20_ledger_id,
                    reimbursed,
                } => EP::ReimbursedErc20Withdrawal {
                    withdrawal_id: cketh_ledger_burn_index.get().into(),
                    burn_in_block: reimbursed.burn_in_block.get().into(),
                    ledger_id: ckerc20_ledger_id,
                    reimbursed_in_block: reimbursed.reimbursed_in_block.get().into(),
                    reimbursed_amount: reimbursed.reimbursed_amount.into(),
                    transaction_hash: reimbursed.transaction_hash.map(|h| h.to_string()),
                },
                EventType::SkippedBlockForContract {
                    contract_address,
                    block_number,
                } => EP::SkippedBlock {
                    contract_address: Some(contract_address.to_string()),
                    block_number: block_number.into(),
                },
                EventType::AddedCkErc20Token(token) => EP::AddedCkErc20Token {
                    chain_id: token.erc20_ethereum_network.chain_id().into(),
                    address: token.erc20_contract_address.to_string(),
                    ckerc20_token_symbol: token.ckerc20_token_symbol.to_string(),
                    ckerc20_ledger_id: token.ckerc20_ledger_id,
                },
                EventType::AcceptedErc20WithdrawalRequest(Erc20WithdrawalRequest {
                    max_transaction_fee,
                    withdrawal_amount,
                    destination,
                    cketh_ledger_burn_index,
                    erc20_contract_address,
                    ckerc20_ledger_id,
                    ckerc20_ledger_burn_index,
                    from,
                    from_subaccount,
                    created_at,
                }) => EP::AcceptedErc20WithdrawalRequest {
                    max_transaction_fee: max_transaction_fee.into(),
                    withdrawal_amount: withdrawal_amount.into(),
                    erc20_contract_address: erc20_contract_address.to_string(),
                    destination: destination.to_string(),
                    cketh_ledger_burn_index: cketh_ledger_burn_index.get().into(),
                    ckerc20_ledger_id,
                    ckerc20_ledger_burn_index: ckerc20_ledger_burn_index.get().into(),
                    from,
                    from_subaccount: from_subaccount.map(LedgerSubaccount::to_bytes),
                    created_at,
                },
                EventType::MintedCkErc20 {
                    event_source,
                    mint_block_index,
                    ckerc20_token_symbol,
                    erc20_contract_address,
                } => EP::MintedCkErc20 {
                    event_source: map_event_source(event_source),
                    mint_block_index: mint_block_index.get().into(),
                    ckerc20_token_symbol,
                    erc20_contract_address: erc20_contract_address.to_string(),
                },
                EventType::FailedErc20WithdrawalRequest(ReimbursementRequest {
                    ledger_burn_index,
                    reimbursed_amount,
                    to,
                    to_subaccount,
                    transaction_hash: _,
                }) => EP::FailedErc20WithdrawalRequest {
                    withdrawal_id: ledger_burn_index.get().into(),
                    reimbursed_amount: reimbursed_amount.into(),
                    to,
                    to_subaccount: to_subaccount.map(LedgerSubaccount::to_bytes),
                },
                EventType::QuarantinedDeposit { event_source } => EP::QuarantinedDeposit {
                    event_source: map_event_source(event_source),
                },
                EventType::QuarantinedReimbursement { index } => EP::QuarantinedReimbursement {
                    index: map_reimbursement_index(index),
                },
            },
        }
    }

    let events = storage::with_event_iter(|it| {
        it.skip(arg.start as usize)
            .take(arg.length.min(MAX_EVENTS_PER_RESPONSE) as usize)
            .map(map_event)
            .collect()
    });

    GetEventsResult {
        events,
        total_event_count: storage::total_event_count(),
    }
}

#[query]
fn decode_ledger_memo(arg: DecodeLedgerMemoArgs) -> DecodeLedgerMemoResult {
    match args.memo_type {
        MemoType::Burn => match minicbor::decode::<memo::BurnMemo>(&args.encoded_memo) {
            Ok(burn_memo) => Ok(Some(DecodedMemo::Burn(Some(BurnMemo::from(burn_memo))))),
            Err(err) => Err(Some(DecodeLedgerMemoError::InvalidMemo(format!(
                "Error decoding BurnMemo: {}",
                err
            )))),
        },
        MemoType::Mint => match minicbor::decode::<memo::MintMemo>(&args.encoded_memo) {
            Ok(mint_memo) => Ok(Some(DecodedMemo::Mint(Some(MintMemo::from(mint_memo))))),
            Err(err) => Err(Some(DecodeLedgerMemoError::InvalidMemo(format!(
                "Error decoding MintMemo: {}",
                err
            )))),
        },
    }
}

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_metrics_encoder::MetricsEncoder;

    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/metrics" {
        let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        fn last_processed_block_metric_name(id: &LogScrapingId) -> &'static str {
            match *id {
                LogScrapingId::EthDepositWithoutSubaccount => "cketh_minter_last_processed_block",
                LogScrapingId::Erc20DepositWithoutSubaccount => {
                    "ckerc20_minter_last_processed_block"
                }
                LogScrapingId::EthOrErc20DepositWithSubaccount => {
                    "subaccount_minter_last_processed_block"
                }
            }
        }

        fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
            const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

            read_state(|s| {
                w.encode_gauge(
                    "stable_memory_bytes",
                    ic_cdk::api::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
                    "Size of the stable memory allocated by this canister.",
                )?;

                w.encode_gauge(
                    "heap_memory_bytes",
                    heap_memory_size_bytes() as f64,
                    "Size of the heap memory allocated by this canister.",
                )?;

                w.gauge_vec("cycle_balance", "Cycle balance of this canister.")?
                    .value(
                        &[("canister", "cketh-minter")],
                        ic_cdk::api::canister_balance128() as f64,
                    )?;

                w.encode_gauge(
                    "cketh_minter_last_observed_block",
                    s.last_observed_block_number
                        .map(|n| n.as_f64())
                        .unwrap_or(0.0),
                    "The last Ethereum block the ckETH minter observed.",
                )?;

                for (id, scraping_state) in s.log_scrapings.iter() {
                    w.encode_gauge(
                        last_processed_block_metric_name(id),
                        scraping_state.last_scraped_block_number().as_f64(),
                        &format!(
                            "The last Ethereum block the ckETH minter checked for {id} deposits."
                        ),
                    )?;
                }

                w.encode_counter(
                    "cketh_minter_skipped_blocks",
                    s.skipped_blocks
                        .values()
                        .flat_map(|blocks| blocks.iter())
                        .count() as f64,
                    "Total count of Ethereum blocks that were skipped for deposits.",
                )?;

                w.gauge_vec(
                    "cketh_minter_accepted_deposits",
                    "The number of deposits the ckETH minter processed, by status.",
                )?
                .value(&[("status", "accepted")], s.minted_events.len() as f64)?
                .value(&[("status", "rejected")], s.invalid_events.len() as f64)?;

                w.encode_gauge(
                    "cketh_event_count",
                    storage::total_event_count() as f64,
                    "Total number of events in the event log.",
                )?;
                w.encode_gauge(
                    "cketh_minter_eth_balance",
                    s.eth_balance.eth_balance().as_f64(),
                    "Known amount of ETH on the minter's address",
                )?;
                let mut erc20_balances = w.gauge_vec(
                    "cketh_minter_erc20_balances",
                    "Known amount of ERC-20 on the minter's address",
                )?;
                for (token, balance) in s.erc20_balances_by_token_symbol().iter() {
                    erc20_balances = erc20_balances
                        .value(&[("erc20_token", &token.to_string())], balance.as_f64())?;
                }
                w.encode_gauge(
                    "cketh_minter_total_effective_tx_fees",
                    s.eth_balance.total_effective_tx_fees().as_f64(),
                    "Total amount of fees across all finalized transactions ckETH -> ETH",
                )?;
                w.encode_gauge(
                    "cketh_minter_total_unspent_tx_fees",
                    s.eth_balance.total_unspent_tx_fees().as_f64(),
                    "Total amount of unspent fees across all finalized transaction ckETH -> ETH",
                )?;

                let now_nanos = ic_cdk::api::time();
                let age_nanos = now_nanos.saturating_sub(
                    s.eth_transactions
                        .oldest_incomplete_withdrawal_timestamp()
                        .unwrap_or(now_nanos),
                );
                w.encode_gauge(
                    "cketh_oldest_incomplete_eth_withdrawal_request_age_seconds",
                    (age_nanos / 1_000_000_000) as f64,
                    "The age of the oldest incomplete ETH withdrawal request in seconds.",
                )?;

                w.encode_gauge(
                    "cketh_minter_last_max_fee_per_gas",
                    s.last_transaction_price_estimate
                        .clone()
                        .map(|(_, fee)| fee.estimate_max_fee_per_gas().as_f64())
                        .unwrap_or_default(),
                    "Last max fee per gas",
                )?;

                Ok(())
            })
        }

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        use askama::Template;

        let paging_parameters = match DashboardPaginationParameters::from_query_params(&req) {
            Ok(args) => args,
            Err(error) => {
                return HttpResponseBuilder::bad_request()
                    .with_body_and_content_length(error)
                    .build();
            }
        };
        let dashboard = read_state(|state| DashboardTemplate::from_state(state, paging_parameters));
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard.render().unwrap())
            .build()
    } else if req.path() == "/logs" {
        use ic_cketh_minter::logs::{Log, Priority, Sort};
        use std::str::FromStr;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build();
                }
            },
            None => 0,
        };

        let mut log: Log = Default::default();

        match req.raw_query_param("priority") {
            Some(priority_str) => match Priority::from_str(priority_str) {
                Ok(priority) => match priority {
                    Priority::Info => log.push_logs(Priority::Info),
                    Priority::TraceHttp => log.push_logs(Priority::TraceHttp),
                    Priority::Debug => log.push_logs(Priority::Debug),
                },
                Err(_) => log.push_all(),
            },
            None => log.push_all(),
        }

        log.entries
            .retain(|entry| entry.timestamp >= max_skip_timestamp);

        fn ordering_from_query_params(sort: Option<&str>, max_skip_timestamp: u64) -> Sort {
            match sort {
                Some(ord_str) => match Sort::from_str(ord_str) {
                    Ok(order) => order,
                    Err(_) => {
                        if max_skip_timestamp == 0 {
                            Sort::Ascending
                        } else {
                            Sort::Descending
                        }
                    }
                },
                None => {
                    if max_skip_timestamp == 0 {
                        Sort::Ascending
                    } else {
                        Sort::Descending
                    }
                }
            }
        }

        log.sort_logs(ordering_from_query_params(
            req.raw_query_param("sort"),
            max_skip_timestamp,
        ));

        const MAX_BODY_SIZE: usize = 2_000_000;
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[cfg(feature = "debug_checks")]
#[query]
fn check_audit_log() {
    use ic_cketh_minter::state::audit::replay_events;

    emit_preupgrade_events();

    read_state(|s| {
        replay_events()
            .is_equivalent_to(s)
            .expect("replaying the audit log should produce an equivalent state")
    })
}

/// Returns the amount of heap memory in bytes that has been allocated.
#[cfg(target_arch = "wasm32")]
pub fn heap_memory_size_bytes() -> usize {
    const WASM_PAGE_SIZE_BYTES: usize = 65536;
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn heap_memory_size_bytes() -> usize {
    0
}

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid_parser::utils::CandidSource) -> String {
        match source {
            candid_parser::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid_parser::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(
        new_name: &str,
        new: candid_parser::utils::CandidSource,
        old_name: &str,
        old: candid_parser::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid_parser::utils::service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{new_name} is not compatible with {old_name}!\n\n\
            {new_name}:\n\
            {new_str}\n\n\
            {old_name}:\n\
            {old_str}\n"
                );
                panic!("{e:?}");
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("cketh_minter.did");

    check_service_equal(
        "actual ledger candid interface",
        candid_parser::utils::CandidSource::Text(&new_interface),
        "declared candid interface in cketh_minter.did file",
        candid_parser::utils::CandidSource::File(old_interface.as_path()),
    );
}
