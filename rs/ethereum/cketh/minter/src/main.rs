use candid::Nat;
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::{validate_address_as_destination, AddressValidationError};
use ic_cketh_minter::deposit::scrape_logs;
use ic_cketh_minter::endpoints::events::{
    Event as CandidEvent, EventSource as CandidEventSource, GetEventsArg, GetEventsResult,
};
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, Eip1559TransactionPrice, GasFeeEstimate, MinterInfo, RetrieveEthRequest,
    RetrieveEthStatus, WithdrawalArg, WithdrawalError,
};
use ic_cketh_minter::erc20::CkErc20Token;
use ic_cketh_minter::eth_logs::{EventSource, ReceivedErc20Event, ReceivedEthEvent};
use ic_cketh_minter::guard::retrieve_eth_guard;
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::logs::{DEBUG, INFO};
use ic_cketh_minter::memo::BurnMemo;
use ic_cketh_minter::numeric::{LedgerBurnIndex, Wei};
use ic_cketh_minter::state::audit::{process_event, Event, EventType};
use ic_cketh_minter::state::transactions::{EthWithdrawalRequest, Reimbursed};
use ic_cketh_minter::state::{lazy_call_ecdsa_public_key, mutate_state, read_state, State, STATE};
use ic_cketh_minter::withdraw::{
    process_reimbursement, process_retrieve_eth_requests, CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
};
use ic_cketh_minter::{
    state, storage, PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_REIMBURSEMENT,
    SCRAPPING_ETH_LOGS_INTERVAL,
};
use ic_ethereum_types::Address;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use num_traits::cast::ToPrimitive;
use std::str::FromStr;
use std::time::Duration;

mod dashboard;

pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;

fn validate_caller_not_anonymous() -> candid::Principal {
    let principal = ic_cdk::caller();
    if principal == candid::Principal::anonymous() {
        panic!("anonymous principal is not allowed");
    }
    principal
}

fn setup_timers() {
    ic_cdk_timers::set_timer(Duration::from_secs(0), || {
        // Initialize the minter's public key to make the address known.
        ic_cdk::spawn(async {
            let _ = lazy_call_ecdsa_public_key().await;
        })
    });
    // Start scraping logs immediately after the install, then repeat with the interval.
    ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(scrape_logs()));
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || ic_cdk::spawn(scrape_logs()));
    ic_cdk_timers::set_timer_interval(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, || {
        ic_cdk::spawn(process_retrieve_eth_requests())
    });
    ic_cdk_timers::set_timer_interval(PROCESS_REIMBURSEMENT, || {
        ic_cdk::spawn(process_reimbursement())
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
        storage::record_event(EventType::SyncedToBlock {
            block_number: s.last_scraped_block_number,
        });
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
    read_state(|s| s.eth_helper_contract_address)
        .map(|a| a.to_string())
        .unwrap_or("N/A".to_string())
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[query]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    match read_state(|s| s.last_transaction_price_estimate.clone()) {
        Some((ts, estimate)) => {
            let mut result = Eip1559TransactionPrice::from(
                estimate.to_price(CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT),
            );
            result.timestamp = Some(ts);
            result
        }
        None => ic_cdk::trap("ERROR: last transaction price estimate is not available"),
    }
}

/// Returns the current parameters used by the minter.
/// This includes information that can be retrieved form other endpoints as well.
/// To retain some flexibility in the API all fields in the return value are optional.
#[query]
async fn get_minter_info() -> MinterInfo {
    read_state(|s| MinterInfo {
        minter_address: s.minter_address().map(|a| a.to_string()),
        smart_contract_address: s.eth_helper_contract_address.map(|a| a.to_string()),
        minimum_withdrawal_amount: Some(s.minimum_withdrawal_amount.into()),
        ethereum_block_height: Some(s.ethereum_block_height.into()),
        last_observed_block_number: s.last_observed_block_number.map(|n| n.into()),
        eth_balance: Some(s.eth_balance.eth_balance().into()),
        last_gas_fee_estimate: s.last_transaction_price_estimate.as_ref().map(
            |(timestamp, estimate)| GasFeeEstimate {
                max_fee_per_gas: estimate.max_fee_per_gas.into(),
                max_priority_fee_per_gas: estimate.max_priority_fee_per_gas.into(),
                timestamp: *timestamp,
            },
        ),
    })
}

#[update]
async fn withdraw_eth(
    WithdrawalArg { amount, recipient }: WithdrawalArg,
) -> Result<RetrieveEthRequest, WithdrawalError> {
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_eth_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "Failed retrieving guard for principal {}: {:?}",
            caller, e
        ))
    });

    let destination = validate_address_as_destination(&recipient).map_err(|e| match e {
        AddressValidationError::Invalid { .. } | AddressValidationError::NotSupported(_) => {
            ic_cdk::trap(&e.to_string())
        }
        AddressValidationError::Blocked(address) => WithdrawalError::RecipientAddressBlocked {
            address: address.to_string(),
        },
    })?;

    let amount = Wei::try_from(amount).expect("failed to convert Nat to u256");

    let minimum_withdrawal_amount = read_state(|s| s.minimum_withdrawal_amount);
    if amount < minimum_withdrawal_amount {
        return Err(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: minimum_withdrawal_amount.into(),
        });
    }

    let ledger_canister_id = read_state(|s| s.ledger_id);
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    };

    let now = ic_cdk::api::time();

    log!(INFO, "[withdraw]: burning {:?}", amount);
    match client
        .transfer_from(TransferFromArgs {
            spender_subaccount: None,
            from: caller.into(),
            to: ic_cdk::id().into(),
            amount: Nat::from(amount),
            fee: None,
            memo: Some(Memo::from(BurnMemo::Convert {
                to_address: destination,
            })),
            created_at_time: None, // We don't set this field to disable transaction deduplication
                                   // which is unnecessary in canister-to-canister calls.
        })
        .await
    {
        Ok(Ok(block_index)) => {
            let ledger_burn_index =
                LedgerBurnIndex::new(block_index.0.to_u64().expect("nat does not fit into u64"));
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount: amount,
                destination,
                ledger_burn_index,
                from: caller,
                from_subaccount: None,
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
        Ok(Err(error)) => {
            log!(
                DEBUG,
                "[withdraw]: failed to transfer_from with error: {error:?}"
            );
            Err(WithdrawalError::from(error))
        }
        Err((error_code, message)) => {
            log!(
                DEBUG,
                "[withdraw]: failed to call ledger with error_code: {error_code} and message: {message}",
            );
            Err(WithdrawalError::TemporarilyUnavailable(
                "failed to call ledger with error_code: {error_code} and message: {message}"
                    .to_string(),
            ))
        }
    }
}

#[update]
async fn retrieve_eth_status(block_index: u64) -> RetrieveEthStatus {
    let ledger_burn_index = LedgerBurnIndex::new(block_index);
    read_state(|s| s.eth_transactions.transaction_status(&ledger_burn_index))
}

#[query]
fn is_address_blocked(address_string: String) -> bool {
    let address = Address::from_str(&address_string)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("invalid recipient address: {:?}", e)));
    ic_cketh_minter::blocklist::is_blocked(&address)
}

#[update]
async fn add_ckerc20_token(erc20_token: AddCkErc20Token) {
    let orchestrator_id = read_state(|s| s.ledger_suite_orchestrator_id)
        .unwrap_or_else(|| ic_cdk::trap("ERROR: ERC-20 feature is not activated"));
    if orchestrator_id != ic_cdk::caller() {
        ic_cdk::trap(&format!(
            "ERROR: only the orchestrator {} can add ERC-20 tokens",
            orchestrator_id
        ));
    }
    let ckerc20_token = CkErc20Token::try_from(erc20_token)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("ERROR: {}", e)));
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
        AccessListItem, TransactionReceipt as CandidTransactionReceipt,
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
                }) => EP::AcceptedDeposit {
                    transaction_hash: transaction_hash.to_string(),
                    block_number: block_number.into(),
                    log_index: log_index.into(),
                    from_address: from_address.to_string(),
                    value: value.into(),
                    principal,
                },
                EventType::AcceptedErc20Deposit(ReceivedErc20Event {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value,
                    principal,
                    erc20_contract_address,
                }) => EP::AcceptedErc20Deposit {
                    transaction_hash: transaction_hash.to_string(),
                    block_number: block_number.into(),
                    log_index: log_index.into(),
                    from_address: from_address.to_string(),
                    value: value.into(),
                    principal,
                    erc20_contract_address: erc20_contract_address.to_string(),
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
                    from_subaccount: from_subaccount.map(|s| s.0),
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
                    raw_transaction: transaction.raw_transaction_hex(),
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
                    withdrawal_id,
                    reimbursed_in_block,
                    reimbursed_amount,
                    transaction_hash,
                }) => EP::ReimbursedEthWithdrawal {
                    withdrawal_id: withdrawal_id.get().into(),
                    reimbursed_in_block: reimbursed_in_block.get().into(),
                    reimbursed_amount: reimbursed_amount.into(),
                    transaction_hash: transaction_hash.map(|h| h.to_string()),
                },
                EventType::SkippedBlock(block_number) => EP::SkippedBlock {
                    block_number: block_number.into(),
                },
                EventType::AddedCkErc20Token(token) => EP::AddedCkErc20Token {
                    chain_id: token.erc20_ethereum_network.chain_id().into(),
                    address: token.erc20_contract_address.to_string(),
                    ckerc20_token_symbol: token.ckerc20_token_symbol,
                    ckerc20_ledger_id: token.ckerc20_ledger_id,
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

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_metrics_encoder::MetricsEncoder;

    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/metrics" {
        let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
            const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

            read_state(|s| {
                w.encode_gauge(
                    "cketh_minter_stable_memory_bytes",
                    ic_cdk::api::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
                    "Size of the stable memory allocated by this canister.",
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

                w.encode_gauge(
                    "cketh_minter_last_processed_block",
                    s.last_scraped_block_number.as_f64(),
                    "The last Ethereum block the ckETH minter checked for deposits.",
                )?;

                w.encode_counter(
                    "cketh_minter_skipped_blocks",
                    s.skipped_blocks.len() as f64,
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
                        .map(|(_, fee)| fee.max_fee_per_gas.as_f64())
                        .unwrap_or_default(),
                    "Last max fee per gas",
                )?;

                ic_cketh_minter::eth_rpc::encode_metrics(w)?;

                Ok(())
            })
        }

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        use askama::Template;
        let dashboard = read_state(dashboard::DashboardTemplate::from_state);
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

        const MAX_BODY_SIZE: usize = 3_000_000;
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
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
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
