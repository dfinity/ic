use candid::{candid_method, Nat};
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::{validate_address_as_destination, Address};
use ic_cketh_minter::deposit::scrap_eth_logs;
use ic_cketh_minter::endpoints::events::{
    Event as CandidEvent, EventSource as CandidEventSource, GetEventsArg, GetEventsResult,
};
use ic_cketh_minter::endpoints::{
    Eip1559TransactionPrice, RetrieveEthRequest, RetrieveEthStatus, WithdrawalArg, WithdrawalError,
};
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEthEvent};
use ic_cketh_minter::guard::retrieve_eth_guard;
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::logs::{DEBUG, INFO};
use ic_cketh_minter::numeric::{LedgerBurnIndex, Wei};
use ic_cketh_minter::state::audit::{process_event, Event, EventType};
use ic_cketh_minter::state::{lazy_call_ecdsa_public_key, mutate_state, read_state, State, STATE};
use ic_cketh_minter::transactions::EthWithdrawalRequest;
use ic_cketh_minter::tx::estimate_transaction_price;
use ic_cketh_minter::withdraw::{eth_fee_history, process_retrieve_eth_requests};
use ic_cketh_minter::{
    state, storage, PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, SCRAPPING_ETH_LOGS_INTERVAL,
};
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
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
    ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(scrap_eth_logs()));
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
    ic_cdk_timers::set_timer_interval(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, || {
        ic_cdk::spawn(process_retrieve_eth_requests())
    });
}

#[init]
#[candid_method(init)]
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

#[pre_upgrade]
fn pre_upgrade() {
    read_state(|s| {
        storage::encode_state(s);
        storage::record_event(EventType::SyncedToBlock {
            block_number: s.last_scraped_block_number,
        });
    });
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
#[candid_method(update)]
async fn minter_address() -> String {
    state::minter_address().await.to_string()
}

#[query]
#[candid_method(query)]
async fn smart_contract_address() -> String {
    read_state(|s| s.ethereum_contract_address)
        .map(|a| a.to_string())
        .unwrap_or("N/A".to_string())
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    let transaction_price = estimate_transaction_price(
        &eth_fee_history()
            .await
            .expect("ERROR: failed to retrieve fee history"),
    );
    Eip1559TransactionPrice::from(transaction_price)
}

#[update]
#[candid_method(update)]
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

    let destination = Address::from_str(&recipient)
        .and_then(|a| validate_address_as_destination(a).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| ic_cdk::trap(&format!("invalid recipient address: {:?}", e)));

    if ic_cketh_minter::blocklist::is_blocked(destination) {
        ic_cdk::trap("attempted to withdraw ETH to a blocked address");
    }

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

    log!(INFO, "[withdraw]: burning {:?}", amount);
    match client
        .transfer_from(TransferFromArgs {
            spender_subaccount: None,
            from: caller.into(),
            to: ic_cdk::id().into(),
            amount: Nat::from(amount),
            fee: None,
            memo: None,
            created_at_time: None,
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
#[candid_method(update)]
async fn retrieve_eth_status(block_index: u64) -> RetrieveEthStatus {
    let ledger_burn_index = LedgerBurnIndex::new(block_index);
    read_state(|s| s.eth_transactions.transaction_status(&ledger_burn_index))
}

#[candid_method(query)]
#[query]
fn is_address_blocked(address_string: String) -> bool {
    let address = Address::from_str(&address_string)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("invalid recipient address: {:?}", e)));
    ic_cketh_minter::blocklist::is_blocked(address)
}

#[candid_method(update)]
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
#[candid_method(query)]
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
                }) => EP::AcceptedEthWithdrawalRequest {
                    withdrawal_amount: withdrawal_amount.into(),
                    destination: destination.to_string(),
                    ledger_burn_index: ledger_burn_index.get().into(),
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
fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_metrics_encoder::MetricsEncoder;

    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/metrics" {
        let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
            read_state(|s| {
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

                w.gauge_vec(
                    "cketh_minter_accepted_deposits",
                    "The number of deposits the ckETH minter processed, by status.",
                )?
                .value(&[("status", "accepted")], s.minted_events.len() as f64)?
                .value(&[("status", "rejected")], s.invalid_events.len() as f64)?;

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
                        .build()
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

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid::utils::CandidSource) -> String {
        match source {
            candid::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_equal(new, old) {
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
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in cketh_minter.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
