use crate::eth_logs::{report_transaction_error, ReceivedEvent, ReceivedEventError};
use crate::eth_rpc::{BlockSpec, HttpOutcallError};
use crate::eth_rpc_client::EthRpcClient;
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, LedgerMintIndex};
use crate::state::{
    audit::process_event, event::EventType, mutate_state, read_state, State, TaskType,
};
use hex_literal::hex;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use num_traits::ToPrimitive;
use scopeguard::ScopeGuard;
use std::cmp::{min, Ordering};
use std::time::Duration;

pub(crate) const RECEIVED_ETH_EVENT_TOPIC: [u8; 32] =
    hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");

pub(crate) const RECEIVED_ERC20_EVENT_TOPIC: [u8; 32] =
    hex!("4d69d0bd4287b7f66c548f90154dc81bc98f65a1b362775df5ae171a2ccd262b");

async fn mint() {
    use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
    use icrc_ledger_types::icrc1::transfer::TransferArg;

    let _guard = match TimerGuard::new(TaskType::Mint) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let (eth_ledger_canister_id, events) = read_state(|s| (s.cketh_ledger_id, s.events_to_mint()));
    let mut error_count = 0;

    for event in events {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this event will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(event.clone(), |event| {
            mutate_state(|s| {
                process_event(
                    s,
                    EventType::QuarantinedDeposit {
                        event_source: event.source(),
                    },
                )
            });
        });
        let (token_symbol, ledger_canister_id) = match &event {
            ReceivedEvent::Eth(_) => ("ckETH".to_string(), eth_ledger_canister_id),
            ReceivedEvent::Erc20(event) => {
                if let Some(result) = read_state(|s| {
                    s.ckerc20_tokens
                        .get_entry_alt(&event.erc20_contract_address)
                        .map(|(principal, symbol)| (symbol.to_string(), *principal))
                }) {
                    result
                } else {
                    panic!(
                        "Failed to mint ckERC20: {event:?} Unsupported ERC20 contract address. (This should have already been filtered out by process_event)"
                    )
                }
            }
        };
        let client = ICRC1Client {
            runtime: CdkRuntime,
            ledger_canister_id,
        };
        let block_index = match client
            .transfer(TransferArg {
                from_subaccount: None,
                to: (event.principal()).into(),
                fee: None,
                created_at_time: None,
                memo: Some((&event).into()),
                amount: event.value(),
            })
            .await
        {
            Ok(Ok(block_index)) => block_index.0.to_u64().expect("nat does not fit into u64"),
            Ok(Err(err)) => {
                log!(INFO, "Failed to mint {token_symbol}: {event:?} {err}");
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
            Err(err) => {
                log!(
                    INFO,
                    "Failed to send a message to the ledger ({ledger_canister_id}): {err:?}"
                );
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
        };
        mutate_state(|s| {
            process_event(
                s,
                match &event {
                    ReceivedEvent::Eth(event) => EventType::MintedCkEth {
                        event_source: event.source(),
                        mint_block_index: LedgerMintIndex::new(block_index),
                    },

                    ReceivedEvent::Erc20(event) => EventType::MintedCkErc20 {
                        event_source: event.source(),
                        mint_block_index: LedgerMintIndex::new(block_index),
                        erc20_contract_address: event.erc20_contract_address,
                        ckerc20_token_symbol: token_symbol.clone(),
                    },
                },
            )
        });
        log!(
            INFO,
            "Minted {} {token_symbol} to {} in block {block_index}",
            event.value(),
            event.principal()
        );
        // minting succeeded, defuse guard
        ScopeGuard::into_inner(prevent_double_minting_guard);
    }

    if error_count > 0 {
        log!(
            INFO,
            "Failed to mint {error_count} events, rescheduling the minting"
        );
        ic_cdk_timers::set_timer(crate::MINT_RETRY_DELAY, || ic_cdk::spawn(mint()));
    }
}

/// Scraps Ethereum logs between `from` and `min(from + MAX_BLOCK_SPREAD, to)` since certain RPC providers
/// require that the number of blocks queried is no greater than MAX_BLOCK_SPREAD.
/// Returns the last block number that was scraped (which is `min(from + MAX_BLOCK_SPREAD, to)`) if there
/// was no error when querying the providers, otherwise returns `None`.
async fn scrape_logs_range_inclusive<F>(
    topic: &[u8; 32],
    topic_name: &str,
    helper_contract_address: Address,
    token_contract_addresses: &[Address],
    from: BlockNumber,
    to: BlockNumber,
    max_block_spread: u16,
    update_last_scraped_block_number: &F,
) -> Option<BlockNumber>
where
    F: Fn(BlockNumber),
{
    match from.cmp(&to) {
        Ordering::Less | Ordering::Equal => {
            let max_to = from
                .checked_add(BlockNumber::from(max_block_spread))
                .unwrap_or(BlockNumber::MAX);
            let mut last_block_number = min(max_to, to);
            log!(
                DEBUG,
                "Scrapping {topic_name} logs from block {:?} to block {:?}...",
                from,
                last_block_number
            );

            let (transaction_events, errors) = loop {
                match crate::eth_logs::last_received_events(
                    topic,
                    helper_contract_address,
                    token_contract_addresses,
                    from,
                    last_block_number,
                )
                .await
                {
                    Ok((events, errors)) => break (events, errors),
                    Err(e) => {
                        log!(
                        INFO,
                        "Failed to get {topic_name} logs from block {from} to block {last_block_number}: {e:?}",
                    );
                        if e.has_http_outcall_error_matching(
                            HttpOutcallError::is_response_too_large,
                        ) {
                            if from == last_block_number {
                                mutate_state(|s| {
                                    process_event(
                                        s,
                                        EventType::SkippedBlockForContract {
                                            contract_address: helper_contract_address,
                                            block_number: last_block_number,
                                        },
                                    );
                                });
                                update_last_scraped_block_number(last_block_number);
                                return Some(last_block_number);
                            } else {
                                let new_last_block_number = from
                                    .checked_add(last_block_number
                                            .checked_sub(from)
                                            .expect("last_scraped_block_number is greater or equal than from")
                                            .div_by_two())
                                    .expect("must be less than last_scraped_block_number");
                                log!(INFO, "Too many logs received in range [{from}, {last_block_number}]. Will retry with range [{from}, {new_last_block_number}]");
                                last_block_number = new_last_block_number;
                                continue;
                            }
                        }
                        return None;
                    }
                };
            };

            for event in transaction_events {
                log!(
                    INFO,
                    "Received event {event:?}; will mint {} {topic_name} to {}",
                    event.value(),
                    event.principal()
                );
                if crate::blocklist::is_blocked(&event.from_address()) {
                    log!(
                        INFO,
                        "Received event from a blocked address: {} for {} {topic_name}",
                        event.from_address(),
                        event.value(),
                    );
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::InvalidDeposit {
                                event_source: event.source(),
                                reason: format!("blocked address {}", event.from_address()),
                            },
                        )
                    });
                } else {
                    mutate_state(|s| process_event(s, event.into_deposit()));
                }
            }
            if read_state(State::has_events_to_mint) {
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint()));
            }
            for error in errors {
                if let ReceivedEventError::InvalidEventSource { source, error } = &error {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::InvalidDeposit {
                                event_source: *source,
                                reason: error.to_string(),
                            },
                        )
                    });
                }
                report_transaction_error(error);
            }
            update_last_scraped_block_number(last_block_number);
            Some(last_block_number)
        }
        Ordering::Greater => {
            ic_cdk::trap(&format!(
                "BUG: last scraped block number ({:?}) is greater than the last queried block number ({:?})",
                from, to
            ));
        }
    }
}

async fn scrape_contract_logs<F>(
    topic: &[u8; 32],
    topic_name: &str,
    helper_contract_address: Option<Address>,
    token_contract_addresses: &[Address],
    last_block_number: BlockNumber,
    mut last_scraped_block_number: BlockNumber,
    max_block_spread: u16,
    update_last_scraped_block_number: F,
) where
    F: Fn(BlockNumber),
{
    let helper_contract_address = match helper_contract_address {
        Some(address) => address,
        None => {
            log!(
                DEBUG,
                "[scrape_contract_logs]: skipping scrapping logs: no contract address"
            );
            return;
        }
    };

    while last_scraped_block_number < last_block_number {
        let next_block_to_query = last_scraped_block_number
            .checked_increment()
            .unwrap_or(BlockNumber::MAX);
        last_scraped_block_number = match scrape_logs_range_inclusive(
            topic,
            topic_name,
            helper_contract_address,
            token_contract_addresses,
            next_block_to_query,
            last_block_number,
            max_block_spread,
            &update_last_scraped_block_number,
        )
        .await
        {
            Some(last_scraped_block_number) => last_scraped_block_number,
            None => {
                return;
            }
        };
    }
}

async fn scrape_eth_logs(last_block_number: BlockNumber, max_block_spread: u16) {
    scrape_contract_logs(
        &RECEIVED_ETH_EVENT_TOPIC,
        "ETH",
        read_state(|s| s.eth_helper_contract_address),
        &[],
        last_block_number,
        read_state(|s| s.last_scraped_block_number),
        max_block_spread,
        &|last_block_number| mutate_state(|s| s.last_scraped_block_number = last_block_number),
    )
    .await
}

async fn scrape_erc20_logs(last_block_number: BlockNumber, max_block_spread: u16) {
    let token_contract_addresses =
        read_state(|s| s.ckerc20_tokens.alt_keys().cloned().collect::<Vec<_>>());
    if token_contract_addresses.is_empty() {
        log!(
            DEBUG,
            "[scrape_contract_logs]: skipping scrapping ERC-20 logs: no token contract address"
        );
        return;
    }
    scrape_contract_logs(
        &RECEIVED_ERC20_EVENT_TOPIC,
        "ERC-20",
        read_state(|s| s.erc20_helper_contract_address),
        &token_contract_addresses,
        last_block_number,
        read_state(|s| s.last_erc20_scraped_block_number),
        max_block_spread,
        &|last_block_number| {
            mutate_state(|s| s.last_erc20_scraped_block_number = last_block_number)
        },
    )
    .await
}

pub async fn scrape_logs() {
    let _guard = match TimerGuard::new(TaskType::ScrapEthLogs) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let last_block_number = match update_last_observed_block_number().await {
        Some(block_number) => block_number,
        None => {
            log!(
                DEBUG,
                "[scrape_logs]: skipping scrapping logs: no last observed block number"
            );
            return;
        }
    };
    let max_block_spread = read_state(|s| s.max_block_spread_for_logs_scraping());
    scrape_eth_logs(last_block_number, max_block_spread).await;
    scrape_erc20_logs(last_block_number, max_block_spread).await;
}

pub async fn update_last_observed_block_number() -> Option<BlockNumber> {
    let block_height = read_state(State::ethereum_block_height);
    match read_state(EthRpcClient::from_state)
        .eth_get_block_by_number(BlockSpec::Tag(block_height))
        .await
    {
        Ok(latest_block) => {
            let block_number = Some(latest_block.number);
            mutate_state(|s| s.last_observed_block_number = block_number);
            block_number
        }
        Err(e) => {
            log!(
                INFO,
                "Failed to get the latest {block_height} block number: {e:?}"
            );
            read_state(|s| s.last_observed_block_number)
        }
    }
}
