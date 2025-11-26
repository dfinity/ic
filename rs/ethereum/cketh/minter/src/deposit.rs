use crate::{
    eth_logs::{
        LogParser, LogScraping, ReceivedErc20LogScraping, ReceivedEthLogScraping,
        ReceivedEthOrErc20LogScraping, ReceivedEvent, ReceivedEventError, report_transaction_error,
    },
    eth_rpc::{Topic, is_response_too_large},
    eth_rpc_client::{
        ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE, HEADER_SIZE_LIMIT, MIN_ATTACHED_CYCLES,
        MultiCallError, NoReduction, ToReducedWithStrategy, rpc_client,
    },
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{BlockNumber, BlockRangeInclusive, LedgerMintIndex},
    state::{
        State, TaskType, audit::process_event, eth_logs_scraping::LogScrapingId, event::EventType,
        mutate_state, read_state,
    },
};
use evm_rpc_client::{CandidResponseConverter, DoubleCycles, EvmRpcClient, IcRuntime};
use evm_rpc_types::{Hex32, LogEntry};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use num_traits::ToPrimitive;
use scopeguard::ScopeGuard;
use std::{collections::VecDeque, time::Duration};

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
                to: event.beneficiary(),
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
            event.beneficiary()
        );
        // minting succeeded, defuse guard
        ScopeGuard::into_inner(prevent_double_minting_guard);
    }

    if error_count > 0 {
        log!(
            INFO,
            "Failed to mint {error_count} events, rescheduling the minting"
        );
        ic_cdk_timers::set_timer(crate::MINT_RETRY_DELAY, || {
            ic_cdk::futures::spawn_017_compat(mint())
        });
    }
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
    scrape_until_block::<ReceivedEthLogScraping>(last_block_number, max_block_spread).await;
    scrape_until_block::<ReceivedErc20LogScraping>(last_block_number, max_block_spread).await;
    scrape_until_block::<ReceivedEthOrErc20LogScraping>(last_block_number, max_block_spread).await;
}

pub async fn update_last_observed_block_number() -> Option<BlockNumber> {
    let block_height = read_state(State::ethereum_block_height);
    match read_state(rpc_client)
        .get_block_by_number(block_height.clone())
        .with_cycles(MIN_ATTACHED_CYCLES)
        .send()
        .await
        .reduce_with_strategy(NoReduction)
    {
        Ok(latest_block) => {
            let block_number = Some(BlockNumber::from(latest_block.number));
            mutate_state(|s| s.last_observed_block_number = block_number);
            block_number
        }
        Err(e) => {
            log!(
                INFO,
                "Failed to get the latest {block_height:?} block number: {e:?}"
            );
            read_state(|s| s.last_observed_block_number)
        }
    }
}

async fn scrape_until_block<S>(last_block_number: BlockNumber, max_block_spread: u16)
where
    S: LogScraping,
{
    let scrape = match read_state(S::next_scrape) {
        Some(s) => s,
        None => {
            log!(
                DEBUG,
                "[scrape_contract_logs]: skipping scraping {} logs: not active",
                S::ID
            );
            return;
        }
    };
    let block_range = BlockRangeInclusive::new(
        scrape
            .last_scraped_block_number
            .checked_increment()
            .unwrap_or(BlockNumber::MAX),
        last_block_number,
    );
    log!(
        DEBUG,
        "[scrape_contract_logs]: Scraping {} logs in block range {block_range}",
        S::ID
    );
    let rpc_client = read_state(rpc_client);
    for block_range in block_range.into_chunks(max_block_spread) {
        match scrape_block_range::<S>(
            &rpc_client,
            scrape.contract_address,
            scrape.topics.clone(),
            block_range.clone(),
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                log!(
                    INFO,
                    "[scrape_contract_logs]: Failed to scrape {} logs in range {block_range}: {e:?}",
                    S::ID
                );
                return;
            }
        }
    }
}

async fn scrape_block_range<S>(
    rpc_client: &EvmRpcClient<IcRuntime, CandidResponseConverter, DoubleCycles>,
    contract_address: Address,
    topics: Vec<Topic>,
    block_range: BlockRangeInclusive,
) -> Result<(), MultiCallError<Vec<LogEntry>>>
where
    S: LogScraping,
{
    let mut subranges = VecDeque::new();
    subranges.push_back(block_range);

    while !subranges.is_empty() {
        let range = subranges.pop_front().unwrap();
        let (from_block, to_block) = range.clone().into_inner();

        let result = rpc_client
            .get_logs(vec![contract_address.into_bytes()])
            .with_from_block(from_block)
            .with_to_block(to_block)
            .with_topics(into_evm_topic(topics.clone()))
            .with_cycles(MIN_ATTACHED_CYCLES)
            .with_response_size_estimate(
                ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT,
            )
            .send()
            .await
            .reduce_with_strategy(NoReduction)
            .map(<S::Parser>::parse_all_logs);

        match result {
            Ok((events, errors)) => {
                register_deposit_events(S::ID, events, errors);
                mutate_state(|s| S::update_last_scraped_block_number(s, to_block));
            }
            Err(e) => {
                log!(INFO, "Failed to get {} logs in range {range}: {e:?}", S::ID);
                if e.has_http_outcall_error_matching(is_response_too_large) {
                    if from_block == to_block {
                        mutate_state(|s| {
                            process_event(
                                s,
                                EventType::SkippedBlockForContract {
                                    contract_address,
                                    block_number: to_block,
                                },
                            );
                        });
                        mutate_state(|s| S::update_last_scraped_block_number(s, to_block));
                    } else {
                        let (left_half, right_half) = range.partition_into_halves();
                        if let Some(r) = right_half {
                            let upper_range = subranges
                                .pop_front()
                                .map(|current_next| r.clone().join_with(current_next))
                                .unwrap_or(r);
                            subranges.push_front(upper_range);
                        }
                        if let Some(lower_range) = left_half {
                            subranges.push_front(lower_range);
                        }
                        log!(
                            INFO,
                            "Too many logs received. Will retry with ranges {subranges:?}"
                        );
                    }
                } else {
                    log!(INFO, "Failed to get {} logs in range {range}: {e:?}", S::ID);
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

pub fn register_deposit_events(
    scraping_id: LogScrapingId,
    transaction_events: Vec<ReceivedEvent>,
    errors: Vec<ReceivedEventError>,
) {
    for event in transaction_events {
        log!(
            INFO,
            "Received event {event:?}; will mint {} {scraping_id} to {}",
            event.value(),
            event.beneficiary()
        );
        if crate::blocklist::is_blocked(&event.from_address()) {
            log!(
                INFO,
                "Received event from a blocked address: {} for {} {scraping_id}",
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
        ic_cdk_timers::set_timer(Duration::from_secs(0), || {
            ic_cdk::futures::spawn_017_compat(mint())
        });
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
}

fn into_evm_topic(topics: Vec<Topic>) -> Vec<Vec<Hex32>> {
    let mut result = Vec::with_capacity(topics.len());
    for topic in topics {
        result.push(match topic {
            Topic::Single(single_topic) => vec![single_topic],
            Topic::Multiple(multiple_topic) => multiple_topic.into_iter().collect(),
        });
    }
    result
}
