use crate::address::Address;
use crate::eth_logs::{report_transaction_error, ReceivedEthEventError};
use crate::eth_rpc::BlockSpec;
use crate::eth_rpc_client::EthRpcClient;
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, LedgerMintIndex};
use crate::state::{
    audit::process_event, event::EventType, mutate_state, read_state, State, TaskType,
};
use ic_canister_log::log;
use num_traits::ToPrimitive;
use std::cmp::{min, Ordering};
use std::time::Duration;

async fn mint_cketh() {
    use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
    use icrc_ledger_types::icrc1::transfer::TransferArg;

    let _guard = match TimerGuard::new(TaskType::MintCkEth) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let (ledger_canister_id, events) = read_state(|s| (s.ledger_id, s.events_to_mint.clone()));
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    };

    let mut error_count = 0;

    for (event_source, event) in events {
        let block_index = match client
            .transfer(TransferArg {
                from_subaccount: None,
                to: event.principal.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: candid::Nat::from(event.value),
            })
            .await
        {
            Ok(Ok(block_index)) => block_index.0.to_u64().expect("nat does not fit into u64"),
            Ok(Err(err)) => {
                log!(INFO, "Failed to mint ckETH: {event:?} {err}");
                error_count += 1;
                continue;
            }
            Err(err) => {
                log!(
                    INFO,
                    "Failed to send a message to the ledger ({ledger_canister_id}): {err:?}"
                );
                error_count += 1;
                continue;
            }
        };
        mutate_state(|s| {
            process_event(
                s,
                EventType::MintedCkEth {
                    event_source,
                    mint_block_index: LedgerMintIndex::new(block_index),
                },
            )
        });
        log!(
            INFO,
            "Minted {} ckWei to {} in block {block_index}",
            event.value,
            event.principal
        );
    }

    if error_count > 0 {
        log!(
            INFO,
            "Failed to mint {error_count} events, rescheduling the minting"
        );
        ic_cdk_timers::set_timer(crate::MINT_RETRY_DELAY, || ic_cdk::spawn(mint_cketh()));
    }
}

/// Scraps Ethereum logs between `from` and `min(from + 1024, to)` since certain RPC providers
/// require that the number of blocks queried is no greater than 1024.
/// Returns the last block number that was scraped (which is `min(from + 1024, to)`).
pub async fn scrap_eth_logs_between(
    contract_address: Address,
    from: BlockNumber,
    to: BlockNumber,
) -> BlockNumber {
    const MAX_BLOCK_SPREAD: u16 = 1024;
    match from.cmp(&to) {
        Ordering::Less => {
            let max_to = from
                .checked_add(BlockNumber::from(MAX_BLOCK_SPREAD))
                .unwrap_or(BlockNumber::MAX);
            let last_scraped_block_number = min(max_to, to);
            log!(
                DEBUG,
                "Scrapping ETH logs from block {:?} to block {:?}...",
                from,
                last_scraped_block_number
            );

            let (transaction_events, errors) = match crate::eth_logs::last_received_eth_events(
                contract_address,
                from,
                last_scraped_block_number,
            )
            .await
            {
                Ok((events, errors)) => (events, errors),
                Err(e) => {
                    log!(
                        INFO,
                        "Failed to get ETH logs from block {from} to block {to}: {e:?}",
                    );
                    return from;
                }
            };
            let has_new_events = !transaction_events.is_empty();
            for event in transaction_events {
                log!(
                    INFO,
                    "Received event {event:?}; will mint {} wei to {}",
                    event.value,
                    event.principal
                );
                if crate::blocklist::is_blocked(event.from_address) {
                    log!(
                        INFO,
                        "Received event from a blocked address: {} for {} WEI",
                        event.from_address,
                        event.value,
                    );
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::InvalidDeposit {
                                event_source: crate::eth_logs::EventSource {
                                    transaction_hash: event.transaction_hash,
                                    log_index: event.log_index,
                                },
                                reason: format!("blocked address {}", event.from_address),
                            },
                        )
                    });
                } else {
                    mutate_state(|s| process_event(s, EventType::AcceptedDeposit(event)));
                }
            }
            if has_new_events {
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint_cketh()));
            }
            for error in errors {
                if let ReceivedEthEventError::InvalidEventSource { source, error } = &error {
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
            mutate_state(|s| s.last_scraped_block_number = last_scraped_block_number);
            last_scraped_block_number
        }
        Ordering::Equal => {
            log!(
                DEBUG,
                "[scrap_eth_logs] Skipping scrapping ETH logs: no new blocks",
            );
            to
        }
        Ordering::Greater => {
            ic_cdk::trap(&format!(
                "BUG: last scraped block number ({:?}) is greater than the last queried block number ({:?})",
                from, to
            ));
        }
    }
}

pub async fn scrap_eth_logs() {
    let _guard = match TimerGuard::new(TaskType::ScrapEthLogs) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let contract_address = match read_state(|s| s.ethereum_contract_address) {
        Some(address) => address,
        None => {
            log!(
                DEBUG,
                "[scrap_eth_logs]: skipping scrapping ETH logs: no contract address"
            );
            return;
        }
    };
    let last_block_number = match update_last_observed_block_number().await {
        Some(block_number) => block_number,
        None => {
            log!(
                DEBUG,
                "[scrap_eth_logs]: skipping scrapping ETH logs: no last observed block number"
            );
            return;
        }
    };
    let mut last_scraped_block_number = read_state(|s| s.last_scraped_block_number);
    while last_scraped_block_number < last_block_number {
        last_scraped_block_number = scrap_eth_logs_between(
            contract_address,
            last_scraped_block_number,
            last_block_number,
        )
        .await;
    }
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
