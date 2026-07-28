pub mod batcher;

#[cfg(test)]
mod tests;

use crate::eth_rpc_client::{AnyOf, MIN_ATTACHED_CYCLES, ToReducedWithStrategy, rpc_client};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::{State, TaskType, mutate_state, read_state};
use crate::timed_sized_map::Timestamp;
use batcher::BalanceOfCall;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

const MAX_CALLS_PER_BATCH: usize = 200;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BalanceScanStats {
    pub scanned_at_ns: u64,
    pub addresses_scanned: usize,
    pub candidates_found: usize,
    pub chunks_failed: usize,
}

pub async fn balance_scan() {
    let _guard = match TimerGuard::new(TaskType::BalanceScan) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let now = Timestamp::from_nanos(ic_cdk::api::time());
    let (latest_block, tokens, due) = read_state(|s| select(s, now));

    // Nothing to do this tick if the latest block height hasn't been refreshed yet, there are no
    // supported tokens, or no address is due for a scan.
    let latest_block = match latest_block {
        Some(latest_block) if !tokens.is_empty() && !due.is_empty() => latest_block,
        _ => {
            record_stats(now, 0, 0, 0);
            return;
        }
    };

    let client = read_state(rpc_client);
    let min = min_erc20_deposit();
    // Chunk by address so an address' per-token calls never straddle a chunk boundary; this keeps
    // the per-address scan-state advance below all-or-nothing per chunk.
    let addresses_per_chunk = (MAX_CALLS_PER_BATCH / tokens.len()).max(1);
    let mut candidates = 0_usize;
    let mut chunks_failed = 0_usize;
    let mut scanned: Vec<Account> = Vec::new();

    for chunk in due.chunks(addresses_per_chunk) {
        let calls = balance_of_calls(chunk, &tokens);
        let input = batcher::encode_balance_batch(&calls);
        match client
            .call(call_args(input, latest_block))
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(AnyOf)
        {
            Ok(hex) => match batcher::decode_balance_batch(hex.as_ref(), calls.len()) {
                Ok(balances) => {
                    candidates += count_candidates(&balances, min);
                    scanned.extend(chunk.iter().map(|(account, _)| *account));
                }
                Err(e) => {
                    chunks_failed += 1;
                    log!(INFO, "balance scan decode error: {e:?}");
                }
            },
            Err(e) => {
                chunks_failed += 1;
                log!(INFO, "balance scan eth_call error: {e:?}");
            }
        }
    }

    // Advance only the addresses actually scanned, so a failed chunk is retried next tick rather
    // than silently skipped until its next scheduled slot.
    let addresses_scanned = scanned.len();
    mutate_state(|s| {
        for account in &scanned {
            s.automatic_deposits.record_scan(now, account, latest_block);
        }
    });

    log!(
        INFO,
        "[balance_scan]: scanned {addresses_scanned} addresses, found {candidates} candidate(s), {chunks_failed} chunk(s) failed",
    );
    record_stats(now, addresses_scanned, candidates, chunks_failed);
}

/// The latest known block height, the supported ERC-20 token contracts, and the deposit addresses
/// due for a scan at that height.
fn select(
    state: &State,
    now: Timestamp,
) -> (Option<BlockNumber>, Vec<Address>, Vec<(Account, Address)>) {
    let latest_block = state.latest_block_height;
    let tokens: Vec<Address> = state
        .supported_ck_erc20_tokens()
        .map(|token| token.erc20_contract_address)
        .collect();
    let due: Vec<(Account, Address)> = match latest_block {
        Some(latest_block) => state
            .automatic_deposits
            .addresses_to_scan_iter(now, latest_block)
            .collect(),
        None => Vec::new(),
    };
    (latest_block, tokens, due)
}

fn balance_of_calls(addresses: &[(Account, Address)], tokens: &[Address]) -> Vec<BalanceOfCall> {
    let mut calls = Vec::with_capacity(addresses.len() * tokens.len());
    for (_account, holder) in addresses {
        for token in tokens {
            calls.push(BalanceOfCall {
                token: *token,
                holder: *holder,
            });
        }
    }
    calls
}

fn count_candidates(balances: &[Erc20Value], min: Erc20Value) -> usize {
    balances.iter().filter(|balance| **balance >= min).count()
}

fn min_erc20_deposit() -> Erc20Value {
    // TODO(R7): per-token configurable minimum
    Erc20Value::from(1_000_000_u64)
}

fn record_stats(
    now: Timestamp,
    addresses_scanned: usize,
    candidates_found: usize,
    chunks_failed: usize,
) {
    mutate_state(|s| {
        s.last_balance_scan = Some(BalanceScanStats {
            scanned_at_ns: now.as_nanos(),
            addresses_scanned,
            candidates_found,
            chunks_failed,
        })
    });
}

fn call_args(input: Vec<u8>, block: BlockNumber) -> evm_rpc_types::CallArgs {
    evm_rpc_types::CallArgs {
        transaction: evm_rpc_types::TransactionRequest {
            // Create-style call (no `to`): the node runs `input` as init code and returns its
            // `RETURN`, so the deployless batcher executes as a pure read.
            to: None,
            input: Some(evm_rpc_types::Hex::from(input)),
            ..Default::default()
        },
        // Pinned to the refreshed latest block height so every provider reads the same block (and
        // the scanned block is known, to advance the per-address schedule).
        block: Some(evm_rpc_types::BlockTag::from(block)),
    }
}
