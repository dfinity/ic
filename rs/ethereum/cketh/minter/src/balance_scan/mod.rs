pub mod multicall3;

#[cfg(test)]
mod tests;

use crate::eth_rpc_client::{AnyOf, MIN_ATTACHED_CYCLES, ToReducedWithStrategy, rpc_client};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::numeric::Erc20Value;
use crate::state::automatic_deposits::DEPOSIT_ADDRESS_SCAN_WINDOW;
use crate::state::{State, TaskType, mutate_state, read_state};
use crate::timed_sized_map::Timestamp;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use multicall3::{BalanceOfCall, MULTICALL3_ADDRESS};
use std::collections::BTreeSet;

const MAX_CALLS_PER_MULTICALL: usize = 200;

/// Cumulative offsets (in seconds) from an address's registration time at which
/// it is scanned. The per-address scan cadence is governed by this schedule;
/// after the last offset the address is no longer scanned (it expires at 24h).
const SCAN_SCHEDULE_SECS: [u64; 33] = [
    30, 60, 120, 240, 360, 600, 900, 1200, 1500, 1800, 5400, 9000, 12600, 16200, 19800, 23400,
    27000, 30600, 34200, 37800, 41400, 45000, 48600, 52200, 55800, 59400, 63000, 66600, 70200,
    73800, 77400, 81000, 84600,
];

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
    let (due_accounts, pairs, calls) = read_state(|s| build_due_calls(s, now));
    if calls.is_empty() {
        mutate_state(|s| {
            prune_dead_progress(s, now);
            s.last_balance_scan = Some(BalanceScanStats {
                scanned_at_ns: now.as_nanos(),
                addresses_scanned: 0,
                candidates_found: 0,
                chunks_failed: 0,
            })
        });
        return;
    }

    let client = read_state(rpc_client);
    let min = min_erc20_deposit();
    let mut candidates = 0_usize;
    let mut chunks_failed = 0_usize;
    for (chunk_pairs, chunk_calls) in pairs
        .chunks(MAX_CALLS_PER_MULTICALL)
        .zip(calls.chunks(MAX_CALLS_PER_MULTICALL))
    {
        let input = multicall3::encode_balance_of_aggregate3(chunk_calls);
        match client
            .call(call_args(input))
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(AnyOf)
        {
            Ok(hex) => match multicall3::decode_balance_of_aggregate3(hex.as_ref()) {
                Ok(balances) => {
                    if balances.len() != chunk_pairs.len() {
                        log!(
                            INFO,
                            "[balance_scan]: decoded {} balances for {} calls; processing aligned prefix",
                            balances.len(),
                            chunk_pairs.len()
                        );
                    }
                    candidates += count_candidates(chunk_pairs, &balances, min);
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

    let addresses_scanned = due_accounts.len();
    log!(
        INFO,
        "[balance_scan]: scanned {addresses_scanned} addresses, found {candidates} candidate(s), {chunks_failed} chunk(s) failed",
    );
    mutate_state(|s| {
        for account in &due_accounts {
            let entry = s.deposit_scan_progress.entry(*account).or_default();
            *entry = entry.saturating_add(1);
        }
        prune_dead_progress(s, now);
        s.last_balance_scan = Some(BalanceScanStats {
            scanned_at_ns: now.as_nanos(),
            addresses_scanned,
            candidates_found: candidates,
            chunks_failed,
        })
    });
}

fn build_due_calls(
    state: &State,
    now: Timestamp,
) -> (Vec<Account>, Vec<(Account, Address)>, Vec<BalanceOfCall>) {
    let tokens: Vec<Address> = state
        .supported_ck_erc20_tokens()
        .map(|token| token.erc20_contract_address)
        .collect();
    let mut due_accounts = Vec::new();
    let mut pairs = Vec::new();
    let mut calls = Vec::new();
    for (account, deposit_address, expires_at) in state.automatic_deposits.live_addresses(now) {
        let registered_at = Timestamp::from_nanos(
            expires_at
                .as_nanos()
                .saturating_sub(DEPOSIT_ADDRESS_SCAN_WINDOW.as_nanos() as u64),
        );
        let scans_done = state
            .deposit_scan_progress
            .get(&account)
            .copied()
            .unwrap_or(0) as usize;
        if !is_scan_due(registered_at, scans_done, now) {
            continue;
        }
        due_accounts.push(account);
        for token in &tokens {
            pairs.push((account, *token));
            calls.push(BalanceOfCall {
                token: *token,
                holder: deposit_address,
            });
        }
    }
    (due_accounts, pairs, calls)
}

fn is_scan_due(registered_at: Timestamp, scans_done: usize, now: Timestamp) -> bool {
    match SCAN_SCHEDULE_SECS.get(scans_done) {
        None => false,
        Some(&offset_secs) => {
            let age_ns = now.as_nanos().saturating_sub(registered_at.as_nanos());
            age_ns >= offset_secs.saturating_mul(1_000_000_000)
        }
    }
}

fn prune_dead_progress(state: &mut State, now: Timestamp) {
    let live: BTreeSet<Account> = state
        .automatic_deposits
        .live_addresses(now)
        .map(|(account, _, _)| account)
        .collect();
    state
        .deposit_scan_progress
        .retain(|account, _| live.contains(account));
}

fn count_candidates(
    pairs: &[(Account, Address)],
    balances: &[Option<Erc20Value>],
    min: Erc20Value,
) -> usize {
    pairs
        .iter()
        .zip(balances)
        .filter(|&(_pair, balance)| matches!(balance, Some(balance) if *balance >= min))
        .count()
}

fn min_erc20_deposit() -> Erc20Value {
    // TODO(R7): per-token configurable minimum
    Erc20Value::from(1_000_000_u64)
}

fn call_args(input: Vec<u8>) -> evm_rpc_types::CallArgs {
    evm_rpc_types::CallArgs {
        transaction: evm_rpc_types::TransactionRequest {
            to: Some(evm_rpc_types::Hex20::from(MULTICALL3_ADDRESS.into_bytes())),
            input: Some(evm_rpc_types::Hex::from(input)),
            ..Default::default()
        },
        block: Some(evm_rpc_types::BlockTag::Latest),
    }
}
