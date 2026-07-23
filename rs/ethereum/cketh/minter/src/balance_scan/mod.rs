pub mod multicall3;

#[cfg(test)]
mod tests;

use crate::eth_rpc_client::{AnyOf, MIN_ATTACHED_CYCLES, ToReducedWithStrategy, rpc_client};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::numeric::Erc20Value;
use crate::state::{State, TaskType, mutate_state, read_state};
use crate::timed_sized_map::Timestamp;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use multicall3::{BalanceOfCall, MULTICALL3_ADDRESS};

const MAX_CALLS_PER_MULTICALL: usize = 200;

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
    let (addresses_scanned, pairs, calls) = read_state(|s| build_calls(s, now));
    if calls.is_empty() {
        mutate_state(|s| {
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

    log!(
        INFO,
        "[balance_scan]: scanned {addresses_scanned} addresses, found {candidates} candidate(s), {chunks_failed} chunk(s) failed",
    );
    mutate_state(|s| {
        s.last_balance_scan = Some(BalanceScanStats {
            scanned_at_ns: now.as_nanos(),
            addresses_scanned,
            candidates_found: candidates,
            chunks_failed,
        })
    });
}

fn build_calls(
    state: &State,
    now: Timestamp,
) -> (usize, Vec<(Account, Address)>, Vec<BalanceOfCall>) {
    let tokens: Vec<Address> = state
        .supported_ck_erc20_tokens()
        .map(|token| token.erc20_contract_address)
        .collect();
    let mut addresses_scanned = 0_usize;
    let mut pairs = Vec::new();
    let mut calls = Vec::new();
    for (account, deposit_address) in state.automatic_deposits.live_addresses(now) {
        addresses_scanned += 1;
        for token in &tokens {
            pairs.push((account, *token));
            calls.push(BalanceOfCall {
                token: *token,
                holder: deposit_address,
            });
        }
    }
    (addresses_scanned, pairs, calls)
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
