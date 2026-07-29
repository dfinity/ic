pub mod batcher;

#[cfg(test)]
mod tests;

use crate::eth_rpc_client::{AnyOf, MIN_ATTACHED_CYCLES, ToReducedWithStrategy, rpc_client};
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::{TaskType, mutate_state, read_state};
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
    let latest_block = match read_state(|s| s.latest_block_height) {
        Some(b) => b,
        None => {
            log!(
                DEBUG,
                "[balance_scan] SKIPPING: latest block height unknown"
            );
            return;
        }
    };
    let erc20_tokens: Vec<_> = read_state(|s| {
        s.supported_ck_erc20_tokens()
            .map(|t| t.erc20_contract_address)
            .collect()
    });
    if erc20_tokens.is_empty() {
        log!(
            DEBUG,
            "[balance_scan] SKIPPING: no ERC-20 contracts supported"
        );
        return;
    }
    let now = Timestamp::from_nanos(ic_cdk::api::time());
    let (addresses_to_scan, watchlist_len) = read_state(|s| {
        (
            s.automatic_deposits
                .addresses_to_scan_iter(now, latest_block)
                .collect::<Vec<_>>(),
            s.automatic_deposits.watchlist_len(),
        )
    });
    if addresses_to_scan.is_empty() {
        log!(
            DEBUG,
            "[balance_scan] SKIPPING: 0/{watchlist_len} user addresses ready to be scanned"
        );
        return;
    }

    let client = read_state(rpc_client);
    // Chunk by address so an address' per-token calls never straddle a chunk boundary, keeping
    // the per-address scan-state advance all-or-nothing per chunk. `erc20_tokens.len()` is the number of
    // supported ckERC20 tokens (a handful, far below MAX_CALLS_PER_BATCH), so a chunk holds many
    // addresses. A single address is never split across chunks — that would let a partially
    // scanned address be advanced — so if the token set ever grew past the cap, one address' calls
    // would still be sent together (the batcher response is only 32 bytes per call, so a larger
    // chunk stays cheap).
    let addresses_per_chunk = (MAX_CALLS_PER_BATCH / erc20_tokens.len()).max(1);
    let mut candidates = 0_usize;
    let mut chunks_failed = 0_usize;
    let mut scanned: Vec<Account> = Vec::new();

    for chunk in addresses_to_scan.chunks(addresses_per_chunk) {
        let calls = balance_of_calls(chunk, &erc20_tokens);
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
                    candidates += count_candidates(&calls, &balances);
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

fn count_candidates(calls: &[BalanceOfCall], balances: &[Erc20Value]) -> usize {
    calls
        .iter()
        .zip(balances)
        .filter(|(call, balance)| **balance >= min_deposit(&call.token))
        .count()
}

/// Minimum balance for `token` to count as a scan candidate; a token absent from
/// [`MIN_DEPOSITS`] never counts.
fn min_deposit(token: &Address) -> Erc20Value {
    MIN_DEPOSITS
        .iter()
        .find(|(contract, _)| contract == token)
        .map(|(_, min)| *min)
        .unwrap_or(Erc20Value::MAX)
}

/// Per-token minimum deposit that counts as a balance-scan candidate: the amount of each token
/// worth about 0.005 ETH (5_000_000_000_000_000 wei) or roughly $10, covering every ckERC20 token the mainnet
/// (`sv3dd-oaaaa-aaaar-qacoa-cai`) and Sepolia (`jzenf-aiaaa-aaaar-qaa7q-cai`) minters support.
///
/// These are a hard-coded rate snapshot (ETH ≈ $1_877 on 2026-07-28), rounded to a round token
/// amount close to $10 (shown in the trailing comment). TODO(DEFI-2961): recompute daily from the
/// exchange-rate canister so the thresholds track live prices.
const MIN_DEPOSITS: &[(Address, Erc20Value)] = &[
    // --- mainnet ---
    (
        Address::new([
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]),
        Erc20Value::new(10_000_000),
    ), // ckUSDC = 10
    (
        Address::new([
            0x51, 0x49, 0x10, 0x77, 0x1a, 0xf9, 0xca, 0x65, 0x6a, 0xf8, 0x40, 0xdf, 0xf8, 0x3e,
            0x82, 0x64, 0xec, 0xf9, 0x86, 0xca,
        ]),
        Erc20Value::new(1_000_000_000_000_000_000),
    ), // ckLINK = 1
    (
        Address::new([
            0x69, 0x82, 0x50, 0x81, 0x45, 0x45, 0x4c, 0xe3, 0x25, 0xdd, 0xbe, 0x47, 0xa2, 0x5d,
            0x4e, 0xc3, 0xd2, 0x31, 0x19, 0x33,
        ]),
        Erc20Value::new(3_500_000_000_000_000_000_000_000),
    ), // ckPEPE = 3.5M
    (
        Address::new([
            0xf5, 0xcf, 0xbc, 0x74, 0x05, 0x7c, 0x61, 0x0c, 0x8e, 0xf1, 0x51, 0xa4, 0x39, 0x25,
            0x26, 0x80, 0xac, 0x68, 0xc6, 0xdc,
        ]),
        Erc20Value::new(5_000_000_000_000_000_000_000),
    ), // ckOCT = 5000
    (
        Address::new([
            0x95, 0xad, 0x61, 0xb0, 0xa1, 0x50, 0xd7, 0x92, 0x19, 0xdc, 0xf6, 0x4e, 0x1e, 0x6c,
            0xc0, 0x1f, 0x0b, 0x64, 0xc4, 0xce,
        ]),
        Erc20Value::new(2_000_000_000_000_000_000_000_000),
    ), // ckSHIB = 2M
    (
        Address::new([
            0x22, 0x60, 0xfa, 0xc5, 0xe5, 0x54, 0x2a, 0x77, 0x3a, 0xa4, 0x4f, 0xbc, 0xfe, 0xdf,
            0x7c, 0x19, 0x3b, 0xc2, 0xc5, 0x99,
        ]),
        Erc20Value::new(15_000),
    ), // ckWBTC = 0.00015
    (
        Address::new([
            0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45,
            0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7,
        ]),
        Erc20Value::new(10_000_000),
    ), // ckUSDT = 10
    (
        Address::new([
            0x7f, 0x39, 0xc5, 0x81, 0xf5, 0x95, 0xb5, 0x3c, 0x5c, 0xb1, 0x9b, 0xd0, 0xb3, 0xf8,
            0xda, 0x6c, 0x93, 0x5e, 0x2c, 0xa0,
        ]),
        Erc20Value::new(4_000_000_000_000_000),
    ), // ckWSTETH = 0.004
    (
        Address::new([
            0x1f, 0x98, 0x40, 0xa8, 0x5d, 0x5a, 0xf5, 0xbf, 0x1d, 0x17, 0x62, 0xf9, 0x25, 0xbd,
            0xad, 0xdc, 0x42, 0x01, 0xf9, 0x84,
        ]),
        Erc20Value::new(2_500_000_000_000_000_000),
    ), // ckUNI = 2.5
    (
        Address::new([
            0x1a, 0xba, 0xea, 0x1f, 0x7c, 0x83, 0x0b, 0xd8, 0x9a, 0xcc, 0x67, 0xec, 0x4a, 0xf5,
            0x16, 0x28, 0x4b, 0x1b, 0xc3, 0x3c,
        ]),
        Erc20Value::new(8_000_000),
    ), // ckEURC = 8
    (
        Address::new([
            0x68, 0x74, 0x96, 0x65, 0xff, 0x8d, 0x2d, 0x11, 0x2f, 0xa8, 0x59, 0xaa, 0x29, 0x3f,
            0x07, 0xa6, 0x22, 0x78, 0x2f, 0x38,
        ]),
        Erc20Value::new(2_500),
    ), // ckXAUT = 0.0025
    // --- sepolia (testnet analogs, priced as their mainnet counterpart) ---
    (
        Address::new([
            0x1c, 0x7d, 0x4b, 0x19, 0x6c, 0xb0, 0xc7, 0xb0, 0x1d, 0x74, 0x3f, 0xbc, 0x61, 0x16,
            0xa9, 0x02, 0x37, 0x9c, 0x72, 0x38,
        ]),
        Erc20Value::new(10_000_000),
    ), // ckSepoliaUSDC
    (
        Address::new([
            0x77, 0x98, 0x77, 0xa7, 0xb0, 0xd9, 0xe8, 0x60, 0x31, 0x69, 0xdd, 0xbd, 0x78, 0x36,
            0xe4, 0x78, 0xb4, 0x62, 0x47, 0x89,
        ]),
        Erc20Value::new(1_000_000_000_000_000_000),
    ), // ckSepoliaLINK
    (
        Address::new([
            0x56, 0x0e, 0xf9, 0xf3, 0x9e, 0x4b, 0x08, 0xf9, 0x69, 0x39, 0x87, 0xca, 0xd3, 0x07,
            0xf6, 0xfb, 0xfd, 0x97, 0xb2, 0xf6,
        ]),
        Erc20Value::new(3_500_000_000_000_000_000_000_000),
    ), // ckSepoliaPEPE
];

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
