pub mod batcher;

#[cfg(test)]
mod tests;

use crate::eth_rpc_client::{AnyOf, MIN_ATTACHED_CYCLES, ToReducedWithStrategy, rpc_client};
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::audit::process_event;
use crate::state::automatic_deposits::{AutomaticDeposits, DepositAccount};
use crate::state::event::{AutomaticDeposit, EventType};
use crate::state::{TaskType, mutate_state, read_state};
use crate::timed_sized_map::Timestamp;
use batcher::BalanceOfCall;
use evm_rpc_client::{CandidResponseConverter, DoubleCycles, EvmRpcClient};
use ic_canister_log::log;
use ic_canister_runtime::Runtime;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

/// Maximum number of `balanceOf` sub-calls in a single deployless-batcher `eth_call`.
///
/// The batch runs as one create-style `eth_call`, so the ceiling is the provider's `eth_call` gas
/// cap (commonly 50M — geth's `--rpc.gascap` default). A `debug_traceCall` of an 8-call batch
/// against proxied stablecoins (ckUSDC + ckUSDT, the priciest shape: `STATICCALL` → proxy `SLOAD`
/// → `DELEGATECALL` → balance `SLOAD`) used 153_452 gas, i.e. ~19k gas/call. The create/init-code
/// overhead is negligible and no code-deposit gas is charged for the returned data, so essentially
/// all of it is the `balanceOf`s. At that worst-case rate 1_000 calls ≈ 19M gas, ~2.6x under a 50M
/// cap. Payloads stay small — 64 bytes of calldata and 32 bytes of return per call, so 1_000 calls
/// is ~64 KiB in / ~32 KiB out, far below the 2 MiB HTTPS-outcall limit.
///
/// Not set arbitrarily high: a batch advances all-or-nothing (see [`balance_scan`]), so a
/// whole-call failure re-does the entire chunk on the next tick — and a batch that ever exceeds a
/// provider's gas cap fails *every* time, permanently stalling its addresses. 1_000 keeps a
/// comfortable margin against that for the current token set; re-measure (and lower if needed) if
/// the supported tokens grow or skew more gas-heavy.
const MAX_CALLS_PER_BATCH: usize = 1_000;

pub async fn balance_scan() {
    let now = Timestamp::from_nanos(ic_cdk::api::time());
    // TODO DEFI-2923: use a lower threshold rpc client, e.g. 2-out-of-3 since we use latest block height
    // and only to notify the sweeper (no minting)
    let client = read_state(rpc_client);
    scan(now, client).await;
}

async fn scan<R: Runtime>(
    now: Timestamp,
    client: EvmRpcClient<R, CandidResponseConverter, DoubleCycles>,
) {
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

    let mut candidates_by_account: BTreeMap<Account, Vec<(Address, Erc20Value)>> = BTreeMap::new();
    let mut decode_errors = 0_usize;
    let mut call_errors = 0_usize;
    let mut scanned: Vec<Account> = Vec::new();

    for batch in plan_batches(&addresses_to_scan, &erc20_tokens) {
        let input = batcher::encode_balance_batch(&batch.calls);
        match client
            .call(call_args(input, latest_block))
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(AnyOf)
        {
            Ok(hex) => match batcher::decode_balance_batch(hex.as_ref(), batch.calls.len()) {
                Ok(balances) => {
                    for candidate in collect_candidates(&batch, &erc20_tokens, &balances) {
                        candidates_by_account
                            .entry(candidate.account)
                            .or_default()
                            .push((candidate.token, candidate.balance));
                    }
                    scanned.extend(batch.addresses.iter().map(|da| da.account));
                }
                Err(e) => {
                    decode_errors += 1;
                    log!(INFO, "balance scan decode error: {e:?}");
                }
            },
            Err(e) => {
                call_errors += 1;
                log!(INFO, "balance scan eth_call error: {e:?}");
            }
        }
    }

    let candidates_found: usize = candidates_by_account.values().map(Vec::len).sum();

    // Advance only the addresses actually scanned, so a failed chunk is retried next tick rather
    // than silently skipped until its next scheduled slot. A funded address is event-sourced into
    // the sweep queue (durable the moment funds are detected) instead of being advanced, so it is
    // no longer re-scanned.
    let addresses_scanned = scanned.len();
    mutate_state(|s| {
        for account in &scanned {
            match candidates_by_account.get(account) {
                Some(cands) => {
                    for deposit in automatic_deposits_received(
                        &s.automatic_deposits,
                        now,
                        account,
                        latest_block,
                        cands,
                    ) {
                        process_event(s, EventType::AutomaticDepositReceived(deposit));
                    }
                }
                None => s.automatic_deposits.record_scan(now, account, latest_block),
            }
        }
    });

    log!(
        INFO,
        "[balance_scan]: scanned {addresses_scanned} addresses, found {candidates_found} candidate(s), {decode_errors} decode error(s), {call_errors} call error(s)",
    );
}

/// One balance-scan batch: the [`DepositAccount`]s whose balances are read together in a single
/// `eth_call`, and the flat `(token, holder)` calls for exactly those addresses.
struct ScanBatch<'a> {
    addresses: &'a [DepositAccount],
    calls: Vec<BalanceOfCall>,
}

/// Split the due addresses into `eth_call`-sized batches, chunking *by address* so an address'
/// per-token calls never straddle a batch boundary. This keeps the per-address scan-state advance
/// all-or-nothing per batch: were an address split, a failing batch could advance it with only
/// part of its balances read. The supported token set is a handful (far below
/// `MAX_CALLS_PER_BATCH`), so a batch holds many addresses; if the set ever grew past the cap, a
/// single address' calls would still be sent together (the batcher response is only 32 bytes per
/// call, so an oversized batch stays cheap).
fn plan_batches<'a>(addresses: &'a [DepositAccount], tokens: &[Address]) -> Vec<ScanBatch<'a>> {
    addresses
        .chunks(addresses_per_chunk(tokens.len()))
        .map(|chunk| {
            let holders: Vec<Address> = chunk.iter().map(|da| da.address).collect();
            ScanBatch {
                addresses: chunk,
                calls: balance_of_calls(&holders, tokens),
            }
        })
        .collect()
}

/// How many deposit addresses fit in one `MAX_CALLS_PER_BATCH`-bounded batch, given the number of
/// supported tokens (one `balanceOf` sub-call per address-token pair). At least one address per
/// batch even if the token set alone exceeds the cap.
fn addresses_per_chunk(num_tokens: usize) -> usize {
    (MAX_CALLS_PER_BATCH / num_tokens.max(1)).max(1)
}

fn balance_of_calls(holders: &[Address], tokens: &[Address]) -> Vec<BalanceOfCall> {
    let mut calls = Vec::with_capacity(holders.len() * tokens.len());
    for holder in holders {
        for token in tokens {
            calls.push(BalanceOfCall {
                token: *token,
                holder: *holder,
            });
        }
    }
    calls
}

/// A scanned `(account, token)` whose balance is at or above the token's minimum deposit.
struct Candidate {
    account: Account,
    token: Address,
    balance: Erc20Value,
}

/// Collect the candidates from one scanned batch. `balances` is aligned with `batch.calls`, which
/// are laid out holder-major/token-minor by [`balance_of_calls`], so call index `i` maps to holder
/// `i / tokens.len()` (its account) and `batch.calls[i].token` (its token). Keeps a candidate iff
/// its balance is at or above the token's minimum deposit.
fn collect_candidates(
    batch: &ScanBatch,
    tokens: &[Address],
    balances: &[Erc20Value],
) -> Vec<Candidate> {
    batch
        .calls
        .iter()
        .zip(balances)
        .enumerate()
        .filter(|(_, (call, balance))| **balance >= min_deposit(&call.token))
        .map(|(i, (call, balance))| Candidate {
            account: batch.addresses[i / tokens.len()].account,
            token: call.token,
            balance: *balance,
        })
        .collect()
}

/// Build one [`AutomaticDeposit`] per candidate `(token, balance)` for a scanned, funded `account`,
/// reading the address and scan count from its watchlist entry (the recorded `scan_count` counts
/// this finding scan). Empty if the account is no longer live as of `now`. All of the account's
/// deposits are built here, before any is recorded, since recording the first removes the watchlist
/// entry.
fn automatic_deposits_received(
    deposits: &AutomaticDeposits,
    now: Timestamp,
    account: &Account,
    block: BlockNumber,
    candidates: &[(Address, Erc20Value)],
) -> Vec<AutomaticDeposit> {
    let Some(entry) = deposits.get_entry(now, account) else {
        return Vec::new();
    };
    let address = entry.value.address;
    let scan_count = entry.value.scan_count.saturating_add(1);
    candidates
        .iter()
        .map(|(token, balance)| AutomaticDeposit {
            owner: account.owner,
            subaccount: account.subaccount,
            token: *token,
            address,
            last_scanned_block: block,
            scan_count,
            scanned_balance: *balance,
        })
        .collect()
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
