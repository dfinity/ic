use super::*;
use crate::erc20::{CkErc20Token, CkTokenSymbol};
use crate::state::automatic_deposits::DepositRequest;
use crate::test_fixtures;
use evm_rpc_types::{ConsensusStrategy, Hex, MultiRpcResult, RpcServices};
use ic_canister_runtime::{IcError, StubRuntime};
use std::str::FromStr;

const DEPOSIT_ADDRESS: Address = Address::new([0x11; 20]);
const TOKEN_A: Address = Address::new([0x22; 20]);
const TOKEN_B: Address = Address::new([0x33; 20]);

fn account(owner: u8) -> Account {
    Account {
        owner: candid::Principal::from_slice(&[owner]),
        subaccount: None,
    }
}

#[test]
fn should_count_candidates_at_and_above_the_per_token_minimum() {
    let (token, min) = MIN_DEPOSITS[0]; // ckUSDC
    let calls = vec![
        BalanceOfCall {
            token,
            holder: DEPOSIT_ADDRESS,
        };
        4
    ];
    let balances = vec![
        min,                                              // == min      -> candidate
        min.checked_sub(Erc20Value::from(1_u8)).unwrap(), // < min      -> excluded
        min.checked_add(Erc20Value::from(1_u8)).unwrap(), // > min      -> candidate
        Erc20Value::from(0_u8),                           // failed/zero -> excluded
    ];

    assert_eq!(count_candidates(&calls, &balances), 2);
}

#[test]
fn should_not_count_candidates_for_an_unsupported_token() {
    // TOKEN_A is absent from MIN_DEPOSITS, so even a huge balance is never a candidate.
    let calls = vec![BalanceOfCall {
        token: TOKEN_A,
        holder: DEPOSIT_ADDRESS,
    }];
    let balances = vec![Erc20Value::from(u128::MAX)];

    assert_eq!(count_candidates(&calls, &balances), 0);
}

#[test]
fn should_build_one_call_per_address_and_token_in_order() {
    let addresses = vec![
        (account(1), DEPOSIT_ADDRESS),
        (account(2), Address::new([0x99; 20])),
    ];
    let tokens = vec![TOKEN_A, TOKEN_B];

    let calls = balance_of_calls(&addresses, &tokens);

    assert_eq!(
        calls,
        vec![
            BalanceOfCall {
                token: TOKEN_A,
                holder: DEPOSIT_ADDRESS
            },
            BalanceOfCall {
                token: TOKEN_B,
                holder: DEPOSIT_ADDRESS
            },
            BalanceOfCall {
                token: TOKEN_A,
                holder: Address::new([0x99; 20])
            },
            BalanceOfCall {
                token: TOKEN_B,
                holder: Address::new([0x99; 20])
            },
        ]
    );
}

#[test]
fn should_build_no_calls_when_no_addresses_or_no_tokens() {
    assert!(balance_of_calls(&[], &[TOKEN_A]).is_empty());
    assert!(balance_of_calls(&[(account(1), DEPOSIT_ADDRESS)], &[]).is_empty());
}

#[test]
fn should_bound_addresses_per_chunk_by_the_batch_cap() {
    assert_eq!(addresses_per_chunk(1), MAX_CALLS_PER_BATCH);
    assert_eq!(addresses_per_chunk(2), MAX_CALLS_PER_BATCH / 2);
    assert_eq!(addresses_per_chunk(MAX_CALLS_PER_BATCH), 1);
    // More tokens than the whole cap still keeps one address per chunk.
    assert_eq!(addresses_per_chunk(MAX_CALLS_PER_BATCH + 1), 1);
    // Defensive against a zero token count.
    assert_eq!(addresses_per_chunk(0), MAX_CALLS_PER_BATCH);
}

#[tokio::test]
async fn should_skip_without_recording_stats_when_latest_block_is_unknown() {
    let now = ts();
    seed_state(
        None,
        Some(MIN_DEPOSITS[0].0),
        &[(account(1), Address::new([0xa1; 20]))],
        now,
    );

    // No stub responses: the scan must short-circuit before any outcall.
    scan(now, stub_client(vec![])).await;

    assert!(read_state(|s| s.last_balance_scan.clone()).is_none());
}

#[tokio::test]
async fn should_skip_without_recording_stats_when_no_tokens_are_supported() {
    let now = ts();
    seed_state(
        Some(BlockNumber::new(1_000)),
        None,
        &[(account(1), Address::new([0xa1; 20]))],
        now,
    );

    scan(now, stub_client(vec![])).await;

    assert!(read_state(|s| s.last_balance_scan.clone()).is_none());
}

#[tokio::test]
async fn should_skip_without_recording_stats_when_no_address_is_due() {
    let now = ts();
    seed_state(
        Some(BlockNumber::new(1_000)),
        Some(MIN_DEPOSITS[0].0),
        &[],
        now,
    );

    scan(now, stub_client(vec![])).await;

    assert!(read_state(|s| s.last_balance_scan.clone()).is_none());
}

#[tokio::test]
async fn should_advance_scanned_addresses_and_count_candidates() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let below_min = min.checked_sub(Erc20Value::from(1_u8)).unwrap();
    let candidate = (account(1), Address::new([0xa1; 20]));
    let non_candidate = (account(2), Address::new([0xa2; 20]));
    seed_state(Some(latest), Some(token), &[candidate, non_candidate], now);

    // Single chunk, holders in call order: first at the minimum (candidate), second below it.
    scan(now, stub_client(vec![ok_balances(&[min, below_min])])).await;

    for (account, _) in [candidate, non_candidate] {
        let entry = live_entry(now, &account);
        assert_eq!(entry.scan_count, 1);
        assert_eq!(entry.last_scanned_block, Some(latest));
    }
    let stats = last_stats();
    assert_eq!(stats.addresses_scanned, 2);
    assert_eq!(stats.candidates_found, 1);
    assert_eq!(stats.chunks_failed, 0);
}

#[tokio::test]
async fn should_split_into_chunks_when_calls_exceed_the_batch_cap() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    // One token, so addresses_per_chunk == MAX_CALLS_PER_BATCH; this many holders spills into a
    // second chunk.
    let extra = 50_usize;
    let holders: Vec<_> = (0..MAX_CALLS_PER_BATCH + extra)
        .map(|i| (account(i as u8), Address::new([i as u8; 20])))
        .collect();
    seed_state(Some(latest), Some(token), &holders, now);

    // Two responses, one per chunk, sized to the chunk's call count; all balances are candidates.
    scan(
        now,
        stub_client(vec![
            ok_balances(&vec![min; MAX_CALLS_PER_BATCH]),
            ok_balances(&vec![min; extra]),
        ]),
    )
    .await;

    let stats = last_stats();
    assert_eq!(stats.addresses_scanned, MAX_CALLS_PER_BATCH + extra);
    assert_eq!(stats.candidates_found, MAX_CALLS_PER_BATCH + extra);
    assert_eq!(stats.chunks_failed, 0);
}

#[tokio::test]
async fn should_not_advance_addresses_when_the_chunk_rpc_call_fails() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let holder = (account(1), Address::new([0xa1; 20]));
    seed_state(Some(latest), Some(MIN_DEPOSITS[0].0), &[holder], now);

    scan(now, stub_client(vec![Err(IcError::CallPerformFailed)])).await;

    let entry = live_entry(now, &holder.0);
    assert_eq!(
        entry.scan_count, 0,
        "a failed chunk must be retried, not advanced"
    );
    assert_eq!(entry.last_scanned_block, None);
    let stats = last_stats();
    assert_eq!(stats.addresses_scanned, 0);
    assert_eq!(stats.chunks_failed, 1);
}

#[tokio::test]
async fn should_not_advance_addresses_when_the_chunk_response_fails_to_decode() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let holder = (account(1), Address::new([0xa1; 20]));
    seed_state(Some(latest), Some(MIN_DEPOSITS[0].0), &[holder], now);

    // A one-call chunk expects a single 32-byte word; five bytes cannot decode.
    let malformed = MultiRpcResult::Consistent(Ok(Hex::from(vec![0_u8; 5])));
    scan(now, stub_client(vec![Ok(malformed)])).await;

    let entry = live_entry(now, &holder.0);
    assert_eq!(entry.scan_count, 0);
    assert_eq!(entry.last_scanned_block, None);
    let stats = last_stats();
    assert_eq!(stats.addresses_scanned, 0);
    assert_eq!(stats.chunks_failed, 1);
}

fn ts() -> Timestamp {
    Timestamp::from_nanos(1_000)
}

fn seed_state(
    latest_block: Option<BlockNumber>,
    token: Option<Address>,
    holders: &[(Account, Address)],
    now: Timestamp,
) {
    let mut state = test_fixtures::initial_state();
    state.latest_block_height = latest_block;
    if let Some(token) = token {
        let network = state.ethereum_network();
        state.record_add_ckerc20_token(CkErc20Token {
            erc20_ethereum_network: network,
            erc20_contract_address: token,
            ckerc20_token_symbol: CkTokenSymbol::from_str("ckUSDC").unwrap(),
            ckerc20_ledger_id: candid::Principal::anonymous(),
        });
    }
    for (account, address) in holders {
        state
            .automatic_deposits
            .watch_address_for_account(now, *account, *address)
            .expect("BUG: failed to arm deposit address");
    }
    test_fixtures::init_state(state);
}

fn stub_client(
    responses: Vec<Result<MultiRpcResult<Hex>, IcError>>,
) -> EvmRpcClient<StubRuntime, CandidResponseConverter, DoubleCycles> {
    let mut runtime = StubRuntime::new();
    for response in responses {
        runtime = match response {
            Ok(result) => runtime.add_stub_response(result),
            Err(error) => runtime.add_stub_error(error),
        };
    }
    EvmRpcClient::builder(runtime, candid::Principal::anonymous())
        .with_rpc_sources(RpcServices::EthMainnet(None))
        .with_consensus_strategy(ConsensusStrategy::Threshold {
            total: Some(4),
            min: 3,
        })
        .with_retry_strategy(DoubleCycles::with_max_num_retries(10))
        .build()
}

fn ok_balances(balances: &[Erc20Value]) -> Result<MultiRpcResult<Hex>, IcError> {
    let blob: Vec<u8> = balances.iter().flat_map(|b| b.to_be_bytes()).collect();
    Ok(MultiRpcResult::Consistent(Ok(Hex::from(blob))))
}

fn live_entry(now: Timestamp, account: &Account) -> DepositRequest {
    read_state(|s| s.automatic_deposits.get_entry(now, account).cloned())
        .expect("BUG: expected a live watchlist entry")
        .value
}

fn last_stats() -> BalanceScanStats {
    read_state(|s| s.last_balance_scan.clone()).expect("BUG: expected balance scan stats")
}
