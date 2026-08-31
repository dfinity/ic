use super::*;
use crate::deposit_address::DepositAddress;
use crate::state::automatic_deposits::{DepositRequest, ScanProgress};
use crate::test_fixtures;
use crate::test_fixtures::mock::MockTimeProvider;
use evm_rpc_types::{ConsensusStrategy, Hex, MultiRpcResult, RpcServices};
use ic_canister_runtime::{IcError, StubRuntime};
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;

const TOKEN_A: Address = Address::new([0x22; 20]);

fn account(owner: u64) -> Account {
    Account {
        owner: candid::Principal::from_slice(&owner.to_be_bytes()),
        subaccount: None,
    }
}

#[test]
fn unsupported_token_has_an_unreachable_minimum_deposit() {
    // A token absent from MIN_DEPOSITS gets Erc20Value::MAX as its threshold, so no real balance
    // (below the u256 max) ever clears it and it is never a candidate.
    assert_eq!(min_deposit(&TOKEN_A), Erc20Value::MAX);
    assert!(Erc20Value::from(u128::MAX) < min_deposit(&TOKEN_A));
}

#[test]
fn should_have_a_min_deposit_for_every_deployed_supported_token() {
    // Independently transcribed list of the ckERC20 contract addresses the mainnet
    // (sv3dd-oaaaa-aaaar-qacoa-cai) and Sepolia (jzenf-aiaaa-aaaar-qaa7q-cai) minters currently
    // support (hex form, so it does not share the byte-array representation of `MIN_DEPOSITS`). A
    // supported token missing from `MIN_DEPOSITS` would be scanned but never flagged, so its
    // deposits would go undetected; this test catches a dropped or typo'd entry.
    let deployed: &[(&str, &str)] = &[
        // --- mainnet ---
        ("ckUSDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        ("ckLINK", "0x514910771AF9Ca656af840dff83E8264EcF986CA"),
        ("ckPEPE", "0x6982508145454Ce325dDbE47a25d4ec3d2311933"),
        ("ckOCT", "0xF5cFBC74057C610c8EF151A439252680AC68c6dc"),
        ("ckSHIB", "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"),
        ("ckWBTC", "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"),
        ("ckUSDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
        ("ckWSTETH", "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
        ("ckUNI", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"),
        ("ckEURC", "0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c"),
        ("ckXAUT", "0x68749665FF8D2d112Fa859AA293F07A622782F38"),
        // --- sepolia ---
        (
            "ckSepoliaUSDC",
            "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        ),
        (
            "ckSepoliaLINK",
            "0x779877A7B0D9E8603169DdbD7836e478b4624789",
        ),
        (
            "ckSepoliaPEPE",
            "0x560ef9f39e4b08f9693987cad307f6fbfd97b2f6",
        ),
    ];

    for (symbol, address) in deployed {
        let contract = Address::from_str(address)
            .unwrap_or_else(|e| panic!("{symbol}: invalid test address {address}: {e}"));
        assert!(
            MIN_DEPOSITS.iter().any(|(c, _)| *c == contract),
            "{symbol} ({address}) has no MIN_DEPOSITS entry"
        );
    }
}

#[tokio::test]
async fn should_skip_without_scanning() {
    struct Case {
        name: &'static str,
        latest_block: Option<BlockNumber>,
        holders: Vec<(Account, DepositAddress)>,
    }

    let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    let cases = vec![
        Case {
            name: "latest block height unknown",
            latest_block: None,
            holders: vec![holder],
        },
        Case {
            name: "no pair due for a scan",
            latest_block: Some(BlockNumber::new(1_000)),
            holders: vec![],
        },
    ];

    for case in cases {
        let now = ts();
        seed_state(case.latest_block, MIN_DEPOSITS[0].0, &case.holders, now);

        // No stub responses: the scan must short-circuit before any outcall.
        scan(now, stub_client(vec![]), &records_no_event()).await;

        // A skipped scan advances no watchlist entry.
        for (account, _) in &case.holders {
            let entry = live_entry(now, account, MIN_DEPOSITS[0].0);
            assert_eq!(entry.scan_count, 0, "case: {}", case.name);
            assert_eq!(entry.last_scanned_block, None, "case: {}", case.name);
        }
    }
}

#[tokio::test]
async fn should_advance_scanned_non_candidate_pairs() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let below_min = min.checked_sub(Erc20Value::from(1_u8)).unwrap();
    let a = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    let b = (account(2), DepositAddress::new(Address::new([0xa2; 20])));
    seed_state(Some(latest), token, &[a, b], now);

    // Both balances are below the minimum, so neither is a candidate: they advance the schedule
    // and nothing is moved to the sweep queue.
    scan(
        now,
        stub_client(vec![ok_balances(&[below_min, below_min])]),
        &records_no_event(),
    )
    .await;

    for (account, _) in [a, b] {
        let entry = live_entry(now, &account, token);
        assert_eq!(entry.scan_count, 1);
        assert_eq!(entry.last_scanned_block, Some(latest));
    }
    assert_eq!(read_state(|s| s.automatic_deposits.sweep_len()), 0);
}

#[tokio::test]
async fn should_split_into_chunks_when_calls_exceed_the_batch_cap() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let below_min = min.checked_sub(Erc20Value::from(1_u8)).unwrap();
    // Each pair is one call, so a batch holds up to MAX_CALLS_PER_BATCH pairs; this many holders
    // spills into a second chunk.
    let extra = 50_usize;
    let holders: Vec<_> = (0..MAX_CALLS_PER_BATCH + extra)
        .map(|i| {
            let i = i as u64;
            let mut address = [0_u8; 20];
            address[..8].copy_from_slice(&i.to_be_bytes());
            (account(i), DepositAddress::new(Address::new(address)))
        })
        .collect();
    seed_state(Some(latest), token, &holders, now);

    // Two responses, one per chunk, sized to the chunk's call count. Below-min balances so the
    // whole set advances (no sweep events), letting the test assert the chunk split directly.
    scan(
        now,
        stub_client(vec![
            ok_balances(&vec![below_min; MAX_CALLS_PER_BATCH]),
            ok_balances(&vec![below_min; extra]),
        ]),
        &records_no_event(),
    )
    .await;

    // Both chunks succeeded, so every pair across the split is advanced. Check the boundary holders
    // of each chunk (first/last of chunk 1, first/last of chunk 2).
    for i in [
        0,
        MAX_CALLS_PER_BATCH - 1,
        MAX_CALLS_PER_BATCH,
        MAX_CALLS_PER_BATCH + extra - 1,
    ] {
        let entry = live_entry(now, &holders[i].0, token);
        assert_eq!(entry.scan_count, 1, "holder {i} must be advanced");
        assert_eq!(entry.last_scanned_block, Some(latest), "holder {i}");
    }
}

#[tokio::test]
async fn should_not_advance_pairs_when_the_chunk_fails() {
    struct Case {
        name: &'static str,
        response: Result<MultiRpcResult<Hex>, IcError>,
    }

    let cases = vec![
        Case {
            name: "rpc call fails",
            response: Err(IcError::CallPerformFailed),
        },
        Case {
            // A one-call chunk expects a single 32-byte word; five bytes cannot decode.
            name: "response fails to decode",
            response: Ok(MultiRpcResult::Consistent(Ok(Hex::from(vec![0_u8; 5])))),
        },
    ];

    for case in cases {
        let now = ts();
        let latest = BlockNumber::new(1_000);
        let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
        seed_state(Some(latest), MIN_DEPOSITS[0].0, &[holder], now);

        scan(now, stub_client(vec![case.response]), &records_no_event()).await;

        let entry = live_entry(now, &holder.0, MIN_DEPOSITS[0].0);
        assert_eq!(
            entry.scan_count, 0,
            "case '{}': a failed chunk must be retried, not advanced",
            case.name
        );
        assert_eq!(entry.last_scanned_block, None, "case: {}", case.name);
    }
}

#[tokio::test]
async fn should_detect_a_funded_pair_from_pre_scan_targets_even_after_eviction() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    seed_state(Some(latest), token, &[holder], now);

    // Capture the due targets, then wipe the watchlist — as a concurrent arming/expiry could evict
    // between reading the targets and applying the scan's outcome.
    let targets = due_targets(now, latest);
    seed_state(Some(latest), token, &[], now);

    // The funded pair is still detected: scan_balances works off the captured targets alone, so the
    // detection is never lost to a mid-scan eviction.
    let outcomes = scan_balances(&targets, latest, stub_client(vec![ok_balances(&[min])])).await;

    assert_eq!(
        outcomes,
        vec![ScanOutcome::Detected(AutomaticDeposit {
            owner: holder.0.owner,
            subaccount: holder.0.subaccount,
            address: holder.1,
            erc20_contract_address: token,
            last_scanned_block: latest,
            scan_count: 1,
            scanned_balance: min,
        })]
    );
}

#[tokio::test]
async fn should_yield_nothing_found_for_a_below_minimum_pair() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let below = min.checked_sub(Erc20Value::from(1_u8)).unwrap();
    let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    seed_state(Some(latest), token, &[holder], now);

    let targets = due_targets(now, latest);
    let outcomes = scan_balances(&targets, latest, stub_client(vec![ok_balances(&[below])])).await;

    assert_eq!(
        outcomes,
        vec![ScanOutcome::NothingFound(DepositRequest::new(
            holder.0, token
        ))]
    );
}

#[tokio::test]
async fn should_yield_no_outcome_for_a_pair_whose_chunk_failed() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    seed_state(Some(latest), MIN_DEPOSITS[0].0, &[holder], now);

    let targets = due_targets(now, latest);
    let outcomes = scan_balances(
        &targets,
        latest,
        stub_client(vec![Err(IcError::CallPerformFailed)]),
    )
    .await;

    assert!(outcomes.is_empty(), "a failed chunk must yield no outcome");
}

fn due_targets(now: Timestamp, latest: BlockNumber) -> Vec<ScanTarget> {
    read_state(|s| {
        s.automatic_deposits
            .scan_targets_iter(now, latest)
            .collect()
    })
}

#[tokio::test]
async fn should_timestamp_a_detected_deposit_with_the_current_time() {
    const DETECTED_AT_NANOS: u64 = 1_620_328_630_000_000_000;
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let holder = (account(1), DepositAddress::new(Address::new([0xa1; 20])));
    seed_state(Some(latest), token, &[holder], now);
    let mut time_provider = MockTimeProvider::new();
    time_provider
        .expect_time()
        .times(1)
        .return_const(DETECTED_AT_NANOS);

    scan(now, stub_client(vec![ok_balances(&[min])]), &time_provider).await;

    let recorded = last_recorded_event().expect("the detected deposit should be recorded");
    assert_eq!(recorded.timestamp, DETECTED_AT_NANOS);
}

fn last_recorded_event() -> Option<crate::state::event::Event> {
    crate::storage::with_event_iter(|events| events.last())
}

/// A [`TimeProvider`] for scans that must not record any event: it has no expectation, so
/// reading the time at all fails the test.
fn records_no_event() -> MockTimeProvider {
    MockTimeProvider::new()
}

fn ts() -> Timestamp {
    Timestamp::from_nanos(1_000)
}

fn seed_state(
    latest_block: Option<BlockNumber>,
    token: Address,
    holders: &[(Account, DepositAddress)],
    now: Timestamp,
) {
    let mut state = test_fixtures::initial_state();
    state.latest_block_height = latest_block;
    for (account, address) in holders {
        state
            .automatic_deposits
            .watch_deposit(now, *account, token, *address)
            .expect("BUG: failed to arm deposit");
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

fn live_entry(now: Timestamp, account: &Account, token: Address) -> ScanProgress {
    read_state(|s| {
        s.automatic_deposits
            .get_entry(now, &DepositRequest::new(*account, token))
            .cloned()
    })
    .expect("BUG: expected a live watchlist entry")
    .value
}
