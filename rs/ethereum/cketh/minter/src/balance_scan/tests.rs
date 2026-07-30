use super::*;
use crate::erc20::{CkErc20Token, CkTokenSymbol};
use crate::state::automatic_deposits::DepositRequest;
use crate::test_fixtures;
use evm_rpc_types::{ConsensusStrategy, Hex, MultiRpcResult, RpcServices};
use ic_canister_runtime::{IcError, StubRuntime};
use std::collections::BTreeSet;
use std::str::FromStr;

const DEPOSIT_ADDRESS: Address = Address::new([0x11; 20]);
const TOKEN_A: Address = Address::new([0x22; 20]);
const TOKEN_B: Address = Address::new([0x33; 20]);

fn account(owner: u64) -> Account {
    Account {
        owner: candid::Principal::from_slice(&owner.to_be_bytes()),
        subaccount: None,
    }
}

#[test]
fn should_collect_candidates_at_and_above_the_per_token_minimum() {
    let (usdc, usdc_min) = MIN_DEPOSITS[0]; // min 10_000_000
    let (link, link_min) = MIN_DEPOSITS[1]; // min 1e18
    let tokens = vec![usdc, link];
    let addresses = vec![
        (account(1), Address::new([0xa1; 20])),
        (account(2), Address::new([0xa2; 20])),
    ];
    let holders: Vec<Address> = addresses.iter().map(|(_, holder)| *holder).collect();
    let batch = ScanBatch {
        addresses: &addresses,
        calls: balance_of_calls(&holders, &tokens),
    };

    struct Case {
        desc: &'static str,
        // One balance per call, holder-major/token-minor:
        // [a1/usdc, a1/link, a2/usdc, a2/link].
        balances: Vec<Erc20Value>,
        expected: Vec<(Account, Address, Erc20Value)>,
    }

    let cases = vec![
        Case {
            desc: "at, above, and below/zero the minimum across two addresses and tokens",
            balances: vec![
                usdc_min,                                       // a1/usdc == min -> candidate
                link_min.checked_add(Erc20Value::ONE).unwrap(), // a1/link > min -> candidate
                usdc_min.checked_add(Erc20Value::ONE).unwrap(), // a2/usdc > min -> candidate
                link_min,                                       // a2/link == min -> candidate
            ],
            expected: vec![
                (account(1), usdc, usdc_min),
                (
                    account(1),
                    link,
                    link_min.checked_add(Erc20Value::ONE).unwrap(),
                ),
                (
                    account(2),
                    usdc,
                    usdc_min.checked_add(Erc20Value::ONE).unwrap(),
                ),
                (account(2), link, link_min),
            ],
        },
        Case {
            // Only the second address' ckUSDC clears its minimum; a wrong holder index would
            // wrongly attribute it to account(1).
            desc: "single surviving candidate is attributed to the right address",
            balances: vec![
                usdc_min.checked_sub(Erc20Value::ONE).unwrap(), // a1/usdc < min -> excluded
                Erc20Value::ZERO,                               // a1/link zero  -> excluded
                usdc_min,                                       // a2/usdc == min -> candidate
                link_min.checked_sub(Erc20Value::ONE).unwrap(), // a2/link < min -> excluded
            ],
            expected: vec![(account(2), usdc, usdc_min)],
        },
    ];

    for case in cases {
        let collected: Vec<(Account, Address, Erc20Value)> =
            collect_candidates(&batch, &tokens, &case.balances)
                .into_iter()
                .map(|c| (c.account, c.token, c.balance))
                .collect();
        assert_eq!(collected, case.expected, "case: {}", case.desc);
    }
}

#[test]
fn should_not_collect_candidates_for_an_unsupported_token() {
    // TOKEN_A is absent from MIN_DEPOSITS, so even a huge balance is never a candidate.
    let addresses = vec![(account(1), DEPOSIT_ADDRESS)];
    let tokens = vec![TOKEN_A];
    let batch = ScanBatch {
        addresses: &addresses,
        calls: balance_of_calls(&[DEPOSIT_ADDRESS], &tokens),
    };
    let balances = vec![Erc20Value::from(u128::MAX)];

    assert!(collect_candidates(&batch, &tokens, &balances).is_empty());
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

#[test]
fn should_build_one_call_per_address_and_token_in_order() {
    let holders = vec![DEPOSIT_ADDRESS, Address::new([0x99; 20])];
    let tokens = vec![TOKEN_A, TOKEN_B];

    let calls = balance_of_calls(&holders, &tokens);

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
    assert!(balance_of_calls(&[DEPOSIT_ADDRESS], &[]).is_empty());
}

#[test]
fn should_never_split_an_address_across_batches() {
    // Scan-state is tracked per address, not per (address, token): `record_scan` advances a whole
    // address once its batch succeeds. `plan_batches` must therefore keep every `balanceOf` for an
    // address in the same batch — otherwise a failing batch could advance an address whose balances
    // were only partially read — even when a single address's token calls alone exceed the cap.
    fn address_at(index: u64) -> Address {
        let mut bytes = [0_u8; 20];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        Address::new(bytes)
    }

    let addresses: Vec<(Account, Address)> = (0..5)
        .map(|i| (account(i), address_at(1_000 + i)))
        .collect();

    for num_tokens in [1, 2, 7, MAX_CALLS_PER_BATCH, MAX_CALLS_PER_BATCH + 1] {
        let tokens: Vec<Address> = (0..num_tokens as u64).map(address_at).collect();

        let batches = plan_batches(&addresses, &tokens);

        let mut seen: BTreeSet<Address> = BTreeSet::new();
        for batch in &batches {
            let batch_holders: Vec<Address> = batch.addresses.iter().map(|(_, h)| *h).collect();
            for holder in &batch_holders {
                // Batches never intersect: an address belongs to exactly one batch.
                assert!(
                    !seen.contains(holder),
                    "num_tokens={num_tokens}: address {holder:?} appears in more than one batch"
                );
                // The batch queries every token for the address, and only for its own addresses.
                let queried: Vec<Address> = batch
                    .calls
                    .iter()
                    .filter(|call| call.holder == *holder)
                    .map(|call| call.token)
                    .collect();
                assert_eq!(
                    queried, tokens,
                    "num_tokens={num_tokens}: address {holder:?} is not fully covered by its batch"
                );
            }
            assert!(
                batch
                    .calls
                    .iter()
                    .all(|call| batch_holders.contains(&call.holder)),
                "num_tokens={num_tokens}: batch issues a call for an address outside it"
            );
            seen.extend(batch_holders);
        }
        assert_eq!(
            seen.len(),
            addresses.len(),
            "num_tokens={num_tokens}: every address must be scanned in exactly one batch"
        );
    }
}

#[tokio::test]
async fn should_skip_without_scanning() {
    struct Case {
        name: &'static str,
        latest_block: Option<BlockNumber>,
        token: Option<Address>,
        holders: Vec<(Account, Address)>,
    }

    let holder = (account(1), Address::new([0xa1; 20]));
    let cases = vec![
        Case {
            name: "latest block height unknown",
            latest_block: None,
            token: Some(MIN_DEPOSITS[0].0),
            holders: vec![holder],
        },
        Case {
            name: "no supported tokens",
            latest_block: Some(BlockNumber::new(1_000)),
            token: None,
            holders: vec![holder],
        },
        Case {
            name: "no address due for a scan",
            latest_block: Some(BlockNumber::new(1_000)),
            token: Some(MIN_DEPOSITS[0].0),
            holders: vec![],
        },
    ];

    for case in cases {
        let now = ts();
        seed_state(case.latest_block, case.token, &case.holders, now);

        // No stub responses: the scan must short-circuit before any outcall.
        scan(now, stub_client(vec![])).await;

        // A skipped scan advances no watchlist entry.
        for (account, _) in &case.holders {
            let entry = live_entry(now, account);
            assert_eq!(entry.scan_count, 0, "case: {}", case.name);
            assert_eq!(entry.last_scanned_block, None, "case: {}", case.name);
        }
    }
}

#[test]
fn should_build_one_automatic_deposit_per_candidate_token() {
    let now = ts();
    let block = BlockNumber::new(900);
    let address = Address::new([0xa1; 20]);
    let acc = account(1);
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_address_for_account(now, acc, address)
        .unwrap();
    // Two prior scans, so the finding scan is the third (moved scan_count = 2 + 1 = 3).
    deposits.record_scan(now, &acc, BlockNumber::new(400));
    deposits.record_scan(now, &acc, BlockNumber::new(500));

    let moves = automatic_deposits_received(
        &deposits,
        now,
        &acc,
        block,
        &[
            (TOKEN_A, Erc20Value::from(10_u8)),
            (TOKEN_B, Erc20Value::from(20_u8)),
        ],
    );

    // One move per token, each carrying the watchlist address, the finding block, scan_count = 3,
    // and its own balance.
    assert_eq!(
        moves,
        vec![
            AutomaticDeposit {
                owner: acc.owner,
                subaccount: acc.subaccount,
                token: TOKEN_A,
                address,
                last_scanned_block: block,
                scan_count: 3,
                scanned_balance: Erc20Value::from(10_u8),
            },
            AutomaticDeposit {
                owner: acc.owner,
                subaccount: acc.subaccount,
                token: TOKEN_B,
                address,
                last_scanned_block: block,
                scan_count: 3,
                scanned_balance: Erc20Value::from(20_u8),
            },
        ]
    );

    // No live watchlist entry -> nothing to move.
    assert!(
        automatic_deposits_received(
            &deposits,
            now,
            &account(999),
            block,
            &[(TOKEN_A, Erc20Value::from(1_u8))]
        )
        .is_empty()
    );
}

#[tokio::test]
async fn should_advance_scanned_non_candidate_addresses() {
    let now = ts();
    let latest = BlockNumber::new(1_000);
    let (token, min) = MIN_DEPOSITS[0];
    let below_min = min.checked_sub(Erc20Value::from(1_u8)).unwrap();
    let a = (account(1), Address::new([0xa1; 20]));
    let b = (account(2), Address::new([0xa2; 20]));
    seed_state(Some(latest), Some(token), &[a, b], now);

    // Both balances are below the minimum, so neither is a candidate: they advance the schedule
    // and nothing is moved to the sweep queue.
    scan(now, stub_client(vec![ok_balances(&[below_min, below_min])])).await;

    for (account, _) in [a, b] {
        let entry = live_entry(now, &account);
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
    // One token, so addresses_per_chunk == MAX_CALLS_PER_BATCH; this many holders spills into a
    // second chunk.
    let extra = 50_usize;
    let holders: Vec<_> = (0..MAX_CALLS_PER_BATCH + extra)
        .map(|i| {
            let i = i as u64;
            let mut address = [0_u8; 20];
            address[..8].copy_from_slice(&i.to_be_bytes());
            (account(i), Address::new(address))
        })
        .collect();
    seed_state(Some(latest), Some(token), &holders, now);

    // Two responses, one per chunk, sized to the chunk's call count. Below-min balances so the
    // whole set advances (no sweep events), letting the test assert the chunk split directly.
    scan(
        now,
        stub_client(vec![
            ok_balances(&vec![below_min; MAX_CALLS_PER_BATCH]),
            ok_balances(&vec![below_min; extra]),
        ]),
    )
    .await;

    // Both chunks succeeded, so every address across the split is advanced. Check the boundary
    // holders of each chunk (first/last of chunk 1, first/last of chunk 2).
    for i in [
        0,
        MAX_CALLS_PER_BATCH - 1,
        MAX_CALLS_PER_BATCH,
        MAX_CALLS_PER_BATCH + extra - 1,
    ] {
        let entry = live_entry(now, &holders[i].0);
        assert_eq!(entry.scan_count, 1, "holder {i} must be advanced");
        assert_eq!(entry.last_scanned_block, Some(latest), "holder {i}");
    }
}

#[tokio::test]
async fn should_not_advance_addresses_when_the_chunk_fails() {
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
        let holder = (account(1), Address::new([0xa1; 20]));
        seed_state(Some(latest), Some(MIN_DEPOSITS[0].0), &[holder], now);

        scan(now, stub_client(vec![case.response])).await;

        let entry = live_entry(now, &holder.0);
        assert_eq!(
            entry.scan_count, 0,
            "case '{}': a failed chunk must be retried, not advanced",
            case.name
        );
        assert_eq!(entry.last_scanned_block, None, "case: {}", case.name);
    }
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
