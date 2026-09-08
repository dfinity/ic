use super::{
    AppliedBy, AutomaticDeposits, DEPOSIT_ADDRESS_SCAN_WINDOW, Delegation, DepositRequest,
    DepositStage, DepositStatusInfo, MAX_ACTIVE_DEPOSITS, MAX_ASSETS_PER_ACCOUNT,
    RegisterDepositError, SCAN_GAP_SECS, SECS_PER_BLOCK, ScanProgress, SweepEntry, SweepTarget,
};
use crate::asset::Asset;
use crate::deposit_address::DepositAddress;
use crate::eth_rpc_client::responses::TransactionStatus;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, Erc20Value, TransactionNonce};
use crate::state::State;
use crate::state::audit::{EventType, apply_state_transition, process_event};
use crate::state::event::{AutomaticDeposit, DepositAddressRegistration, DepositAddressRegistry};
use crate::state::transactions::{AuthorizedSweepItem, SweepId, SweepRequest, sweep_gas_limit};
use crate::storage::with_event_iter;
use crate::sweeper_contract::SweepItem;
use crate::test_fixtures::mock::MockTimeProvider;
use crate::test_fixtures::{
    deposit_address, deposits_with_enqueued_sweep, gas_fee_estimate, initial_state,
    prepay_sweep_gas, state_with_enqueued_sweep, sweep_pipeline_events, sweep_pipeline_outcome,
    sweeper_contract, transaction_signature, usdc, usdt,
};
use crate::timed_sized_map::{Entry, Timestamp};
use crate::tx::{AuthorizationRequest, SignedAuthorization};
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

/// A delegate other than the sweeper contract every fixture sweep names, for the tests that rotate
/// an account onto a second one. Sorts before the incumbent, so a test reading the delegation off
/// the last key rather than off the highest nonce fails.
const ANOTHER_DELEGATE: Address = Address::new([0x1e; 20]);

#[test]
fn should_watch_a_pair_for_the_scan_window() {
    struct Case {
        name: &'static str,
        arms: Vec<(Timestamp, Account, Address)>,
        expected: Result<Entry<ScanProgress>, RegisterDepositError>,
        live_lookups: Vec<(Account, Address)>,
        expected_len: usize,
    }

    let cases = vec![
        Case {
            name: "arms a fresh pair for the scan window",
            arms: vec![(ts(1_000), account(0), usdc())],
            expected: Ok(entry(&account(0), ts(1_000 + window_nanos()))),
            live_lookups: vec![(account(0), usdc())],
            expected_len: 1,
        },
        Case {
            name: "returns the stored entry without re-arming on re-registration",
            arms: vec![(ts(0), account(0), usdc()), (ts(1_000), account(0), usdc())],
            expected: Ok(entry(&account(0), ts(window_nanos()))),
            live_lookups: vec![(account(0), usdc())],
            expected_len: 1,
        },
        Case {
            name: "treats missing and all-zero subaccount as the same account",
            arms: vec![
                (ts(0), account_with(None), usdc()),
                (ts(1_000), account_with(Some([0_u8; 32])), usdc()),
            ],
            expected: Ok(entry(&account_with(None), ts(window_nanos()))),
            live_lookups: vec![
                (account_with(None), usdc()),
                (account_with(Some([0_u8; 32])), usdc()),
            ],
            expected_len: 1,
        },
    ];

    for case in cases {
        let mut deposits = AutomaticDeposits::default();
        for (now, account, token) in &case.arms {
            let outcome = deposits.watch_deposit(
                *now,
                *account,
                Asset::Erc20(*token),
                deposit_address(account),
            );
            assert_eq!(outcome, case.expected, "case: {}", case.name);
        }

        assert_eq!(
            deposits.watchlist_snapshot().registrations.len(),
            case.expected_len,
            "case: {}",
            case.name
        );
        for (account, token) in &case.live_lookups {
            assert_eq!(
                deposits.get_entry(ts(0), &request(*account, *token)),
                case.expected.as_ref().ok(),
                "case: {}",
                case.name
            );
        }
    }
}

#[test]
fn should_treat_the_same_account_with_different_tokens_as_distinct_pairs() {
    let mut deposits = AutomaticDeposits::default();
    let a = account(0);
    deposits
        .watch_deposit(ts(0), a, Asset::Erc20(usdc()), deposit_address(&a))
        .unwrap();
    deposits
        .watch_deposit(ts(0), a, Asset::Erc20(usdt()), deposit_address(&a))
        .unwrap();

    assert_eq!(deposits.watchlist_len(), 2);
    assert!(deposits.get_entry(ts(0), &request(a, usdc())).is_some());
    assert!(deposits.get_entry(ts(0), &request(a, usdt())).is_some());
    // Both pairs share the one deposit address derived for the account.
    assert_eq!(
        deposits
            .get_entry(ts(0), &request(a, usdc()))
            .unwrap()
            .value
            .address,
        deposits
            .get_entry(ts(0), &request(a, usdt()))
            .unwrap()
            .value
            .address,
    );
}

#[test]
fn should_count_eth_against_the_per_account_asset_cap() {
    let mut deposits = AutomaticDeposits::default();
    let a = account(0);
    deposits
        .watch_deposit(ts(0), a, Asset::Eth, deposit_address(&a))
        .unwrap();
    for i in 1..MAX_ASSETS_PER_ACCOUNT {
        deposits
            .watch_deposit(ts(0), a, Asset::Erc20(token(i as u8)), deposit_address(&a))
            .unwrap();
    }

    let rejected = deposits.watch_deposit(
        ts(0),
        a,
        Asset::Erc20(token(MAX_ASSETS_PER_ACCOUNT as u8)),
        deposit_address(&a),
    );
    assert_eq!(rejected, Err(RegisterDepositError::TooManyAssetsForAccount));

    assert!(
        deposits
            .watch_deposit(ts(0), a, Asset::Eth, deposit_address(&a))
            .is_ok(),
        "BUG: re-arming the already-armed ETH pair is idempotent, not a cap hit"
    );
}

#[test]
fn should_reject_more_than_the_per_account_token_cap() {
    let mut deposits = AutomaticDeposits::default();
    let a = account(0);
    for i in 0..MAX_ASSETS_PER_ACCOUNT {
        deposits
            .watch_deposit(ts(0), a, Asset::Erc20(token(i as u8)), deposit_address(&a))
            .unwrap();
    }

    // A further distinct token for the same account is rejected...
    let rejected = deposits.watch_deposit(
        ts(0),
        a,
        Asset::Erc20(token(MAX_ASSETS_PER_ACCOUNT as u8)),
        deposit_address(&a),
    );
    assert_eq!(rejected, Err(RegisterDepositError::TooManyAssetsForAccount));

    // ...but re-arming one of its already-armed tokens is idempotent, not a cap hit...
    assert!(
        deposits
            .watch_deposit(ts(0), a, Asset::Erc20(token(0)), deposit_address(&a))
            .is_ok()
    );

    // ...and the cap is per account: a different account can still arm a token.
    let b = account(1);
    deposits
        .watch_deposit(ts(0), b, Asset::Erc20(token(0)), deposit_address(&b))
        .unwrap();
    assert_eq!(deposits.watchlist_len(), MAX_ASSETS_PER_ACCOUNT + 1);
}

#[test]
fn should_reject_new_pair_when_watchlist_is_full() {
    let mut deposits = AutomaticDeposits::default();
    let capacity = MAX_ACTIVE_DEPOSITS.get();
    for i in 0..capacity {
        let account = account(i as u64);
        deposits
            .watch_deposit(
                ts(0),
                account,
                Asset::Erc20(usdc()),
                deposit_address(&account),
            )
            .unwrap();
    }

    let account = account(capacity as u64);
    let rejected = deposits.watch_deposit(
        ts(0),
        account,
        Asset::Erc20(usdc()),
        deposit_address(&account),
    );

    assert_eq!(rejected, Err(RegisterDepositError::TooManyActiveDeposits));
    assert_eq!(deposits.watchlist_snapshot().registrations.len(), capacity);
}

#[test]
fn should_rebuild_watchlist_exactly_from_snapshot() {
    let mut source = AutomaticDeposits::default();
    // account(0) and account(1) are armed in the same round, so they share an
    // expiry bucket; a faithful rebuild must preserve their order too.
    source
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    source
        .watch_deposit(
            ts(0),
            account(1),
            Asset::Erc20(usdc()),
            deposit_address(&account(1)),
        )
        .unwrap();
    source
        .watch_deposit(
            ts(10),
            account(2),
            Asset::Erc20(usdc()),
            deposit_address(&account(2)),
        )
        .unwrap();
    let registry = source.watchlist_snapshot();

    let mut restored = AutomaticDeposits::default();
    restored
        .watch_deposit(
            ts(5),
            account(9),
            Asset::Erc20(usdc()),
            deposit_address(&account(9)),
        )
        .unwrap();
    restored.rebuild_watchlist(&registry);

    assert_eq!(restored, source);
    assert_eq!(restored.watchlist_snapshot(), registry);
}

#[test]
fn should_restore_the_limits_recorded_in_the_snapshot() {
    let registry = DepositAddressRegistry {
        scan_window_nanos: 12_345,
        capacity: 3,
        registrations: vec![
            registration(account(0), usdc(), ts(50)),
            registration(account(1), usdc(), ts(100)),
        ],
    };
    let mut deposits = AutomaticDeposits::default();

    deposits.rebuild_watchlist(&registry);

    assert_eq!(deposits.watchlist_snapshot(), registry);
}

#[test]
fn should_snapshot_entries_in_time_index_order() {
    let mut deposits = AutomaticDeposits::default();
    // account(0) and account(2) share an expiry; within a bucket the snapshot
    // keeps insertion order, and buckets come in ascending-expiry order.
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    deposits
        .watch_deposit(
            ts(10),
            account(1),
            Asset::Erc20(usdc()),
            deposit_address(&account(1)),
        )
        .unwrap();
    deposits
        .watch_deposit(
            ts(0),
            account(2),
            Asset::Erc20(usdc()),
            deposit_address(&account(2)),
        )
        .unwrap();

    let snapshot = deposits.watchlist_snapshot();

    assert_eq!(
        snapshot.registrations,
        vec![
            registration(account(0), usdc(), ts(window_nanos())),
            registration(account(2), usdc(), ts(window_nanos())),
            registration(account(1), usdc(), ts(10 + window_nanos())),
        ]
    );
}

mod scan_targets_iter {
    use super::{
        Asset, BlockNumber, SCAN_GAP_SECS, SECS_PER_BLOCK, account, deposit_address, deposits_from,
        scan_state, ts, usdc, window_nanos,
    };

    #[test]
    fn should_partition_due_targets_by_asset_kind() {
        let deposits = deposits_from(vec![
            scan_state(account(0), Asset::Eth, ts(window_nanos()), None, 0),
            scan_state(account(0), usdc(), ts(window_nanos()), None, 0),
        ]);

        let due = deposits.due_scan_targets(ts(0), BlockNumber::new(1_000));

        assert_eq!(
            due.eth
                .iter()
                .map(|t| (t.account(), t.address()))
                .collect::<Vec<_>>(),
            vec![(account(0), deposit_address(&account(0)))]
        );
        assert_eq!(
            due.erc20
                .iter()
                .map(|t| (t.account(), t.token(), t.address()))
                .collect::<Vec<_>>(),
            vec![(account(0), usdc(), deposit_address(&account(0)))]
        );
    }

    #[test]
    fn should_mark_never_scanned_pair_as_due() {
        let deposits = deposits_from(vec![scan_state(
            account(0),
            usdc(),
            ts(window_nanos()),
            None,
            0,
        )]);

        let due = deposits.due_scan_targets(ts(0), BlockNumber::new(1_000));

        assert!(due.eth.is_empty());
        assert_eq!(
            due.erc20
                .iter()
                .map(|t| (t.account(), t.token(), t.address()))
                .collect::<Vec<_>>(),
            vec![(account(0), usdc(), deposit_address(&account(0)))]
        );
    }

    #[test]
    fn should_mark_scanned_pair_due_only_after_the_current_gap() {
        // A scanned pair with scan_count N consults SCAN_GAP_SECS[N-1] (the first backoff scan,
        // scan_count 1, uses SCAN_GAP_SECS[0]).
        struct Case {
            scan_count: u32,
        }
        // scan_count 1 -> SCAN_GAP_SECS[0] = 30s; scan_count 3 -> SCAN_GAP_SECS[2] = 60s.
        let cases = vec![Case { scan_count: 1 }, Case { scan_count: 3 }];

        for case in cases {
            let last_scanned = BlockNumber::new(1_000);
            let deposits = deposits_from(vec![scan_state(
                account(0),
                usdc(),
                ts(window_nanos()),
                Some(last_scanned),
                case.scan_count,
            )]);
            let gap_secs = SCAN_GAP_SECS[(case.scan_count - 1) as usize];
            // First block count whose elapsed seconds (blocks * 12) reaches the gap.
            let gap_blocks = gap_secs.div_ceil(SECS_PER_BLOCK);

            let just_before = BlockNumber::new(1_000 + u128::from(gap_blocks) - 1);
            let at_boundary = BlockNumber::new(1_000 + u128::from(gap_blocks));

            assert!(
                deposits.due_scan_targets(ts(0), just_before).is_empty(),
                "scan_count {}: not due one block before the gap elapses",
                case.scan_count
            );
            assert_eq!(
                deposits
                    .due_scan_targets(ts(0), at_boundary)
                    .erc20
                    .iter()
                    .map(|t| (t.account(), t.address()))
                    .collect::<Vec<_>>(),
                vec![(account(0), deposit_address(&account(0)))],
                "scan_count {}: due exactly when the gap elapses",
                case.scan_count
            );
        }
    }

    #[test]
    fn should_never_yield_an_expired_entry() {
        let deposits = deposits_from(vec![scan_state(account(0), usdc(), ts(100), None, 0)]);

        assert!(
            deposits
                .due_scan_targets(ts(101), BlockNumber::new(1_000_000))
                .is_empty()
        );
    }

    #[test]
    fn should_not_yield_pair_past_the_schedule_end() {
        // scan_count N consults SCAN_GAP_SECS[N-1], so the schedule is exhausted once N exceeds the
        // number of gaps (index N-1 falls outside SCAN_GAP_SECS).
        let deposits = deposits_from(vec![scan_state(
            account(0),
            usdc(),
            ts(window_nanos()),
            Some(BlockNumber::new(1)),
            SCAN_GAP_SECS.len() as u32 + 1,
        )]);

        assert!(
            deposits
                .due_scan_targets(ts(0), BlockNumber::new(u128::MAX))
                .is_empty()
        );
    }
}

#[test]
fn scan_gap_secs_invariants_hold() {
    assert!(!SCAN_GAP_SECS.is_empty());
    // Burst then ramp then hourly tail.
    assert_eq!(
        &SCAN_GAP_SECS[..10],
        &[30, 30, 60, 120, 120, 240, 300, 300, 300, 300]
    );
    assert!(SCAN_GAP_SECS[10..].iter().all(|&gap| gap == 3600));

    let cumulative: u64 = SCAN_GAP_SECS.iter().sum();
    assert!(
        cumulative <= DEPOSIT_ADDRESS_SCAN_WINDOW.as_secs(),
        "the full schedule must fit within the 24h scan window"
    );
}

#[test]
fn should_reproduce_equal_watchlist_across_snapshot_round_trip() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    deposits
        .watch_deposit(
            ts(10),
            account(1),
            Asset::Erc20(usdc()),
            deposit_address(&account(1)),
        )
        .unwrap();
    deposits
        .watch_deposit(
            ts(20),
            account(2),
            Asset::Erc20(usdc()),
            deposit_address(&account(2)),
        )
        .unwrap();
    deposits.record_scan(ts(30), &request(account(1), usdc()), BlockNumber::new(500));

    let registry = deposits.watchlist_snapshot();
    assert_eq!(registry.registrations.len(), 3);

    let mut restored = AutomaticDeposits::default();
    restored.rebuild_watchlist(&registry);

    assert_eq!(restored, deposits);
    assert_eq!(restored.watchlist_snapshot(), registry);
}

#[test]
fn snapshot_does_not_carry_the_sweep_queue() {
    // The sweep queue is event-sourced (via AutomaticDepositReceived), not part of the watchlist
    // snapshot, so rebuild() from a snapshot must NOT resurrect it.
    let mut deposits = AutomaticDeposits::default();
    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));
    assert_eq!(deposits.sweep_len(), 1);

    let registry = deposits.watchlist_snapshot();
    assert!(registry.registrations.is_empty());

    let mut restored = AutomaticDeposits::default();
    restored.rebuild_watchlist(&registry);
    assert_eq!(restored.sweep_len(), 0);
}

fn deposits_from(states: Vec<DepositAddressRegistration>) -> AutomaticDeposits {
    let mut deposits = AutomaticDeposits::default();
    deposits.rebuild_watchlist(&DepositAddressRegistry {
        scan_window_nanos: window_nanos(),
        capacity: MAX_ACTIVE_DEPOSITS.get() as u64,
        registrations: states,
    });
    deposits
}

fn scan_state(
    account: Account,
    asset: impl Into<Asset>,
    expires_at: Timestamp,
    last_scanned_block: Option<BlockNumber>,
    scan_count: u32,
) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        asset: asset.into(),
        address: deposit_address(&account),
        expires_at_nanos: expires_at,
        last_scanned_block,
        scan_count,
    }
}

#[test]
fn record_scan_advances_the_schedule() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    // Never scanned -> due immediately.
    assert_eq!(
        deposits
            .due_scan_targets(ts(0), BlockNumber::new(1_000))
            .erc20
            .len(),
        1
    );

    deposits.record_scan(ts(0), &request(account(0), usdc()), BlockNumber::new(1_000));

    // The scan bookkeeping is advanced, and survives into the snapshot.
    let snapshot = deposits.watchlist_snapshot();
    assert_eq!(
        snapshot.registrations[0].last_scanned_block,
        Some(BlockNumber::new(1_000))
    );
    assert_eq!(snapshot.registrations[0].scan_count, 1);

    // Not due at the just-scanned block; due again well after the next gap.
    assert!(
        deposits
            .due_scan_targets(ts(0), BlockNumber::new(1_000))
            .is_empty()
    );
    assert_eq!(
        deposits
            .due_scan_targets(ts(0), BlockNumber::new(2_000))
            .erc20
            .len(),
        1
    );
}

#[test]
fn record_scan_is_a_noop_for_an_expired_pair() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();

    // Past the scan window the entry is no longer live; record_scan must not touch it.
    deposits.record_scan(
        ts(window_nanos() + 1),
        &request(account(0), usdc()),
        BlockNumber::new(1_000),
    );

    let snapshot = deposits.watchlist_snapshot();
    assert_eq!(snapshot.registrations[0].last_scanned_block, None);
    assert_eq!(snapshot.registrations[0].scan_count, 0);
}

#[test]
fn record_automatic_deposit_received_removes_the_pair_and_queues_it() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();

    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));

    // The watchlist entry is gone (removed by the move).
    assert_eq!(
        deposits.get_entry(ts(0), &request(account(0), usdc())),
        None
    );
    assert_eq!(deposits.watchlist_len(), 0);

    // One sweep entry for the pair, carrying the deposit address, finding block, scan_count, and
    // the scanned balance.
    assert_eq!(deposits.sweep_len(), 1);
    assert_eq!(
        deposits.sweep.get(&request(account(0), usdc())),
        Some(&sweep_entry(
            deposit_address(&account(0)),
            BlockNumber::new(900),
            3,
            10
        ))
    );
}

#[test]
fn funding_one_token_leaves_the_account_other_tokens_armed() {
    let mut deposits = AutomaticDeposits::default();
    let a = account(0);
    deposits
        .watch_deposit(ts(0), a, Asset::Erc20(usdc()), deposit_address(&a))
        .unwrap();
    deposits
        .watch_deposit(ts(0), a, Asset::Erc20(usdt()), deposit_address(&a))
        .unwrap();

    deposits.record_automatic_deposit_received(&automatic_deposit(
        a,
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));

    // Only the funded token left the watchlist; its sibling keeps scanning.
    assert_eq!(deposits.get_entry(ts(0), &request(a, usdc())), None);
    assert!(deposits.get_entry(ts(0), &request(a, usdt())).is_some());
    assert_eq!(deposits.watchlist_len(), 1);
    assert_eq!(deposits.sweep_len(), 1);
}

#[test]
#[should_panic(expected = "it already has funds queued for sweeping")]
fn watch_deposit_traps_on_a_pair_awaiting_sweep() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));
    assert_eq!(deposits.watchlist_len(), 0);
    assert_eq!(deposits.sweep_len(), 1);

    let _ = deposits.watch_deposit(
        ts(0),
        account(0),
        Asset::Erc20(usdc()),
        deposit_address(&account(0)),
    );
}

#[test]
#[should_panic(expected = "sweep queue already has an entry")]
fn record_automatic_deposit_received_traps_on_a_duplicate_pair() {
    let mut deposits = AutomaticDeposits::default();
    let deposit = automatic_deposit(account(0), usdc(), 10, BlockNumber::new(900), 3);
    deposits.record_automatic_deposit_received(&deposit);
    // Recording the same (account, token) twice means the same funds were queued twice.
    deposits.record_automatic_deposit_received(&deposit);
}

#[test]
fn record_automatic_deposit_received_inserts_unconditionally_without_a_watchlist_entry() {
    // No watchlist entry for account(0): apply still queues the move. This is exactly how event
    // replay reconstructs the queue, since the watchlist is empty until the final snapshot event.
    let mut deposits = AutomaticDeposits::default();

    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));

    assert_eq!(deposits.watchlist_len(), 0);
    assert_eq!(deposits.sweep_len(), 1);
    assert_eq!(
        deposits.sweep.get(&request(account(0), usdc())),
        Some(&sweep_entry(
            deposit_address(&account(0)),
            BlockNumber::new(900),
            3,
            10
        ))
    );
}

#[test]
fn deposit_status_reports_none_scanning_then_awaiting_sweep() {
    let mut deposits = AutomaticDeposits::default();

    // Unknown pair: neither armed nor funded.
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdc())),
        None
    );

    // Armed but not yet funded: Scanning until the window closes.
    deposits
        .watch_deposit(
            ts(0),
            account(0),
            Asset::Erc20(usdc()),
            deposit_address(&account(0)),
        )
        .unwrap();
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdc())),
        Some(DepositStatusInfo {
            address: deposit_address(&account(0)),
            stage: DepositStage::Scanning {
                valid_until: ts(window_nanos()),
                last_scanned_block: None,
                scan_count: 0,
            },
        })
    );

    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));
    // A different pair's move must not leak into this pair's status.
    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(1),
        usdc(),
        30,
        BlockNumber::new(901),
        4,
    ));

    // Once funds are detected, AwaitingSweep takes precedence over Scanning, carrying the balance
    // and finding block for that one token.
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdc())),
        Some(DepositStatusInfo {
            address: deposit_address(&account(0)),
            stage: DepositStage::AwaitingSweep {
                scanned_balance: Erc20Value::new(10),
                detected_at_block: BlockNumber::new(900),
            },
        })
    );
    // A different token at the same account is still unknown.
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdt())),
        None
    );
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(2), usdc())),
        None
    );
}

fn ts(nanos: u64) -> Timestamp {
    Timestamp::from_nanos(nanos)
}

fn token(byte: u8) -> Address {
    Address::new([byte; 20])
}

fn request(account: Account, token: Address) -> DepositRequest {
    DepositRequest::new(account, Asset::Erc20(token))
}

fn automatic_deposit(
    account: Account,
    asset: impl Into<Asset>,
    scanned_balance: u128,
    last_scanned_block: BlockNumber,
    scan_count: u32,
) -> AutomaticDeposit {
    AutomaticDeposit {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(&account),
        asset: asset.into(),
        last_scanned_block,
        scan_count,
        scanned_balance: Erc20Value::new(scanned_balance),
    }
}

#[test]
fn should_batch_eth_entries_alongside_tokens() {
    let mut deposits = AutomaticDeposits::default();
    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(0),
        Asset::Eth,
        10,
        BlockNumber::new(900),
        3,
    ));
    deposits.record_automatic_deposit_received(&automatic_deposit(
        account(1),
        usdc(),
        10,
        BlockNumber::new(900),
        3,
    ));

    let batches = deposits.requests_batch(10);

    assert_eq!(batches.len(), 2);
    assert_eq!(accounts_in(&batches, Asset::Eth), vec![account(0)]);
    assert_eq!(accounts_in(&batches, usdc()), vec![account(1)]);
}

#[test]
fn should_batch_queued_deposits_by_token() {
    let deposits = queued(&[
        (account(0), usdc()),
        (account(1), usdc()),
        (account(2), usdt()),
    ]);

    let batches = deposits.requests_batch(10);

    assert_eq!(
        batches.keys().copied().collect::<Vec<_>>(),
        vec![Asset::Erc20(usdc()), Asset::Erc20(usdt())]
    );
    assert_eq!(accounts_in(&batches, usdc()), vec![account(0), account(1)]);
    assert_eq!(accounts_in(&batches, usdt()), vec![account(2)]);

    // Nothing has taken them, so batching again offers the same deposits.
    let again = deposits.requests_batch(10);
    assert_eq!(accounts_in(&again, usdc()), vec![account(0), account(1)]);
    assert_eq!(accounts_in(&again, usdt()), vec![account(2)]);
}

#[test]
fn should_stop_offering_a_deposit_a_sweep_has_taken() {
    let mut deposits = queued(&[(account(0), usdc()), (account(1), usdc())]);

    deposits.record_sweep_scheduled(SweepId(7), Asset::Erc20(usdc()), [account(0)]);

    let batches = deposits.requests_batch(10);
    assert_eq!(accounts_in(&batches, usdc()), vec![account(1)]);

    // The taken deposit is still queued: only a settled sweep removes it.
    assert_eq!(deposits.sweep_len(), 2);
}

#[test]
fn should_offer_nothing_once_every_deposit_is_taken() {
    let mut deposits = queued(&[(account(0), usdc()), (account(1), usdt())]);

    deposits.record_sweep_scheduled(SweepId(1), Asset::Erc20(usdc()), [account(0)]);
    deposits.record_sweep_scheduled(SweepId(2), Asset::Erc20(usdt()), [account(1)]);

    assert!(deposits.requests_batch(10).is_empty());
    assert_eq!(deposits.sweep_len(), 2);
}

#[test]
#[should_panic(expected = "was already taken by another sweep")]
fn should_refuse_to_hand_the_same_deposit_to_two_sweeps() {
    let mut deposits = queued(&[(account(0), usdc())]);

    deposits.record_sweep_scheduled(SweepId(1), Asset::Erc20(usdc()), [account(0)]);
    deposits.record_sweep_scheduled(SweepId(2), Asset::Erc20(usdc()), [account(0)]);
}

#[test]
#[should_panic(expected = "is not queued for sweeping")]
fn should_refuse_to_schedule_a_deposit_that_is_not_queued() {
    let mut deposits = queued(&[(account(0), usdc())]);

    deposits.record_sweep_scheduled(SweepId(1), Asset::Erc20(usdt()), [account(0)]);
}

#[tokio::test]
async fn should_release_a_deposit_once_its_sweep_succeeds() {
    let (mut deposits, request) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;
    queue(&mut deposits, &[(account(1), usdc())]);

    finalize_sweep(&mut deposits, &request, TransactionStatus::Success);

    // The swept pair is gone from the queue; the pair queued after the sweep was decided is still
    // offered.
    assert_eq!(deposits.sweep_len(), 1);
    assert_eq!(
        accounts_in(&deposits.requests_batch(10), usdc()),
        vec![account(1)]
    );
}

#[tokio::test]
async fn should_drop_a_deposit_once_its_sweep_fails() {
    let (mut deposits, request) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;

    finalize_sweep(&mut deposits, &request, TransactionStatus::Failure);

    // A reverted sweep moved nothing, but the minter does not retry: the pair leaves the queue and
    // has to be armed afresh.
    assert_eq!(deposits.sweep_len(), 0);
    assert!(deposits.requests_batch(10).is_empty());
}

#[tokio::test]
async fn should_release_every_account_a_sweep_held() {
    let (mut deposits, request) =
        deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;

    finalize_sweep(&mut deposits, &request, TransactionStatus::Success);

    assert_eq!(deposits.sweep_len(), 0);
}

/// The mismatch this test finalizes cannot come out of `create_pending_sweeper_requests`, which
/// schedules exactly the deposits its request names. Hence the request the production code built
/// for both accounts is replayed against a queue that never held the second one.
#[tokio::test]
#[should_panic(expected = "is not queued for sweeping")]
async fn should_refuse_to_finalize_a_sweep_whose_deposit_left_the_queue() {
    let (_, request) =
        deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;
    let mut deposits = queued(&[(account(0), usdc())]);
    deposits.record_sweep_scheduled(SweepId(0), Asset::Erc20(usdc()), [account(0)]);
    deposits.record_sweep_request(request.clone());

    finalize_sweep(&mut deposits, &request, TransactionStatus::Success);
}

#[tokio::test]
async fn should_mark_the_authorizations_a_finalized_sweep_carried_as_applied() {
    // A tuple applies before the call runs and stays applied when the call reverts, so both
    // outcomes leave the delegation installed.
    for status in [TransactionStatus::Success, TransactionStatus::Failure] {
        let (mut deposits, request) =
            deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;

        finalize_sweep(&mut deposits, &request, status);

        for account in [account(0), account(1)] {
            assert_eq!(
                deposits.delegation(&account),
                Some(Delegation {
                    delegate: sweeper_contract(),
                    nonce: TransactionNonce::ONE,
                }),
                "a {status:?} sweep installs the delegations it carried"
            );
        }
        assert_eq!(deposits.applied_authorizations_len(), 2);
    }
}

#[test]
fn should_leave_a_tuple_unapplied_and_its_address_undelegated_when_a_sweep_leaves_it_out() {
    let mut deposits = AutomaticDeposits::default();
    deposits.record_authorization(
        authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO),
        transaction_signature(),
    );

    finalize_sweep_carrying(&mut deposits, SweepId(0), None);

    assert_eq!(deposits.authorizations_len(), 1);
    assert_eq!(deposits.applied_authorizations_len(), 0);
    assert_eq!(deposits.delegation(&account(0)), None);
}

#[tokio::test]
async fn should_not_mark_a_tuple_whose_nonce_the_account_has_already_spent() {
    let (mut deposits, first) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;
    finalize_sweep(&mut deposits, &first, TransactionStatus::Success);
    let authorization = first.items[0].authorization.clone();
    assert!(authorization.is_some(), "the fixture must carry a tuple");

    // Applying the tuple spent nonce zero, so the protocol skips the very same tuple when a later
    // sweep carries it again: the mark stays on the sweep that did apply it.
    finalize_sweep_carrying(&mut deposits, SweepId(1), authorization);

    assert_eq!(
        applied_by(
            &deposits,
            &authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO)
        ),
        Some(AppliedBy::Sweep(first.id))
    );
    assert_eq!(
        deposits.delegation(&account(0)),
        Some(Delegation {
            delegate: sweeper_contract(),
            nonce: TransactionNonce::ONE,
        })
    );
    assert_eq!(deposits.applied_authorizations_len(), 1);
}

/// Two sweeps of the same account can be in flight at once — one per token it has queued — and
/// both carry a tuple for nonce zero, since the minter always signs for nonce zero. Whichever
/// lands first spends the nonce; the other is skipped, even when it names a different delegate.
#[test]
fn should_apply_only_the_first_of_two_sweeps_carrying_the_same_nonce() {
    let mut deposits = AutomaticDeposits::default();
    let incumbent = authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO);
    let rotated = authorization_request(account(0), ANOTHER_DELEGATE, TransactionNonce::ZERO);
    deposits.record_authorization(incumbent.clone(), transaction_signature());
    deposits.record_authorization(rotated.clone(), transaction_signature());

    finalize_sweep_carrying(&mut deposits, SweepId(0), Some(signed(&incumbent)));
    finalize_sweep_carrying(&mut deposits, SweepId(1), Some(signed(&rotated)));

    assert_eq!(
        applied_by(&deposits, &incumbent),
        Some(AppliedBy::Sweep(SweepId(0)))
    );
    assert_eq!(applied_by(&deposits, &rotated), None);
    assert_eq!(
        deposits.delegation(&account(0)),
        Some(Delegation {
            delegate: sweeper_contract(),
            nonce: TransactionNonce::ONE,
        })
    );
    assert_eq!(deposits.applied_authorizations_len(), 1);
}

#[test]
fn should_not_mark_a_tuple_signed_for_a_nonce_the_account_has_not_reached() {
    let mut deposits = AutomaticDeposits::default();
    let ahead = authorization_request(account(0), sweeper_contract(), TransactionNonce::ONE);
    deposits.record_authorization(ahead.clone(), transaction_signature());

    finalize_sweep_carrying(&mut deposits, SweepId(0), Some(signed(&ahead)));

    assert_eq!(applied_by(&deposits, &ahead), None);
    assert_eq!(deposits.delegation(&account(0)), None);
    assert_eq!(deposits.applied_authorizations_len(), 0);
}

#[tokio::test]
async fn should_report_the_delegate_of_the_highest_applied_authorization() {
    let (mut deposits, first) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;
    finalize_sweep(&mut deposits, &first, TransactionStatus::Success);

    let rotated = authorization_request(account(0), ANOTHER_DELEGATE, TransactionNonce::ONE);
    deposits.record_authorization(rotated.clone(), transaction_signature());
    finalize_sweep_carrying(&mut deposits, SweepId(1), Some(signed(&rotated)));

    assert_eq!(
        deposits.delegation(&account(0)),
        Some(Delegation {
            delegate: ANOTHER_DELEGATE,
            nonce: TransactionNonce::new(2),
        })
    );
    assert_eq!(deposits.applied_authorizations_len(), 2);
}

#[tokio::test]
async fn should_rebuild_the_applied_marks_by_replaying_the_event_log() {
    let (mut live, request) = state_with_enqueued_sweep(&[(account(0), usdc())]).await;
    let mut time_provider = MockTimeProvider::new();
    time_provider.expect_time().return_const(0_u64);
    for event in sweep_pipeline_events(
        live.automatic_deposits.next_sweeper_transaction_nonce(),
        &request,
        TransactionStatus::Success,
    ) {
        process_event(&mut live, event, &time_provider);
    }

    let replayed = replay_of_the_event_log();

    assert_eq!(
        replayed.automatic_deposits.delegation(&account(0)),
        Some(Delegation {
            delegate: sweeper_contract(),
            nonce: TransactionNonce::ONE,
        })
    );
    assert_eq!(
        replayed
            .automatic_deposits
            .is_equivalent_to(&live.automatic_deposits),
        Ok(())
    );

    let mut unmarked = replayed.automatic_deposits.clone();
    for stored in unmarked.authorizations.values_mut() {
        stored.applied_by = None;
    }
    assert_ne!(
        unmarked.is_equivalent_to(&live.automatic_deposits),
        Ok(()),
        "equivalence must notice which authorizations were applied"
    );
}

#[tokio::test]
async fn should_leave_nonces_unverified_only_where_a_sweep_reverted() {
    for (status, unverified) in [
        (TransactionStatus::Success, false),
        (TransactionStatus::Failure, true),
    ] {
        let (mut deposits, request) =
            deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;

        finalize_sweep(&mut deposits, &request, status);

        for account in [account(0), account(1)] {
            assert_eq!(
                deposits.has_unverified_nonce(&account),
                unverified,
                "a {status:?} sweep must leave its addresses' nonces {}",
                if unverified {
                    "unverified"
                } else {
                    "as they were"
                }
            );
        }
        assert!(
            !deposits.has_unverified_nonce(&account(2)),
            "an address the sweep never touched keeps its nonce"
        );
    }
}

#[test]
fn should_reanchor_the_applied_marks_on_the_observed_deposit_address_nonce() {
    struct Case {
        name: &'static str,
        observed: TransactionNonce,
        expected_delegation: Option<Delegation>,
        expected_applied: usize,
    }

    for case in [
        Case {
            name: "the record already agreed with the chain",
            observed: TransactionNonce::ONE,
            expected_delegation: Some(Delegation {
                delegate: sweeper_contract(),
                nonce: TransactionNonce::ONE,
            }),
            expected_applied: 1,
        },
        Case {
            name: "the chain is ahead: the tuples below the observed nonce did apply",
            observed: TransactionNonce::new(3),
            expected_delegation: Some(Delegation {
                delegate: ANOTHER_DELEGATE,
                nonce: TransactionNonce::new(3),
            }),
            expected_applied: 3,
        },
        Case {
            name: "the chain is behind: nothing at or above the observed nonce applied",
            observed: TransactionNonce::ZERO,
            expected_delegation: None,
            expected_applied: 0,
        },
    ] {
        let mut deposits = deposits_with_three_rotations_of_which_one_applied();
        let reverted = sweep_carrying(&mut deposits, SweepId(1), None);
        finalize_sweep(&mut deposits, &reverted, TransactionStatus::Failure);

        deposits.record_observed_deposit_address_nonce(account(0), case.observed);

        assert_eq!(
            deposits.delegation(&account(0)),
            case.expected_delegation,
            "{}",
            case.name
        );
        assert_eq!(
            deposits.applied_authorizations_len(),
            case.expected_applied,
            "{}",
            case.name
        );
        assert!(
            !deposits.has_unverified_nonce(&account(0)),
            "{}: re-anchoring the record verifies the nonce",
            case.name
        );
    }
}

/// Two tuples at one nonce is state from before the minter signed at most one per nonce. The
/// observed nonce cannot say which of them applied, so the one already marked applied stays the
/// answer.
#[test]
fn should_keep_the_applied_tuple_when_two_share_a_nonce_below_the_observed_one() {
    let mut deposits = AutomaticDeposits::default();
    let incumbent = authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO);
    let rival = authorization_request(account(0), ANOTHER_DELEGATE, TransactionNonce::ZERO);
    for request in [&incumbent, &rival] {
        deposits.record_authorization(request.clone(), transaction_signature());
    }
    finalize_sweep_carrying(&mut deposits, SweepId(0), Some(signed(&incumbent)));

    deposits.record_observed_deposit_address_nonce(account(0), TransactionNonce::ONE);

    assert_eq!(
        applied_by(&deposits, &incumbent),
        Some(AppliedBy::Sweep(SweepId(0)))
    );
    assert_eq!(applied_by(&deposits, &rival), None);
    assert_eq!(
        deposits.delegation(&account(0)),
        Some(Delegation {
            delegate: sweeper_contract(),
            nonce: TransactionNonce::ONE,
        })
    );
}

#[test]
fn should_leave_the_nonce_unresolved_when_two_unapplied_tuples_share_a_nonce_below_it() {
    let mut deposits = AutomaticDeposits::default();
    for delegate in [sweeper_contract(), ANOTHER_DELEGATE] {
        deposits.record_authorization(
            authorization_request(account(0), delegate, TransactionNonce::ZERO),
            transaction_signature(),
        );
    }
    let reverted = sweep_carrying(&mut deposits, SweepId(0), None);
    finalize_sweep(&mut deposits, &reverted, TransactionStatus::Failure);

    deposits.record_observed_deposit_address_nonce(account(0), TransactionNonce::ONE);

    assert_unresolved(&deposits, account(0));
    assert_eq!(deposits.applied_authorizations_len(), 0);
    assert_eq!(deposits.delegation(&account(0)), None);
}

/// The minter holds the deposit address' only key, so no nonce above the tuples it signed is
/// explainable: reading one back means the record is missing tuples, which no arithmetic recovers.
#[test]
fn should_leave_the_nonce_unresolved_when_the_observed_one_is_beyond_every_signed_tuple() {
    for (observed, explainable) in [
        (TransactionNonce::ONE, true),
        (TransactionNonce::new(2), false),
    ] {
        let mut deposits = AutomaticDeposits::default();
        deposits.record_authorization(
            authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO),
            transaction_signature(),
        );
        let reverted = sweep_carrying(&mut deposits, SweepId(0), None);
        finalize_sweep(&mut deposits, &reverted, TransactionStatus::Failure);

        deposits.record_observed_deposit_address_nonce(account(0), observed);

        if explainable {
            assert!(
                deposits.has_trusted_nonce(&account(0)),
                "{observed} is the nonce the one tuple the minter signed takes the address to"
            );
        } else {
            assert_unresolved(&deposits, account(0));
        }
    }
}

/// An address the minter cannot place takes no slot in a token's sweep batch: leaving it in would
/// let a handful of stuck addresses hold back every healthy one queued behind them.
#[tokio::test]
async fn should_offer_no_sweep_of_an_address_whose_nonce_is_not_trusted() {
    let (mut deposits, request) =
        deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;
    finalize_sweep(&mut deposits, &request, TransactionStatus::Failure);
    rearm(&mut deposits, &[(account(0), usdc()), (account(1), usdc())]);
    assert_eq!(accounts_in(&deposits.requests_batch(10), usdc()), vec![]);

    deposits.record_observed_deposit_address_nonce(account(0), TransactionNonce::ONE);
    deposits.record_observed_deposit_address_nonce(account(1), TransactionNonce::new(9));

    assert_eq!(
        accounts_in(&deposits.requests_batch(10), usdc()),
        vec![account(0)],
        "only the address the nonce read back placed is offered for sweeping again"
    );
    assert_unresolved(&deposits, account(1));
    assert!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(10)
            .is_empty(),
        "neither address is read again: one is placed, the other no read can place"
    );
}

/// A tick pays for the nonce reads it takes, a batch at a time, as it does for the sweeps it
/// sends: a delegate that reverts every batch leaves every address those sweeps touched waiting on
/// a read, and reading all of them at once would fan one timer out into a chain read per queued
/// address.
#[tokio::test]
async fn should_offer_at_most_a_batch_of_deposit_addresses_to_read_the_nonce_of() {
    let pairs = [
        (account(0), usdc()),
        (account(1), usdc()),
        (account(2), usdc()),
    ];
    let (mut deposits, request) = deposits_with_enqueued_sweep(&pairs).await;
    finalize_sweep(&mut deposits, &request, TransactionStatus::Failure);
    rearm(&mut deposits, &pairs);

    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(0)
            .into_keys()
            .collect::<Vec<_>>(),
        vec![]
    );
    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(2)
            .into_keys()
            .collect::<Vec<_>>(),
        vec![account(0), account(1)]
    );
    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(pairs.len())
            .into_keys()
            .collect::<Vec<_>>(),
        vec![account(0), account(1), account(2)],
        "a batch wide enough for them offers every address still waiting on a read"
    );
}

/// A sweep in flight applies its tuple when it finalizes, moving the marks a read re-anchors. An
/// address one still holds is therefore not read while it is in flight: a count read before that
/// sweep lands would undo what it left behind. It is read once the sweep is done with it.
#[tokio::test]
async fn should_read_no_nonce_of_an_address_a_sweep_still_holds() {
    let (mut deposits, reverted) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;
    finalize_sweep(&mut deposits, &reverted, TransactionStatus::Failure);
    rearm(&mut deposits, &[(account(0), usdc()), (account(0), usdt())]);
    let in_flight = sweep_request(
        SweepId(1),
        Asset::Erc20(usdt()),
        vec![authorized_item(account(0), None)],
    );
    deposits.record_sweep_scheduled(SweepId(1), Asset::Erc20(usdt()), [account(0)]);
    deposits.record_sweep_request(in_flight.clone());

    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(10)
            .into_keys()
            .collect::<Vec<_>>(),
        vec![],
        "reading the nonce now would race the tuple that sweep applies when it finalizes"
    );

    finalize_sweep(&mut deposits, &in_flight, TransactionStatus::Success);

    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(10)
            .into_keys()
            .collect::<Vec<_>>(),
        vec![account(0)],
        "the sweep has settled what it applied, so the read anchors on a record that stands still"
    );
}

/// One read places an account's deposit address whatever that account has queued, so a second
/// funded token of the same account may not cost the batch a slot.
#[tokio::test]
async fn should_offer_a_deposit_address_once_however_many_of_its_tokens_are_queued() {
    let (mut deposits, request) =
        deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;
    finalize_sweep(&mut deposits, &request, TransactionStatus::Failure);
    rearm(
        &mut deposits,
        &[
            (account(0), usdc()),
            (account(0), usdt()),
            (account(1), usdc()),
        ],
    );

    assert_eq!(
        deposits
            .deposit_addresses_awaiting_a_nonce_read(2)
            .into_keys()
            .collect::<Vec<_>>(),
        vec![account(0), account(1)]
    );
}

/// A signature is only usable on the chain its tuple names, so a tuple recorded for another chain
/// is not the one this chain will apply at that nonce.
#[test]
fn should_not_recarry_a_tuple_signed_for_another_chain() {
    let mut deposits = AutomaticDeposits::default();
    deposits.record_authorization(
        AuthorizationRequest::new(
            account(0),
            EthereumNetwork::default().chain_id() + 1,
            sweeper_contract(),
            TransactionNonce::ZERO,
        ),
        transaction_signature(),
    );

    assert_eq!(
        deposits.unapplied_authorization_at(
            &account(0),
            EthereumNetwork::default().chain_id(),
            TransactionNonce::ZERO
        ),
        None
    );
}

fn assert_unresolved(deposits: &AutomaticDeposits, account: Account) {
    assert!(
        !deposits.has_trusted_nonce(&account),
        "an address the observed nonce cannot place stays out of every sweep"
    );
    assert!(
        !deposits.has_unverified_nonce(&account),
        "re-reading a nonce that explains nothing would burn cycles every tick to no end"
    );
}

#[tokio::test]
async fn should_rebuild_the_unverified_nonces_and_their_repair_by_replaying_the_event_log() {
    let (mut live, request) = state_with_enqueued_sweep(&[(account(0), usdc())]).await;
    let mut time_provider = MockTimeProvider::new();
    time_provider.expect_time().return_const(0_u64);
    for event in sweep_pipeline_events(
        live.automatic_deposits.next_sweeper_transaction_nonce(),
        &request,
        TransactionStatus::Failure,
    ) {
        process_event(&mut live, event, &time_provider);
    }
    assert!(live.automatic_deposits.has_unverified_nonce(&account(0)));

    let flagged = replay_of_the_event_log();
    assert_eq!(
        flagged
            .automatic_deposits
            .is_equivalent_to(&live.automatic_deposits),
        Ok(())
    );

    process_event(
        &mut live,
        EventType::ObservedDepositAddressNonce {
            account: account(0),
            nonce: TransactionNonce::ONE,
        },
        &time_provider,
    );

    let repaired = replay_of_the_event_log();
    assert!(repaired.automatic_deposits.has_trusted_nonce(&account(0)));
    assert_eq!(
        repaired
            .automatic_deposits
            .is_equivalent_to(&live.automatic_deposits),
        Ok(())
    );
    assert_ne!(
        flagged
            .automatic_deposits
            .is_equivalent_to(&live.automatic_deposits),
        Ok(()),
        "equivalence must notice which addresses are still awaiting a nonce read"
    );
}

/// The event that leaves an address unresolved rebuilds that on replay too, so an upgrade does not
/// quietly put a stuck address back into sweeps.
#[tokio::test]
async fn should_rebuild_the_unresolved_nonces_by_replaying_the_event_log() {
    let (mut live, request) = state_with_enqueued_sweep(&[(account(0), usdc())]).await;
    let mut time_provider = MockTimeProvider::new();
    time_provider.expect_time().return_const(0_u64);
    for event in sweep_pipeline_events(
        live.automatic_deposits.next_sweeper_transaction_nonce(),
        &request,
        TransactionStatus::Failure,
    ) {
        process_event(&mut live, event, &time_provider);
    }
    process_event(
        &mut live,
        EventType::ObservedDepositAddressNonce {
            account: account(0),
            nonce: TransactionNonce::new(9),
        },
        &time_provider,
    );
    assert_unresolved(&live.automatic_deposits, account(0));

    let replayed = replay_of_the_event_log();

    assert_unresolved(&replayed.automatic_deposits, account(0));
    assert_eq!(
        replayed
            .automatic_deposits
            .is_equivalent_to(&live.automatic_deposits),
        Ok(())
    );
}

/// [`account(0)`] with a tuple recorded for each of the nonces zero, one and two — the first on
/// the sweeper contract, the two rotations onto [`ANOTHER_DELEGATE`] — of which only the first is
/// marked applied, so the record says the address stands at nonce one on the sweeper contract.
fn deposits_with_three_rotations_of_which_one_applied() -> AutomaticDeposits {
    let mut deposits = AutomaticDeposits::default();
    let installed = authorization_request(account(0), sweeper_contract(), TransactionNonce::ZERO);
    deposits.record_authorization(installed.clone(), transaction_signature());
    for nonce in [TransactionNonce::ONE, TransactionNonce::new(2)] {
        deposits.record_authorization(
            authorization_request(account(0), ANOTHER_DELEGATE, nonce),
            transaction_signature(),
        );
    }
    finalize_sweep_carrying(&mut deposits, SweepId(0), Some(signed(&installed)));
    deposits
}

/// The minter state the event log alone reconstructs. The prepaid sweep gas is not event-sourced,
/// so it is put back by hand for the accepted sweeps in the log to draw on.
fn replay_of_the_event_log() -> State {
    let mut state = initial_state();
    prepay_sweep_gas(&mut state);
    with_event_iter(|events| {
        for event in events {
            apply_state_transition(&mut state, &event.payload);
        }
    });
    state
}

/// Queue [`account(0)`]'s deposit of the token sweep `id` alone moves, hand it to that sweep
/// carrying `authorization`, and finalize the sweep. One token per id, so several sweeps of the
/// same account can follow one another.
fn finalize_sweep_carrying(
    deposits: &mut AutomaticDeposits,
    id: SweepId,
    authorization: Option<SignedAuthorization>,
) {
    let request = sweep_carrying(deposits, id, authorization);
    finalize_sweep(deposits, &request, TransactionStatus::Success);
}

/// [`finalize_sweep_carrying`] up to the receipt, so a test can pick the status itself.
fn sweep_carrying(
    deposits: &mut AutomaticDeposits,
    id: SweepId,
    authorization: Option<SignedAuthorization>,
) -> SweepRequest {
    let account = account(0);
    let token = token(id.0 as u8);
    let request = sweep_request(
        id,
        Asset::Erc20(token),
        vec![authorized_item(account, authorization)],
    );
    queue(deposits, &[(account, token)]);
    deposits.record_sweep_scheduled(id, Asset::Erc20(token), [account]);
    deposits.record_sweep_request(request.clone());
    request
}

fn signed(request: &AuthorizationRequest) -> SignedAuthorization {
    request.signed_with(transaction_signature())
}

fn sweep_request(id: SweepId, asset: Asset, items: Vec<AuthorizedSweepItem>) -> SweepRequest {
    let max_transaction_fee = gas_fee_estimate()
        .to_price(sweep_gas_limit(&items))
        .max_transaction_fee();
    SweepRequest {
        id,
        destination: sweeper_contract(),
        asset,
        items,
        max_transaction_fee,
        created_at: 0,
    }
}

fn authorized_item(
    account: Account,
    authorization: Option<SignedAuthorization>,
) -> AuthorizedSweepItem {
    AuthorizedSweepItem {
        item: SweepItem {
            deposit: deposit_address(&account),
            account,
            attestation: transaction_signature(),
        },
        authorization,
    }
}

fn authorization_request(
    account: Account,
    delegate: Address,
    nonce: TransactionNonce,
) -> AuthorizationRequest {
    AuthorizationRequest::new(
        account,
        EthereumNetwork::default().chain_id(),
        delegate,
        nonce,
    )
}

fn applied_by(deposits: &AutomaticDeposits, request: &AuthorizationRequest) -> Option<AppliedBy> {
    deposits
        .authorizations
        .get(request)
        .and_then(|stored| stored.applied_by)
}

/// Drives the already-recorded `request` through the sweeper pipeline to a receipt of `status`.
fn finalize_sweep(
    deposits: &mut AutomaticDeposits,
    request: &SweepRequest,
    status: TransactionStatus,
) {
    let sweep = sweep_pipeline_outcome(deposits.next_sweeper_transaction_nonce(), request, status);
    deposits.record_created_sweep_transaction(request.id, sweep.transaction);
    deposits.record_signed_sweep_transaction(sweep.signed);
    deposits.record_finalized_sweep_transaction(request.id, &sweep.receipt);
}

/// An [`AutomaticDeposits`] whose sweep queue holds exactly these funded pairs.
fn queued(pairs: &[(Account, Address)]) -> AutomaticDeposits {
    let mut deposits = AutomaticDeposits::default();
    queue(&mut deposits, pairs);
    assert_eq!(deposits.sweep_len(), pairs.len());
    deposits
}

/// Queue these pairs again, as arming them afresh does. What a reverted sweep's deposits need
/// before any test can offer them for sweeping again: failing dropped them from the queue.
fn rearm(deposits: &mut AutomaticDeposits, pairs: &[(Account, Address)]) {
    queue(deposits, pairs);
}

fn queue(deposits: &mut AutomaticDeposits, pairs: &[(Account, Address)]) {
    for (account, token) in pairs {
        deposits
            .watch_deposit(
                ts(0),
                *account,
                Asset::Erc20(*token),
                deposit_address(account),
            )
            .unwrap();
        deposits.record_automatic_deposit_received(&automatic_deposit(
            *account,
            *token,
            10,
            BlockNumber::new(900),
            3,
        ));
    }
}

fn accounts_in(
    batches: &BTreeMap<Asset, Vec<SweepTarget>>,
    asset: impl Into<Asset>,
) -> Vec<Account> {
    batches
        .get(&asset.into())
        .map(|targets| targets.iter().map(|target| target.account()).collect())
        .unwrap_or_default()
}

fn sweep_entry(
    address: DepositAddress,
    last_scanned_block: BlockNumber,
    scan_count: u32,
    scanned_balance: u128,
) -> SweepEntry {
    SweepEntry {
        address,
        last_scanned_block,
        scan_count,
        scanned_balance: Erc20Value::new(scanned_balance),
        swept_by: None,
    }
}

fn window_nanos() -> u64 {
    DEPOSIT_ADDRESS_SCAN_WINDOW.as_nanos() as u64
}

fn account(index: u64) -> Account {
    let mut subaccount = [0_u8; 32];
    subaccount[..8].copy_from_slice(&index.to_be_bytes());
    account_with(Some(subaccount))
}

fn account_with(subaccount: Option<[u8; 32]>) -> Account {
    Account {
        owner: owner(),
        subaccount,
    }
}

fn owner() -> Principal {
    Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap()
}

fn entry(account: &Account, expires_at: Timestamp) -> Entry<ScanProgress> {
    Entry {
        value: ScanProgress::from(deposit_address(account)),
        expires_at,
    }
}

/// The deposit address is a deterministic function of the account, so a given
/// account always maps to the same address (mirroring the production key
/// derivation).
fn registration(
    account: Account,
    token: Address,
    expires_at: Timestamp,
) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        asset: Asset::Erc20(token),
        address: deposit_address(&account),
        expires_at_nanos: expires_at,
        last_scanned_block: None,
        scan_count: 0,
    }
}
