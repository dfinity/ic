use super::{
    AutomaticDeposits, DEPOSIT_ADDRESS_SCAN_WINDOW, DepositRequest, MAX_ACTIVE_DEPOSITS,
    MAX_TOKENS_PER_ACCOUNT, SCAN_GAP_SECS, SECS_PER_BLOCK, ScanProgress, SweepEntry, SweepTarget,
};
use crate::deposit_address::DepositAddress;
use crate::endpoints::{DepositErc20Error, DepositErc20Response, DepositStatus, DetectedDeposit};
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::event::{AutomaticDeposit, DepositAddressRegistration, DepositAddressRegistry};
use crate::state::transactions::{PipelineRequest, SweepId, SweepRequest};
use crate::test_fixtures::{
    deposit_address, deposits_with_enqueued_sweep, gas_fee_estimate, usdc, usdt,
};
use crate::timed_sized_map::{Entry, Timestamp};
use crate::tx::{SignableTransaction, Signed, TransactionSignature};
use candid::{Nat, Principal};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

#[test]
fn should_watch_a_pair_for_the_scan_window() {
    struct Case {
        name: &'static str,
        arms: Vec<(Timestamp, Account, Address)>,
        expected: Result<Entry<ScanProgress>, DepositErc20Error>,
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
            let outcome = deposits.watch_deposit(*now, *account, *token, deposit_address(account));
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
        .watch_deposit(ts(0), a, usdc(), deposit_address(&a))
        .unwrap();
    deposits
        .watch_deposit(ts(0), a, usdt(), deposit_address(&a))
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
fn should_reject_more_than_the_per_account_token_cap() {
    let mut deposits = AutomaticDeposits::default();
    let a = account(0);
    for i in 0..MAX_TOKENS_PER_ACCOUNT {
        deposits
            .watch_deposit(ts(0), a, token(i as u8), deposit_address(&a))
            .unwrap();
    }

    // A further distinct token for the same account is rejected...
    let rejected = deposits.watch_deposit(
        ts(0),
        a,
        token(MAX_TOKENS_PER_ACCOUNT as u8),
        deposit_address(&a),
    );
    assert_eq!(rejected, Err(DepositErc20Error::TooManyTokensForAccount));

    // ...but re-arming one of its already-armed tokens is idempotent, not a cap hit...
    assert!(
        deposits
            .watch_deposit(ts(0), a, token(0), deposit_address(&a))
            .is_ok()
    );

    // ...and the cap is per account: a different account can still arm a token.
    let b = account(1);
    deposits
        .watch_deposit(ts(0), b, token(0), deposit_address(&b))
        .unwrap();
    assert_eq!(deposits.watchlist_len(), MAX_TOKENS_PER_ACCOUNT + 1);
}

#[test]
fn should_reject_new_pair_when_watchlist_is_full() {
    let mut deposits = AutomaticDeposits::default();
    let capacity = MAX_ACTIVE_DEPOSITS.get();
    for i in 0..capacity {
        let account = account(i as u64);
        deposits
            .watch_deposit(ts(0), account, usdc(), deposit_address(&account))
            .unwrap();
    }

    let account = account(capacity as u64);
    let rejected = deposits.watch_deposit(ts(0), account, usdc(), deposit_address(&account));

    assert_eq!(rejected, Err(DepositErc20Error::TooManyActiveDeposits));
    assert_eq!(deposits.watchlist_snapshot().registrations.len(), capacity);
}

#[test]
fn should_rebuild_watchlist_exactly_from_snapshot() {
    let mut source = AutomaticDeposits::default();
    // account(0) and account(1) are armed in the same round, so they share an
    // expiry bucket; a faithful rebuild must preserve their order too.
    source
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
        .unwrap();
    source
        .watch_deposit(ts(0), account(1), usdc(), deposit_address(&account(1)))
        .unwrap();
    source
        .watch_deposit(ts(10), account(2), usdc(), deposit_address(&account(2)))
        .unwrap();
    let registry = source.watchlist_snapshot();

    let mut restored = AutomaticDeposits::default();
    restored
        .watch_deposit(ts(5), account(9), usdc(), deposit_address(&account(9)))
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
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
        .unwrap();
    deposits
        .watch_deposit(ts(10), account(1), usdc(), deposit_address(&account(1)))
        .unwrap();
    deposits
        .watch_deposit(ts(0), account(2), usdc(), deposit_address(&account(2)))
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
        BlockNumber, SCAN_GAP_SECS, SECS_PER_BLOCK, account, deposit_address, deposits_from,
        scan_state, ts, usdc, window_nanos,
    };

    #[test]
    fn should_mark_never_scanned_pair_as_due() {
        let deposits = deposits_from(vec![scan_state(
            account(0),
            usdc(),
            ts(window_nanos()),
            None,
            0,
        )]);

        let due: Vec<_> = deposits
            .scan_targets_iter(ts(0), BlockNumber::new(1_000))
            .map(|t| (t.account(), t.token(), t.address()))
            .collect();

        assert_eq!(
            due,
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

            assert_eq!(
                deposits.scan_targets_iter(ts(0), just_before).count(),
                0,
                "scan_count {}: not due one block before the gap elapses",
                case.scan_count
            );
            assert_eq!(
                deposits
                    .scan_targets_iter(ts(0), at_boundary)
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

        assert_eq!(
            deposits
                .scan_targets_iter(ts(101), BlockNumber::new(1_000_000))
                .count(),
            0
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

        assert_eq!(
            deposits
                .scan_targets_iter(ts(0), BlockNumber::new(u128::MAX))
                .count(),
            0
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
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
        .unwrap();
    deposits
        .watch_deposit(ts(10), account(1), usdc(), deposit_address(&account(1)))
        .unwrap();
    deposits
        .watch_deposit(ts(20), account(2), usdc(), deposit_address(&account(2)))
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
    token: Address,
    expires_at: Timestamp,
    last_scanned_block: Option<BlockNumber>,
    scan_count: u32,
) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        erc20_contract_address: token,
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
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
        .unwrap();
    // Never scanned -> due immediately.
    assert_eq!(
        deposits
            .scan_targets_iter(ts(0), BlockNumber::new(1_000))
            .count(),
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
    assert_eq!(
        deposits
            .scan_targets_iter(ts(0), BlockNumber::new(1_000))
            .count(),
        0
    );
    assert_eq!(
        deposits
            .scan_targets_iter(ts(0), BlockNumber::new(2_000))
            .count(),
        1
    );
}

#[test]
fn record_scan_is_a_noop_for_an_expired_pair() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
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
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
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
        .watch_deposit(ts(0), a, usdc(), deposit_address(&a))
        .unwrap();
    deposits
        .watch_deposit(ts(0), a, usdt(), deposit_address(&a))
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
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
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

    let _ = deposits.watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)));
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
    const MINIMUM_DEPOSIT_AMOUNT: u128 = 10_000_000;

    let mut deposits = AutomaticDeposits::default();
    let minimum = Erc20Value::new(MINIMUM_DEPOSIT_AMOUNT);

    // Unknown pair: neither armed nor funded.
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdc()), minimum),
        None
    );

    // Armed but not yet funded: Scanning until the window closes, with the token's minimum
    // reported alongside it.
    deposits
        .watch_deposit(ts(0), account(0), usdc(), deposit_address(&account(0)))
        .unwrap();
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdc()), minimum),
        Some(DepositErc20Response {
            address: deposit_address(&account(0)).to_string(),
            minimum_deposit_amount: Nat::from(MINIMUM_DEPOSIT_AMOUNT),
            status: DepositStatus::Scanning {
                valid_until: window_nanos(),
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
        deposits.deposit_status(ts(0), &request(account(0), usdc()), minimum),
        Some(DepositErc20Response {
            address: deposit_address(&account(0)).to_string(),
            minimum_deposit_amount: Nat::from(MINIMUM_DEPOSIT_AMOUNT),
            status: DepositStatus::AwaitingSweep(DetectedDeposit {
                erc20_contract_address: usdc().to_string(),
                scanned_balance: Nat::from(10_u8),
                detected_at_block: Nat::from(900_u16),
            }),
        })
    );
    // A different token at the same account is still unknown.
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(0), usdt()), minimum),
        None
    );
    assert_eq!(
        deposits.deposit_status(ts(0), &request(account(2), usdc()), minimum),
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
    DepositRequest::new(account, token)
}

fn automatic_deposit(
    account: Account,
    token: Address,
    scanned_balance: u128,
    last_scanned_block: BlockNumber,
    scan_count: u32,
) -> AutomaticDeposit {
    AutomaticDeposit {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(&account),
        erc20_contract_address: token,
        last_scanned_block,
        scan_count,
        scanned_balance: Erc20Value::new(scanned_balance),
    }
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
        vec![usdc(), usdt()]
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

    deposits.record_sweep_scheduled(SweepId(7), usdc(), [account(0)]);

    let batches = deposits.requests_batch(10);
    assert_eq!(accounts_in(&batches, usdc()), vec![account(1)]);

    // The taken deposit is still queued: only a settled sweep removes it.
    assert_eq!(deposits.sweep_len(), 2);
}

#[test]
fn should_offer_nothing_once_every_deposit_is_taken() {
    let mut deposits = queued(&[(account(0), usdc()), (account(1), usdt())]);

    deposits.record_sweep_scheduled(SweepId(1), usdc(), [account(0)]);
    deposits.record_sweep_scheduled(SweepId(2), usdt(), [account(1)]);

    assert!(deposits.requests_batch(10).is_empty());
    assert_eq!(deposits.sweep_len(), 2);
}

#[test]
#[should_panic(expected = "was already taken by another sweep")]
fn should_refuse_to_hand_the_same_deposit_to_two_sweeps() {
    let mut deposits = queued(&[(account(0), usdc())]);

    deposits.record_sweep_scheduled(SweepId(1), usdc(), [account(0)]);
    deposits.record_sweep_scheduled(SweepId(2), usdc(), [account(0)]);
}

#[test]
#[should_panic(expected = "is not queued for sweeping")]
fn should_refuse_to_schedule_a_deposit_that_is_not_queued() {
    let mut deposits = queued(&[(account(0), usdc())]);

    deposits.record_sweep_scheduled(SweepId(1), usdt(), [account(0)]);
}

#[tokio::test]
async fn should_release_a_deposit_once_its_sweep_succeeds() {
    let (mut deposits, request) = deposits_with_enqueued_sweep(&[(account(0), usdc())]).await;
    queue(&mut deposits, &[(account(1), usdc())]);

    finalize_sweep(&mut deposits, request, TransactionStatus::Success);

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

    finalize_sweep(&mut deposits, request, TransactionStatus::Failure);

    // A reverted sweep moved nothing, but the minter does not retry: the pair leaves the queue and
    // has to be armed afresh.
    assert_eq!(deposits.sweep_len(), 0);
    assert!(deposits.requests_batch(10).is_empty());
}

#[tokio::test]
async fn should_release_every_account_a_sweep_held() {
    let (mut deposits, request) =
        deposits_with_enqueued_sweep(&[(account(0), usdc()), (account(1), usdc())]).await;

    finalize_sweep(&mut deposits, request, TransactionStatus::Success);

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
    deposits.record_sweep_scheduled(SweepId(0), usdc(), [account(0)]);
    deposits.record_sweep_request(request.clone());

    finalize_sweep(&mut deposits, request, TransactionStatus::Success);
}

/// Drives the already-recorded `request` through the sweeper pipeline to a receipt of `status`.
fn finalize_sweep(
    deposits: &mut AutomaticDeposits,
    request: SweepRequest,
    status: TransactionStatus,
) {
    let id = request.id;
    let transaction = request
        .create_transaction(
            deposits.next_sweeper_transaction_nonce(),
            gas_fee_estimate(),
            request.gas_limit(),
            EthereumNetwork::Sepolia,
        )
        .expect("BUG: the fixture prices the request with the estimate it creates with");
    deposits.record_created_sweep_transaction(id, transaction.clone());
    let signed = Signed::from((
        transaction,
        TransactionSignature {
            signature_y_parity: false,
            r: Default::default(),
            s: Default::default(),
        },
    ));
    let receipt = TransactionReceipt {
        block_hash: Hash([0x11; 32]),
        block_number: BlockNumber::new(4_190_269),
        effective_gas_price: signed.transaction().max_fee_per_gas(),
        gas_used: signed.transaction().gas_limit(),
        status,
        transaction_hash: signed.hash(),
    };
    deposits.record_signed_sweep_transaction(signed);
    deposits.record_finalized_sweep_transaction(id, &receipt);
}

/// An [`AutomaticDeposits`] whose sweep queue holds exactly these funded pairs.
fn queued(pairs: &[(Account, Address)]) -> AutomaticDeposits {
    let mut deposits = AutomaticDeposits::default();
    queue(&mut deposits, pairs);
    assert_eq!(deposits.sweep_len(), pairs.len());
    deposits
}

fn queue(deposits: &mut AutomaticDeposits, pairs: &[(Account, Address)]) {
    for (account, token) in pairs {
        deposits
            .watch_deposit(ts(0), *account, *token, deposit_address(account))
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

fn accounts_in(batches: &BTreeMap<Address, Vec<SweepTarget>>, token: Address) -> Vec<Account> {
    batches
        .get(&token)
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
        erc20_contract_address: token,
        address: deposit_address(&account),
        expires_at_nanos: expires_at,
        last_scanned_block: None,
        scan_count: 0,
    }
}
