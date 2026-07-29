use super::{
    AutomaticDeposits, DEPOSIT_ADDRESS_SCAN_WINDOW, DepositRequest, MAX_ACTIVE_DEPOSIT_ADDRESSES,
    SCAN_GAP_SECS, SECS_PER_BLOCK,
};
use crate::endpoints::DepositErc20Error;
use crate::numeric::BlockNumber;
use crate::state::event::{DepositAddressRegistration, DepositAddressRegistry};
use crate::timed_sized_map::{Entry, Timestamp};
use candid::Principal;
use ic_ethereum_types::Address;
use ic_sha3::Keccak256;
use icrc_ledger_types::icrc1::account::Account;

#[test]
fn should_watch_address_for_account() {
    struct Case {
        name: &'static str,
        arms: Vec<(Timestamp, Account)>,
        expected: Result<Entry<DepositRequest>, DepositErc20Error>,
        live_lookups: Vec<Account>,
        expected_len: usize,
    }

    let cases = vec![
        Case {
            name: "arms a fresh address for the scan window",
            arms: vec![(ts(1_000), account(0))],
            expected: Ok(entry(&account(0), ts(1_000 + window_nanos()))),
            live_lookups: vec![account(0)],
            expected_len: 1,
        },
        Case {
            name: "returns the stored entry without re-arming on re-registration",
            arms: vec![(ts(0), account(0)), (ts(1_000), account(0))],
            expected: Ok(entry(&account(0), ts(window_nanos()))),
            live_lookups: vec![account(0)],
            expected_len: 1,
        },
        Case {
            name: "treats missing and all-zero subaccount as the same account",
            arms: vec![
                (ts(0), account_with(None)),
                (ts(1_000), account_with(Some([0_u8; 32]))),
            ],
            expected: Ok(entry(&account_with(None), ts(window_nanos()))),
            live_lookups: vec![account_with(None), account_with(Some([0_u8; 32]))],
            expected_len: 1,
        },
    ];

    for case in cases {
        let mut deposits = AutomaticDeposits::default();
        for (now, account) in &case.arms {
            let outcome =
                deposits.watch_address_for_account(*now, *account, deposit_address(account));
            assert_eq!(outcome, case.expected, "case: {}", case.name);
        }

        assert_eq!(
            deposits.watchlist_snapshot().registrations.len(),
            case.expected_len,
            "case: {}",
            case.name
        );
        for account in &case.live_lookups {
            assert_eq!(
                deposits.get_entry(ts(0), account),
                case.expected.as_ref().ok(),
                "case: {}",
                case.name
            );
        }
    }
}

#[test]
fn should_reject_new_address_when_watchlist_is_full() {
    let mut deposits = AutomaticDeposits::default();
    let capacity = MAX_ACTIVE_DEPOSIT_ADDRESSES.get();
    for i in 0..capacity {
        let account = account(i as u64);
        deposits
            .watch_address_for_account(ts(0), account, deposit_address(&account))
            .unwrap();
    }

    let account = account(capacity as u64);
    let rejected = deposits.watch_address_for_account(ts(0), account, deposit_address(&account));

    assert_eq!(rejected, Err(DepositErc20Error::TooManyActiveAddresses));
    assert_eq!(deposits.watchlist_snapshot().registrations.len(), capacity);
}

#[test]
fn should_rebuild_watchlist_exactly_from_snapshot() {
    let mut source = AutomaticDeposits::default();
    // account(0) and account(1) are armed in the same round, so they share an
    // expiry bucket; a faithful rebuild must preserve their order too.
    source
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();
    source
        .watch_address_for_account(ts(0), account(1), deposit_address(&account(1)))
        .unwrap();
    source
        .watch_address_for_account(ts(10), account(2), deposit_address(&account(2)))
        .unwrap();
    let registry = source.watchlist_snapshot();

    let mut restored = AutomaticDeposits::default();
    restored
        .watch_address_for_account(ts(5), account(9), deposit_address(&account(9)))
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
            registration(account(0), ts(50)),
            registration(account(1), ts(100)),
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
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();
    deposits
        .watch_address_for_account(ts(10), account(1), deposit_address(&account(1)))
        .unwrap();
    deposits
        .watch_address_for_account(ts(0), account(2), deposit_address(&account(2)))
        .unwrap();

    let snapshot = deposits.watchlist_snapshot();

    assert_eq!(
        snapshot.registrations,
        vec![
            registration(account(0), ts(window_nanos())),
            registration(account(2), ts(window_nanos())),
            registration(account(1), ts(10 + window_nanos())),
        ]
    );
}

mod addresses_to_scan_iter {
    use super::{
        BlockNumber, SCAN_GAP_SECS, SECS_PER_BLOCK, account, deposit_address, deposits_from,
        scan_state, ts, window_nanos,
    };

    #[test]
    fn should_mark_never_scanned_address_as_due() {
        let deposits = deposits_from(vec![scan_state(account(0), ts(window_nanos()), None, 0)]);

        let due: Vec<_> = deposits
            .addresses_to_scan_iter(ts(0), BlockNumber::new(1_000))
            .collect();

        assert_eq!(due, vec![(account(0), deposit_address(&account(0)))]);
    }

    #[test]
    fn should_mark_scanned_address_due_only_after_the_current_gap() {
        // A scanned address with scan_count N consults SCAN_GAP_SECS[N-1] (the first backoff scan,
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
                deposits.addresses_to_scan_iter(ts(0), just_before).count(),
                0,
                "scan_count {}: not due one block before the gap elapses",
                case.scan_count
            );
            assert_eq!(
                deposits
                    .addresses_to_scan_iter(ts(0), at_boundary)
                    .collect::<Vec<_>>(),
                vec![(account(0), deposit_address(&account(0)))],
                "scan_count {}: due exactly when the gap elapses",
                case.scan_count
            );
        }
    }

    #[test]
    fn should_never_yield_an_expired_entry() {
        let deposits = deposits_from(vec![scan_state(account(0), ts(100), None, 0)]);

        assert_eq!(
            deposits
                .addresses_to_scan_iter(ts(101), BlockNumber::new(1_000_000))
                .count(),
            0
        );
    }

    #[test]
    fn should_not_yield_address_past_the_schedule_end() {
        // scan_count N consults SCAN_GAP_SECS[N-1], so the schedule is exhausted once N exceeds the
        // number of gaps (index N-1 falls outside SCAN_GAP_SECS).
        let deposits = deposits_from(vec![scan_state(
            account(0),
            ts(window_nanos()),
            Some(BlockNumber::new(1)),
            SCAN_GAP_SECS.len() as u32 + 1,
        )]);

        assert_eq!(
            deposits
                .addresses_to_scan_iter(ts(0), BlockNumber::new(u128::MAX))
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
fn should_reproduce_equal_deposits_across_snapshot_round_trip() {
    let deposits = deposits_from(vec![
        scan_state(
            account(0),
            ts(window_nanos()),
            Some(BlockNumber::new(500)),
            3,
        ),
        scan_state(account(1), ts(window_nanos()), None, 0),
        scan_state(
            account(2),
            ts(10 + window_nanos()),
            Some(BlockNumber::new(1_234)),
            7,
        ),
    ]);

    let registry = deposits.watchlist_snapshot();
    let mut restored = AutomaticDeposits::default();
    restored.rebuild_watchlist(&registry);

    assert_eq!(restored, deposits);
    assert_eq!(restored.watchlist_snapshot(), registry);
}

fn deposits_from(states: Vec<DepositAddressRegistration>) -> AutomaticDeposits {
    let mut deposits = AutomaticDeposits::default();
    deposits.rebuild_watchlist(&DepositAddressRegistry {
        scan_window_nanos: window_nanos(),
        capacity: MAX_ACTIVE_DEPOSIT_ADDRESSES.get() as u64,
        registrations: states,
    });
    deposits
}

fn scan_state(
    account: Account,
    expires_at: Timestamp,
    last_scanned_block: Option<BlockNumber>,
    scan_count: u32,
) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
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
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();
    // Never scanned -> due immediately.
    assert_eq!(
        deposits
            .addresses_to_scan_iter(ts(0), BlockNumber::new(1_000))
            .count(),
        1
    );

    deposits.record_scan(ts(0), &account(0), BlockNumber::new(1_000));

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
            .addresses_to_scan_iter(ts(0), BlockNumber::new(1_000))
            .count(),
        0
    );
    assert_eq!(
        deposits
            .addresses_to_scan_iter(ts(0), BlockNumber::new(2_000))
            .count(),
        1
    );
}

#[test]
fn record_scan_is_a_noop_for_an_expired_account() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();

    // Past the scan window the entry is no longer live; record_scan must not touch it.
    deposits.record_scan(ts(window_nanos() + 1), &account(0), BlockNumber::new(1_000));

    let snapshot = deposits.watchlist_snapshot();
    assert_eq!(snapshot.registrations[0].last_scanned_block, None);
    assert_eq!(snapshot.registrations[0].scan_count, 0);
}

fn ts(nanos: u64) -> Timestamp {
    Timestamp::from_nanos(nanos)
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

fn entry(account: &Account, expires_at: Timestamp) -> Entry<DepositRequest> {
    Entry {
        value: DepositRequest::from(deposit_address(account)),
        expires_at,
    }
}

/// The deposit address is a deterministic function of the account, so a given
/// account always maps to the same address (mirroring the production key
/// derivation).
fn deposit_address(account: &Account) -> Address {
    let mut preimage = account.owner.as_slice().to_vec();
    preimage.extend_from_slice(account.effective_subaccount());
    let hash = Keccak256::hash(&preimage);
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&hash[12..32]);
    Address::new(bytes)
}

fn registration(account: Account, expires_at: Timestamp) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(&account),
        expires_at_nanos: expires_at,
        last_scanned_block: None,
        scan_count: 0,
    }
}
