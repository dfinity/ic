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

#[test]
fn should_mark_never_scanned_address_as_due() {
    let deposits = deposits_from(vec![scan_state(account(0), ts(window_nanos()), None, 0)]);

    let due: Vec<_> = deposits
        .addresses_due_for_scan(ts(0), BlockNumber::new(1_000))
        .collect();

    assert_eq!(due, vec![(account(0), deposit_address(&account(0)))]);
}

#[test]
fn should_mark_scanned_address_due_only_after_the_current_gap() {
    // scan_count 2 selects a 60s gap, i.e. 5 blocks at 12s per block.
    let last_scanned = BlockNumber::new(1_000);
    let deposits = deposits_from(vec![scan_state(
        account(0),
        ts(window_nanos()),
        Some(last_scanned),
        2,
    )]);
    let gap_blocks = SCAN_GAP_SECS[2] / SECS_PER_BLOCK;
    assert_eq!(gap_blocks, 5);

    let just_before = BlockNumber::new(1_000 + u128::from(gap_blocks) - 1);
    let at_boundary = BlockNumber::new(1_000 + u128::from(gap_blocks));

    assert_eq!(
        deposits.addresses_due_for_scan(ts(0), just_before).count(),
        0,
        "not due one block before the gap elapses"
    );
    assert_eq!(
        deposits
            .addresses_due_for_scan(ts(0), at_boundary)
            .collect::<Vec<_>>(),
        vec![(account(0), deposit_address(&account(0)))],
        "due exactly when the gap elapses"
    );
}

#[test]
fn should_never_yield_an_expired_entry() {
    let deposits = deposits_from(vec![scan_state(account(0), ts(100), None, 0)]);

    assert_eq!(
        deposits
            .addresses_due_for_scan(ts(101), BlockNumber::new(1_000_000))
            .count(),
        0
    );
}

#[test]
fn should_not_yield_address_past_the_schedule_end() {
    let deposits = deposits_from(vec![scan_state(
        account(0),
        ts(window_nanos()),
        Some(BlockNumber::new(1)),
        SCAN_GAP_SECS.len() as u32,
    )]);

    assert_eq!(
        deposits
            .addresses_due_for_scan(ts(0), BlockNumber::new(u128::MAX))
            .count(),
        0
    );
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

#[test]
fn should_decode_registration_without_scan_fields() {
    #[derive(minicbor::Encode)]
    struct OldRegistration {
        #[cbor(n(0), with = "icrc_cbor::principal")]
        owner: Principal,
        #[cbor(n(1), with = "minicbor::bytes")]
        subaccount: Option<[u8; 32]>,
        #[n(2)]
        address: Address,
        #[n(3)]
        expires_at_nanos: Timestamp,
    }

    let account = account(0);
    let old = OldRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(&account),
        expires_at_nanos: ts(42),
    };
    let bytes = minicbor::to_vec(&old).unwrap();

    let decoded: DepositAddressRegistration = minicbor::decode(&bytes).unwrap();

    assert_eq!(decoded.last_scanned_block, None);
    assert_eq!(decoded.scan_count, None);

    // The absent scan_count is restored as 0 through the rebuild path.
    let mut deposits = AutomaticDeposits::default();
    deposits.rebuild_watchlist(&DepositAddressRegistry {
        scan_window_nanos: window_nanos(),
        capacity: 1,
        registrations: vec![decoded],
    });
    let entry = deposits.get_entry(ts(0), &account).unwrap();
    assert_eq!(entry.value.last_scanned_block, None);
    assert_eq!(entry.value.scan_count, 0);
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
        scan_count: Some(scan_count),
    }
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
        scan_count: Some(0),
    }
}
