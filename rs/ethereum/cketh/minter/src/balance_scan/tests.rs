use super::*;
use crate::erc20::CkErc20Token;
use crate::lifecycle::EthereumNetwork;
use crate::test_fixtures::initial_state;

const DEPOSIT_ADDRESS: Address = Address::new([0x11; 20]);
const TOKEN_CONTRACT: Address = Address::new([0x22; 20]);
const DEPOSIT_ADDRESS_2: Address = Address::new([0x33; 20]);
const SEC: u64 = 1_000_000_000;

fn account(owner: u8) -> Account {
    Account {
        owner: candid::Principal::from_slice(&[owner]),
        subaccount: None,
    }
}

fn sepolia_token() -> CkErc20Token {
    CkErc20Token {
        erc20_ethereum_network: EthereumNetwork::Sepolia,
        erc20_contract_address: TOKEN_CONTRACT,
        ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
        ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
    }
}

#[test]
fn should_count_candidates_at_and_above_minimum_only() {
    let min = Erc20Value::from(1_000_000_u64);
    let pairs = vec![
        (account(1), TOKEN_CONTRACT),
        (account(2), TOKEN_CONTRACT),
        (account(3), TOKEN_CONTRACT),
        (account(4), TOKEN_CONTRACT),
    ];
    let balances = vec![
        Some(Erc20Value::from(1_000_000_u64)),
        Some(Erc20Value::from(999_999_u64)),
        Some(Erc20Value::from(1_000_001_u64)),
        None,
    ];

    // Exactly the entries at/above `min`: account(1) (== min) and account(3) (> min);
    // account(2) (< min) and account(4) (None) are excluded.
    assert_eq!(count_candidates(&pairs, &balances, min), 2);
}

#[test]
fn should_have_valid_scan_schedule() {
    assert_eq!(SCAN_SCHEDULE_SECS.len(), 33);
    assert_eq!(SCAN_SCHEDULE_SECS[0], 30);
    assert_eq!(SCAN_SCHEDULE_SECS[SCAN_SCHEDULE_SECS.len() - 1], 84600);

    for window in SCAN_SCHEDULE_SECS.windows(2) {
        assert!(
            window[0] < window[1],
            "schedule must be strictly increasing"
        );
    }

    let day_secs = 86400;
    assert!(SCAN_SCHEDULE_SECS[SCAN_SCHEDULE_SECS.len() - 1] < day_secs);
}

#[test]
fn should_compute_scan_due_from_registration_time() {
    let t0 = Timestamp::from_nanos(1_000);
    let at = |secs: u64| Timestamp::from_nanos(t0.as_nanos() + secs * SEC);

    assert!(!is_scan_due(t0, 0, at(29)));
    assert!(is_scan_due(t0, 0, at(30)));
    assert!(is_scan_due(t0, 0, at(31)));

    assert!(!is_scan_due(t0, 1, at(59)));
    assert!(is_scan_due(t0, 1, at(60)));

    assert!(!is_scan_due(t0, 10, at(5399)));
    assert!(is_scan_due(t0, 10, at(5400)));

    assert!(!is_scan_due(t0, 33, at(1_000_000)));
    assert!(!is_scan_due(t0, 34, at(1_000_000)));
}

#[test]
fn should_select_only_due_addresses() {
    let t0 = Timestamp::from_nanos(1_000);
    let mut state = initial_state();
    state.record_add_ckerc20_token(sepolia_token());
    state
        .automatic_deposits
        .watch_address_for_account(t0, account(1), DEPOSIT_ADDRESS)
        .expect("BUG: failed to register live address");
    state
        .automatic_deposits
        .watch_address_for_account(t0, account(2), DEPOSIT_ADDRESS_2)
        .expect("BUG: failed to register live address");
    state.deposit_scan_progress.insert(account(2), 5);

    let now = Timestamp::from_nanos(t0.as_nanos() + 40 * SEC);
    let (due_accounts, pairs, calls) = build_due_calls(&state, now);

    assert_eq!(due_accounts, vec![account(1)]);
    assert_eq!(pairs, vec![(account(1), TOKEN_CONTRACT)]);
    assert_eq!(
        calls,
        vec![BalanceOfCall {
            token: TOKEN_CONTRACT,
            holder: DEPOSIT_ADDRESS,
        }]
    );
}

#[test]
fn should_keep_due_accounts_pairs_and_calls_parallel() {
    let t0 = Timestamp::from_nanos(1_000);
    let mut state = initial_state();
    state.record_add_ckerc20_token(sepolia_token());
    state
        .automatic_deposits
        .watch_address_for_account(t0, account(1), DEPOSIT_ADDRESS)
        .expect("BUG: failed to register live address");
    state
        .automatic_deposits
        .watch_address_for_account(t0, account(2), DEPOSIT_ADDRESS_2)
        .expect("BUG: failed to register live address");

    let now = Timestamp::from_nanos(t0.as_nanos() + 30 * SEC);
    let (due_accounts, pairs, calls) = build_due_calls(&state, now);

    assert_eq!(due_accounts, vec![account(1), account(2)]);
    assert_eq!(
        pairs,
        vec![(account(1), TOKEN_CONTRACT), (account(2), TOKEN_CONTRACT),]
    );
    assert_eq!(
        calls,
        vec![
            BalanceOfCall {
                token: TOKEN_CONTRACT,
                holder: DEPOSIT_ADDRESS,
            },
            BalanceOfCall {
                token: TOKEN_CONTRACT,
                holder: DEPOSIT_ADDRESS_2,
            },
        ]
    );
}

#[test]
fn should_not_select_addresses_past_schedule_end() {
    let t0 = Timestamp::from_nanos(1_000);
    let mut state = initial_state();
    state.record_add_ckerc20_token(sepolia_token());
    state
        .automatic_deposits
        .watch_address_for_account(t0, account(1), DEPOSIT_ADDRESS)
        .expect("BUG: failed to register live address");
    state
        .deposit_scan_progress
        .insert(account(1), SCAN_SCHEDULE_SECS.len() as u8);

    let now = Timestamp::from_nanos(t0.as_nanos() + 84_600 * SEC);
    let (due_accounts, pairs, calls) = build_due_calls(&state, now);

    assert!(due_accounts.is_empty());
    assert!(pairs.is_empty());
    assert!(calls.is_empty());
}
