use super::*;
use crate::erc20::CkErc20Token;
use crate::lifecycle::EthereumNetwork;
use crate::test_fixtures::initial_state;

const DEPOSIT_ADDRESS: Address = Address::new([0x11; 20]);
const TOKEN_CONTRACT: Address = Address::new([0x22; 20]);

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
fn should_build_parallel_calls_for_live_addresses_and_tokens() {
    let now = Timestamp::from_nanos(1_000);
    let mut state = initial_state();
    state.record_add_ckerc20_token(sepolia_token());
    state
        .automatic_deposits
        .watch_address_for_account(now, account(1), DEPOSIT_ADDRESS)
        .expect("BUG: failed to register live address");

    let (addresses_scanned, pairs, calls) = build_calls(&state, now);

    assert_eq!(addresses_scanned, 1);
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
fn should_skip_expired_addresses_in_build_calls() {
    let now = Timestamp::from_nanos(1_000);
    let mut state = initial_state();
    state.record_add_ckerc20_token(sepolia_token());
    state
        .automatic_deposits
        .watch_address_for_account(now, account(1), DEPOSIT_ADDRESS)
        .expect("BUG: failed to register live address");

    let (addresses_scanned, pairs, calls) = build_calls(&state, Timestamp::from_nanos(u64::MAX));

    assert_eq!(addresses_scanned, 0);
    assert!(pairs.is_empty());
    assert!(calls.is_empty());
}
