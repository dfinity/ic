use super::*;

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
fn should_count_candidates_at_and_above_minimum_only() {
    let min = Erc20Value::from(1_000_000_u64);
    let balances = vec![
        Erc20Value::from(1_000_000_u64), // == min      -> candidate
        Erc20Value::from(999_999_u64),   // < min       -> excluded
        Erc20Value::from(1_000_001_u64), // > min       -> candidate
        Erc20Value::from(0_u64),         // failed/zero -> excluded
    ];

    assert_eq!(count_candidates(&balances, min), 2);
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
