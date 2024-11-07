use candid::Nat;
use ic_base_types::PrincipalId;
use ic_cketh_minter::memo::MintMemo;
use ic_cketh_test_utils::ckerc20::{
    CkErc20Setup,
    DepositCkErc20WithSubaccountParams,
    ONE_USDC,
};
use ic_cketh_test_utils::flow::{
    DepositCkEthParams,
    DepositCkEthWithSubaccountParams,
    DepositParams,
};
use ic_cketh_test_utils::{
    CkEthSetup,
    DEFAULT_DEPOSIT_FROM_ADDRESS,
    DEFAULT_DEPOSIT_LOG_INDEX,
    DEFAULT_DEPOSIT_TRANSACTION_HASH,
    DEFAULT_ERC20_DEPOSIT_LOG_INDEX,
    DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH,
    DEFAULT_PRINCIPAL_ID,
    DEFAULT_USER_SUBACCOUNT,
    EXPECTED_BALANCE,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;

#[test]
fn should_deposit_and_withdraw_cketh() {
    let cketh = CkEthSetup::default_with_maybe_evm_rpc().add_support_for_subaccount();

    cketh
        .deposit(DepositCkEthWithSubaccountParams {
            recipient_subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            ..Default::default()
        })
        .expect_mint()
        .call_ledger_get_transaction(0_u8)
        .expect_mint(Mint {
            amount: EXPECTED_BALANCE.into(),
            to: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
    //TODO XC-221: continue test to withdraw from subaccount
}

#[test]
fn should_deposit_ckerc20() {
    let ckerc20 = CkErc20Setup::default()
        .add_supported_erc20_tokens()
        .add_support_for_subaccount();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let caller = ckerc20.caller();

    ckerc20
        .deposit(DepositCkErc20WithSubaccountParams::new(
            ONE_USDC,
            ckusdc.clone(),
            Account {
                owner: caller,
                subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            },
        ))
        .expect_mint()
        .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 0_u8)
        .expect_mint(Mint {
            amount: Nat::from(ONE_USDC),
            to: Account {
                owner: caller,
                subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
    //TODO XC-221: continue test to withdraw from subaccount
}

#[test]
fn should_deposit_cketh_without_subaccount_and_ckerc20_with_subaccount() {
    let ckerc20 = CkErc20Setup::default()
        .add_supported_erc20_tokens()
        .add_support_for_subaccount();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let caller = ckerc20.caller();
    let ckusdc_subaccount = Some([43; 32]);

    ckerc20
        .deposit(DepositCkErc20WithSubaccountParams {
            cketh_deposit: Some(DepositParams::from(DepositCkEthParams {
                recipient: caller,
                ..Default::default()
            })),
            ..DepositCkErc20WithSubaccountParams::new(
                ONE_USDC,
                ckusdc.clone(),
                Account {
                    owner: caller,
                    subaccount: ckusdc_subaccount,
                },
            )
        })
        .expect_mint()
        .call_cketh_ledger_get_transaction(0_u8)
        .expect_mint(Mint {
            amount: EXPECTED_BALANCE.into(),
            to: Account {
                owner: caller,
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        })
        .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 0_u8)
        .expect_mint(Mint {
            amount: ONE_USDC.into(),
            to: Account {
                owner: caller,
                subaccount: ckusdc_subaccount,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
    //TODO XC-221: continue test to withdraw from subaccount
}

#[test]
fn should_deposit_cketh_with_subaccount_and_ckerc20_with_subaccount() {
    let ckerc20 = CkErc20Setup::default()
        .add_supported_erc20_tokens()
        .add_support_for_subaccount();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let caller = ckerc20.caller();
    let cketh_subaccount = Some(DEFAULT_USER_SUBACCOUNT);
    let ckusdc_subaccount = Some([43; 32]);
    assert_ne!(cketh_subaccount, ckusdc_subaccount);

    ckerc20
        .deposit(DepositCkErc20WithSubaccountParams {
            cketh_deposit: Some(DepositParams::from(DepositCkEthWithSubaccountParams {
                recipient: caller,
                recipient_subaccount: cketh_subaccount,
                ..Default::default()
            })),
            ..DepositCkErc20WithSubaccountParams::new(
                ONE_USDC,
                ckusdc.clone(),
                Account {
                    owner: caller,
                    subaccount: ckusdc_subaccount,
                },
            )
        })
        .expect_mint()
        .call_cketh_ledger_get_transaction(0_u8)
        .expect_mint(Mint {
            amount: EXPECTED_BALANCE.into(),
            to: Account {
                owner: caller,
                subaccount: cketh_subaccount,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        })
        .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 0_u8)
        .expect_mint(Mint {
            amount: ONE_USDC.into(),
            to: Account {
                owner: caller,
                subaccount: ckusdc_subaccount,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
    //TODO XC-221: continue test to withdraw from subaccount
}
