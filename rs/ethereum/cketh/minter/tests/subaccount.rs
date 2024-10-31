use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::memo::MintMemo;
use ic_cketh_test_utils::{
    flow::DepositParams, CkEthSetup, CKETH_WITHDRAWAL_AMOUNT, DEFAULT_DEPOSIT_FROM_ADDRESS,
    DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_DEPOSIT_TRANSACTION_HASH, DEFAULT_PRINCIPAL_ID,
    DEFAULT_USER_SUBACCOUNT, DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS, EXPECTED_BALANCE,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;

#[test]
fn should_deposit_and_withdraw_cketh() {
    let cketh = CkEthSetup::default_with_maybe_evm_rpc();
    let minter: Principal = cketh.minter_id.into();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let destination = DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string();

    let cketh = cketh
        .deposit(DepositParams {
            recipient_subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            ..DepositParams::default()
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
}
