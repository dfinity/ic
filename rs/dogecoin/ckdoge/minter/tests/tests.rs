use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
use ic_ckdoge_minter_test_utils::{
    DOGECOIN_ADDRESS_1, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, assert_trap,
};

#[test]
fn should_fail_withdrawal() {
    let setup = Setup::default();
    let minter = setup.minter();
    let correct_withdrawal_args = RetrieveDogeWithApprovalArgs {
        amount: RETRIEVE_DOGE_MIN_AMOUNT,
        address: DOGECOIN_ADDRESS_1.to_string(),
        from_subaccount: None,
    };

    assert_trap(
        minter.update_call_retrieve_doge_with_approval(
            Principal::anonymous(),
            &correct_withdrawal_args,
        ),
        "anonymous caller not allowed",
    );

    assert_eq!(
        minter.retrieve_doge_with_approval(
            USER_PRINCIPAL,
            &RetrieveDogeWithApprovalArgs {
                amount: RETRIEVE_DOGE_MIN_AMOUNT - 1,
                ..correct_withdrawal_args.clone()
            },
        ),
        Err(RetrieveDogeWithApprovalError::AmountTooLow(
            RETRIEVE_DOGE_MIN_AMOUNT
        ))
    );

    assert_eq!(
        minter.retrieve_doge_with_approval(
            USER_PRINCIPAL,
            &RetrieveDogeWithApprovalArgs {
                amount: RETRIEVE_DOGE_MIN_AMOUNT,
                ..correct_withdrawal_args.clone()
            },
        ),
        Err(RetrieveDogeWithApprovalError::InsufficientAllowance { allowance: 0 })
    )

    // TODO XC-495: create sufficient allowance (which requires funds to pay for the ledger fee)
    // and test failure when insufficient funds
}

mod get_doge_address {
    use candid::Principal;
    use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
    use ic_ckdoge_minter_test_utils::{Setup, USER_PRINCIPAL, assert_trap};

    #[test]
    fn should_fail_to_get_doge_address() {
        let setup = Setup::default();
        let minter = setup.minter();

        assert_trap(
            minter.update_call_get_doge_address(
                USER_PRINCIPAL,
                &GetDogeAddressArgs {
                    owner: Some(Principal::anonymous()),
                    subaccount: None,
                },
            ),
            "owner must be non-anonymous",
        );

        assert_trap(
            minter.update_call_get_doge_address(
                Principal::anonymous(),
                &GetDogeAddressArgs {
                    owner: None,
                    subaccount: None,
                },
            ),
            "owner must be non-anonymous",
        );
    }

    #[test]
    fn should_get_doge_address() {
        let setup = Setup::default();
        let minter = setup.minter();

        let address_from_caller = minter.get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: None,
                subaccount: None,
            },
        );

        let address_with_owner = minter.get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: Some(USER_PRINCIPAL),
                subaccount: None,
            },
        );

        assert_eq!(address_from_caller, address_with_owner);
        assert_eq!(
            address_from_caller, "D95u8BQWiN21ER5LqrNwSk4WDVe25WHWHT",
            "BUG: result of public key derivation changed!"
        );

        let address_with_subaccount = minter.get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: None,
                subaccount: Some([42_u8; 32]),
            },
        );
        assert_ne!(address_from_caller, address_with_subaccount);
        assert_eq!(
            address_with_subaccount, "DPZ2c7wS53i9nGrMh25iCZABdPs718NRA9",
            "BUG: result of public key derivation changed!"
        );
    }
}

mod deposit {
    use ic_ckdoge_minter::{
        MintMemo, OutPoint, UpdateBalanceArgs, Utxo, UtxoStatus, candid_api::GetDogeAddressArgs,
        memo_encode,
    };
    use ic_ckdoge_minter_test_utils::{Setup, USER_PRINCIPAL, txid};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use icrc_ledger_types::icrc3::transactions::Mint;

    #[test]
    fn should_mint_ckdoge() {
        let setup = Setup::default();
        let minter = setup.minter();
        let ledger = setup.ledger();
        let dogecoin = setup.dogecoin();
        let subaccount = Some([42_u8; 32]);

        let deposit_address = minter.get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: None,
                subaccount,
            },
        );

        let utxo = Utxo {
            height: 0,
            outpoint: OutPoint {
                txid: txid(),
                vout: 1,
            },
            value: 1_000_000_000,
        };
        dogecoin.simulate_transaction(utxo.clone(), deposit_address);

        let utxo_status = minter
            .update_balance(
                USER_PRINCIPAL,
                &UpdateBalanceArgs {
                    owner: Some(USER_PRINCIPAL),
                    subaccount,
                },
            )
            .unwrap();
        assert_eq!(
            utxo_status,
            vec![UtxoStatus::Minted {
                block_index: 0,
                minted_amount: utxo.value,
                utxo: utxo.clone(),
            }]
        );

        ledger
            .assert_that_transaction(0_u64)
            .is_equal_to_mint_ignoring_timestamp(Mint {
                amount: utxo.value.into(),
                to: Account {
                    owner: USER_PRINCIPAL,
                    subaccount,
                },
                memo: Some(Memo::from(memo_encode(&MintMemo::Convert {
                    txid: Some(utxo.outpoint.txid.as_ref()),
                    vout: Some(utxo.outpoint.vout),
                    kyt_fee: Some(0),
                }))),
                created_at_time: None,
            });
    }
}
