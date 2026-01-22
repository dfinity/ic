use crate::CKETH_LEDGER_MEMO_SIZE;
use crate::cbor::tests::check_roundtrip;
use crate::checked_amount::CheckedAmountOf;
use crate::endpoints::{
    BurnMemo as EndpointsBurn, DecodeLedgerMemoArgs, DecodeLedgerMemoError, DecodeLedgerMemoResult,
    DecodedMemo, MemoType, MintMemo as EndpointsMint,
};
use crate::erc20::CkTokenSymbol;
use crate::eth_logs::{ReceivedEthEvent, ReceivedEvent};
use crate::eth_rpc::Hash;
use crate::memo::{Address, BurnMemo, MintMemo, decode_ledger_memo};
use crate::numeric::{BlockNumber, CkTokenAmount, Erc20Value, LedgerBurnIndex, LogIndex, Wei};
use crate::state::transactions::ReimbursementRequest;
use arbitrary::{arb_burn_memo, arb_mint_memo, arb_reimbursement_request};
use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_test_utils::{
    DEFAULT_DEPOSIT_TRANSACTION_HASH, DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS,
    USDC_ERC20_CONTRACT_ADDRESS, USDC_ERC20_CONTRACT_ADDRESS_LOWERCASE,
};
use icrc_ledger_types::icrc1::transfer::Memo;
use proptest::prelude::*;
use std::str::FromStr;

fn endpoints_mint_to_mint_memo(memo: EndpointsMint) -> Result<MintMemo, String> {
    let memo = match memo {
        EndpointsMint::Convert {
            from_address,
            tx_hash,
            log_index,
        } => MintMemo::Convert {
            from_address: Address::from_str(&from_address)?,
            tx_hash: Hash::from_str(&tx_hash)?,
            log_index: LogIndex::try_from(log_index)?,
        },
        EndpointsMint::ReimburseTransaction {
            withdrawal_id,
            tx_hash,
        } => MintMemo::ReimburseTransaction {
            withdrawal_id,
            tx_hash: Hash::from_str(&tx_hash)?,
        },
        EndpointsMint::ReimburseWithdrawal { withdrawal_id } => {
            MintMemo::ReimburseWithdrawal { withdrawal_id }
        }
    };
    Ok(memo)
}

fn endpoints_burn_to_burn_memo(memo: EndpointsBurn) -> Result<BurnMemo, String> {
    let memo = match memo {
        EndpointsBurn::Convert { to_address } => BurnMemo::Convert {
            to_address: Address::from_str(&to_address)?,
        },
        EndpointsBurn::Erc20GasFee {
            ckerc20_token_symbol,
            ckerc20_withdrawal_amount,
            to_address,
        } => BurnMemo::Erc20GasFee {
            ckerc20_token_symbol: CkTokenSymbol::from_str(&ckerc20_token_symbol)?,
            ckerc20_withdrawal_amount: Erc20Value::try_from(ckerc20_withdrawal_amount)?,
            to_address: Address::from_str(&to_address)?,
        },
        EndpointsBurn::Erc20Convert {
            ckerc20_withdrawal_id,
            to_address,
        } => BurnMemo::Erc20Convert {
            ckerc20_withdrawal_id,
            to_address: Address::from_str(&to_address)?,
        },
    };
    Ok(memo)
}

proptest! {
    #[test]
    fn mint_memo_round_trip(mint_memo in arb_mint_memo()) {
        check_roundtrip(&mint_memo)?;
    }

    #[test]
    fn burn_memo_round_trip(burn_memo in arb_burn_memo()) {
        check_roundtrip(&burn_memo)?;
    }

    #[test]
    fn should_be_less_than_80_bytes(mint_memo in arb_mint_memo(), burn_memo in arb_burn_memo()) {
        let encoded_mint_memo = Memo::from(mint_memo);
        prop_assert!(encoded_mint_memo.0.len() <= 80, "encoded mint memo is too large: {:?}", encoded_mint_memo);

        let encoded_burn_memo = Memo::from(burn_memo);
        prop_assert!(encoded_burn_memo.0.len() <= 80, "encoded burn memo is too large: {:?}", encoded_burn_memo);
    }


    #[test]
    fn should_convert_reimbursement_request_to_mint_memo(reimbursement_request in arb_reimbursement_request()) {
        let mint_memo = MintMemo::from(reimbursement_request.clone());

        match mint_memo {
            MintMemo::Convert{ .. } => panic!("BUG: unexpected mint memo variant"),
            MintMemo::ReimburseTransaction{withdrawal_id,tx_hash  } => {
                prop_assert_eq!(withdrawal_id, reimbursement_request.ledger_burn_index.get());
                prop_assert_eq!(tx_hash, reimbursement_request.transaction_hash.unwrap());
            }
            MintMemo::ReimburseWithdrawal{withdrawal_id } => {
                prop_assert_eq!(withdrawal_id, reimbursement_request.ledger_burn_index.get());
            }
        }
    }

    #[test]
    fn should_decode_mint_memo(mint_memo in arb_mint_memo()) {
        let mut buf = vec![];
        minicbor::encode(&mint_memo, &mut buf).expect("encoding should succeed");
        let args = DecodeLedgerMemoArgs {
            memo_type: MemoType::Mint,
            encoded_memo: buf,
        };
        let result = decode_ledger_memo(args);
        let memo = match result.expect("decoding memo failed").unwrap() {
            DecodedMemo::Mint(mint_memo) => mint_memo.unwrap(),
            DecodedMemo::Burn(_) => panic!("found burn memo instead of mint memo"),
        };
        let decoded_memo = endpoints_mint_to_mint_memo(memo).expect("failed to convert back to original memo");
        assert_eq!(mint_memo, decoded_memo);
    }

    #[test]
    fn should_decode_burn_memo(burn_memo in arb_burn_memo()) {
        let mut buf = vec![];
        minicbor::encode(&burn_memo, &mut buf).expect("encoding should succeed");
        let args = DecodeLedgerMemoArgs {
            memo_type: MemoType::Burn,
            encoded_memo: buf,
        };
        let result = decode_ledger_memo(args);
        let memo = match result.expect("decoding memo failed").unwrap() {
            DecodedMemo::Mint(_) => panic!("found mint memo instead of burn memo"),
            DecodedMemo::Burn(burn_memo) => burn_memo.unwrap(),
        };
        let decoded_memo = endpoints_burn_to_burn_memo(memo).expect("failed to convert back to original memo");
        assert_eq!(burn_memo, decoded_memo);
    }
}

#[test]
fn encode_mint_convert_memo_is_stable() {
    let transaction_hash: Hash =
        "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
            .parse()
            .unwrap();
    let from_address: Address = "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
        .parse()
        .unwrap();
    let event = ReceivedEthEvent {
        transaction_hash,
        block_number: BlockNumber::new(3974279),
        log_index: LogIndex::from(39_u8),
        from_address,
        value: Wei::from(10_000_000_000_000_000_u128),
        principal: Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
        subaccount: None,
    };
    let memo: Memo = (&ReceivedEvent::from(event)).into();

    assert_eq!(
        memo.0,
        [
            130, 0, 131, 84, 221, 40, 81, 205, 212, 10, 230, 83, 104, 49, 85, 141, 212, 109, 182,
            47, 172, 122, 132, 77, 88, 32, 112, 95, 130, 104, 97, 200, 2, 180, 7, 132, 62, 153,
            175, 152, 108, 253, 232, 116, 155, 102, 158, 94, 10, 90, 21, 15, 67, 80, 188, 170, 155,
            195, 24, 39,
        ]
    );
}

#[test]
fn encode_mint_reimburse_memo_is_stable() {
    let transaction_hash: Hash =
        "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
            .parse()
            .unwrap();
    let reimbursment_request = ReimbursementRequest {
        ledger_burn_index: LedgerBurnIndex::from(1234_u64),
        reimbursed_amount: CkTokenAmount::from(100_u64),
        to: Principal::anonymous(),
        to_subaccount: None,
        transaction_hash: Some(transaction_hash),
    };
    let memo: Memo = reimbursment_request.into();

    assert_eq!(
        memo.0,
        [
            130, 1, 130, 25, 4, 210, 88, 32, 112, 95, 130, 104, 97, 200, 2, 180, 7, 132, 62, 153,
            175, 152, 108, 253, 232, 116, 155, 102, 158, 94, 10, 90, 21, 15, 67, 80, 188, 170, 155,
            195,
        ]
    );
}

#[test]
fn encode_burn_memo_is_stable() {
    let memo = Memo::from(BurnMemo::Convert {
        to_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
            .parse()
            .unwrap(),
    });

    assert_eq!(
        memo.0,
        [
            130, 0, 129, 84, 221, 40, 81, 205, 212, 10, 230, 83, 104, 49, 85, 141, 212, 109, 182,
            47, 172, 122, 132, 77,
        ]
    );
}

#[test]
fn should_return_error_for_invalid_mint_memo() {
    // empty array
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo: vec![],
    };
    let result = decode_ledger_memo(args);
    assert_matches!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(msg)))
        if msg.contains("Error decoding MintMemo")
    );
    // bogus memo
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo: vec![10u8],
    };
    let result = decode_ledger_memo(args);
    assert_matches!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(msg)))
        if msg.contains("Error decoding MintMemo")
    );
}

#[test]
fn should_decode_ledger_burn_gas_fee_memo() {
    for amount in [
        "0x23",
        "0xffffffffffffffff",                 // u64 max
        "0xffffffffffffffffffffffffffffffff", // u128 max
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // u256 max
    ] {
        let ckerc20_withdrawal_amount =
            CheckedAmountOf::from_str_hex(amount).expect("should decode number");
        let memo = BurnMemo::Erc20GasFee {
            ckerc20_token_symbol: CkTokenSymbol::from_str("ckTEST")
                .expect("failed to create token symbol"),
            ckerc20_withdrawal_amount,
            to_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.parse().unwrap(),
        };
        let mut buf = vec![];
        minicbor::encode(memo, &mut buf).expect("encoding should succeed");
        let args = DecodeLedgerMemoArgs {
            memo_type: MemoType::Burn,
            encoded_memo: buf,
        };
        let result = decode_ledger_memo(args);
        let expected: DecodeLedgerMemoResult =
            Ok(Some(DecodedMemo::Burn(Some(EndpointsBurn::Erc20GasFee {
                ckerc20_token_symbol: "ckTEST".to_string(),
                ckerc20_withdrawal_amount: Nat::from(ckerc20_withdrawal_amount),
                to_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
            }))));
        assert_eq!(
            result, expected,
            "Decoded Memo mismatch: {:?} vs {:?}",
            result, expected
        );
    }
}

#[test]
fn should_decode_ledger_burn_erc20_convert_memo() {
    let memo = BurnMemo::Erc20Convert {
        ckerc20_withdrawal_id: 123u64,
        to_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.parse().unwrap(),
    };
    let mut buf = vec![];
    minicbor::encode(memo, &mut buf).expect("encoding should succeed");
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo: buf,
    };
    let result = decode_ledger_memo(args);
    let expected: DecodeLedgerMemoResult =
        Ok(Some(DecodedMemo::Burn(Some(EndpointsBurn::Erc20Convert {
            ckerc20_withdrawal_id: 123u64,
            to_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn should_use_mixed_case_checksum_while_decoding_address() {
    let memo = BurnMemo::Erc20Convert {
        ckerc20_withdrawal_id: 123u64,
        to_address: USDC_ERC20_CONTRACT_ADDRESS_LOWERCASE.parse().unwrap(),
    };
    let mut buf = vec![];
    minicbor::encode(memo, &mut buf).expect("encoding should succeed");
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo: buf,
    };
    let result = decode_ledger_memo(args);
    let expected: DecodeLedgerMemoResult =
        Ok(Some(DecodedMemo::Burn(Some(EndpointsBurn::Erc20Convert {
            ckerc20_withdrawal_id: 123u64,
            to_address: USDC_ERC20_CONTRACT_ADDRESS.to_string(),
        }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn should_return_error_for_invalid_burn_memo() {
    // empty array
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo: vec![],
    };
    let result = decode_ledger_memo(args);
    assert_matches!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(msg)))
        if msg.contains("Error decoding BurnMemo")
    );
    // bogus memo
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo: vec![10u8],
    };
    let result = decode_ledger_memo(args);
    assert_matches!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(msg)))
        if msg.contains("Error decoding BurnMemo")
    );
}

#[test]
fn should_decode_memo_only_if_size_below_limit() {
    let memo_max_bytes = vec![0u8; CKETH_LEDGER_MEMO_SIZE as usize];
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo: memo_max_bytes,
    };
    let result = decode_ledger_memo(args);
    assert_matches!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(msg)))
        if msg.contains("Error decoding MintMemo")
    );
    let memo_more_than_max_bytes = vec![0u8; CKETH_LEDGER_MEMO_SIZE as usize + 1];
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo: memo_more_than_max_bytes,
    };
    let result = decode_ledger_memo(args);
    assert_eq!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(format!(
            "Memo longer than permitted length {}",
            CKETH_LEDGER_MEMO_SIZE
        ))))
    );

    // Mint convert memo with u256::MAX log_index is above the size limit.
    // We accept that since u128::MAX is still within the limit and should
    // be orders of magnitude larger that the maximum possible log_index.
    let log_index = CheckedAmountOf::from_str_hex(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .expect("should decode number");
    let memo = MintMemo::Convert {
        from_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.parse().unwrap(),
        tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
        log_index,
    };
    let mut buf = vec![];
    minicbor::encode(memo, &mut buf).expect("encoding should succeed");
    let args = DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo: buf,
    };
    let result = decode_ledger_memo(args);
    assert_eq!(
        result,
        Err(Some(DecodeLedgerMemoError::InvalidMemo(format!(
            "Memo longer than permitted length {}",
            CKETH_LEDGER_MEMO_SIZE
        ))))
    );
}

mod arbitrary {
    use crate::eth_rpc::Hash;
    use crate::memo::{BurnMemo, MintMemo};
    use crate::numeric::{LedgerBurnIndex, LogIndex};
    use crate::state::transactions::ReimbursementRequest;
    use crate::test_fixtures::arb::{
        arb_address, arb_checked_amount_of, arb_hash, arb_ledger_subaccount, arb_principal,
    };
    use ic_ethereum_types::Address;
    use proptest::arbitrary::any;
    use proptest::option;
    use proptest::prelude::{BoxedStrategy, Strategy};
    use proptest::prop_oneof;

    pub fn arb_mint_memo() -> BoxedStrategy<MintMemo> {
        prop_oneof![
            arb_mint_convert_memo(),
            arb_mint_reimburse_transaction_memo(),
            arb_mint_reimburse_withdrawal_memo()
        ]
        .boxed()
    }

    fn arb_mint_convert_memo() -> impl Strategy<Value = MintMemo> {
        (arb_hash(), arb_address(), any::<u128>()).prop_map(|(tx_hash, from_address, log_index)| {
            MintMemo::Convert {
                from_address,
                log_index: LogIndex::from(log_index),
                tx_hash,
            }
        })
    }

    fn arb_mint_reimburse_transaction_memo() -> impl Strategy<Value = MintMemo> {
        (arb_hash(), any::<u64>()).prop_map(|(tx_hash, withdrawal_id)| {
            MintMemo::ReimburseTransaction {
                withdrawal_id,
                tx_hash,
            }
        })
    }

    fn arb_mint_reimburse_withdrawal_memo() -> impl Strategy<Value = MintMemo> {
        (any::<u64>()).prop_map(|withdrawal_id| MintMemo::ReimburseWithdrawal { withdrawal_id })
    }
    pub fn arb_burn_memo() -> BoxedStrategy<BurnMemo> {
        prop_oneof![
            arb_burn_cketh_memo(),
            arb_burn_cketh_for_erc20_fee_memo(),
            arb_burn_ckerc20_memo()
        ]
        .boxed()
    }

    fn arb_burn_cketh_memo() -> impl Strategy<Value = BurnMemo> {
        arb_address().prop_map(|to_address| BurnMemo::Convert { to_address })
    }

    fn arb_burn_cketh_for_erc20_fee_memo() -> impl Strategy<Value = BurnMemo> {
        use crate::erc20::test_fixtures::arb_ck_token_symbol;

        (
            arb_ck_token_symbol(),
            arb_checked_amount_of(),
            arb_address(),
        )
            .prop_map(
                |(ckerc20_token_symbol, ckerc20_withdrawal_amount, to_address)| {
                    BurnMemo::Erc20GasFee {
                        ckerc20_token_symbol,
                        ckerc20_withdrawal_amount,
                        to_address,
                    }
                },
            )
    }

    fn arb_burn_ckerc20_memo() -> impl Strategy<Value = BurnMemo> {
        (any::<u64>(), arb_address()).prop_map(|(ckerc20_withdrawal_id, to_address)| {
            BurnMemo::Erc20Convert {
                ckerc20_withdrawal_id,
                to_address,
            }
        })
    }

    pub fn arb_reimbursement_request() -> impl Strategy<Value = ReimbursementRequest> {
        (
            any::<u64>(),
            arb_checked_amount_of(),
            arb_principal(),
            arb_ledger_subaccount(),
            option::of(arb_hash()),
        )
            .prop_map(
                |(ledger_burn_index, reimbursed_amount, to, to_subaccount, transaction_hash)| {
                    ReimbursementRequest {
                        ledger_burn_index: LedgerBurnIndex::from(ledger_burn_index),
                        reimbursed_amount,
                        to,
                        to_subaccount,
                        transaction_hash,
                    }
                },
            )
    }

    #[test]
    fn should_have_a_strategy_for_each_mint_memo_variant() {
        let memo_to_match = MintMemo::ReimburseTransaction {
            withdrawal_id: 0,
            tx_hash: Hash(Default::default()),
        };
        let _ = match memo_to_match {
            MintMemo::Convert { .. } => arb_mint_convert_memo().boxed(),
            MintMemo::ReimburseTransaction { .. } => arb_mint_reimburse_transaction_memo().boxed(),
            MintMemo::ReimburseWithdrawal { .. } => arb_mint_reimburse_withdrawal_memo().boxed(),
        };
    }

    #[test]
    fn should_have_a_strategy_for_each_burn_memo_variant() {
        let memo_to_match = BurnMemo::Convert {
            to_address: Address::new(Default::default()),
        };

        let _ = match memo_to_match {
            BurnMemo::Convert { .. } => arb_burn_cketh_memo().boxed(),
            BurnMemo::Erc20GasFee { .. } => arb_burn_cketh_for_erc20_fee_memo().boxed(),
            BurnMemo::Erc20Convert { .. } => arb_burn_ckerc20_memo().boxed(),
        };
    }
}
