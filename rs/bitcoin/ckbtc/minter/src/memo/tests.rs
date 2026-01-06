use crate::memo::{BurnMemo, MintMemo, Status};
use crate::state::LedgerBurnIndex;
use crate::test_fixtures::arbitrary::{
    burn_consolidate_memo, burn_convert_memo, burn_memo, mint_convert_memo, mint_kyt_fail_memo,
    mint_kyt_memo, mint_memo, mint_reimburse_withdrawal_memo,
};
use icrc_ledger_types::icrc1::transfer::Memo;
use proptest::prelude::*;

proptest! {
    #[test]
    fn mint_memo_round_trip(mint_memo in mint_memo()) {
        let mut buf = vec![];
        minicbor::encode(&mint_memo, &mut buf).expect("encoding should succeed");

        let decoded: MintMemo = minicbor::decode(&buf).expect("decoding should succeed");

        prop_assert_eq!(mint_memo, decoded);
    }

    #[test]
    fn burn_memo_round_trip(burn_memo in burn_memo()) {
        let mut buf = vec![];
        minicbor::encode(&burn_memo, &mut buf).expect("encoding should succeed");

        let decoded: BurnMemo = minicbor::decode(&buf).expect("decoding should succeed");

        prop_assert_eq!(burn_memo, decoded);
    }

    #[test]
    fn should_be_less_than_80_bytes(mint_memo in mint_memo(), burn_memo in burn_memo()) {
        let encoded_mint_memo = crate::memo::encode(&mint_memo);
        let memo = Memo::from(encoded_mint_memo);
        prop_assert!(memo.0.len() <= 80, "encoded mint memo is too large: {:?}", memo);

        let encoded_burn_memo = crate::memo::encode(&burn_memo);
        let memo = Memo::from(encoded_burn_memo);
        prop_assert!(memo.0.len() <= 80, "encoded burn memo is too large: {:?}", memo);
    }
}

#[test]
fn encode_mint_convert_memo_is_stable() {
    let txid: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf0,
    ];
    let mint_memo = MintMemo::Convert {
        txid: Some(&txid),
        vout: Some(0),
        kyt_fee: Some(1000),
    };
    let encoded = crate::memo::encode(&mint_memo);
    let memo = Memo::from(encoded);

    assert_eq!(
        memo.0,
        [
            130, 0, 131, 88, 32, 18, 52, 86, 120, 154, 188, 222, 240, 18, 52, 86, 120, 154, 188,
            222, 240, 18, 52, 86, 120, 154, 188, 222, 240, 18, 52, 86, 120, 154, 188, 222, 240, 0,
            25, 3, 232
        ]
    );
}

#[test]
fn encode_mint_reimburse_withdrawal_memo_is_stable() {
    let mint_memo = MintMemo::ReimburseWithdrawal {
        withdrawal_id: LedgerBurnIndex::from(1234_u64),
    };
    let encoded = crate::memo::encode(&mint_memo);
    let memo = Memo::from(encoded);

    assert_eq!(memo.0, [130, 3, 129, 25, 4, 210]);
}

#[test]
fn encode_burn_memo_is_stable() {
    let burn_memo = BurnMemo::Convert {
        address: Some("bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c"),
        kyt_fee: Some(2000),
        status: Some(Status::Accepted),
    };
    let encoded = crate::memo::encode(&burn_memo);
    let memo = Memo::from(encoded);

    assert_eq!(
        memo.0,
        [
            130, 0, 131, 120, 42, 98, 99, 49, 113, 51, 52, 97, 113, 53, 100, 114, 112, 117, 119,
            121, 51, 119, 103, 108, 57, 108, 104, 117, 112, 57, 56, 57, 50, 113, 112, 54, 115, 118,
            114, 56, 108, 100, 122, 121, 121, 55, 99, 25, 7, 208, 0
        ]
    );
}

#[test]
fn should_have_a_strategy_for_each_mint_memo_variant() {
    let memo_to_match = MintMemo::Convert {
        txid: None,
        vout: None,
        kyt_fee: None,
    };
    let _ = match memo_to_match {
        MintMemo::Convert { .. } => mint_convert_memo().boxed(),
        MintMemo::Kyt => mint_kyt_memo().boxed(),
        MintMemo::KytFail { .. } => mint_kyt_fail_memo().boxed(),
        MintMemo::ReimburseWithdrawal { .. } => mint_reimburse_withdrawal_memo().boxed(),
    };
}

#[test]
fn should_have_a_strategy_for_each_burn_memo_variant() {
    let memo_to_match = BurnMemo::Convert {
        address: None,
        kyt_fee: None,
        status: None,
    };

    let _ = match memo_to_match {
        BurnMemo::Convert { .. } => burn_convert_memo().boxed(),
        BurnMemo::Consolidate { .. } => burn_consolidate_memo().boxed(),
    };
}
