use crate::memo::{BurnMemo, MintMemo, Status};
use crate::state::LedgerBurnIndex;
use icrc_ledger_types::icrc1::transfer::Memo;
use proptest::prelude::*;

proptest! {
    #[test]
    fn mint_memo_round_trip(mint_memo in arb_mint_memo()) {
        let mut buf = vec![];
        minicbor::encode(&mint_memo, &mut buf).expect("encoding should succeed");

        let decoded: MintMemo = minicbor::decode(&buf).expect("decoding should succeed");

        prop_assert_eq!(mint_memo, decoded);
    }

    #[test]
    fn burn_memo_round_trip(burn_memo in arb_burn_memo()) {
        let mut buf = vec![];
        minicbor::encode(&burn_memo, &mut buf).expect("encoding should succeed");

        let decoded: BurnMemo = minicbor::decode(&buf).expect("decoding should succeed");

        prop_assert_eq!(burn_memo, decoded);
    }

    #[test]
    fn should_be_less_than_80_bytes(mint_memo in arb_mint_memo(), burn_memo in arb_burn_memo()) {
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

pub(crate) fn arb_mint_memo() -> impl Strategy<Value = MintMemo<'static>> {
    prop_oneof![
        arb_mint_convert_memo(),
        arb_mint_kyt_memo(),
        arb_mint_kyt_fail_memo(),
        arb_mint_reimburse_withdrawal_memo()
    ]
}

pub(crate) fn arb_mint_convert_memo() -> impl Strategy<Value = MintMemo<'static>> {
    (
        proptest::option::of(proptest::collection::vec(any::<u8>(), 32)),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(|(txid, vout, kyt_fee)| {
            MintMemo::Convert {
                txid: txid.as_ref().map(|v| {
                    // For property testing, we leak memory intentionally to get 'static lifetime
                    // This is acceptable in tests as they are short-lived
                    let leaked: &'static [u8] = Box::leak(v.clone().into_boxed_slice());
                    leaked
                }),
                vout,
                kyt_fee,
            }
        })
}

pub(crate) fn arb_mint_kyt_memo() -> impl Strategy<Value = MintMemo<'static>> {
    Just(MintMemo::Kyt)
}

pub(crate) fn arb_mint_kyt_fail_memo() -> impl Strategy<Value = MintMemo<'static>> {
    (
        proptest::option::of(any::<u64>()),
        proptest::option::of(arb_status()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(kyt_fee, status, associated_burn_index)| MintMemo::KytFail {
                kyt_fee,
                status,
                associated_burn_index,
            },
        )
}

pub(crate) fn arb_mint_reimburse_withdrawal_memo() -> impl Strategy<Value = MintMemo<'static>> {
    any::<u64>().prop_map(|withdrawal_id| MintMemo::ReimburseWithdrawal {
        withdrawal_id: LedgerBurnIndex::from(withdrawal_id),
    })
}

pub(crate) fn arb_burn_memo() -> impl Strategy<Value = BurnMemo<'static>> {
    (
        proptest::option::of("[a-z0-9]{20,62}"),
        proptest::option::of(any::<u64>()),
        proptest::option::of(arb_status()),
    )
        .prop_map(|(address, kyt_fee, status)| {
            BurnMemo::Convert {
                address: address.as_ref().map(|s| {
                    // For property testing, we leak memory intentionally to get 'static lifetime
                    // This is acceptable in tests as they are short-lived
                    let leaked: &'static str = Box::leak(s.clone().into_boxed_str());
                    leaked
                }),
                kyt_fee,
                status,
            }
        })
}

pub(crate) fn arb_status() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Accepted),
        Just(Status::Rejected),
        Just(Status::CallFailed),
    ]
}

#[test]
fn should_have_a_strategy_for_each_mint_memo_variant() {
    let memo_to_match = MintMemo::Convert {
        txid: None,
        vout: None,
        kyt_fee: None,
    };
    let _ = match memo_to_match {
        MintMemo::Convert { .. } => arb_mint_convert_memo().boxed(),
        MintMemo::Kyt => arb_mint_kyt_memo().boxed(),
        MintMemo::KytFail { .. } => arb_mint_kyt_fail_memo().boxed(),
        MintMemo::ReimburseWithdrawal { .. } => arb_mint_reimburse_withdrawal_memo().boxed(),
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
        BurnMemo::Convert { .. } => arb_burn_memo().boxed(),
    };
}
