use super::*;
use crate::memo;
use crate::memo::tests::{arb_burn_memo, arb_mint_memo};
use crate::queries::DecodeLedgerMemoError::InvalidMemo;
use assert_matches::assert_matches;
use proptest::prelude::*;

#[test]
fn test_decode_burn_convert_memo_is_stable() {
    let encoded_memo = vec![
        130, 0, 131, 120, 62, 98, 99, 49, 112, 116, 102, 101, 57, 116, 117, 106, 102, 99, 113, 107,
        115, 52, 104, 113, 107, 108, 117, 102, 100, 52, 122, 53, 112, 51, 101, 108, 54, 108, 117,
        109, 109, 120, 122, 121, 104, 106, 110, 114, 53, 101, 116, 112, 101, 114, 121, 120, 106,
        52, 104, 57, 113, 114, 122, 117, 108, 50, 115, 246, 246,
    ];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Burn(Some(BurnMemo::Convert {
        address: Some("bc1ptfe9tujfcqks4hqklufd4z5p3el6lummxzyhjnr5etperyxj4h9qrzul2s".to_string()),
        kyt_fee: None,
        status: None,
    }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn test_decode_mint_convert_memo_is_stable() {
    let encoded_memo = vec![
        130, 0, 131, 88, 32, 39, 78, 251, 50, 13, 191, 179, 251, 19, 4, 167, 16, 210, 217, 69, 205,
        96, 249, 132, 85, 201, 243, 32, 2, 237, 70, 177, 202, 65, 218, 170, 31, 0, 24, 100,
    ];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Mint(Some(MintMemo::Convert {
        txid: Some(vec![
            39, 78, 251, 50, 13, 191, 179, 251, 19, 4, 167, 16, 210, 217, 69, 205, 96, 249, 132,
            85, 201, 243, 32, 2, 237, 70, 177, 202, 65, 218, 170, 31,
        ]),
        vout: Some(0),
        kyt_fee: Some(100),
    }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn test_decode_mint_reimburse_withdrawal_memo_is_stable() {
    let encoded_memo = vec![130, 3, 129, 25, 4, 210];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Mint(Some(
        MintMemo::ReimburseWithdrawal {
            withdrawal_id: 1234,
        },
    ))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn test_decode_empty_array() {
    let encoded_memo = vec![];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    assert_matches!(
        result,
        Err(Some(InvalidMemo(msg)))
        if msg.contains("Could not decode")
    );
}

#[test]
fn test_decode_bogus_memo_bytes() {
    let encoded_memo = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    assert_matches!(
        result,
        Err(Some(InvalidMemo(msg)))
        if msg.contains("Could not decode")
    );
}

#[test]
fn test_decode_too_long_memo() {
    let encoded_memo = vec![0x67; 1 + CKBTC_LEDGER_MEMO_SIZE as usize];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs { encoded_memo });

    assert_matches!(
        result,
        Err(Some(InvalidMemo(msg)))
        if msg.contains("Memo longer than permitted length")
    );
}

proptest! {
    #[test]
    fn prop_decode_mint_memo_roundtrip(mint_memo in arb_mint_memo()) {
        let encoded = memo::encode(&mint_memo);
        let result = decode_ledger_memo(DecodeLedgerMemoArgs {
            encoded_memo: encoded,
        });

        let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Mint(Some(MintMemo::from(mint_memo)))));
        prop_assert_eq!(result, expected, "Decoded Memo mismatch: {:?} vs {:?}", result, expected);
    }

    #[test]
    fn prop_decode_burn_memo_roundtrip(burn_memo in arb_burn_memo()) {
        // Filter out ambiguous cases: BurnMemo needs address field to be distinguishable
        // from MintMemo because the other fields (kyt_fee, status/vout) can have ambiguous
        // CBOR encodings at the same field positions. We don't need this filtering for mint memos,
        // because we currently first try to decode a memo as a mint memo.
        let has_distinguishing_field = match &burn_memo {
            memo::BurnMemo::Convert { address, .. } => address.is_some()
        };
        prop_assume!(has_distinguishing_field);

        let encoded = memo::encode(&burn_memo);
        let result = decode_ledger_memo(DecodeLedgerMemoArgs {
            encoded_memo: encoded,
        });

        let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Burn(Some(BurnMemo::from(burn_memo)))));
        prop_assert_eq!(result, expected, "Decoded Memo mismatch: {:?} vs {:?}", result, expected);
    }
}
