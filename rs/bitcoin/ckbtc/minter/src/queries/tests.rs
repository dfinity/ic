use super::*;
use crate::queries::DecodeLedgerMemoError::InvalidMemo;
use assert_matches::assert_matches;

#[test]
fn test_decode_burn_convert_memo_is_stable() {
    let encoded_memo = vec![
        130, 0, 131, 120, 62, 98, 99, 49, 112, 116, 102, 101, 57, 116, 117, 106, 102, 99, 113, 107,
        115, 52, 104, 113, 107, 108, 117, 102, 100, 52, 122, 53, 112, 51, 101, 108, 54, 108, 117,
        109, 109, 120, 122, 121, 104, 106, 110, 114, 53, 101, 116, 112, 101, 114, 121, 120, 106,
        52, 104, 57, 113, 114, 122, 117, 108, 50, 115, 246, 246,
    ];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo,
    });

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
    let result = decode_ledger_memo(DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo,
    });

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
    let result = decode_ledger_memo(DecodeLedgerMemoArgs {
        memo_type: MemoType::Mint,
        encoded_memo,
    });

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
fn test_decode_burn_consolidate_memo_is_stable() {
    let encoded_memo = vec![130, 1, 130, 26, 5, 245, 225, 0, 5];
    let result = decode_ledger_memo(DecodeLedgerMemoArgs {
        memo_type: MemoType::Burn,
        encoded_memo,
    });

    let expected: DecodeLedgerMemoResult = Ok(Some(DecodedMemo::Burn(Some(BurnMemo::Consolidate {
        value: 100_000_000,
        inputs: 5,
    }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

#[test]
fn test_decode_empty_array() {
    for memo_type in &[MemoType::Burn, MemoType::Mint] {
        let encoded_memo = vec![];
        let result = decode_ledger_memo(DecodeLedgerMemoArgs {
            memo_type: *memo_type,
            encoded_memo,
        });

        assert_matches!(
            result,
            Err(Some(InvalidMemo(msg)))
            if msg.contains("Error decoding")
        );
    }
}

#[test]
fn test_decode_bogus_memo_bytes() {
    for memo_type in &[MemoType::Burn, MemoType::Mint] {
        let encoded_memo = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = decode_ledger_memo(DecodeLedgerMemoArgs {
            memo_type: *memo_type,
            encoded_memo,
        });

        assert_matches!(
            result,
            Err(Some(InvalidMemo(msg)))
            if msg.contains("Error decoding")
        );
    }
}

#[test]
fn test_decode_too_long_memo() {
    for memo_type in &[MemoType::Burn, MemoType::Mint] {
        let encoded_memo = vec![0x67; 1 + CKBTC_LEDGER_MEMO_SIZE as usize];
        let result = decode_ledger_memo(DecodeLedgerMemoArgs {
            memo_type: *memo_type,
            encoded_memo,
        });

        assert_matches!(
            result,
            Err(Some(InvalidMemo(msg)))
            if msg.contains("Memo longer than permitted length")
        );
    }
}
