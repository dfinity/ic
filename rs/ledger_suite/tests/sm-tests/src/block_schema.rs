//! Test-only validation of the CBOR encoding of ICRC-1/ICRC-2 ledger blocks.
//!
//! This is a hand-written validator for the legacy ledger block format,
//! expressed with the [`icrc_ledger_types::icrc::generic_value_predicate`]
//! combinators. It replaces the `cddl` crate (and its large, otherwise-unused
//! dependency tree) that previously validated blocks against a `block.cddl`
//! schema file. The CDDL grammar is reproduced inline in the comments below,
//! next to the predicates that enforce it (the original `block.cddl` file
//! remains in the git history). It lives in this test-only crate because it is
//! exercised solely by ledger tests.
//!
//! Note on strictness: the shared `icrc3`/`icrc107` schema validators do not
//! reject *unknown* map keys, because ICRC standards intentionally allow blocks
//! to carry extra fields for forward compatibility. The legacy block format, by
//! contrast, is a closed CDDL map: unknown keys are rejected. We preserve that
//! here with the local [`only_keys`] combinator, so this validator matches the
//! strictness the `cddl` crate provided.

use std::borrow::Cow;
use std::sync::Arc;

use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicate, ValuePredicateFailures, and, element, is, is_array,
        is_blob, is_equal_to, is_map, is_more_or_equal_to, item, len, or,
    },
};

/// The CBOR encoding of the self-describe tag (`#6.55799`,
/// `ic_icrc1::known_tags::SELF_DESCRIBED`): major type 6 with a 2-byte tag,
/// i.e. the three bytes `0xD9 0xD9 0xF7`. Every encoded block starts with it.
const SELF_DESCRIBE_TAG_BYTES: [u8; 3] = [0xD9, 0xD9, 0xF7];

/// Validates that `encoded_block` conforms to the ledger block CBOR schema: the
/// outer self-describe CBOR tag plus the structure of the block content.
pub fn validate(encoded_block: &EncodedBlock) -> Result<(), String> {
    // 1. `Block = #6.55799(BlockContent)`: the encoding must be wrapped in the
    // self-describe CBOR tag.
    if !encoded_block
        .as_slice()
        .starts_with(&SELF_DESCRIBE_TAG_BYTES)
    {
        return Err(
            "expected the block to be wrapped in the self-describe CBOR tag (#6.55799)".to_string(),
        );
    }

    // 2. `BlockContent`: validate the decoded block content.
    let block = encoded_block_to_generic_block(encoded_block);
    block_content_schema()(Cow::Borrowed(&block)).map_err(|e| e.to_string())
}

/// Fails if the map contains any key outside `allowed`.
///
/// CDDL maps are closed by default (a map matches only if every entry is
/// accounted for by the group), so this restores the strictness that the
/// `cddl` crate provided: extra, unexpected keys are rejected.
fn only_keys(allowed: &'static [&'static str]) -> ValuePredicate {
    Arc::new(move |v: Cow<Value>| match v.as_ref() {
        Value::Map(map) => {
            let unknown: Vec<&str> = map
                .keys()
                .map(String::as_str)
                .filter(|k| !allowed.contains(k))
                .collect();
            if unknown.is_empty() {
                Ok(())
            } else {
                Err(ValuePredicateFailures::new(format!(
                    "unexpected key(s) in map: {}",
                    unknown.join(", ")
                )))
            }
        }
        _ => Err(ValuePredicateFailures::new("expected a map")),
    })
}

/// `Account = [1*2 bytes]`: an array of one or two byte strings.
fn is_account() -> ValuePredicate {
    and(vec![
        is_array(),
        or(vec![
            and(vec![len(is_equal_to(1)), element(0, is_blob())]),
            and(vec![
                len(is_equal_to(2)),
                element(0, is_blob()),
                element(1, is_blob()),
            ]),
        ]),
    ])
}

/// `TransactionContent = { MintTx // BurnTx // TransferTx // ApproveTx }`.
fn transaction_content_schema() -> ValuePredicate {
    use ItemRequirement::*;

    // `Amount = uint`, `Timestamp = uint`: non-negative integers.
    let is_amount = || is_more_or_equal_to(0);
    let is_timestamp = || is_more_or_equal_to(0);
    // `Memo = bytes`.
    let is_memo = || is_blob();

    // `TxCommon = ( amt: Amount, ? memo: Memo, ? ts: Timestamp )`.
    let tx_common = || {
        vec![
            item("amt", Required, is_amount()),
            item("memo", Optional, is_memo()),
            item("ts", Optional, is_timestamp()),
        ]
    };

    // `MintTx = ( op: "mint", to: Account, ? fee: Amount, TxCommon )`.
    let is_mint = and([
        vec![
            is_map(),
            only_keys(&["op", "to", "fee", "amt", "memo", "ts"]),
            item("op", Required, is(Value::text("mint"))),
            item("to", Required, is_account()),
            item("fee", Optional, is_amount()),
        ],
        tx_common(),
    ]
    .concat());

    // `BurnTx = ( op: "burn", from: Account, ? spender: Account, ? fee: Amount, TxCommon )`.
    let is_burn = and([
        vec![
            is_map(),
            only_keys(&["op", "from", "spender", "fee", "amt", "memo", "ts"]),
            item("op", Required, is(Value::text("burn"))),
            item("from", Required, is_account()),
            item("spender", Optional, is_account()),
            item("fee", Optional, is_amount()),
        ],
        tx_common(),
    ]
    .concat());

    // `TransferTx = ( op: "xfer", from: Account, to: Account, ? spender: Account, ? fee: Amount, TxCommon )`.
    let is_transfer = and([
        vec![
            is_map(),
            only_keys(&["op", "from", "to", "spender", "fee", "amt", "memo", "ts"]),
            item("op", Required, is(Value::text("xfer"))),
            item("from", Required, is_account()),
            item("to", Required, is_account()),
            item("spender", Optional, is_account()),
            item("fee", Optional, is_amount()),
        ],
        tx_common(),
    ]
    .concat());

    // `ApproveTx = ( op: "approve", from: Account, spender: Account, ? fee: Amount,
    //                ? expected_allowance: Amount, ? expires_at: Timestamp, TxCommon )`.
    let is_approve = and([
        vec![
            is_map(),
            only_keys(&[
                "op",
                "from",
                "spender",
                "fee",
                "expected_allowance",
                "expires_at",
                "amt",
                "memo",
                "ts",
            ]),
            item("op", Required, is(Value::text("approve"))),
            item("from", Required, is_account()),
            item("spender", Required, is_account()),
            item("fee", Optional, is_amount()),
            item("expected_allowance", Optional, is_amount()),
            item("expires_at", Optional, is_timestamp()),
        ],
        tx_common(),
    ]
    .concat());

    or(vec![is_mint, is_burn, is_transfer, is_approve])
}

/// `BlockContent`: the map wrapped by the self-describe tag.
fn block_content_schema() -> ValuePredicate {
    use ItemRequirement::*;

    // `Hash = bytes`.
    let is_hash = is_blob();
    // `Amount = uint`, `Timestamp = uint`, `fee_col_block: uint`.
    let is_amount = is_more_or_equal_to(0);
    let is_timestamp = is_more_or_equal_to(0);
    let is_uint = is_more_or_equal_to(0);

    and(vec![
        is_map(),
        only_keys(&["phash", "tx", "fee", "ts", "fee_col", "fee_col_block"]),
        item("phash", Optional, is_hash),
        item("tx", Required, transaction_content_schema()),
        item("fee", Optional, is_amount),
        item("ts", Required, is_timestamp),
        item("fee_col", Optional, is_account()),
        item("fee_col_block", Optional, is_uint),
    ])
}

/// Asserts that [`validate`] rejects a representative set of malformed blocks.
///
/// The happy path (real, randomly-generated blocks) is exercised by the
/// `block_encoding_agrees_with_the_schema` proptest; this complements it by
/// checking that the validator actually has teeth. Blocks are built from
/// generic values and encoded with the real encoder, so they carry the
/// self-describe tag unless we deliberately strip it.
pub fn assert_catches_malformed_blocks() {
    use ic_icrc1::blocks::generic_block_to_encoded_block;

    let account = Value::Array(vec![Value::blob(vec![1, 2, 3])]);
    let valid_mint_block = || {
        Value::map([
            ("ts", Value::Nat64(100)),
            (
                "tx",
                Value::map([
                    ("op", Value::text("mint")),
                    ("to", account.clone()),
                    ("amt", Value::Nat64(10)),
                ]),
            ),
        ])
    };
    let encode = |block: Value| generic_block_to_encoded_block(block).unwrap();

    // Sanity: a well-formed block is accepted.
    assert_eq!(validate(&encode(valid_mint_block())), Ok(()));

    // A block that is not wrapped in the self-describe tag is rejected.
    let encoded = encode(valid_mint_block());
    let untagged =
        EncodedBlock::from_vec(encoded.as_slice()[SELF_DESCRIBE_TAG_BYTES.len()..].to_vec());
    assert!(
        validate(&untagged).is_err(),
        "should reject a block without the self-describe tag"
    );

    // Unknown key at the block level (closed-map strictness).
    let mut block = valid_mint_block();
    if let Value::Map(map) = &mut block {
        map.insert("surprise".to_string(), Value::Nat64(1));
    }
    assert!(
        validate(&encode(block)).is_err(),
        "should reject an unknown block-level key"
    );

    // Unknown key at the transaction level.
    let bad_tx_key = Value::map([
        ("ts", Value::Nat64(100)),
        (
            "tx",
            Value::map([
                ("op", Value::text("mint")),
                ("to", account.clone()),
                ("amt", Value::Nat64(10)),
                // `spender` is not part of a mint transaction.
                ("spender", account.clone()),
            ]),
        ),
    ]);
    assert!(
        validate(&encode(bad_tx_key)).is_err(),
        "should reject an unknown transaction-level key"
    );

    // Unknown operation.
    let unknown_op = Value::map([
        ("ts", Value::Nat64(100)),
        (
            "tx",
            Value::map([("op", Value::text("frobnicate")), ("amt", Value::Nat64(10))]),
        ),
    ]);
    assert!(
        validate(&encode(unknown_op)).is_err(),
        "should reject an unknown operation"
    );

    // Missing the required `ts` field.
    let missing_ts = Value::map([(
        "tx",
        Value::map([
            ("op", Value::text("mint")),
            ("to", account.clone()),
            ("amt", Value::Nat64(10)),
        ]),
    )]);
    assert!(
        validate(&encode(missing_ts)).is_err(),
        "should reject a block missing the required timestamp"
    );

    // Malformed account: `Account = [1*2 bytes]`, so an empty array is invalid.
    let bad_account = Value::map([
        ("ts", Value::Nat64(100)),
        (
            "tx",
            Value::map([
                ("op", Value::text("mint")),
                ("to", Value::Array(vec![])),
                ("amt", Value::Nat64(10)),
            ]),
        ),
    ]);
    assert!(
        validate(&encode(bad_account)).is_err(),
        "should reject a malformed account"
    );
}
