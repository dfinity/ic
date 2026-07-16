//! Validation of the CBOR encoding of ICRC-1/ICRC-2 ledger blocks.
//!
//! This is a hand-written port of the `block.cddl` schema
//! (`rs/ledger_suite/icrc1/ledger/block.cddl`) onto the
//! [`icrc_ledger_types::icrc::generic_value_predicate`] combinators, replacing
//! the `cddl` crate (and its large, otherwise-unused dependency tree) that was
//! previously used to validate the schema in tests.
//!
//! Note on strictness: the shared `icrc3`/`icrc107` schema validators do not
//! reject *unknown* map keys, because ICRC standards intentionally allow blocks
//! to carry extra fields for forward compatibility. The legacy `block.cddl`
//! format, by contrast, is a closed CDDL map: unknown keys are rejected. We
//! preserve that here with the local [`only_keys`] combinator, so this port
//! matches the strictness the `cddl` crate provided.

use std::borrow::Cow;
use std::sync::Arc;

use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicate, ValuePredicateFailures, and, element, is, is_array,
        is_blob, is_equal_to, is_map, is_more_or_equal_to, item, len, or,
    },
};

use crate::blocks::encoded_block_to_generic_block;
use crate::known_tags::SELF_DESCRIBED;

/// Validates that `encoded_block` conforms to the `block.cddl` schema.
///
/// This checks both:
///  1. the outer self-describe CBOR tag (`#6.55799`), which the block encoder
///     always emits and which `encoded_block_to_generic_block` transparently
///     strips, and
///  2. the structure of the decoded block content.
pub fn validate(encoded_block: &EncodedBlock) -> Result<(), String> {
    // 1. `Block = #6.55799(BlockContent)`: the encoding must be wrapped in the
    // self-describe CBOR tag.
    let cbor: ciborium::value::Value = ciborium::de::from_reader(encoded_block.as_slice())
        .map_err(|e| format!("failed to decode block as CBOR: {e}"))?;
    match &cbor {
        ciborium::value::Value::Tag(tag, _) if *tag == SELF_DESCRIBED => {}
        other => {
            return Err(format!(
                "expected the block to be wrapped in the self-describe CBOR tag \
                 (#6.{SELF_DESCRIBED}), got: {other:?}"
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value as C;

    // The happy path (real, randomly-generated blocks) is exercised by the
    // `block_encoding_agrees_with_the_schema` proptest in the ledger tests.
    // These unit tests verify the complementary property: that the validator
    // actually *rejects* malformed blocks.

    /// Wraps `content` in the self-describe tag and CBOR-encodes it, as the
    /// block encoder does.
    fn encode_tagged(content: C) -> EncodedBlock {
        let tagged = C::Tag(SELF_DESCRIBED, Box::new(content));
        let mut bytes = vec![];
        ciborium::into_writer(&tagged, &mut bytes).unwrap();
        EncodedBlock::from_vec(bytes)
    }

    fn nat(n: u64) -> C {
        C::Integer(n.into())
    }

    /// `Account = [1*2 bytes]`.
    fn account() -> C {
        C::Array(vec![C::Bytes(vec![1, 2, 3])])
    }

    fn valid_mint_block() -> C {
        C::Map(vec![
            (C::Text("ts".into()), nat(100)),
            (
                C::Text("tx".into()),
                C::Map(vec![
                    (C::Text("op".into()), C::Text("mint".into())),
                    (C::Text("to".into()), account()),
                    (C::Text("amt".into()), nat(10)),
                ]),
            ),
        ])
    }

    #[test]
    fn accepts_valid_block() {
        assert_eq!(validate(&encode_tagged(valid_mint_block())), Ok(()));
    }

    #[test]
    fn rejects_block_without_self_describe_tag() {
        let mut bytes = vec![];
        ciborium::into_writer(&valid_mint_block(), &mut bytes).unwrap();
        assert!(validate(&EncodedBlock::from_vec(bytes)).is_err());
    }

    #[test]
    fn rejects_block_missing_required_timestamp() {
        let mut block = valid_mint_block();
        if let C::Map(entries) = &mut block {
            entries.retain(|(k, _)| k != &C::Text("ts".into()));
        }
        assert!(validate(&encode_tagged(block)).is_err());
    }

    #[test]
    fn rejects_unknown_operation() {
        let block = C::Map(vec![
            (C::Text("ts".into()), nat(100)),
            (
                C::Text("tx".into()),
                C::Map(vec![
                    (C::Text("op".into()), C::Text("frobnicate".into())),
                    (C::Text("amt".into()), nat(10)),
                ]),
            ),
        ]);
        assert!(validate(&encode_tagged(block)).is_err());
    }

    #[test]
    fn rejects_unknown_block_level_key() {
        // The legacy block format is a closed CDDL map: extra keys are rejected.
        let mut block = valid_mint_block();
        if let C::Map(entries) = &mut block {
            entries.push((C::Text("surprise".into()), nat(1)));
        }
        assert!(validate(&encode_tagged(block)).is_err());
    }

    #[test]
    fn rejects_unknown_transaction_level_key() {
        let block = C::Map(vec![
            (C::Text("ts".into()), nat(100)),
            (
                C::Text("tx".into()),
                C::Map(vec![
                    (C::Text("op".into()), C::Text("mint".into())),
                    (C::Text("to".into()), account()),
                    (C::Text("amt".into()), nat(10)),
                    // `spender` is not part of a mint transaction.
                    (C::Text("spender".into()), account()),
                ]),
            ),
        ]);
        assert!(validate(&encode_tagged(block)).is_err());
    }

    #[test]
    fn rejects_malformed_account() {
        // `Account = [1*2 bytes]`: an empty array is not a valid account.
        let block = C::Map(vec![
            (C::Text("ts".into()), nat(100)),
            (
                C::Text("tx".into()),
                C::Map(vec![
                    (C::Text("op".into()), C::Text("mint".into())),
                    (C::Text("to".into()), C::Array(vec![])),
                    (C::Text("amt".into()), nat(10)),
                ]),
            ),
        ]);
        assert!(validate(&encode_tagged(block)).is_err());
    }
}
