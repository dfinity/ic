use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicateFailures, and, is, is_account, is_blob, is_equal_to, is_map,
        is_more_or_equal_to, is_nat, is_principal, is_text, item, len,
    },
};

pub const BTYPE_122_BURN: &str = "122burn";
pub const BTYPE_122_MINT: &str = "122mint";
pub const OP_152_BURN: &str = "152burn";
pub const OP_152_MINT: &str = "152mint";

/// Validate whether a block conforms to the ICRC-122 `122burn` block schema.
pub fn validate_burn(block: &Value) -> Result<(), ValuePredicateFailures> {
    burn_block_predicate()(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-122 `122mint` block schema.
pub fn validate_mint(block: &Value) -> Result<(), ValuePredicateFailures> {
    mint_block_predicate()(Cow::Borrowed(block))
}

fn burn_block_predicate() -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_tx = and(vec![
        is_map(),
        item("op", Optional, is_text()),
        item("amt", Required, is_nat()),
        item("from", Required, is_account()),
        item("caller", Optional, is_principal()),
        item("reason", Optional, is_text()),
        item("ts", Optional, is_timestamp.clone()),
    ]);
    move |block| {
        and(vec![
            is_map(),
            item("phash", Optional, is_parent_hash.clone()),
            item("btype", Required, is(Value::text(BTYPE_122_BURN))),
            item("ts", Required, is_timestamp.clone()),
            item("tx", Required, is_tx.clone()),
        ])(block)
    }
}

fn mint_block_predicate() -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_tx = and(vec![
        is_map(),
        item("op", Optional, is_text()),
        item("amt", Required, is_nat()),
        item("to", Required, is_account()),
        item("caller", Optional, is_principal()),
        item("reason", Optional, is_text()),
        item("ts", Optional, is_timestamp.clone()),
    ]);
    move |block| {
        and(vec![
            is_map(),
            item("phash", Optional, is_parent_hash.clone()),
            item("btype", Required, is(Value::text(BTYPE_122_MINT))),
            item("ts", Required, is_timestamp.clone()),
            item("tx", Required, is_tx.clone()),
        ])(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Nat;
    use std::collections::BTreeMap;

    /// Minimal valid account: an array with one blob (principal bytes).
    fn account(owner: &[u8]) -> Value {
        Value::Array(vec![Value::blob(owner.to_vec())])
    }

    /// Build a minimal valid `122burn` block.
    fn minimal_burn_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            (
                "tx",
                Value::map([
                    ("amt", Value::Nat(Nat::from(100_u64))),
                    ("from", account(&[1u8; 29])),
                ]),
            ),
        ])
    }

    /// Build a minimal valid `122mint` block.
    fn minimal_mint_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            (
                "tx",
                Value::map([
                    ("amt", Value::Nat(Nat::from(100_u64))),
                    ("to", account(&[2u8; 29])),
                ]),
            ),
        ])
    }

    #[test]
    fn test_validate_burn_minimal() {
        assert!(validate_burn(&minimal_burn_block()).is_ok());
    }

    #[test]
    fn test_validate_mint_minimal() {
        assert!(validate_mint(&minimal_mint_block()).is_ok());
    }

    #[test]
    fn test_validate_burn_full() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("phash", Value::blob(vec![0u8; 32])),
            (
                "tx",
                Value::map([
                    ("op", Value::text(OP_152_BURN)),
                    ("amt", Value::Nat(Nat::from(500_u64))),
                    ("from", account(&[1u8; 29])),
                    ("caller", Value::blob(vec![1u8; 29])),
                    ("reason", Value::text("treasury rebalance")),
                    ("ts", Value::Nat(Nat::from(999_u64))),
                ]),
            ),
        ]);
        assert!(validate_burn(&block).is_ok());
    }

    #[test]
    fn test_validate_mint_full() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("phash", Value::blob(vec![0u8; 32])),
            (
                "tx",
                Value::map([
                    ("op", Value::text(OP_152_MINT)),
                    ("amt", Value::Nat(Nat::from(500_u64))),
                    ("to", account(&[2u8; 29])),
                    ("caller", Value::blob(vec![1u8; 29])),
                    ("reason", Value::text("emergency issuance")),
                    ("ts", Value::Nat(Nat::from(999_u64))),
                ]),
            ),
        ]);
        assert!(validate_mint(&block).is_ok());
    }

    #[test]
    fn test_validate_burn_missing_btype() {
        let mut block = match minimal_burn_block() {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        block.remove("btype");
        assert!(validate_burn(&Value::Map(block)).is_err());
    }

    #[test]
    fn test_validate_burn_wrong_btype() {
        let mut block = match minimal_burn_block() {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        block.insert("btype".to_string(), Value::text(BTYPE_122_MINT));
        assert!(validate_burn(&Value::Map(block)).is_err());
    }

    #[test]
    fn test_validate_mint_wrong_btype() {
        let mut block = match minimal_mint_block() {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        block.insert("btype".to_string(), Value::text(BTYPE_122_BURN));
        assert!(validate_mint(&Value::Map(block)).is_err());
    }

    #[test]
    fn test_validate_burn_missing_ts() {
        let mut block = match minimal_burn_block() {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        block.remove("ts");
        assert!(validate_burn(&Value::Map(block)).is_err());
    }

    #[test]
    fn test_validate_burn_missing_amt() {
        let inner = Value::map([("from", account(&[1u8; 29]))]);
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", inner),
        ]);
        assert!(validate_burn(&block).is_err());
    }

    #[test]
    fn test_validate_burn_missing_from() {
        let inner = Value::map([("amt", Value::Nat(Nat::from(100_u64)))]);
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", inner),
        ]);
        assert!(validate_burn(&block).is_err());
    }

    #[test]
    fn test_validate_mint_missing_to() {
        let inner = Value::map([("amt", Value::Nat(Nat::from(100_u64)))]);
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", inner),
        ]);
        assert!(validate_mint(&block).is_err());
    }

    #[test]
    fn test_validate_burn_phash_wrong_length() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("phash", Value::blob(vec![0u8; 16])), // should be 32
            (
                "tx",
                Value::map([
                    ("amt", Value::Nat(Nat::from(100_u64))),
                    ("from", account(&[1u8; 29])),
                ]),
            ),
        ]);
        assert!(validate_burn(&block).is_err());
    }

    #[test]
    fn test_validate_not_a_map() {
        assert!(validate_burn(&Value::text("not a block")).is_err());
        assert!(validate_mint(&Value::text("not a block")).is_err());
    }
}
