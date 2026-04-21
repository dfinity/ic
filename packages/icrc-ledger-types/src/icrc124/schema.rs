use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicate, ValuePredicateFailures, and, is, is_blob, is_equal_to,
        is_map, is_more_or_equal_to, is_principal, is_text, item, len,
    },
};

pub const BTYPE_124_PAUSE: &str = "124pause";
pub const BTYPE_124_UNPAUSE: &str = "124unpause";
pub const BTYPE_124_DEACTIVATE: &str = "124deactivate";
pub const MTHD_154_PAUSE: &str = "154pause";
pub const MTHD_154_UNPAUSE: &str = "154unpause";
pub const MTHD_154_DEACTIVATE: &str = "154deactivate";

/// Validate whether a block conforms to the ICRC-124 `124pause` block schema.
pub fn validate_pause(block: &Value) -> Result<(), ValuePredicateFailures> {
    pause_block_predicate()(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-124 `124unpause` block schema.
pub fn validate_unpause(block: &Value) -> Result<(), ValuePredicateFailures> {
    unpause_block_predicate()(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-124 `124deactivate` block schema.
pub fn validate_deactivate(block: &Value) -> Result<(), ValuePredicateFailures> {
    deactivate_block_predicate()(Cow::Borrowed(block))
}

/// All three ICRC-124 block types share the same `tx` schema:
/// no required fields, optional provenance (`mthd`, `caller`, `reason`, `ts`).
fn management_tx_predicate() -> ValuePredicate {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    and(vec![
        is_map(),
        item("mthd", Optional, is_text()),
        item("caller", Optional, is_principal()),
        item("reason", Optional, is_text()),
        item("ts", Optional, is_timestamp),
    ])
}

fn block_predicate(
    btype: &'static str,
) -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_tx = management_tx_predicate();
    move |block| {
        and(vec![
            is_map(),
            item("phash", Optional, is_parent_hash.clone()),
            item("btype", Required, is(Value::text(btype))),
            item("ts", Required, is_timestamp.clone()),
            item("tx", Required, is_tx.clone()),
        ])(block)
    }
}

fn pause_block_predicate() -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    block_predicate(BTYPE_124_PAUSE)
}

fn unpause_block_predicate() -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    block_predicate(BTYPE_124_UNPAUSE)
}

fn deactivate_block_predicate() -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    block_predicate(BTYPE_124_DEACTIVATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Nat;

    /// Build a minimal valid block with the given btype and empty tx.
    fn minimal_block(btype: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("tx", Value::Map(Default::default())),
        ])
    }

    /// Build a full block with all optional provenance fields populated.
    fn full_block(btype: &str, mthd: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("phash", Value::blob(vec![0u8; 32])),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(mthd)),
                    ("caller", Value::blob(vec![1u8; 29])),
                    ("reason", Value::text("scheduled maintenance")),
                    ("ts", Value::Nat(Nat::from(999_u64))),
                ]),
            ),
        ])
    }

    // ---- Minimal block tests (empty tx) ----

    #[test]
    fn test_validate_pause_minimal() {
        assert!(validate_pause(&minimal_block(BTYPE_124_PAUSE)).is_ok());
    }

    #[test]
    fn test_validate_unpause_minimal() {
        assert!(validate_unpause(&minimal_block(BTYPE_124_UNPAUSE)).is_ok());
    }

    #[test]
    fn test_validate_deactivate_minimal() {
        assert!(validate_deactivate(&minimal_block(BTYPE_124_DEACTIVATE)).is_ok());
    }

    // ---- Full block tests (all provenance fields) ----

    #[test]
    fn test_validate_pause_full() {
        assert!(validate_pause(&full_block(BTYPE_124_PAUSE, MTHD_154_PAUSE)).is_ok());
    }

    #[test]
    fn test_validate_unpause_full() {
        assert!(validate_unpause(&full_block(BTYPE_124_UNPAUSE, MTHD_154_UNPAUSE)).is_ok());
    }

    #[test]
    fn test_validate_deactivate_full() {
        assert!(
            validate_deactivate(&full_block(BTYPE_124_DEACTIVATE, MTHD_154_DEACTIVATE)).is_ok()
        );
    }

    // ---- Wrong btype tests ----

    #[test]
    fn test_validate_pause_wrong_btype() {
        assert!(validate_pause(&minimal_block(BTYPE_124_UNPAUSE)).is_err());
    }

    #[test]
    fn test_validate_unpause_wrong_btype() {
        assert!(validate_unpause(&minimal_block(BTYPE_124_DEACTIVATE)).is_err());
    }

    #[test]
    fn test_validate_deactivate_wrong_btype() {
        assert!(validate_deactivate(&minimal_block(BTYPE_124_PAUSE)).is_err());
    }

    // ---- Missing required fields ----

    #[test]
    fn test_validate_pause_missing_btype() {
        let block = Value::map([
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", Value::Map(Default::default())),
        ]);
        assert!(validate_pause(&block).is_err());
    }

    #[test]
    fn test_validate_pause_missing_ts() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_124_PAUSE)),
            ("tx", Value::Map(Default::default())),
        ]);
        assert!(validate_pause(&block).is_err());
    }

    #[test]
    fn test_validate_pause_missing_tx() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_124_PAUSE)),
            ("ts", Value::Nat(Nat::from(1_u64))),
        ]);
        assert!(validate_pause(&block).is_err());
    }

    // ---- Invalid phash length ----

    #[test]
    fn test_validate_pause_phash_wrong_length() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_124_PAUSE)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("phash", Value::blob(vec![0u8; 16])),
            ("tx", Value::Map(Default::default())),
        ]);
        assert!(validate_pause(&block).is_err());
    }

    // ---- Not a map ----

    #[test]
    fn test_validate_not_a_map() {
        assert!(validate_pause(&Value::text("not a block")).is_err());
        assert!(validate_unpause(&Value::text("not a block")).is_err());
        assert!(validate_deactivate(&Value::text("not a block")).is_err());
    }
}
