use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicate, ValuePredicateFailures, and, is, is_account, is_blob,
        is_equal_to, is_map, is_more_or_equal_to, is_principal, is_text, item, len,
    },
};

pub const BTYPE_123_FREEZE_ACCOUNT: &str = "123freezeaccount";
pub const BTYPE_123_UNFREEZE_ACCOUNT: &str = "123unfreezeaccount";
pub const BTYPE_123_FREEZE_PRINCIPAL: &str = "123freezeprincipal";
pub const BTYPE_123_UNFREEZE_PRINCIPAL: &str = "123unfreezeprincipal";
pub const MTHD_153_FREEZE_ACCOUNT: &str = "153freeze_account";
pub const MTHD_153_UNFREEZE_ACCOUNT: &str = "153unfreeze_account";
pub const MTHD_153_FREEZE_PRINCIPAL: &str = "153freeze_principal";
pub const MTHD_153_UNFREEZE_PRINCIPAL: &str = "153unfreeze_principal";

/// Validate whether a block conforms to the ICRC-123 `123freezeaccount` block schema.
pub fn validate_freeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_predicate(BTYPE_123_FREEZE_ACCOUNT)(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-123 `123unfreezeaccount` block schema.
pub fn validate_unfreeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_predicate(BTYPE_123_UNFREEZE_ACCOUNT)(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-123 `123freezeprincipal` block schema.
pub fn validate_freeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_predicate(BTYPE_123_FREEZE_PRINCIPAL)(Cow::Borrowed(block))
}

/// Validate whether a block conforms to the ICRC-123 `123unfreezeprincipal` block schema.
pub fn validate_unfreeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_predicate(BTYPE_123_UNFREEZE_PRINCIPAL)(Cow::Borrowed(block))
}

/// The `tx` predicate for account-targeting blocks: required `account` (array-encoded)
/// plus optional provenance fields (`mthd`, `caller`, `reason`, `ts`).
fn account_tx_predicate() -> ValuePredicate {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    and(vec![
        is_map(),
        item("account", Required, is_account()),
        item("mthd", Optional, is_text()),
        item("caller", Optional, is_principal()),
        item("reason", Optional, is_text()),
        item("ts", Optional, is_timestamp),
    ])
}

/// The `tx` predicate for principal-targeting blocks: required `principal` (blob)
/// plus optional provenance fields (`mthd`, `caller`, `reason`, `ts`).
fn principal_tx_predicate() -> ValuePredicate {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    and(vec![
        is_map(),
        item("principal", Required, is_principal()),
        item("mthd", Optional, is_text()),
        item("caller", Optional, is_principal()),
        item("reason", Optional, is_text()),
        item("ts", Optional, is_timestamp),
    ])
}

fn block_predicate(
    btype: &'static str,
    tx_predicate: ValuePredicate,
) -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;
    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    move |block| {
        and(vec![
            is_map(),
            item("phash", Optional, is_parent_hash.clone()),
            item("btype", Required, is(Value::text(btype))),
            item("ts", Required, is_timestamp.clone()),
            item("tx", Required, tx_predicate.clone()),
        ])(block)
    }
}

fn account_block_predicate(
    btype: &'static str,
) -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    block_predicate(btype, account_tx_predicate())
}

fn principal_block_predicate(
    btype: &'static str,
) -> impl Fn(Cow<Value>) -> Result<(), ValuePredicateFailures> {
    block_predicate(btype, principal_tx_predicate())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Nat;

    fn account_value() -> Value {
        Value::Array(vec![Value::blob(vec![1u8; 20])])
    }

    fn account_with_subaccount_value() -> Value {
        Value::Array(vec![Value::blob(vec![1u8; 20]), Value::blob(vec![2u8; 32])])
    }

    /// Build a minimal valid account-targeting block.
    fn minimal_account_block(btype: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("tx", Value::map([("account", account_value())])),
        ])
    }

    /// Build a minimal valid principal-targeting block.
    fn minimal_principal_block(btype: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            (
                "tx",
                Value::map([("principal", Value::blob(vec![1u8; 20]))]),
            ),
        ])
    }

    /// Build a full account-targeting block with all optional provenance fields.
    fn full_account_block(btype: &str, mthd: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("phash", Value::blob(vec![0u8; 32])),
            (
                "tx",
                Value::map([
                    ("account", account_with_subaccount_value()),
                    ("mthd", Value::text(mthd)),
                    ("caller", Value::blob(vec![1u8; 29])),
                    ("reason", Value::text("compliance action")),
                    ("ts", Value::Nat(Nat::from(999_u64))),
                ]),
            ),
        ])
    }

    /// Build a full principal-targeting block with all optional provenance fields.
    fn full_principal_block(btype: &str, mthd: &str) -> Value {
        Value::map([
            ("btype", Value::text(btype)),
            ("ts", Value::Nat(Nat::from(1_000_000_000_u64))),
            ("phash", Value::blob(vec![0u8; 32])),
            (
                "tx",
                Value::map([
                    ("principal", Value::blob(vec![1u8; 20])),
                    ("mthd", Value::text(mthd)),
                    ("caller", Value::blob(vec![1u8; 29])),
                    ("reason", Value::text("compliance action")),
                    ("ts", Value::Nat(Nat::from(999_u64))),
                ]),
            ),
        ])
    }

    // ---- Minimal block tests ----

    #[test]
    fn test_validate_freeze_account_minimal() {
        assert!(validate_freeze_account(&minimal_account_block(BTYPE_123_FREEZE_ACCOUNT)).is_ok());
    }

    #[test]
    fn test_validate_unfreeze_account_minimal() {
        assert!(
            validate_unfreeze_account(&minimal_account_block(BTYPE_123_UNFREEZE_ACCOUNT)).is_ok()
        );
    }

    #[test]
    fn test_validate_freeze_principal_minimal() {
        assert!(
            validate_freeze_principal(&minimal_principal_block(BTYPE_123_FREEZE_PRINCIPAL)).is_ok()
        );
    }

    #[test]
    fn test_validate_unfreeze_principal_minimal() {
        assert!(
            validate_unfreeze_principal(&minimal_principal_block(BTYPE_123_UNFREEZE_PRINCIPAL))
                .is_ok()
        );
    }

    // ---- Full block tests (all provenance fields) ----

    #[test]
    fn test_validate_freeze_account_full() {
        assert!(
            validate_freeze_account(&full_account_block(
                BTYPE_123_FREEZE_ACCOUNT,
                MTHD_153_FREEZE_ACCOUNT
            ))
            .is_ok()
        );
    }

    #[test]
    fn test_validate_unfreeze_account_full() {
        assert!(
            validate_unfreeze_account(&full_account_block(
                BTYPE_123_UNFREEZE_ACCOUNT,
                MTHD_153_UNFREEZE_ACCOUNT
            ))
            .is_ok()
        );
    }

    #[test]
    fn test_validate_freeze_principal_full() {
        assert!(
            validate_freeze_principal(&full_principal_block(
                BTYPE_123_FREEZE_PRINCIPAL,
                MTHD_153_FREEZE_PRINCIPAL
            ))
            .is_ok()
        );
    }

    #[test]
    fn test_validate_unfreeze_principal_full() {
        assert!(
            validate_unfreeze_principal(&full_principal_block(
                BTYPE_123_UNFREEZE_PRINCIPAL,
                MTHD_153_UNFREEZE_PRINCIPAL
            ))
            .is_ok()
        );
    }

    // ---- Wrong btype tests ----

    #[test]
    fn test_validate_freeze_account_wrong_btype() {
        assert!(
            validate_freeze_account(&minimal_account_block(BTYPE_123_UNFREEZE_ACCOUNT)).is_err()
        );
    }

    #[test]
    fn test_validate_unfreeze_account_wrong_btype() {
        assert!(
            validate_unfreeze_account(&minimal_account_block(BTYPE_123_FREEZE_ACCOUNT)).is_err()
        );
    }

    #[test]
    fn test_validate_freeze_principal_wrong_btype() {
        assert!(
            validate_freeze_principal(&minimal_principal_block(BTYPE_123_UNFREEZE_PRINCIPAL))
                .is_err()
        );
    }

    #[test]
    fn test_validate_unfreeze_principal_wrong_btype() {
        assert!(
            validate_unfreeze_principal(&minimal_principal_block(BTYPE_123_FREEZE_PRINCIPAL))
                .is_err()
        );
    }

    // ---- Missing required fields ----

    #[test]
    fn test_validate_freeze_account_missing_btype() {
        let block = Value::map([
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", Value::map([("account", account_value())])),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_freeze_account_missing_ts() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("tx", Value::map([("account", account_value())])),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_freeze_account_missing_tx() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(Nat::from(1_u64))),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_freeze_account_missing_account_in_tx() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", Value::Map(Default::default())),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_freeze_principal_missing_principal_in_tx() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_PRINCIPAL)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", Value::Map(Default::default())),
        ]);
        assert!(validate_freeze_principal(&block).is_err());
    }

    // ---- Invalid phash length ----

    #[test]
    fn test_validate_freeze_account_phash_wrong_length() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("phash", Value::blob(vec![0u8; 16])),
            ("tx", Value::map([("account", account_value())])),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    // ---- Not a map ----

    #[test]
    fn test_validate_not_a_map() {
        assert!(validate_freeze_account(&Value::text("not a block")).is_err());
        assert!(validate_unfreeze_account(&Value::text("not a block")).is_err());
        assert!(validate_freeze_principal(&Value::text("not a block")).is_err());
        assert!(validate_unfreeze_principal(&Value::text("not a block")).is_err());
    }

    // ---- Account encoding: wrong target type ----

    #[test]
    fn test_validate_freeze_account_principal_instead_of_account() {
        // Using a blob (principal encoding) where an account (array encoding) is expected
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            ("tx", Value::map([("account", Value::blob(vec![1u8; 20]))])),
        ]);
        assert!(validate_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_freeze_principal_account_instead_of_principal() {
        // Using an array (account encoding) where a blob (principal encoding) is expected
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_PRINCIPAL)),
            ("ts", Value::Nat(Nat::from(1_u64))),
            (
                "tx",
                Value::map([("principal", Value::Array(vec![Value::blob(vec![1u8; 20])]))]),
            ),
        ]);
        assert!(validate_freeze_principal(&block).is_err());
    }
}
