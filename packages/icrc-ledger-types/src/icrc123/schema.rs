use std::borrow::Cow;
use std::sync::Arc;

use crate::icrc::generic_value::Value;
use crate::icrc::generic_value_predicate::{
    ItemRequirement, ValuePredicate, ValuePredicateFailures, and, is, is_account, is_blob,
    is_equal_to, is_map, is_more_or_equal_to, is_principal, is_text, item, len, or,
};

// Block type identifiers (ICRC-123)
pub const BTYPE_123_FREEZE_ACCOUNT: &str = "123freezeaccount";
pub const BTYPE_123_UNFREEZE_ACCOUNT: &str = "123unfreezeaccount";
pub const BTYPE_123_FREEZE_PRINCIPAL: &str = "123freezeprincipal";
pub const BTYPE_123_UNFREEZE_PRINCIPAL: &str = "123unfreezeprincipal";

// Method discriminators (ICRC-153)
pub const MTHD_153_FREEZE_ACCOUNT: &str = "153freeze_account";
pub const MTHD_153_UNFREEZE_ACCOUNT: &str = "153unfreeze_account";
pub const MTHD_153_FREEZE_PRINCIPAL: &str = "153freeze_principal";
pub const MTHD_153_UNFREEZE_PRINCIPAL: &str = "153unfreeze_principal";

/// Build a block-level predicate for an ICRC-123 account freeze/unfreeze block.
///
/// * `btype` – block type identifier
/// * `strict` – when `true`, `caller`, `mthd`, and `ts` (in tx) are required (ICRC-153);
///   when `false` they are optional (ICRC-123).
fn account_block_validator(btype: &'static str, strict: bool) -> ValuePredicate {
    use ItemRequirement::*;
    let strict_req = if strict { Required } else { Optional };

    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_created_at_time = is_more_or_equal_to(0);
    let is_transaction = and(vec![
        is_map(),
        item("account", Required, is_account()),
        item("caller", strict_req.clone(), is_principal()),
        item("mthd", strict_req.clone(), is_text()),
        item("ts", strict_req, is_created_at_time),
        item("reason", Optional, is_text()),
        item("policy_ref", Optional, is_text()),
    ]);
    and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(btype))),
        item("ts", Required, is_timestamp),
        item("tx", Required, is_transaction),
    ])
}

/// Build a block-level predicate for an ICRC-123 principal freeze/unfreeze block.
///
/// * `btype` – block type identifier
/// * `strict` – when `true`, `caller`, `mthd`, and `ts` (in tx) are required (ICRC-153);
///   when `false` they are optional (ICRC-123).
fn principal_block_validator(btype: &'static str, strict: bool) -> ValuePredicate {
    use ItemRequirement::*;
    let strict_req = if strict { Required } else { Optional };

    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_created_at_time = is_more_or_equal_to(0);
    let is_transaction = and(vec![
        is_map(),
        item("principal", Required, is_principal()),
        item("caller", strict_req.clone(), is_principal()),
        item("mthd", strict_req.clone(), is_text()),
        item("ts", strict_req, is_created_at_time),
        item("reason", Optional, is_text()),
        item("policy_ref", Optional, is_text()),
    ]);
    and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(btype))),
        item("ts", Required, is_timestamp),
        item("tx", Required, is_transaction),
    ])
}

/// Validate if a block is compatible with the ICRC-123 `123freezeaccount` block schema.
///
/// Permissive ICRC-123 validation: `caller`, `mthd`, and `ts` (in tx) are optional.
/// Use [`validate_153_freeze_account`] for strict ICRC-153 validation.
///
/// Block structure:
/// ```text
/// { btype: "123freezeaccount", phash?: Blob(32), ts: Nat,
///   tx: { account: Account, caller?: Principal, mthd?: Text, ts?: Nat,
///         reason?: Text, policy_ref?: Text } }
/// ```
pub fn validate_123_freeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_validator(BTYPE_123_FREEZE_ACCOUNT, false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-153 freeze_account endpoint.
///
/// Stricter than [`validate_123_freeze_account`]: `caller`, `mthd`, and `ts` are required.
pub fn validate_153_freeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_validator(BTYPE_123_FREEZE_ACCOUNT, true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with the ICRC-123 `123unfreezeaccount` block schema.
///
/// Permissive ICRC-123 validation: `caller`, `mthd`, and `ts` (in tx) are optional.
/// Use [`validate_153_unfreeze_account`] for strict ICRC-153 validation.
pub fn validate_123_unfreeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_validator(BTYPE_123_UNFREEZE_ACCOUNT, false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-153 unfreeze_account endpoint.
///
/// Stricter than [`validate_123_unfreeze_account`]: `caller`, `mthd`, and `ts` are required.
pub fn validate_153_unfreeze_account(block: &Value) -> Result<(), ValuePredicateFailures> {
    account_block_validator(BTYPE_123_UNFREEZE_ACCOUNT, true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with the ICRC-123 `123freezeprincipal` block schema.
///
/// Permissive ICRC-123 validation: `caller`, `mthd`, and `ts` (in tx) are optional.
/// Use [`validate_153_freeze_principal`] for strict ICRC-153 validation.
pub fn validate_123_freeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_validator(BTYPE_123_FREEZE_PRINCIPAL, false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-153 freeze_principal endpoint.
///
/// Stricter than [`validate_123_freeze_principal`]: `caller`, `mthd`, and `ts` are required.
pub fn validate_153_freeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_validator(BTYPE_123_FREEZE_PRINCIPAL, true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with the ICRC-123 `123unfreezeprincipal` block schema.
///
/// Permissive ICRC-123 validation: `caller`, `mthd`, and `ts` (in tx) are optional.
/// Use [`validate_153_unfreeze_principal`] for strict ICRC-153 validation.
pub fn validate_123_unfreeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_validator(BTYPE_123_UNFREEZE_PRINCIPAL, false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-153 unfreeze_principal endpoint.
///
/// Stricter than [`validate_123_unfreeze_principal`]: `caller`, `mthd`, and `ts` are required.
pub fn validate_153_unfreeze_principal(block: &Value) -> Result<(), ValuePredicateFailures> {
    principal_block_validator(BTYPE_123_UNFREEZE_PRINCIPAL, true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with any ICRC-123 schema (permissive).
pub fn validate_123(block: &Value) -> Result<(), ValuePredicateFailures> {
    or(vec![
        Arc::new(|v| validate_123_freeze_account(&v)),
        Arc::new(|v| validate_123_unfreeze_account(&v)),
        Arc::new(|v| validate_123_freeze_principal(&v)),
        Arc::new(|v| validate_123_unfreeze_principal(&v)),
    ])(Cow::Borrowed(block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icrc::generic_value::Value;
    use candid::Principal;

    fn principal_blob() -> Value {
        Value::Blob(Principal::anonymous().as_slice().to_vec().into())
    }

    fn account_value() -> Value {
        Value::Array(vec![principal_blob()])
    }

    // --- Full blocks (all fields) ---

    fn full_freeze_account_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("account", account_value()),
                    ("caller", principal_blob()),
                    ("mthd", Value::text(MTHD_153_FREEZE_ACCOUNT)),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                    ("reason", Value::text("compliance")),
                    ("policy_ref", Value::text("policy-123")),
                ]),
            ),
        ])
    }

    fn full_unfreeze_account_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_ACCOUNT)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("account", account_value()),
                    ("caller", principal_blob()),
                    ("mthd", Value::text(MTHD_153_UNFREEZE_ACCOUNT)),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                    ("reason", Value::text("resolved")),
                    ("policy_ref", Value::text("policy-456")),
                ]),
            ),
        ])
    }

    fn full_freeze_principal_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_PRINCIPAL)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("principal", principal_blob()),
                    ("caller", principal_blob()),
                    ("mthd", Value::text(MTHD_153_FREEZE_PRINCIPAL)),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                    ("reason", Value::text("compliance")),
                    ("policy_ref", Value::text("policy-789")),
                ]),
            ),
        ])
    }

    fn full_unfreeze_principal_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_PRINCIPAL)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("principal", principal_blob()),
                    ("caller", principal_blob()),
                    ("mthd", Value::text(MTHD_153_UNFREEZE_PRINCIPAL)),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                    ("reason", Value::text("resolved")),
                    ("policy_ref", Value::text("policy-012")),
                ]),
            ),
        ])
    }

    // --- Minimal blocks (only required fields for permissive mode) ---

    fn minimal_freeze_account_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map([("account", account_value())])),
        ])
    }

    fn minimal_unfreeze_account_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_ACCOUNT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map([("account", account_value())])),
        ])
    }

    fn minimal_freeze_principal_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_PRINCIPAL)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map([("principal", principal_blob())])),
        ])
    }

    fn minimal_unfreeze_principal_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_PRINCIPAL)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map([("principal", principal_blob())])),
        ])
    }

    // --- Tests: full blocks validate in both modes ---

    #[test]
    fn test_validate_123_freeze_account_full() {
        assert!(validate_123_freeze_account(&full_freeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_123_unfreeze_account_full() {
        assert!(validate_123_unfreeze_account(&full_unfreeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_123_freeze_principal_full() {
        assert!(validate_123_freeze_principal(&full_freeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_123_unfreeze_principal_full() {
        assert!(validate_123_unfreeze_principal(&full_unfreeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_153_freeze_account_full() {
        assert!(validate_153_freeze_account(&full_freeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_153_unfreeze_account_full() {
        assert!(validate_153_unfreeze_account(&full_unfreeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_153_freeze_principal_full() {
        assert!(validate_153_freeze_principal(&full_freeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_153_unfreeze_principal_full() {
        assert!(validate_153_unfreeze_principal(&full_unfreeze_principal_block()).is_ok());
    }

    // --- Tests: minimal blocks pass permissive mode ---

    #[test]
    fn test_validate_123_freeze_account_minimal() {
        assert!(validate_123_freeze_account(&minimal_freeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_123_unfreeze_account_minimal() {
        assert!(validate_123_unfreeze_account(&minimal_unfreeze_account_block()).is_ok());
    }

    #[test]
    fn test_validate_123_freeze_principal_minimal() {
        assert!(validate_123_freeze_principal(&minimal_freeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_123_unfreeze_principal_minimal() {
        assert!(validate_123_unfreeze_principal(&minimal_unfreeze_principal_block()).is_ok());
    }

    // --- Tests: strict mode rejects blocks missing caller/mthd/ts ---

    #[test]
    fn test_validate_153_freeze_account_rejects_minimal() {
        assert!(validate_153_freeze_account(&minimal_freeze_account_block()).is_err());
    }

    #[test]
    fn test_validate_153_unfreeze_account_rejects_minimal() {
        assert!(validate_153_unfreeze_account(&minimal_unfreeze_account_block()).is_err());
    }

    #[test]
    fn test_validate_153_freeze_principal_rejects_minimal() {
        assert!(validate_153_freeze_principal(&minimal_freeze_principal_block()).is_err());
    }

    #[test]
    fn test_validate_153_unfreeze_principal_rejects_minimal() {
        assert!(validate_153_unfreeze_principal(&minimal_unfreeze_principal_block()).is_err());
    }

    // --- Tests: missing required field is rejected ---

    #[test]
    fn test_validate_123_freeze_account_rejects_missing_account() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_ACCOUNT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map::<&str, [(&str, Value); 0]>([])),
        ]);
        assert!(validate_123_freeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_123_unfreeze_account_rejects_missing_account() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_ACCOUNT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map::<&str, [(&str, Value); 0]>([])),
        ]);
        assert!(validate_123_unfreeze_account(&block).is_err());
    }

    #[test]
    fn test_validate_123_freeze_principal_rejects_missing_principal() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_FREEZE_PRINCIPAL)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map::<&str, [(&str, Value); 0]>([])),
        ]);
        assert!(validate_123_freeze_principal(&block).is_err());
    }

    #[test]
    fn test_validate_123_unfreeze_principal_rejects_missing_principal() {
        let block = Value::map([
            ("btype", Value::text(BTYPE_123_UNFREEZE_PRINCIPAL)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map::<&str, [(&str, Value); 0]>([])),
        ]);
        assert!(validate_123_unfreeze_principal(&block).is_err());
    }

    // --- Tests: combined validate() ---

    #[test]
    fn test_validate_accepts_all_block_types() {
        assert!(validate_123(&full_freeze_account_block()).is_ok());
        assert!(validate_123(&full_unfreeze_account_block()).is_ok());
        assert!(validate_123(&full_freeze_principal_block()).is_ok());
        assert!(validate_123(&full_unfreeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_accepts_minimal_blocks() {
        assert!(validate_123(&minimal_freeze_account_block()).is_ok());
        assert!(validate_123(&minimal_unfreeze_account_block()).is_ok());
        assert!(validate_123(&minimal_freeze_principal_block()).is_ok());
        assert!(validate_123(&minimal_unfreeze_principal_block()).is_ok());
    }

    #[test]
    fn test_validate_rejects_unknown_btype() {
        let block = Value::map([
            ("btype", Value::text("unknown")),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            ("tx", Value::map([("account", account_value())])),
        ]);
        assert!(validate_123(&block).is_err());
    }
}
