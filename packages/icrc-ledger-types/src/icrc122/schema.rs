use std::borrow::Cow;

use crate::icrc::generic_value_predicate::{
    ItemRequirement, ValuePredicate, ValuePredicateFailures, and, is, is_blob, is_equal_to, is_map,
    is_more_or_equal_to, is_principal, is_text, item, len, or,
};
use crate::icrc::{generic_value::Value, generic_value_predicate::is_account};

/// Block type identifiers (ICRC-122 standard)
pub const BTYPE_122_MINT: &str = "122mint";
pub const BTYPE_122_BURN: &str = "122burn";

/// Method discriminators (ICRC-152 endpoint standard)
pub const MTHD_152_MINT: &str = "152mint";
pub const MTHD_152_BURN: &str = "152burn";

/// Build a block-level predicate for an ICRC-122 block.
///
/// * `btype` – block type identifier (`BTYPE_122_MINT` or `BTYPE_122_BURN`)
/// * `account_field` – `"to"` for mint, `"from"` for burn
/// * `strict` – when `true`, `caller` and `mthd` are required (ICRC-152);
///   when `false` they are optional (ICRC-122).
fn block_validator(
    btype: &'static str,
    account_field: &'static str,
    strict: bool,
) -> ValuePredicate {
    use ItemRequirement::*;
    let strict_req = if strict { Required } else { Optional };

    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_created_at_time = is_more_or_equal_to(0);
    let is_transaction = and(vec![
        is_map(),
        item("mthd", strict_req.clone(), is_text()),
        item(account_field, Required, is_account()),
        item("amt", Required, is_more_or_equal_to(1)),
        item("caller", strict_req.clone(), is_principal()),
        item("reason", Optional, is_text()),
        item("ts", strict_req, is_created_at_time),
    ]);
    and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(btype))),
        item("ts", Required, is_timestamp),
        item("tx", Required, is_transaction),
    ])
}

/// Validate if a block is compatible with the ICRC-122 `122mint` block schema.
///
/// This is the permissive ICRC-122 validation: `caller`, `mthd`, and `reason`
/// are all optional since the block type standard does not mandate them.
/// Use [`validate_152_mint`] for the stricter ICRC-152 validation where
/// `caller` and `mthd` are required.
///
/// Block structure:
/// ```text
/// { btype: "122mint", phash?: Blob(32), ts: Nat,
///   tx: { mthd?: Text, to: Account, amt: Nat, caller?: Principal, reason?: Text } }
/// ```
pub fn validate_mint(block: &Value) -> Result<(), ValuePredicateFailures> {
    block_validator(BTYPE_122_MINT, "to", false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-152 mint endpoint.
///
/// This is stricter than [`validate_mint`]: `caller` and `mthd` are required,
/// reflecting the guarantees made by ICRC-152 endpoints.
///
/// Block structure:
/// ```text
/// { btype: "122mint", phash?: Blob(32), ts: Nat,
///   tx: { mthd: Text, to: Account, amt: Nat, caller: Principal, reason?: Text } }
/// ```
pub fn validate_152_mint(block: &Value) -> Result<(), ValuePredicateFailures> {
    block_validator(BTYPE_122_MINT, "to", true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with the ICRC-122 `122burn` block schema.
///
/// This is the permissive ICRC-122 validation: `caller`, `mthd`, and `reason`
/// are all optional since the block type standard does not mandate them.
/// Use [`validate_152_burn`] for the stricter ICRC-152 validation where
/// `caller` and `mthd` are required.
///
/// Block structure:
/// ```text
/// { btype: "122burn", phash?: Blob(32), ts: Nat,
///   tx: { mthd?: Text, from: Account, amt: Nat, caller?: Principal, reason?: Text } }
/// ```
pub fn validate_burn(block: &Value) -> Result<(), ValuePredicateFailures> {
    block_validator(BTYPE_122_BURN, "from", false)(Cow::Borrowed(block))
}

/// Validate if a block was produced by an ICRC-152 burn endpoint.
///
/// This is stricter than [`validate_burn`]: `caller` and `mthd` are required,
/// reflecting the guarantees made by ICRC-152 endpoints.
///
/// Block structure:
/// ```text
/// { btype: "122burn", phash?: Blob(32), ts: Nat,
///   tx: { mthd: Text, from: Account, amt: Nat, caller: Principal, reason?: Text } }
/// ```
pub fn validate_152_burn(block: &Value) -> Result<(), ValuePredicateFailures> {
    block_validator(BTYPE_122_BURN, "from", true)(Cow::Borrowed(block))
}

/// Validate if a block is compatible with any ICRC-122 schema (mint or burn).
pub fn validate(block: &Value) -> Result<(), ValuePredicateFailures> {
    use std::sync::Arc;
    or(vec![
        Arc::new(|v| validate_mint(&v)),
        Arc::new(|v| validate_burn(&v)),
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

    fn sample_mint_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(MTHD_152_MINT)),
                    ("to", account_value()),
                    ("amt", Value::Nat(1000_u64.into())),
                    ("caller", principal_blob()),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                ]),
            ),
        ])
    }

    fn sample_burn_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("phash", Value::Blob(vec![0_u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(MTHD_152_BURN)),
                    ("from", account_value()),
                    ("amt", Value::Nat(1000_u64.into())),
                    ("caller", principal_blob()),
                    ("ts", Value::Nat(999_000_000_u64.into())),
                ]),
            ),
        ])
    }

    #[test]
    fn test_validate_mint_block() {
        assert!(validate_mint(&sample_mint_block()).is_ok());
    }

    #[test]
    fn test_validate_burn_block() {
        assert!(validate_burn(&sample_burn_block()).is_ok());
    }

    #[test]
    fn test_validate_mint_with_reason() {
        let mut block = sample_mint_block();
        if let Value::Map(entries) = &mut block
            && let Some(Value::Map(tx_entries)) = entries.get_mut("tx")
        {
            tx_entries.insert("reason".to_string(), Value::text("test reason"));
        }
        assert!(validate_mint(&block).is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid() {
        // Missing required field (amt)
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(MTHD_152_MINT)),
                    ("to", account_value()),
                    ("caller", principal_blob()),
                ]),
            ),
        ]);
        assert!(validate_mint(&block).is_err());
    }

    // --- ICRC-122 permissive validation (no caller/mthd required) ---

    fn minimal_mint_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("to", account_value()),
                    ("amt", Value::Nat(1000_u64.into())),
                ]),
            ),
        ])
    }

    fn minimal_burn_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("ts", Value::Nat(1_000_000_000_u64.into())),
            (
                "tx",
                Value::map([
                    ("from", account_value()),
                    ("amt", Value::Nat(1000_u64.into())),
                ]),
            ),
        ])
    }

    #[test]
    fn test_validate_mint_without_caller_and_mthd() {
        assert!(validate_mint(&minimal_mint_block()).is_ok());
    }

    #[test]
    fn test_validate_burn_without_caller_and_mthd() {
        assert!(validate_burn(&minimal_burn_block()).is_ok());
    }

    // --- ICRC-152 strict validation (caller and mthd required) ---

    #[test]
    fn test_validate_152_mint_full() {
        assert!(validate_152_mint(&sample_mint_block()).is_ok());
    }

    #[test]
    fn test_validate_152_burn_full() {
        assert!(validate_152_burn(&sample_burn_block()).is_ok());
    }

    #[test]
    fn test_validate_152_mint_rejects_missing_caller() {
        assert!(validate_152_mint(&minimal_mint_block()).is_err());
    }

    #[test]
    fn test_validate_152_burn_rejects_missing_caller() {
        assert!(validate_152_burn(&minimal_burn_block()).is_err());
    }
}
