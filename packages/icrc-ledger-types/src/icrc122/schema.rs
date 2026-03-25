use std::borrow::Cow;

use crate::icrc::generic_value_predicate::{
    ItemRequirement, ValuePredicateFailures, and, is, is_blob, is_equal_to, is_map,
    is_more_or_equal_to, is_nat, is_principal, is_text, item, len, or,
};
use crate::icrc::{generic_value::Value, generic_value_predicate::is_account};

/// Block type identifiers (ICRC-122 standard)
pub const BTYPE_122_MINT: &str = "122mint";
pub const BTYPE_122_BURN: &str = "122burn";

/// Method discriminators (ICRC-152 endpoint standard)
pub const MTHD_152_MINT: &str = "152mint";
pub const MTHD_152_BURN: &str = "152burn";

/// Validate if a block is compatible with the ICRC-122 mint schema.
///
/// Block structure:
/// ```text
/// { btype: "122mint", phash?: Blob(32), ts: Nat,
///   tx: { mthd: Text, to: Account, amt: Nat, caller: Principal, reason?: Text } }
/// ```
pub fn validate_mint(block: &Value) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;

    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_mint_transaction = and(vec![
        is_map(),
        item("mthd", Required, is_text()),
        item("to", Required, is_account()),
        item("amt", Required, is_nat()),
        item("caller", Required, is_principal()),
        item("reason", Optional, is_text()),
    ]);
    let is_122mint_block = and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(BTYPE_122_MINT))),
        item("ts", Required, is_timestamp),
        item("tx", Required, is_mint_transaction),
    ]);

    is_122mint_block(Cow::Borrowed(block))
}

/// Validate if a block is compatible with the ICRC-122 burn schema.
///
/// Block structure:
/// ```text
/// { btype: "122burn", phash?: Blob(32), ts: Nat,
///   tx: { mthd: Text, from: Account, amt: Nat, caller: Principal, reason?: Text } }
/// ```
pub fn validate_burn(block: &Value) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;

    let is_timestamp = is_more_or_equal_to(0);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_burn_transaction = and(vec![
        is_map(),
        item("mthd", Required, is_text()),
        item("from", Required, is_account()),
        item("amt", Required, is_nat()),
        item("caller", Required, is_principal()),
        item("reason", Optional, is_text()),
    ]);
    let is_122burn_block = and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(BTYPE_122_BURN))),
        item("ts", Required, is_timestamp),
        item("tx", Required, is_burn_transaction),
    ]);

    is_122burn_block(Cow::Borrowed(block))
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
            ("phash", Value::Blob(vec![0u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000u64.into())),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(MTHD_152_MINT)),
                    ("to", account_value()),
                    ("amt", Value::Nat(1000u64.into())),
                    ("caller", principal_blob()),
                ]),
            ),
        ])
    }

    fn sample_burn_block() -> Value {
        Value::map([
            ("btype", Value::text(BTYPE_122_BURN)),
            ("phash", Value::Blob(vec![0u8; 32].into())),
            ("ts", Value::Nat(1_000_000_000u64.into())),
            (
                "tx",
                Value::map([
                    ("mthd", Value::text(MTHD_152_BURN)),
                    ("from", account_value()),
                    ("amt", Value::Nat(1000u64.into())),
                    ("caller", principal_blob()),
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
        if let Value::Map(entries) = &mut block {
            if let Some(Value::Map(tx_entries)) = entries.get_mut("tx") {
                tx_entries.insert("reason".to_string(), Value::text("test reason"));
            }
        }
        assert!(validate_mint(&block).is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid() {
        // Missing required field (amt)
        let block = Value::map([
            ("btype", Value::text(BTYPE_122_MINT)),
            ("ts", Value::Nat(1_000_000_000u64.into())),
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
}
