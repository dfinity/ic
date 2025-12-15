use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicateFailures, and, is, is_account, is_blob, is_equal_to, is_map,
        is_more_or_equal_to, is_principal, is_text, item, len,
    },
};

pub const BTYPE_107: &str = "107feecol";

/// Validate if a block is compatible with the ICRC-107 schema.
pub fn validate(block: &Value) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;

    let is_timestamp = is_more_or_equal_to(0);
    let is_icrc107_transaction = and(vec![
        is_map(),
        item("op", Optional, is_text()),
        item("fee_collector", Optional, is_account()),
        item("ts", Required, is_timestamp.clone()),
        item("caller", Required, is_principal()),
    ]);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_icrc107_block = and(vec![
        is_map(),
        item("phash", Optional, is_parent_hash),
        item("btype", Required, is(Value::text(BTYPE_107))),
        item("ts", Required, is_timestamp),
        item("tx", Optional, is_icrc107_transaction),
    ]);

    is_icrc107_block(Cow::Borrowed(block))
}
