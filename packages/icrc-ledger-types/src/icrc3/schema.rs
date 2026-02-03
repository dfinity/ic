use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicateFailures, and, is, is_account, is_blob, is_equal_to, is_map,
        is_more_or_equal_to, item, len, or,
    },
};

/// Validate if a block is compatible with the ICRC-3 schema.
// TODO(FI-1241): make it compatible with the final ICRC-3 schema
pub fn validate(block: &Value) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;

    let is_amount = is_more_or_equal_to(0);
    let is_timestamp = is_more_or_equal_to(0);
    let is_memo = is_blob();
    let icrc1_common = and(vec![
        is_map(),
        item("amt", Required, is_amount.clone()),
        item("fee", Optional, is_amount.clone()),
        item("memo", Optional, is_memo),
        item("ts", Optional, is_timestamp.clone()),
    ]);
    let is_icrc1_burn = and(vec![
        icrc1_common.clone(),
        item("op", Required, is(Value::text("burn"))),
        item("from", Required, is_account()),
    ]);
    let is_icrc1_mint = and(vec![
        icrc1_common.clone(),
        item("op", Required, is(Value::text("mint"))),
        item("to", Required, is_account()),
    ]);
    let is_icrc2_approve = and(vec![
        icrc1_common.clone(),
        item("op", Required, is(Value::text("approve"))),
        item("from", Required, is_account()),
        item("spender", Required, is_account()),
        item("expected_allowance", Optional, is_amount.clone()),
        item("expires_at", Optional, is_timestamp.clone()),
    ]);
    let is_icrc2_transfer_from = and(vec![
        icrc1_common,
        item("op", Required, is(Value::text("xfer"))),
        item("from", Required, is_account()),
        item("to", Required, is_account()),
        item("spender", Optional, is_account()),
    ]);
    let is_icrc1_or_icrc2_transaction = or(vec![
        is_icrc1_burn,
        is_icrc1_mint,
        is_icrc2_approve,
        is_icrc2_transfer_from,
    ]);
    let is_parent_hash = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_icrc1_or_icrc2_block = and(vec![
        item("phash", Optional, is_parent_hash),
        item("ts", Required, is_timestamp),
        item("fee", Optional, is_amount.clone()),
        item("tx", Required, is_icrc1_or_icrc2_transaction),
    ]);

    is_icrc1_or_icrc2_block(Cow::Borrowed(block))
}
