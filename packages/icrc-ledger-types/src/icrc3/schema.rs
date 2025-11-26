use std::borrow::Cow;

use crate::icrc::{
    generic_value::Value,
    generic_value_predicate::{
        ItemRequirement, ValuePredicateFailures, and, element, is, is_array, is_blob, is_equal_to,
        is_int, is_less_or_equal_to, is_map, is_more_than, is_nat, is_nat64, item, len, or,
    },
};

/// Validate if a block is compatible with the ICRC-3 schema.
// TODO(FI-1241): make it compatible with the final ICRC-3 schema
pub fn validate(block: &Value) -> Result<(), ValuePredicateFailures> {
    use ItemRequirement::*;

    let is_zero = or(vec![
        and(vec![is_int(), is(Value::Int(0.into()))]),
        and(vec![is_nat(), is(Value::Nat(0_u8.into()))]),
        and(vec![is_nat64(), is(Value::Nat64(0))]),
    ]);
    let is_positive = or(vec![is_zero, is_more_than(0)]);
    let is_amount = is_positive.clone();
    let is_timestamp = is_positive;
    let is_principal = and(vec![is_blob(), len(is_less_or_equal_to(29))]);
    let is_subaccount = and(vec![is_blob(), len(is_equal_to(32))]);
    let is_account = and(vec![
        is_array(),
        element(0, is_principal.clone()),
        or(vec![
            len(is_equal_to(1)),
            and(vec![len(is_equal_to(2)), element(1, is_subaccount.clone())]),
        ]),
    ]);
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
        item("from", Required, is_account.clone()),
    ]);
    let is_icrc1_mint = and(vec![
        icrc1_common.clone(),
        item("op", Required, is(Value::text("mint"))),
        item("to", Required, is_account.clone()),
    ]);
    let is_icrc2_approve = and(vec![
        icrc1_common.clone(),
        item("op", Required, is(Value::text("approve"))),
        item("from", Required, is_account.clone()),
        item("spender", Required, is_account.clone()),
        item("expected_allowance", Optional, is_amount.clone()),
        item("expires_at", Optional, is_timestamp.clone()),
    ]);
    let is_icrc2_transfer_from = and(vec![
        icrc1_common,
        item("op", Required, is(Value::text("xfer"))),
        item("from", Required, is_account.clone()),
        item("to", Required, is_account.clone()),
        item("spender", Optional, is_account.clone()),
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
