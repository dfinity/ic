use anyhow::bail;
use candid::Nat;
use icrc_ledger_types::icrc::generic_value::Value;

#[cfg(test)]
mod tests;

/// Maximum nesting depth accepted for a block `Value` fetched from a ledger or an archive.
///
/// The top-level block map has depth 1. The deepest field of a standard ICRC-3 block is an
/// account (`block -> tx -> account -> subaccount blob`), i.e. depth 4, so this bound leaves
/// ample room for extensions while keeping recursive processing of blocks (cloning, hashing,
/// dropping) shallow.
pub const MAX_BLOCK_VALUE_DEPTH: usize = 64;

/// Returns `true` if the nesting depth of `value` exceeds `max_depth`.
///
/// Traverses the value iteratively so that arbitrarily deep values can be inspected without
/// recursion.
pub fn exceeds_max_depth(value: &Value, max_depth: usize) -> bool {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 1)];
    while let Some((value, depth)) = stack.pop() {
        if depth > max_depth {
            return true;
        }
        match value {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Map(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            Value::Blob(_) | Value::Text(_) | Value::Nat(_) | Value::Nat64(_) | Value::Int(_) => {}
        }
    }
    false
}

/// Drops `value` without recursion, so that dropping an arbitrarily deep value cannot exhaust
/// the stack.
pub fn drop_iteratively(value: Value) {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => stack.extend(items),
            Value::Map(map) => stack.extend(map.into_values()),
            Value::Blob(_) | Value::Text(_) | Value::Nat(_) | Value::Nat64(_) | Value::Int(_) => {}
        }
    }
}

/// Checks that none of the given blocks exceeds [`MAX_BLOCK_VALUE_DEPTH`].
///
/// Returns the blocks unchanged if they are all within the bound. Otherwise, all blocks are
/// dropped iteratively and an error is returned, so that no recursive code ever operates on
/// the rejected blocks.
pub fn ensure_blocks_within_max_depth(
    blocks: Vec<Value>,
    first_index: &Nat,
) -> anyhow::Result<Vec<Value>> {
    let Some(position) = blocks
        .iter()
        .position(|block| exceeds_max_depth(block, MAX_BLOCK_VALUE_DEPTH))
    else {
        return Ok(blocks);
    };
    blocks.into_iter().for_each(drop_iteratively);
    bail!(
        "Block at index {} exceeds the maximum value nesting depth of {MAX_BLOCK_VALUE_DEPTH}",
        first_index.clone() + Nat::from(position)
    )
}
