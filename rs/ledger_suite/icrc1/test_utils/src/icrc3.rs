use candid::Nat;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

pub fn transfer_block<F: Into<Vec<u8>>, T: Into<Vec<u8>>>(
    block_id: u64,
    from: F,
    to: T,
    amount: u64,
    timestamp: u64,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("xfer".to_string()));

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(from))]),
    );
    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(to))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

pub fn mint_block<T: Into<Vec<u8>>>(
    block_id: u64,
    to: T,
    amount: u64,
    timestamp: u64,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("mint".to_string()));

    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(to))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

pub fn burn_block<F: Into<Vec<u8>>>(
    block_id: u64,
    from: F,
    amount: u64,
    timestamp: u64,
    fee: Option<u64>,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("burn".to_string()));

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(from))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    if let Some(fee) = fee {
        block_map.insert("fee".to_string(), ICRC3Value::Nat(Nat::from(fee)));
    }

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}
