use super::*;
use crate::common::storage::types::RosettaBlock;
use candid::{Decode, Encode};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_icrc1_test_utils::valid_blockchain_strategy;
use ic_icrc1_tokens_u256::U256;
use ic_ledger_core::block::BlockType;
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;
use proptest::prelude::*;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

const TOKIO_WORKER_STACK_SIZE: usize = 2 * 1024 * 1024;

fn run_on_thread_with_stack_size<T: Send + 'static>(
    stack_size: usize,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    std::thread::Builder::new()
        .stack_size(stack_size)
        .spawn(f)
        .expect("failed to spawn thread")
        .join()
        .expect("thread panicked")
}

fn nested_arrays(depth: usize) -> Value {
    let mut value = Value::Nat64(0);
    for _ in 1..depth {
        value = Value::Array(vec![value]);
    }
    value
}

fn nested_maps(depth: usize) -> Value {
    let mut value = Value::Nat64(0);
    for _ in 1..depth {
        value = Value::Map(BTreeMap::from([("x".to_string(), value)]));
    }
    value
}

fn mint_block_with_extra_tx_field(extra: Value) -> Value {
    let to = Value::Array(vec![Value::Blob(ByteBuf::from(vec![1_u8; 29]))]);
    let tx = BTreeMap::from([
        ("op".to_string(), Value::Text("mint".to_string())),
        ("to".to_string(), to),
        ("amt".to_string(), Value::Nat(Nat::from(1_u64))),
        ("extra".to_string(), extra),
    ]);
    Value::Map(BTreeMap::from([
        ("ts".to_string(), Value::Nat64(1)),
        ("tx".to_string(), Value::Map(tx)),
    ]))
}

#[test]
fn should_compute_depth_boundaries() {
    assert!(!exceeds_max_depth(&Value::Nat64(0), 1));
    assert!(exceeds_max_depth(&Value::Array(vec![]), 0));
    assert!(!exceeds_max_depth(&nested_arrays(10), 10));
    assert!(exceeds_max_depth(&nested_arrays(11), 10));
    assert!(!exceeds_max_depth(&nested_maps(10), 10));
    assert!(exceeds_max_depth(&nested_maps(11), 10));
}

#[test]
fn should_accept_block_at_max_value_depth() {
    let block = mint_block_with_extra_tx_field(nested_arrays(MAX_BLOCK_VALUE_DEPTH - 2));
    let blocks = ensure_blocks_within_max_depth(vec![block.clone()], &Nat::from(0_u64))
        .expect("block within the bound should be accepted");
    assert_eq!(blocks, vec![block.clone()]);
    assert!(RosettaBlock::from_generic_block(block, 0).is_ok());
}

#[test]
fn should_reject_block_exceeding_max_value_depth() {
    let blocks = vec![
        mint_block_with_extra_tx_field(Value::Nat64(0)),
        mint_block_with_extra_tx_field(nested_arrays(MAX_BLOCK_VALUE_DEPTH - 1)),
    ];
    let error = ensure_blocks_within_max_depth(blocks, &Nat::from(10_u64))
        .expect_err("block exceeding the bound should be rejected");
    assert!(
        error.to_string().contains("Block at index 11"),
        "unexpected error: {error}"
    );
}

#[test]
fn should_reject_and_drop_very_deep_blocks_on_small_stack() {
    for depth in [50_000, 100_000] {
        let result = run_on_thread_with_stack_size(TOKIO_WORKER_STACK_SIZE, move || {
            let blocks = vec![
                mint_block_with_extra_tx_field(nested_arrays(depth)),
                mint_block_with_extra_tx_field(nested_maps(depth)),
            ];
            ensure_blocks_within_max_depth(blocks, &Nat::from(0_u64)).map(|_| ())
        });
        assert!(result.is_err(), "depth {depth} should be rejected");
    }
}

#[test]
fn should_reject_decoded_get_blocks_response_exceeding_max_value_depth() {
    let response = GetBlocksResponse {
        first_index: Nat::from(0_u64),
        chain_length: 1,
        certificate: None,
        blocks: vec![mint_block_with_extra_tx_field(nested_arrays(
            2 * MAX_BLOCK_VALUE_DEPTH,
        ))],
        archived_blocks: vec![],
    };
    let bytes = Encode!(&response).unwrap();
    let result = run_on_thread_with_stack_size(TOKIO_WORKER_STACK_SIZE, move || {
        let response = Decode!(&bytes, GetBlocksResponse).expect("failed to decode response");
        ensure_blocks_within_max_depth(response.blocks, &response.first_index).map(|_| ())
    });
    assert!(result.is_err());
}

proptest! {
    #[test]
    fn should_accept_regular_blocks(blockchain in valid_blockchain_strategy::<U256>(100)) {
        let blocks: Vec<Value> = blockchain
            .into_iter()
            .map(|block| encoded_block_to_generic_block(&block.encode()))
            .collect();
        let accepted = ensure_blocks_within_max_depth(blocks.clone(), &Nat::from(0_u64))
            .expect("regular blocks should be accepted");
        prop_assert_eq!(&accepted, &blocks);
        for (index, block) in accepted.into_iter().enumerate() {
            prop_assert!(RosettaBlock::from_generic_block(block, index as u64).is_ok());
        }
    }
}
