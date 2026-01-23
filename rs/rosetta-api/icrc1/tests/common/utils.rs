use candid::Nat;
use ic_icrc_rosetta::common::storage::types::RosettaBlock;
use ic_icrc_rosetta_client::RosettaClient;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc3::blocks::{BlockWithId, GetBlocksRequest, GetBlocksResult};
use num_traits::ToPrimitive;
use prometheus_parse::{Scrape, Value};
use rosetta_core::identifiers::NetworkIdentifier;
use std::sync::Arc;
use tokio::time::sleep;

pub async fn get_rosetta_blocks_from_icrc1_ledger(
    icrc1_agent: Arc<Icrc1Agent>,
    start: u64,
    length: usize,
) -> Vec<RosettaBlock> {
    let GetBlocksResult {
        blocks: local_blocks_with_id,
        archived_blocks,
        ..
    } = icrc1_agent
        .icrc3_get_blocks(vec![GetBlocksRequest {
            start: Nat::from(start),
            length: Nat::from(length),
        }])
        .await
        .expect("Failed to get blocks");
    let mut generic_blocks: Vec<BlockWithId> = vec![];
    for archived_blocks_entry in archived_blocks {
        let arch_blocks_result = icrc1_agent
            .icrc3_get_blocks_from_archive(archived_blocks_entry)
            .await
            .expect("Failed to get blocks from archive");

        generic_blocks.extend(arch_blocks_result.blocks);
    }
    generic_blocks.extend(local_blocks_with_id);
    generic_blocks
        .into_iter()
        .map(|block_with_id| {
            let block_index = block_with_id
                .id
                .0
                .to_u64()
                .expect("Could not convert Nat to u64");
            RosettaBlock::from_icrc3_generic_block(block_with_id.block, block_index)
                .expect("Failed to convert block")
        })
        .collect()
}

pub fn metrics_gauge_value(metrics: &Scrape, name: &str) -> Result<f64, String> {
    let metric = metrics
        .samples
        .iter()
        .find(|sample| sample.metric == name)
        .ok_or(format!("No metric found with name {name}"))?;
    match &metric.value {
        Value::Gauge(value) => Ok(*value),
        _ => panic!("{name} is not a gauge"),
    }
}

pub async fn wait_for_rosetta_block(
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
    block_index: u64,
) -> Option<u64> {
    const MAX_ATTEMPTS: u8 = 20;
    let mut last_block = None;
    for _ in 0..MAX_ATTEMPTS {
        let response = rosetta_client.ready().await;
        if response.is_success() {
            last_block = Some(
                rosetta_client
                    .network_status(network_identifier.clone())
                    .await
                    .unwrap()
                    .current_block_identifier
                    .index,
            );
            if last_block >= Some(block_index) {
                return last_block;
            }
        }
        sleep(std::time::Duration::from_secs(1)).await;
    }
    last_block
}
