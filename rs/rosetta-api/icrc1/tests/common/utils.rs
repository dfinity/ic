use candid::Nat;
use ic_icrc_rosetta::common::storage::types::RosettaBlock;
use ic_icrc_rosetta_client::RosettaClient;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;
use prometheus_parse::{Scrape, Value};
use rosetta_core::identifiers::NetworkIdentifier;
use std::sync::Arc;
use tokio::time::sleep;

pub async fn get_rosetta_blocks_from_icrc1_ledger(
    icrc1_agent: Arc<Icrc1Agent>,
    start: u64,
    length: usize,
) -> Vec<RosettaBlock> {
    let GetBlocksResponse {
        blocks: local_blocks,
        archived_blocks,
        ..
    } = icrc1_agent
        .get_blocks(GetBlocksRequest {
            start: Nat::from(start),
            length: Nat::from(length),
        })
        .await
        .expect("Failed to get blocks");
    let mut generic_blocks = vec![];
    for archive_fn in archived_blocks.into_iter() {
        generic_blocks.extend(
            icrc1_agent
                .get_blocks_from_archive(archive_fn)
                .await
                .unwrap()
                .blocks,
        )
    }
    generic_blocks.extend(local_blocks);
    generic_blocks
        .into_iter()
        .enumerate()
        .map(|(idx, generic_block)| {
            RosettaBlock::from_generic_block(generic_block, start + idx as u64)
        })
        .collect::<Result<Vec<RosettaBlock>, _>>()
        .unwrap()
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
