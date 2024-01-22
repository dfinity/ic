use candid::Nat;

use ic_icrc_rosetta::common::storage::types::RosettaBlock;

use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;

use std::sync::Arc;

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
