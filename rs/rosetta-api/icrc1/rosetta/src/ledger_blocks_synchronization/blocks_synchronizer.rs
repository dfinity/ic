use std::{ops::RangeInclusive, sync::Arc};

use crate::common::storage::{storage_client::StorageClient, types::RosettaBlock};
use candid::Nat;
use ic_crypto_tree_hash::{LookupStatus, MixedHashTree};
use ic_icrc1::hash::Hash;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResponse};
use serde_bytes::ByteBuf;
use LookupStatus::Found;

// The blocks synchronizer starts by getting the most recent block and starts fetching the blockchain starting from the top of the blockchain
// It verifies fetched blocks and stores verified blocks in the database
// TODO: Make BlocksSynchronizer fetch blocks continously instead of returning once it has finished synching from the tip
pub async fn start_synching_blocks(
    agent: &Icrc1Agent,
    storage_client: Arc<StorageClient>,
    maximum_blocks_per_request: u64,
) -> anyhow::Result<()> {
    // Get the most recent hash and index of the icrc ledger and start fetching from the top of the chain
    let (tip_block_index, tip_block_hash) = get_blockchain_tip_data(agent).await?;

    // The leading index/hash is the highest block index/hash that is requested by the icrc ledger
    let mut index_interval = RangeInclusive::new(
        tip_block_index.saturating_sub(maximum_blocks_per_request),
        tip_block_index,
    );
    let mut leading_block_hash = Some(ByteBuf::from(tip_block_hash));

    // Start fetching blocks starting from the tip of the blockchain and store them in the database
    // Only the genesis block has a parent hash that is none
    while leading_block_hash.is_some() {
        let fetched_blocks = fetch_blocks_interval(agent, index_interval.clone()).await?;

        // Verify that the fetched blocks are valid
        // Leading block hash of a non empty fetched blocks can never be None -> Unwrap is safe
        if !blocks_verifier::is_valid_blockchain(
            &fetched_blocks,
            &leading_block_hash.clone().unwrap(),
        ) {
            // Abort synchronization if blockchain is not valid
            return Err(anyhow::Error::msg(format!(
                "The fetched blockchain contains invalid blocks in index range {} to {}",
                index_interval.start(),
                index_interval.end()
            )));
        }

        // Set variables for next loop iteration
        leading_block_hash = fetched_blocks[0].parent_hash.clone();
        index_interval = RangeInclusive::new(
            index_interval
                .start()
                .saturating_sub(fetched_blocks.len() as u64),
            index_interval
                .end()
                .saturating_sub(fetched_blocks.len() as u64),
        );

        // Store the fetched blocks in the database
        storage_client.store_blocks(fetched_blocks)?;
    }

    Ok(())
}

// Fetches all blocks given a certain interval. The interval is expected to be smaller or equal to the maximum number of blocks than can be requested
pub async fn fetch_blocks_interval(
    agent: &Icrc1Agent,
    index_range: RangeInclusive<u64>,
) -> anyhow::Result<Vec<RosettaBlock>> {
    // Construct the request object for the icrc1 agent
    let get_blocks_request = GetBlocksRequest {
        start: Nat::from(*index_range.start()),
        // To include the block at end_index we have to add one, since the index starts at 0
        length: Nat::from(*index_range.end() - *index_range.start() + 1),
    };

    let mut fetched_blocks_result = vec![];

    // Fetch blocks with a given request from the Icrc1Agent
    let blocks_response: GetBlocksResponse =
        agent.get_blocks(get_blocks_request).await.map_err(|_| {
            let error_msg = format!(
                "Icrc1Agent could not fetch blocks in interval {} to {}",
                index_range.start().clone(),
                index_range.end().clone()
            );
            anyhow::Error::msg(error_msg)
        })?;

    // Convert all Generic Blocks into RosettaBlocks
    for (index, block) in blocks_response.blocks.into_iter().enumerate() {
        // The index of the RosettaBlock is the starting index of the request plus the position of current block in the response object
        fetched_blocks_result.push(RosettaBlock::from_generic_block(
            block,
            *index_range.start() + index as u64,
        )?);
    }

    Ok(fetched_blocks_result)
}

async fn get_blockchain_tip_data(agent: &Icrc1Agent) -> anyhow::Result<(u64, Hash)> {
    // Fetch the data certificate from the icrc ledger
    let data_certificate = agent
        .get_data_certificate()
        .await
        .map_err(|_| anyhow::Error::msg("Could not fetch data certificate from ledger"))?;

    // Extract the hash tree from the data certificate and deserialize it into a Tree object
    let hash_tree: MixedHashTree = serde_cbor::from_slice(&data_certificate.hash_tree)
        .map_err(|err| anyhow::Error::msg(err.to_string()))?;

    // Extract the last block index from the hash tree
    let last_block_index = match hash_tree.lookup(&[b"last_block_index"]) {
        Found(x) => match x {
            MixedHashTree::Leaf(l) => {
                let mut bytes: [u8; 8] = [0u8; 8];
                for (i, e) in l.iter().enumerate() {
                    bytes[i] = *e;
                }
                Ok(u64::from_be_bytes(bytes))
            }
            _ => Err(anyhow::Error::msg(
                "Last block index was found, but MixedHashTree is no a Leaf",
            )),
        },
        _ => Err(anyhow::Error::msg(
            "Last block index was not found in hash tree",
        )),
    }?;

    // Extract the last block hash from the hash tree
    let last_block_hash = match hash_tree.lookup(&[b"tip_hash"]) {
        Found(x) => match x {
            MixedHashTree::Leaf(l) => {
                let mut bytes: Hash = [0u8; 32];
                for (i, e) in l.iter().enumerate() {
                    bytes[i] = *e;
                }
                Ok(bytes)
            }
            _ => Err(anyhow::Error::msg(
                "Last block hash was found, but MixedHashTree is no a Leaf",
            )),
        },
        _ => Err(anyhow::Error::msg(
            "Last block hash was not found in hash tree",
        )),
    }?;
    Ok((last_block_index, last_block_hash))
}

pub mod blocks_verifier {
    use serde_bytes::ByteBuf;

    use crate::common::storage::types::RosettaBlock;
    pub fn is_valid_blockchain(
        blockchain: &Vec<RosettaBlock>,
        leading_block_hash: &ByteBuf,
    ) -> bool {
        if blockchain.is_empty() {
            return true;
        }

        // Check that the leading block has the block hash that is provided
        // Safe to call unwrap as the blockchain is guarenteed to have at least one element
        if blockchain.last().unwrap().block_hash.clone() != leading_block_hash {
            return false;
        }

        let mut parent_hash = Some(blockchain[0].block_hash.clone());
        // The blockchain has more than one element so it is save to skip the first one
        // The first element cannot be verified so we start at element 2
        for block in blockchain.iter().skip(1) {
            if block.parent_hash != parent_hash {
                return false;
            }
            parent_hash = Some(block.block_hash.clone());
        }

        // No invalid blocks were found return true
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::unit_test_utils::strategies::valid_blockchain_strategy;
    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use serde_bytes::ByteBuf;

    proptest! {
            #[test]
        fn test_valid_blockchain(blockchain in valid_blockchain_strategy(1000)){
            let num_blocks = blockchain.len();
            let mut rosetta_blocks = vec![];
            for (index,block) in blockchain.into_iter().enumerate(){
                rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
            }
            // Blockchain is valid and should thus pass the verification
            assert!(blocks_verifier::is_valid_blockchain(&rosetta_blocks,&rosetta_blocks.last().map(|block|block.block_hash.clone()).unwrap_or_else(|| ByteBuf::from(r#"TestBytes"#))));

            // There is no point in shuffling the blockchain if it has length zero
            if num_blocks > 0 {
                // If shuffled, the blockchain is no longer in order and thus no longer valid
                rosetta_blocks.shuffle(&mut rand::thread_rng());
                let shuffled_blocks = rosetta_blocks.to_vec();
                assert!(!blocks_verifier::is_valid_blockchain(&shuffled_blocks,&rosetta_blocks.last().unwrap().block_hash.clone())|| num_blocks<=1||rosetta_blocks==shuffled_blocks);
            }

        }
    }
}
