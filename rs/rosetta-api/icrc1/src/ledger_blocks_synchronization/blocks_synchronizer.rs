#![allow(clippy::disallowed_types)]
use crate::common::storage::storage_client::StorageClient;
use crate::common::storage::types::RosettaBlock;
use anyhow::{Context, bail};
use candid::{Decode, Encode, Nat};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use icrc_ledger_types::icrc3::blocks::{BlockRange, GetBlocksRequest, GetBlocksResponse};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use std::{cmp, collections::HashMap, ops::RangeInclusive, sync::Arc, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{error, info};

// Interval for reporting progress of the synchronization process for each token.
const PROGRESS_REPORT_INTERVAL: Duration = Duration::from_secs(5);

// The Range of indices to be synchronized.
// Contains the hashes of the top and end of the index range, which is used to ensure the fetched block interval is valid.
#[derive(Clone, Eq, PartialEq, Debug)]
struct SyncRange {
    index_range: RangeInclusive<u64>,
    leading_block_hash: ByteBuf,
    trailing_parent_hash: Option<ByteBuf>,
}

impl SyncRange {
    fn new(
        lowest_index: u64,
        highest_index: u64,
        leading_block_hash: ByteBuf,
        trailing_parent_hash: Option<ByteBuf>,
    ) -> Self {
        Self {
            index_range: RangeInclusive::new(lowest_index, highest_index),
            leading_block_hash,
            trailing_parent_hash,
        }
    }
}

// Defines the configuration for the recurrency mode.
#[derive(Clone, Debug)]
pub struct RecurrencyConfig {
    // The minimum time to wait before the next synchronization.
    pub min_recurrency_wait: Duration,
    // The maximum time to wait before the next synchronization.
    pub max_recurrency_wait: Duration,
    // The backoff factor to increase the wait time after each failure.
    pub backoff_factor: u32,
}

pub enum RecurrencyMode {
    // Syncs only once
    OneShot,

    // Syncs recurrently with the given configuration
    Recurrent(RecurrencyConfig),
}

async fn verify_and_fix_gaps(
    agent: Arc<Icrc1Agent>,
    storage_client: Arc<StorageClient>,
    archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
) -> anyhow::Result<()> {
    let sync_ranges = derive_synchronization_gaps(storage_client.clone()).await?;
    let tip = get_tip_block_hash_and_index(agent.clone()).await?;
    let (_tip_block_hash, tip_block_index) = match tip {
        Some(tip) => tip,
        None => return Ok(()),
    };

    for sync_range in sync_ranges {
        sync_blocks_interval(
            agent.clone(),
            storage_client.clone(),
            1000,
            archive_canister_ids.clone(),
            sync_range,
            tip_block_index,
        )
        .await?;
    }
    Ok(())
}

/// This function will check whether there is a gap in the database.
/// Furthermore, if there exists a gap between the genesis block and the lowest stored block, this function will add this synchronization gap to the gaps returned by the storage client.
/// It is guaranteed that all gaps between [0,Highest_Stored_Block] will be returned.
async fn derive_synchronization_gaps(
    storage_client: Arc<StorageClient>,
) -> anyhow::Result<Vec<SyncRange>> {
    if !storage_client.does_blockchain_have_gaps().await? {
        return Ok(vec![]);
    }

    // If there is a gap, compute all the gaps.
    let gap = storage_client.get_blockchain_gaps().await?;

    // The database should have at most one gap. Otherwise the database file was edited and it can no longer be guaranteed that it contains valid blocks.
    if gap.len() > 1 {
        bail!(
            "The database has {} gaps. More than one gap means the database has been tampered with and can no longer be guaranteed to contain valid blocks",
            gap.len()
        );
    } else if gap.is_empty() {
        // The block counter is off
        storage_client.reset_blocks_counter().await?;
    }

    let mut sync_ranges = gap
        .into_iter()
        .map(|(a, b)| {
            SyncRange::new(
                a.index + 1,
                b.index - 1,
                b.get_parent_hash().unwrap(),
                Some(a.clone().get_block_hash()),
            )
        })
        .collect::<Vec<SyncRange>>();

    // Gaps are only determined within stored block ranges. Blocks with indices that are below the lowest stored block and above the highest stored blocks are not considered.
    // Check if the lowest block that was stored is the genesis block.

    let Some(lowest_block) = storage_client.get_block_with_lowest_block_idx().await? else {
        // If the database is empty then there cannot exist any gaps.
        return Ok(vec![]);
    };

    if lowest_block.index != 0 {
        // If the lowest stored block's index is not 0 that means there is a gap between the genesis block and the lowest stored block. Unwrapping parent hash is safe as only the genesis block does not have a parent hash.
        // The first interval to sync is between the genesis block and the lowest stored block.
        sync_ranges.insert(
            0,
            SyncRange::new(
                0,
                lowest_block.index - 1,
                lowest_block.get_parent_hash().unwrap(),
                None,
            ),
        );
    }
    Ok(sync_ranges)
}

pub async fn start_synching_blocks(
    agent: Arc<Icrc1Agent>,
    storage_client: Arc<StorageClient>,
    maximum_blocks_per_request: u64,
    archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
    recurrency_mode: RecurrencyMode,
    heartbeat: Box<dyn Fn() + Send + Sync>,
) -> anyhow::Result<()> {
    let mut current_failure_streak = 0u32;
    let mut is_initial_sync = true;
    loop {
        // Don't start beating heart before initial sync is done,
        // otherwise the watchdog thread will keep killing it.
        if !is_initial_sync {
            heartbeat();
        }
        let mut sync_failed = false;
        // Verify and fix gaps in the database.
        let result = verify_and_fix_gaps(
            agent.clone(),
            storage_client.clone(),
            archive_canister_ids.clone(),
        )
        .await;
        match result {
            Ok(_) => {}
            Err(e) => {
                error!("Error while verifying and fixing gaps: {}", e);
                sync_failed = true;
            }
        }

        if !sync_failed {
            match sync_from_the_tip(
                agent.clone(),
                storage_client.clone(),
                maximum_blocks_per_request,
                archive_canister_ids.clone(),
            )
            .await
            {
                Ok(_) => {
                    is_initial_sync = false;
                }
                Err(e) => {
                    error!("Error while syncing blocks: {}", e);
                    sync_failed = true;
                }
            }
        }

        // Update the account balances. When queried for its status, the ledger will return the
        // highest block index for which the account balances have been processed.
        match storage_client.update_account_balances().await {
            Ok(_) => {
                // We will only end up here if there are no gaps, the blockchain is synced to the
                // tip, and the account balances have been updated.
                let highest_block_index = storage_client
                    .get_block_with_highest_block_idx()
                    .await
                    .unwrap_or(None)
                    .map(|rosetta_block| rosetta_block.index)
                    .unwrap_or(0u64);
                storage_client
                    .get_metrics()
                    .set_verified_height(highest_block_index);
            }
            Err(e) => {
                error!("Error while updating account balances: {}", e);
                sync_failed = true;
            }
        }

        if sync_failed {
            current_failure_streak += 1;
        } else {
            current_failure_streak = 0;
        }

        match recurrency_mode {
            RecurrencyMode::OneShot => break,
            RecurrencyMode::Recurrent(ref config) => {
                let mut wait_time = config
                    .min_recurrency_wait
                    .saturating_mul(config.backoff_factor.saturating_pow(current_failure_streak));
                wait_time = cmp::min(wait_time, config.max_recurrency_wait);
                if wait_time > config.min_recurrency_wait {
                    error!("Error encountered, waiting {:?} before retrying", wait_time);
                }
                tokio::time::sleep(wait_time).await;
            }
        }
    }
    Ok(())
}

pub async fn get_tip_block_hash_and_index(
    agent: Arc<Icrc1Agent>,
) -> anyhow::Result<Option<([u8; 32], u64)>> {
    let (tip_block_hash, tip_block_index) = match agent
        .get_certified_chain_tip()
        .await
        .with_context(|| "Could not fetch certified chain tip from ledger.")?
    {
        Some(tip) => tip,
        None => {
            info!("The ledger is empty, exiting sync!");
            return Ok(None);
        }
    };

    let tip_block_index = match tip_block_index.0.to_u64() {
        Some(n) => n,
        None => bail!("could not convert last_block_index {tip_block_index} to u64"),
    };

    Ok(Some((tip_block_hash, tip_block_index)))
}

/// This function will do a synchronization of the interval (Highest_Stored_Block,Ledger_Tip].
pub async fn sync_from_the_tip(
    agent: Arc<Icrc1Agent>,
    storage_client: Arc<StorageClient>,
    maximum_blocks_per_request: u64,
    archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
) -> anyhow::Result<()> {
    let tip = get_tip_block_hash_and_index(agent.clone()).await?;
    let (tip_block_hash, tip_block_index) = match tip {
        Some(tip) => tip,
        None => return Ok(()),
    };

    storage_client
        .get_metrics()
        .set_target_height(tip_block_index);

    // The starting point of the synchronization process is either 0 if the database is empty or the highest stored block index plus one.
    // The trailing parent hash is either `None` if the database is empty or the block hash of the block with the highest block index in storage.
    let sync_range = storage_client
        .get_block_with_highest_block_idx()
        .await?
        .map_or(
            SyncRange::new(0, tip_block_index, ByteBuf::from(tip_block_hash), None),
            |block| {
                SyncRange::new(
                    // If storage is up to date then the start index is the same as the tip of the ledger.
                    block.index + 1,
                    tip_block_index,
                    ByteBuf::from(tip_block_hash),
                    Some(block.clone().get_block_hash()),
                )
            },
        );

    // Do not make a sync call if the storage is up to date with the replica's ledger.
    if !sync_range.index_range.is_empty() {
        sync_blocks_interval(
            agent.clone(),
            storage_client.clone(),
            maximum_blocks_per_request,
            archive_canister_ids,
            sync_range,
            tip_block_index,
        )
        .await?;
    }
    Ok(())
}

pub struct ProgressReport {
    start: u64,
    end: u64,
    remaining_end: u64,
    last_update: std::time::Instant,
    start_time: std::time::Instant,
    tip_block_index: u64,
}

impl ProgressReport {
    pub fn new(start: u64, end: u64, tip_block_index: u64) -> Self {
        Self {
            start,
            end,
            remaining_end: end,
            start_time: std::time::Instant::now(),
            last_update: std::time::Instant::now(),
            tip_block_index,
        }
    }

    // Reminder: blocks are added from the end of the range to the start.
    pub fn update(&mut self, added_blocks: u64) {
        self.remaining_end = self.remaining_end.saturating_sub(added_blocks);
        let now = std::time::Instant::now();
        if now.duration_since(self.last_update) > PROGRESS_REPORT_INTERVAL {
            let time_spent = now.duration_since(self.start_time).as_secs_f64();
            let current_rate = self.end.saturating_sub(self.remaining_end) as f64 / time_spent;
            let remaining_count = self.remaining_end.saturating_sub(self.start) as f64 + 1.0;
            let expected_remaining_time = remaining_count / current_rate;
            self.last_update = now;
            let progress =
                (self.tip_block_index as f64 - remaining_count) / self.tip_block_index as f64;
            info!(
                "Progress: {:.2}% (fetching {} of {}), ETA: {:.1}min ({:.1} blocks/s)",
                progress * 100.0,
                remaining_count,
                self.tip_block_index,
                expected_remaining_time / 60.0,
                current_rate
            );
        }
    }

    pub fn finish(&self) {
        if self.end == self.tip_block_index {
            info!("Fully synched to block height: {}", self.end);
        } else {
            info!("Synched block range: {} to {}", self.start, self.end);
        }
    }
}

/// Syncs a specific blocks interval, validates it and stores it in storage.
/// Expects the blocks interval to exist on the ledger.
async fn sync_blocks_interval(
    agent: Arc<Icrc1Agent>,
    storage_client: Arc<StorageClient>,
    maximum_blocks_per_request: u64,
    archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
    sync_range: SyncRange,
    tip_block_index: u64,
) -> anyhow::Result<()> {
    // Create a progress bar for visualization.
    let mut pr = ProgressReport::new(
        *sync_range.index_range.start(),
        *sync_range.index_range.end(),
        tip_block_index,
    );

    // The leading index/hash is the highest block index/hash that is requested by the icrc ledger.
    let mut next_index_interval = RangeInclusive::new(
        cmp::max(
            sync_range
                .index_range
                .end()
                .saturating_sub(maximum_blocks_per_request),
            *sync_range.index_range.start(),
        ),
        *sync_range.index_range.end(),
    );
    let mut leading_block_hash = Some(sync_range.leading_block_hash);

    // Start fetching blocks starting from the tip of the blockchain and store them in the
    // database.
    loop {
        // The fetch_blocks_interval function guarantees that all blocks that were asked for are fetched if they exist on the ledger.
        let fetched_blocks = fetch_blocks_interval(
            agent.clone(),
            next_index_interval.clone(),
            archive_canister_ids.clone(),
        )
        .await;

        if let Err(e) = fetched_blocks {
            error!("Error while calling fetch_blocks_interval: {}", e);
            return Err(e);
        }

        let fetched_blocks = fetched_blocks.unwrap();

        // Verify that the fetched blocks are valid.
        // Leading block hash of a non empty fetched blocks can never be `None` -> Unwrap is safe.
        if let Err(error) = blocks_verifier::is_valid_blockchain(
            &fetched_blocks,
            &leading_block_hash.clone().unwrap(),
        ) {
            // Abort synchronization if blockchain is not valid.
            bail!(
                "The fetched blockchain contains invalid blocks in index range {} to {}: {error}",
                next_index_interval.start(),
                next_index_interval.end()
            );
        }

        // Verify that the indices that are returned by the replica match those that were requested (Block Indices are not part of the block hash)
        if !blocks_verifier::indices_are_valid(&fetched_blocks, next_index_interval.clone()) {
            bail!(
                "The fetched blockchain is not a left bound subset of the requested indices in index range {} to {}",
                next_index_interval.start(),
                next_index_interval.end()
            );
        }

        leading_block_hash.clone_from(&fetched_blocks[0].get_parent_hash());
        let number_of_blocks_fetched = fetched_blocks.len() as u64;

        // Store the fetched blocks in the database.
        let result = storage_client.store_blocks(fetched_blocks.clone()).await;
        if let Err(e) = result {
            error!("Error while calling storage_client.store_blocks: {}", e);
            return Err(e);
        }
        storage_client
            .get_metrics()
            .add_blocks_fetched(number_of_blocks_fetched);
        // The first iteration of the loop will fetch blocks up to the end of the `sync_range`.
        // Subsequent iterations will fetch blocks with lower indexes, and calls to
        // `set_synced_height` will be redundant but harmless.
        storage_client
            .get_metrics()
            .set_synced_height(*sync_range.index_range.end());
        pr.update(number_of_blocks_fetched);

        // If the interval of the last iteration started at the target height, then all blocks above and including the target height have been synched.
        if *next_index_interval.start() == *sync_range.index_range.start() {
            // All blocks were fetched, now the parent hash of the lowest block fetched has to match the hash of the highest block in the database or `None` (If database was empty).
            if leading_block_hash == sync_range.trailing_parent_hash {
                break;
            } else {
                bail!(
                    "Hash of block {} in database does not match parent hash of fetched block {}",
                    next_index_interval.start().saturating_sub(1),
                    next_index_interval.start()
                )
            }
        }

        // Set variables for next loop iteration.
        let interval_start = cmp::max(
            next_index_interval
                .start()
                .saturating_sub(number_of_blocks_fetched as u64),
            *sync_range.index_range.start(),
        );
        let interval_end = cmp::max(
            next_index_interval
                .end()
                .saturating_sub(number_of_blocks_fetched as u64),
            *sync_range.index_range.start(),
        );
        next_index_interval = RangeInclusive::new(interval_start, interval_end);
    }
    pr.finish();
    Ok(())
}

/// Fetches all blocks given a certain interval. The interval is expected to be smaller or equal to the maximum number of blocks than can be requested.
/// Guarantees to return only if all blocks in the given interval were fetched.
async fn fetch_blocks_interval(
    agent: Arc<Icrc1Agent>,
    index_range: RangeInclusive<u64>,
    archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
) -> anyhow::Result<Vec<RosettaBlock>> {
    // Construct a hashmap which maps block indices to blocks. Blocks that have not been fetched are `None`.
    let mut fetched_blocks_result: HashMap<u64, Option<RosettaBlock>> = HashMap::new();

    // Initialize fetched blocks map with `None` as no blocks have been fetched yet.
    index_range.for_each(|index| {
        fetched_blocks_result.insert(index, None);
    });

    // Missing blocks are those block indices where the value in the hashmap is missing.
    let missing_blocks = |blocks: &HashMap<u64, Option<RosettaBlock>>| {
        blocks
            .iter()
            .filter_map(
                |(key, value)| {
                    if value.is_none() { Some(*key) } else { None }
                },
            )
            .collect::<Vec<u64>>()
    };

    // Extract all block index intervals that can be fetch.
    let fetchable_intervals = |blocks: &HashMap<u64, Option<RosettaBlock>>| {
        // Get all the missing block indices and sort them.
        let mut missing = missing_blocks(blocks);
        missing.sort();

        // If all blocks have been fetched return an empty vector.
        if missing.is_empty() {
            return vec![];
        }

        let mut block_ranges = vec![];
        let mut start = missing[0];

        // It is possible that the replica returns block intervals that contain patches --> Find all missing indices and aggregate them in the longest consecutive intervals.
        for i in 1..missing.len() {
            if missing[i] != missing[i - 1] + 1 {
                block_ranges.push(RangeInclusive::new(start, missing[i - 1]));
                start = missing[i];
            }
        }
        block_ranges.push(RangeInclusive::new(start, missing[missing.len() - 1]));
        block_ranges
    };

    // Ensure that this function only returns once all blocks have been collected.
    while !missing_blocks(&fetched_blocks_result).is_empty() {
        // Calculate all longest consecutive block index intervals.
        for interval in fetchable_intervals(&fetched_blocks_result) {
            let get_blocks_request = GetBlocksRequest {
                start: Nat::from(*interval.start()),
                // To include the block at end_index we have to add one, since the index starts at 0.
                length: Nat::from(*interval.end() - *interval.start() + 1),
            };

            // Fetch blocks with a given request from the Icrc1Agent
            let blocks_response: GetBlocksResponse = agent
                .get_blocks(get_blocks_request)
                .await
                .with_context(|| {
                    format!(
                        "Icrc1Agent could not fetch blocks in interval {} to {}",
                        interval.start().clone(),
                        interval.end().clone()
                    )
                })?;

            // Convert all Generic Blocks into RosettaBlocks.
            for (index, block) in blocks_response.blocks.into_iter().enumerate() {
                // The index of the RosettaBlock is the starting index of the request plus the position of current block in the response object.
                let block_index = blocks_response
                    .first_index
                    .0
                    .to_u64()
                    .context("Could not convert Nat to u64")?
                    + index as u64;
                fetched_blocks_result.insert(
                    block_index,
                    Some(
                        RosettaBlock::from_generic_block(block, block_index).map_err(|e| {
                            let old_context = e.to_string();
                            e.context(format!(
                                "Failed to parse block at index {block_index}: {old_context}"
                            ))
                        })?,
                    ),
                );
            }

            // Fetch all blocks that could not be returned by the ledger directly, from the
            // archive.
            for archive_query in blocks_response.archived_blocks {
                let arg = Encode!(&GetBlocksRequest {
                    start: archive_query.start.clone(),
                    length: archive_query.length,
                })?;

                // Check if the provided archive canister id is in the list of trusted canister ids
                // (without holding lock across await points)
                let is_trusted = {
                    let trusted_archive_canisters = archive_canister_ids.lock().await;
                    trusted_archive_canisters.iter().any(|archive_info| {
                        archive_info.canister_id == archive_query.callback.canister_id
                    })
                };

                if !is_trusted {
                    // Fetch updated archive info without holding the lock
                    let new_archive_infos = fetch_archive_canister_infos(agent.clone()).await?;

                    // Update the list and check again
                    let mut trusted_archive_canisters = archive_canister_ids.lock().await;
                    *trusted_archive_canisters = new_archive_infos;

                    if !trusted_archive_canisters.iter().any(|archive_info| {
                        archive_info.canister_id == archive_query.callback.canister_id
                    }) {
                        bail!(
                            "Archive canister id {} is not in the list of trusted canister ids",
                            archive_query.callback.canister_id
                        );
                    }
                }

                // Query the archive without holding any lock
                let archive_response = agent
                    .agent
                    .query(
                        &archive_query.callback.canister_id,
                        &archive_query.callback.method,
                    )
                    .with_arg(arg)
                    .call()
                    .await?;

                let arch_blocks_result = Decode!(&archive_response, BlockRange)?;

                // The archive guarantees that the first index of the blocks it returns is the same as requested.
                let first_index = archive_query
                    .start
                    .0
                    .to_u64()
                    .with_context(|| anyhow::Error::msg("Nat could not be converted to u64"))?;

                // Iterate over the blocks returned from the archive and add them to the hashmap.
                for (index, block) in arch_blocks_result.blocks.into_iter().enumerate() {
                    let block_index = first_index + index as u64;
                    // The index of the RosettaBlock is the starting index of the request plus the position of the current block in the response object.
                    fetched_blocks_result.insert(
                        block_index,
                        Some(RosettaBlock::from_generic_block(block, block_index)?),
                    );
                }
            }
        }
    }

    // Get all the blocks from the hashmap.
    let mut result = fetched_blocks_result
        .into_values()
        .map(|block| {
            block.ok_or_else(|| anyhow::Error::msg("Could not fetch all requested blocks"))
        })
        .collect::<Result<Vec<RosettaBlock>, anyhow::Error>>()?;

    // The blocks may not have been fetched in order.
    result.sort_by(|a, b| a.index.partial_cmp(&b.index).unwrap());

    Ok(result)
}

pub async fn fetch_archive_canister_infos(
    icrc1_agent: Arc<Icrc1Agent>,
) -> anyhow::Result<Vec<ArchiveInfo>> {
    Decode!(
        &icrc1_agent
            .agent
            .update(&icrc1_agent.ledger_canister_id, "archives")
            .with_arg(Encode!().context("Failed to encode empty argument")?)
            .call_and_wait()
            .await
            .context("Failed to fetch list of archives from ledger")?,
        Vec<ArchiveInfo>
    )
    .context("Failed to decode list of archives from ledger")
}

pub mod blocks_verifier {
    use crate::common::storage::types::RosettaBlock;
    use serde_bytes::ByteBuf;
    use std::ops::RangeInclusive;

    pub fn is_valid_blockchain(
        blockchain: &[RosettaBlock],
        leading_block_hash: &ByteBuf,
    ) -> Result<(), String> {
        if blockchain.is_empty() {
            return Ok(());
        }

        // Check that the leading block has the block hash that is provided.
        // Safe to call unwrap as the blockchain is guaranteed to have at least one element.
        if blockchain.last().unwrap().clone().get_block_hash().clone() != leading_block_hash {
            return Err(format!(
                "Invalid block at index {}",
                blockchain.last().unwrap().clone().index
            ));
        }

        let mut parent_hash = Some(blockchain[0].clone().get_block_hash().clone());
        // The blockchain has more than one element so it is safe to skip the first one.
        // The first element cannot be verified so we start at element 2.
        for block in blockchain.iter().skip(1) {
            if block.get_parent_hash() != parent_hash {
                if block.index == 0 {
                    return Err("Block with index 0 found at different location".to_string());
                } else {
                    return Err(format!("Invalid block at index {}", block.index - 1));
                }
            }
            parent_hash = Some(block.clone().get_block_hash());
        }

        // No invalid blocks were found return true.
        Ok(())
    }

    /// Checks whether the blocks in the blockchain are a continous subset of the requested indices
    pub fn indices_are_valid(
        blockchain: &[RosettaBlock],
        requested_indices: RangeInclusive<u64>,
    ) -> bool {
        if blockchain.is_empty() {
            return true;
        }

        let mut current_index = *requested_indices.start();
        for block in blockchain {
            // The fetched blockchain should be continous with respect to the requested indices.
            if block.index != current_index {
                return false;
            }
            current_index += 1;
        }

        current_index - 1 == *requested_indices.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_icrc1::blocks::encoded_block_to_generic_block;
    use ic_icrc1_test_utils::valid_blockchain_strategy;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_core::block::BlockType;
    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use serde_bytes::ByteBuf;

    proptest! {
            #[test]
            fn test_valid_blockchain(blockchain in valid_blockchain_strategy::<U256>(1000)){
                let num_blocks = blockchain.len();
                let mut rosetta_blocks = vec![];
                for (index,block) in blockchain.into_iter().enumerate(){
                    rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
                }
                // Blockchain is valid and should thus pass the verification.
                assert!(blocks_verifier::is_valid_blockchain(&rosetta_blocks,&rosetta_blocks.last().map(|block|block.clone().get_block_hash().clone()).unwrap_or_else(|| ByteBuf::from(r#"TestBytes"#))).is_ok());

                // There is no point in shuffling the blockchain if it has length zero.
                if num_blocks > 0 {
                    // If shuffled, the blockchain is no longer in order and thus no longer valid.
                    rosetta_blocks.shuffle(&mut rand::thread_rng());
                    let shuffled_blocks = rosetta_blocks.to_vec();
                    assert!(blocks_verifier::is_valid_blockchain(&shuffled_blocks,&rosetta_blocks.last().unwrap().clone().get_block_hash().clone()).is_err()|| num_blocks<=1||rosetta_blocks==shuffled_blocks);
                }

            }

            #[test]
            fn test_indices_are_valid(blockchain in valid_blockchain_strategy::<U256>(1000)) {
                let mut rosetta_blocks = vec![];
                for (index,block) in blockchain.into_iter().enumerate(){
                    rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
                }
                if !rosetta_blocks.is_empty() {
                let requested_indices = RangeInclusive::new(0, (rosetta_blocks.len()-1) as u64);
                assert!(blocks_verifier::indices_are_valid(
                    &rosetta_blocks,
                    requested_indices
                ));
                let requested_indices = RangeInclusive::new(0, rosetta_blocks.len()as u64);
                assert!(!blocks_verifier::indices_are_valid(
                    &rosetta_blocks,
                    requested_indices
                ));
                let requested_indices = RangeInclusive::new(1, (rosetta_blocks.len()-1) as u64);
                assert!(!blocks_verifier::indices_are_valid(
                    &rosetta_blocks,
                    requested_indices
                ));

                // Simulate a replica that returns a block with an invalid index
                let mid_index:usize = rosetta_blocks.len()/2;
                rosetta_blocks[mid_index].index += 1;
                let requested_indices = RangeInclusive::new(0, (rosetta_blocks.len()-1) as u64);
                assert!(!blocks_verifier::indices_are_valid(
                    &rosetta_blocks,
                    requested_indices
                ));
            }
        else{
            let requested_indices = RangeInclusive::new(0,  rosetta_blocks.len() as u64);
            assert!(blocks_verifier::indices_are_valid(
                &rosetta_blocks,
                requested_indices
            ));
        }
        }
    }
}
