use crate::{
    archive::{Archive, ArchiveCanisterWasm, ArchiveOptions},
    runtime::Runtime,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_hash_of::HashOf;
use std::ops::Range;

// There is a discrepancy in the way the trait uses indices for
// adding and getting blocks - `add_block` uses global indices
// while `get_blocks` uses indices relative to the first unarchived block.
// This is due to the fact that `HeapBlockData` doesn't store
// block indices. Once `HeapBlockData` is removed, the getters
// can be switched to global indices and `Blockchain` code can
// be simplified - it currently needs to offset indices passed
// to getters.
pub trait BlockData {
    // The `index` should take into account archived blocks.
    // I.e. if there are 10 archived blocks and we add 11th block
    // to the ledger, it should be added with index 10.
    fn add_block(&mut self, index: u64, block: EncodedBlock);
    // The `range` should be relative to the first unarchived block.
    // I.e. `get_blocks(0..1)` should always return the first block stored in the ledger.
    fn get_blocks(&self, range: Range<u64>) -> Vec<EncodedBlock>;
    // The `index` should be relative to the first unarchived block.
    // I.e. `get_block(0)` should always return the first block stored in the ledger.
    fn get_block(&self, index: u64) -> Option<EncodedBlock>;
    /// Removes `num_blocks` with the smallest index.
    fn remove_oldest_blocks(&mut self, num_blocks: u64);
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool;
    fn migrate_one_block(&mut self, num_archived_blocks: u64) -> bool;
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(transparent)]
pub struct HeapBlockData {
    blocks: Vec<EncodedBlock>,
}

impl BlockData for HeapBlockData {
    fn add_block(&mut self, _index: u64, block: EncodedBlock) {
        self.blocks.push(block);
    }

    fn get_blocks(&self, range: Range<u64>) -> Vec<EncodedBlock> {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize,
        };
        self.blocks[range].to_vec()
    }

    fn get_block(&self, index: u64) -> Option<EncodedBlock> {
        self.blocks.get(index as usize).cloned()
    }

    fn remove_oldest_blocks(&mut self, num_blocks: u64) {
        self.blocks = self.blocks.split_off(num_blocks as usize);
    }

    fn len(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn migrate_one_block(&mut self, _num_archived_blocks: u64) -> bool {
        panic!("HeapBlockData cannot perform migration!");
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound = "BD: Serialize, for<'a> BD: Deserialize<'a>")]
pub struct Blockchain<Rt: Runtime, Wasm: ArchiveCanisterWasm, BD>
where
    BD: BlockData + Serialize + Default,
    for<'a> BD: Deserialize<'a>,
{
    pub blocks: BD,
    pub last_hash: Option<HashOf<EncodedBlock>>,

    /// The timestamp of the most recent block. Must be monotonically
    /// non-decreasing.
    pub last_timestamp: TimeStamp,

    /// This `Arc` is safe to (de)serialize because uniqueness is guaranteed
    /// by the canister upgrade procedure.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub archive: Arc<RwLock<Option<Archive<Rt, Wasm>>>>,

    /// How many blocks have been sent to the archive
    pub num_archived_blocks: u64,
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm, BD> Default for Blockchain<Rt, Wasm, BD>
where
    BD: BlockData + Serialize + Default,
    for<'a> BD: Deserialize<'a>,
{
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            last_hash: None,
            last_timestamp: TimeStamp::from_nanos_since_unix_epoch(0),
            archive: Arc::new(RwLock::new(None)),
            num_archived_blocks: 0,
        }
    }
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm, BD> Blockchain<Rt, Wasm, BD>
where
    BD: BlockData + Serialize + Default,
    for<'a> BD: Deserialize<'a>,
{
    pub fn new_with_archive(archive_options: ArchiveOptions) -> Self {
        Self {
            archive: Arc::new(RwLock::new(Some(Archive::new(archive_options)))),
            ..Self::default()
        }
    }

    pub fn add_block<B>(&mut self, block: B) -> Result<BlockIndex, String>
    where
        B: BlockType,
    {
        if block.parent_hash() != self.last_hash {
            return Err("Cannot apply block because its parent hash doesn't match.".to_string());
        }
        if block.timestamp() < self.last_timestamp {
            return Err(
                "Cannot apply block because its timestamp is older than the previous tip."
                    .to_owned(),
            );
        }
        self.last_timestamp = block.timestamp();
        let encoded_block = block.encode();
        self.last_hash = Some(B::block_hash(&encoded_block));
        self.blocks.add_block(self.chain_length(), encoded_block);
        Ok(self.chain_length().checked_sub(1).unwrap())
    }

    pub fn get(&self, height: BlockIndex) -> Option<EncodedBlock> {
        if height < self.num_archived_blocks() {
            None
        } else {
            self.blocks
                .get_block(height.checked_sub(self.num_archived_blocks()).unwrap())
        }
    }

    pub fn num_archived_blocks(&self) -> u64 {
        self.num_archived_blocks
    }

    pub fn num_unarchived_blocks(&self) -> u64 {
        self.blocks.len()
    }

    /// The range of block indices that are not archived yet.
    pub fn local_block_range(&self) -> std::ops::Range<u64> {
        self.num_archived_blocks..self.num_archived_blocks + self.blocks.len()
    }

    /// Returns the blocks stored locally.
    ///
    /// # Panic
    ///
    /// This function panics if the specified range is not a subset of locally available blocks.
    pub fn get_blocks(&self, local_blocks: std::ops::Range<u64>) -> Vec<EncodedBlock> {
        use crate::range_utils::{is_subrange, offset};

        assert!(
            is_subrange(&local_blocks, &self.local_block_range()),
            "requested block range {:?} is not a subrange of local blocks {:?}",
            local_blocks,
            self.local_block_range()
        );

        self.blocks
            .get_blocks(offset(&local_blocks, self.num_archived_blocks))
    }

    pub fn chain_length(&self) -> BlockIndex {
        self.num_archived_blocks() + self.num_unarchived_blocks() as BlockIndex
    }

    pub fn remove_archived_blocks(&mut self, len: usize) {
        if len as u64 > self.blocks.len() {
            panic!(
                "Asked to remove more blocks than present. Present: {}, to remove: {}",
                self.blocks.len(),
                len
            );
        }
        self.blocks.remove_oldest_blocks(len as u64);
        self.num_archived_blocks += len as u64;
    }

    pub fn get_blocks_for_archiving(
        &self,
        trigger_threshold: usize,
        num_blocks_to_archive: usize,
    ) -> VecDeque<EncodedBlock> {
        // Upon reaching the `trigger_threshold` we will archive
        // `num_blocks_to_archive`. For example, when set to (2000, 1000)
        // archiving will trigger when there are 2000 blocks in the ledger and
        // the 1000 oldest blocks will be archived, leaving the remaining 1000
        // blocks in place.
        let num_blocks_before = self.num_unarchived_blocks();

        if num_blocks_before < trigger_threshold as u64 {
            return VecDeque::new();
        }

        let blocks_to_archive: VecDeque<EncodedBlock> = VecDeque::from(
            self.blocks
                .get_blocks(0..(num_blocks_to_archive as u64).min(num_blocks_before)),
        );

        println!(
            "get_blocks_for_archiving(): trigger_threshold: {}, num_blocks: {}, blocks before archiving: {}, blocks to archive: {}",
            trigger_threshold,
            num_blocks_to_archive,
            num_blocks_before,
            blocks_to_archive.len(),
        );

        blocks_to_archive
    }

    pub fn migrate_one_block(&mut self) -> bool {
        self.blocks.migrate_one_block(self.num_archived_blocks)
    }
}
