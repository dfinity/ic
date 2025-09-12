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
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, memory_manager::VirtualMemory};
use std::marker::PhantomData;
use std::ops::Range;

/// Stores a chain of transactions with their metadata
#[derive(Debug, Deserialize, Serialize)]
pub struct Blockchain<Rt: Runtime, Wasm: ArchiveCanisterWasm, BDC>
where
    BDC: BlockDataContainer + Default,
{
    blocks: BlockData<BDC>,
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

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm, BDC> Default for Blockchain<Rt, Wasm, BDC>
where
    BDC: BlockDataContainer + Default,
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

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm, BDC> Blockchain<Rt, Wasm, BDC>
where
    BDC: BlockDataContainer + Default,
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
        self.blocks.get_block(height)
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

    /// Returns the blocks stored locally. If the requested range is (partially) outside
    /// of the local blocks range, the intersections with the local blocks range
    /// is returned - the function does not panic in this case.
    pub fn get_blocks(&self, local_blocks: std::ops::Range<u64>) -> Vec<EncodedBlock> {
        self.blocks.get_blocks(local_blocks)
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

        let start = self.num_archived_blocks;
        let end = start + (num_blocks_to_archive as u64).min(num_blocks_before);
        let blocks_to_archive: VecDeque<EncodedBlock> =
            VecDeque::from(self.blocks.get_blocks(start..end));

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

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(transparent)]
struct BlockData<BDC>
where
    BDC: BlockDataContainer + Default,
{
    blocks: Vec<EncodedBlock>,

    _marker: PhantomData<BDC>,
}

// All indices used to add and retrieve blocks should be global,
// taking into account archived blocks. E.g. if there are 10 archived
// blocks and no blocks in the ledger, the next block should be added
// with index 10, and retrieved with `get_block(10)` or `get_blocks(10..11)`.
impl<BDC> BlockData<BDC>
where
    BDC: BlockDataContainer + Default,
{
    fn add_block(&mut self, index: u64, block: EncodedBlock) {
        BDC::with_blocks_mut(|blocks| {
            assert!(blocks.insert(index, block.into_vec()).is_none());
        });
    }

    fn get_blocks(&self, range: Range<u64>) -> Vec<EncodedBlock> {
        BDC::with_blocks(|blocks| {
            blocks
                .range(range)
                .map(|kv| EncodedBlock::from_vec(kv.1))
                .collect()
        })
    }

    fn get_block(&self, index: u64) -> Option<EncodedBlock> {
        BDC::with_blocks(|blocks| blocks.get(&index).map(EncodedBlock::from_vec))
    }

    /// Removes `num_blocks` with the smallest index.
    fn remove_oldest_blocks(&mut self, num_blocks: u64) {
        BDC::with_blocks_mut(|blocks| {
            let mut removed = 0;
            while !blocks.is_empty() && removed < num_blocks {
                blocks.pop_first();
                removed += 1;
            }
        });
    }

    /// The number of blocks stored in the ledger, i.e. excluding archived blocks.
    fn len(&self) -> u64 {
        BDC::with_blocks(|blocks| blocks.len())
    }

    fn migrate_one_block(&mut self, num_archived_blocks: u64) -> bool {
        let num_migrated = self.len();
        if num_migrated < self.blocks.len() as u64 {
            self.add_block(
                num_archived_blocks + num_migrated,
                self.blocks[num_migrated as usize].clone(),
            );
            true
        } else {
            self.blocks.clear();
            false
        }
    }
}

pub trait BlockDataContainer {
    fn with_blocks<R>(
        f: impl FnOnce(&StableBTreeMap<u64, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>) -> R,
    ) -> R;

    fn with_blocks_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<u64, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>) -> R,
    ) -> R;
}
