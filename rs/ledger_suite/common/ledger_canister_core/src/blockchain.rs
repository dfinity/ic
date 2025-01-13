use crate::{
    archive::{Archive, ArchiveCanisterWasm, ArchiveOptions},
    runtime::Runtime,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_hash_of::HashOf;

/// Stores a chain of transactions with their metadata
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Blockchain<Rt: Runtime, Wasm: ArchiveCanisterWasm> {
    pub blocks: Vec<EncodedBlock>,
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

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm> Default for Blockchain<Rt, Wasm> {
    fn default() -> Self {
        Self {
            blocks: vec![],
            last_hash: None,
            last_timestamp: TimeStamp::from_nanos_since_unix_epoch(0),
            archive: Arc::new(RwLock::new(None)),
            num_archived_blocks: 0,
        }
    }
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm> Blockchain<Rt, Wasm> {
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
        self.blocks.push(encoded_block);
        Ok(self.chain_length().checked_sub(1).unwrap())
    }

    pub fn get(&self, height: BlockIndex) -> Option<&EncodedBlock> {
        if height < self.num_archived_blocks() {
            None
        } else {
            self.blocks
                .get(usize::try_from(height - self.num_archived_blocks()).unwrap())
        }
    }

    pub fn last(&self) -> Option<&EncodedBlock> {
        self.blocks.last()
    }

    pub fn num_archived_blocks(&self) -> u64 {
        self.num_archived_blocks
    }

    pub fn num_unarchived_blocks(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// The range of block indices that are not archived yet.
    pub fn local_block_range(&self) -> std::ops::Range<u64> {
        self.num_archived_blocks..self.num_archived_blocks + self.blocks.len() as u64
    }

    /// Returns the slice of blocks stored locally.
    ///
    /// # Panic
    ///
    /// This function panics if the specified range is not a subset of locally available blocks.
    pub fn block_slice(&self, local_blocks: std::ops::Range<u64>) -> &[EncodedBlock] {
        use crate::range_utils::{is_subrange, offset};

        assert!(
            is_subrange(&local_blocks, &self.local_block_range()),
            "requested block range {:?} is not a subrange of local blocks {:?}",
            local_blocks,
            self.local_block_range()
        );

        &self.blocks[offset(&local_blocks, self.num_archived_blocks)]
    }

    pub fn chain_length(&self) -> BlockIndex {
        self.num_archived_blocks() + self.num_unarchived_blocks() as BlockIndex
    }

    pub fn remove_archived_blocks(&mut self, len: usize) {
        // redundant since split_off would panic, but here we can give a more
        // descriptive message
        if len > self.blocks.len() {
            panic!(
                "Asked to remove more blocks than present. Present: {}, to remove: {}",
                self.blocks.len(),
                len
            );
        }
        self.blocks = self.blocks.split_off(len);
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
        // the 1000 oldest bocks will be archived, leaving the remaining 1000
        // blocks in place.
        let num_blocks_before = self.num_unarchived_blocks() as usize;

        if num_blocks_before < trigger_threshold {
            return VecDeque::new();
        }

        let blocks_to_archive: VecDeque<EncodedBlock> =
            VecDeque::from(self.blocks[0..num_blocks_to_archive.min(num_blocks_before)].to_vec());

        println!(
            "get_blocks_for_archiving(): trigger_threshold: {}, num_blocks: {}, blocks before archiving: {}, blocks to archive: {}",
            trigger_threshold,
            num_blocks_to_archive,
            num_blocks_before,
            blocks_to_archive.len(),
        );

        blocks_to_archive
    }
}
