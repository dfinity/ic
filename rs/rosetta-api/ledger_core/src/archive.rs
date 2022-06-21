use crate::{block::EncodedBlock, runtime::Runtime, spawn};
use candid::{CandidType, Encode};
use ic_base_types::CanisterId;
use ic_ic00_types::IC_00;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

fn default_cycles_for_archive_creation() -> u64 {
    0
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct ArchiveOptions {
    /// The number of blocks which, when exceeded, will trigger an archiving
    /// operation
    pub trigger_threshold: usize,
    /// The number of blocks to archive when trigger threshold is exceeded
    pub num_blocks_to_archive: usize,
    pub node_max_memory_size_bytes: Option<usize>,
    pub max_message_size_bytes: Option<usize>,
    pub controller_id: CanisterId,
    // cycles to use for the call to create a new archive canister
    #[serde(default)]
    pub cycles_for_archive_creation: Option<u64>,
}

/// A scope guard for block archiving.
/// It sets archivating flag to true on the archive when constructed and disables the flag
/// when dropped.
pub struct ArchivingGuard<Rt: Runtime, Wasm: ArchiveCanisterWasm>(
    Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
);

pub enum ArchivingGuardError {
    /// There is no archive to lock, the archiving is disabled.
    NoArchive,
    /// There is already one active ArchivingGuard.
    AlreadyArchiving,
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm> ArchivingGuard<Rt, Wasm> {
    pub fn new(
        archive: Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
    ) -> Result<Self, ArchivingGuardError> {
        let mut archive_guard = archive.write().expect("failed to obtain archive lock");
        match archive_guard.as_mut() {
            Some(archive) => {
                if archive.archiving_in_progress {
                    return Err(ArchivingGuardError::AlreadyArchiving);
                }
                archive.archiving_in_progress = true;
            }
            None => {
                return Err(ArchivingGuardError::NoArchive);
            }
        }
        drop(archive_guard);
        Ok(Self(archive))
    }
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm> Drop for ArchivingGuard<Rt, Wasm> {
    fn drop(&mut self) {
        inspect_archive(&self.0, |archive| {
            archive.archiving_in_progress = false;
        });
    }
}

/// This trait specifies how to obtain the Wasm for the archive canister.
pub trait ArchiveCanisterWasm {
    fn archive_wasm() -> Cow<'static, [u8]>;
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "")]
pub struct Archive<Rt: Runtime, Wasm: ArchiveCanisterWasm> {
    // List of Archive Nodes
    nodes: Vec<CanisterId>,

    controller_id: CanisterId,

    // BlockHeights of Blocks stored in each archive node.

    // We need this because Blocks are stored in encoded format as
    // EncodedBlocks, and different EncodedBlocks may have different lengths.
    // Moreover, archive node capacity is specified in bytes instead of a fixed
    // number of Blocks. Thus, it is not possible to statically compute how
    // many EncodedBlocks will fit into an archive node -- the actual number
    // will vary slightly.

    // To facilitate lookup by index we will keep track of the number of Blocks
    // stored in each archive. We store an inclusive range [from, to]. Thus,
    // the range [0..9] means we store 10 blocks with indices from 0 to 9
    nodes_block_ranges: Vec<(u64, u64)>,

    // Maximum amount of data that can be stored in an Archive Node canister
    node_max_memory_size_bytes: usize,

    // Maximum inter-canister message size in bytes
    max_message_size_bytes: usize,

    /// How many blocks have been sent to the archive
    num_archived_blocks: u64,

    /// The number of blocks which, when exceeded, will trigger an archiving
    /// operation
    pub trigger_threshold: usize,
    /// The number of blocks to archive when trigger threshold is exceeded
    pub num_blocks_to_archive: usize,
    // cycles to use for the call to create a new canister and to install the archive
    #[serde(default = "default_cycles_for_archive_creation")]
    pub cycles_for_archive_creation: u64,

    /// Whether there are outstanding calls to the archive at the moment.
    // We do not need to persist this flag because we cannot have any oustanding calls
    // on upgrade.
    #[serde(skip)]
    archiving_in_progress: bool,

    #[serde(skip)]
    _marker: PhantomData<(Rt, Wasm)>,
}

impl<Rt: Runtime, Wasm: ArchiveCanisterWasm> Archive<Rt, Wasm> {
    pub fn new(options: ArchiveOptions) -> Self {
        Self {
            nodes: vec![],
            controller_id: options.controller_id,
            nodes_block_ranges: vec![],
            node_max_memory_size_bytes: options
                .node_max_memory_size_bytes
                .unwrap_or(1024 * 1024 * 1024),
            max_message_size_bytes: options.max_message_size_bytes.unwrap_or(2 * 1024 * 1024),
            num_archived_blocks: 0,
            trigger_threshold: options.trigger_threshold,
            num_blocks_to_archive: options.num_blocks_to_archive,
            cycles_for_archive_creation: options.cycles_for_archive_creation.unwrap_or(0),
            archiving_in_progress: false,
            _marker: PhantomData,
        }
    }

    fn last_node_index(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn index(&self) -> Vec<((u64, u64), CanisterId)> {
        self.nodes_block_ranges
            .iter()
            .cloned()
            .zip(self.nodes.clone())
            .collect()
    }

    pub fn nodes(&self) -> &[CanisterId] {
        &self.nodes
    }
}

/// Grabs a write lock on the archive and executes a synchronous function under the lock.
/// Use this function exclusively in this module to make sure that you do not keep the archive
/// locked between async calls.
fn inspect_archive<R, Rt: Runtime, Wasm: ArchiveCanisterWasm>(
    archive: &Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
    f: impl FnOnce(&mut Archive<Rt, Wasm>) -> R,
) -> R {
    let mut archive_guard = archive
        .write()
        .expect("bug: failed to obtain archive write lock for archiving");
    let archive = archive_guard.as_mut().expect("bug: archive is missing");
    assert!(
        archive.archiving_in_progress,
        "Archive metadata must be locked during archiving"
    );
    f(archive)
}

/// Sends the blocks to an archive canister (creating new archive canister if necessary).
/// On success, returns the number of blocks archived (equal to blocks.len()).
/// On failure, returns the number of successfully archived blocks and a description of the error.
pub async fn send_blocks_to_archive<Rt: Runtime, Wasm: ArchiveCanisterWasm>(
    archive: Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
    mut blocks: VecDeque<EncodedBlock>,
    max_ledger_msg_size_bytes: usize,
) -> Result<usize, (usize, FailedToArchiveBlocks)> {
    Rt::print("[archive] send_blocks_to_archive(): start");

    let max_chunk_size = inspect_archive(&archive, |archive| {
        archive
            .max_message_size_bytes
            .min(max_ledger_msg_size_bytes)
    });

    let mut num_sent_blocks = 0usize;
    while !blocks.is_empty() {
        Rt::print(format!(
            "[archive] send_blocks_to_archive(): number of blocks remaining: {}",
            blocks.len()
        ));

        // Get the CanisterId and remaining capacity of the node that can
        // accept at least the first block
        let (node_canister_id, node_index, remaining_capacity) =
            node_and_capacity(&archive, blocks[0].size_bytes())
                .await
                .map_err(|e| (num_sent_blocks, e))?;

        // Take as many blocks as can be sent and send those in
        let mut first_blocks: VecDeque<_> = take_prefix(&mut blocks, remaining_capacity).into();
        if first_blocks.is_empty() {
            return Err((num_sent_blocks, FailedToArchiveBlocks("empty chunk".into())));
        }

        Rt::print(format!(
                "[archive] appending blocks to node {:?}. number of blocks that fit: {}, remaining blocks to archive: {}",
                node_canister_id.get(),
                first_blocks.len(),
                blocks.len()
            ));

        // Additionally, need to respect the inter-canister message size
        while !first_blocks.is_empty() {
            let chunk = take_prefix(&mut first_blocks, max_chunk_size);
            let chunk_len = chunk.len() as u64;
            if chunk.is_empty() {
                return Err((num_sent_blocks, FailedToArchiveBlocks("empty chunk".into())));
            }
            Rt::print(format!(
                "[archive] calling append_blocks() with a chunk of size {}",
                chunk_len
            ));
            match Rt::call(node_canister_id, "append_blocks", 0, (chunk,)).await {
                Ok(()) => num_sent_blocks += chunk_len as usize,
                Err((_, msg)) => return Err((num_sent_blocks, FailedToArchiveBlocks(msg))),
            };

            // Keep track of BlockHeights
            let heights = inspect_archive(&archive, |archive| {
                let heights = archive.nodes_block_ranges.get_mut(node_index);
                match heights {
                    // We haven't inserted any Blocks into this archive node yet.
                    None => {
                        match archive.nodes_block_ranges.last().copied() {
                            // If we haven't recorded any heights yet in any of the
                            // nodes then this is the **first archive node** and it
                            // starts with Block at height 0
                            None => archive.nodes_block_ranges.push((0, chunk_len - 1)),
                            // If we haven't recorded any heights for this node but
                            // a previous node exists then the current heights
                            // start one above those in the previous node
                            Some((_, last_height)) => archive
                                .nodes_block_ranges
                                .push((last_height + 1, last_height + chunk_len)),
                        }
                    }
                    // We have already inserted some Blocks into this archive node.
                    // Hence, we already have a value to work with
                    Some(heights) => {
                        heights.1 += chunk_len as u64;
                    }
                }
                archive.nodes_block_ranges.get(node_index).cloned().unwrap()
            });

            Rt::print(format!(
                "[archive] archive node [{}] block heights {:?}",
                node_index, heights
            ));
        }
    }

    Rt::print("[archive] send_blocks_to_archive() done");
    Ok(num_sent_blocks)
}

// Helper function to create a canister and install the node Wasm bytecode.
async fn create_and_initialize_node_canister<Rt: Runtime, Wasm: ArchiveCanisterWasm>(
    archive: &Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
) -> Result<(CanisterId, usize, usize), FailedToArchiveBlocks> {
    Rt::print("[archive] calling create_canister()");

    let (
        cycles_for_archive_creation,
        node_block_height_offset,
        node_max_memory_size_bytes,
        controller_id,
    ) = inspect_archive(archive, |archive| {
        let node_block_height_offset: u64 = archive
            .nodes_block_ranges
            .last()
            .map(|(_, height_to)| *height_to + 1)
            .unwrap_or(0);
        (
            archive.cycles_for_archive_creation,
            node_block_height_offset,
            archive.node_max_memory_size_bytes,
            archive.controller_id,
        )
    });

    let node_canister_id: CanisterId = spawn::create_canister::<Rt>(cycles_for_archive_creation)
        .await
        .map_err(|(code, msg)| FailedToArchiveBlocks(format!("{} {}", code, msg)))?;

    Rt::print("[archive] calling install_code()");

    let () = spawn::install_code::<Rt>(
        node_canister_id,
        Wasm::archive_wasm().into_owned(),
        Encode!(
            &Rt::id(),
            &node_block_height_offset,
            &Some(node_max_memory_size_bytes)
        )
        .unwrap(),
    )
    .await
    .map_err(|(reject_code, message)| {
        FailedToArchiveBlocks(format!(
            "install_code failed; reject_code={}, message={}",
            reject_code, message
        ))
    })?;

    Rt::print(format!(
        "[archive] setting controller_id for archive node: {}",
        controller_id
    ));

    let res: Result<(), (i32, String)> = Rt::call(
        IC_00,
        "set_controller",
        0,
        (ic_ic00_types::SetControllerArgs::new(
            node_canister_id,
            controller_id.into(),
        ),),
    )
    .await;

    res.map_err(|(code, msg)| {
        let s = format!(
            "Setting controller of archive node failed with code {}: {}",
            code, msg
        );
        FailedToArchiveBlocks(s)
    })?;

    let node_index = inspect_archive(archive, |archive| {
        archive.nodes.push(node_canister_id);
        archive.last_node_index()
    });

    let (remaining_capacity,): (usize,) = Rt::call(node_canister_id, "remaining_capacity", 0, ())
        .await
        .map_err(|(_, msg)| FailedToArchiveBlocks(msg))?;

    Ok((node_canister_id, node_index, remaining_capacity))
}

/// Helper function to find the CanisterId of the node that can accept
/// blocks, or create one, and find how many blocks can be accepted.
async fn node_and_capacity<Rt: Runtime, Wasm: ArchiveCanisterWasm>(
    archive: &Arc<RwLock<Option<Archive<Rt, Wasm>>>>,
    needed: usize,
) -> Result<(CanisterId, usize, usize), FailedToArchiveBlocks> {
    let last_node_canister_id: Option<CanisterId> =
        inspect_archive(archive, |archive| archive.nodes.last().copied());

    match last_node_canister_id {
        // Not a single archive node exists. Create one.
        None => {
            Rt::print("[archive] creating the first archive node");
            let (node_canister_id, node_index, remaining_capacity) =
                create_and_initialize_node_canister(archive).await?;
            Rt::print(format!(
                "[archive] node canister id: {}, index: {}",
                node_canister_id, node_index
            ));

            Ok((node_canister_id, node_index, remaining_capacity))
        }
        // Some archive node exists. Use it, or, if already full, create a
        // new node.
        Some(last_node_canister_id) => {
            let (remaining_capacity,): (usize,) =
                Rt::call(last_node_canister_id, "remaining_capacity", 0, ())
                    .await
                    .map_err(|(_, msg)| FailedToArchiveBlocks(msg))?;

            if remaining_capacity < needed {
                Rt::print("[archive] last node is full. creating a new archive node");
                let (node_canister_id, node_index, remaining_capacity) =
                    create_and_initialize_node_canister(archive).await?;
                Rt::print(format!(
                    "[archive] node canister id: {}, index: {}",
                    node_canister_id, node_index
                ));
                Ok((node_canister_id, node_index, remaining_capacity))
            } else {
                let node_index = inspect_archive(archive, |archive| archive.last_node_index());
                Rt::print(format!(
                    "[archive] reusing existing last node {} with index {} and capacity {}",
                    last_node_canister_id, node_index, remaining_capacity
                ));
                Ok((last_node_canister_id, node_index, remaining_capacity))
            }
        }
    }
}

/// Extract longest prefix from `blocks` which fits in `max_size`
fn take_prefix(blocks: &mut VecDeque<EncodedBlock>, mut max_size: usize) -> Vec<EncodedBlock> {
    let mut result = vec![];
    while let Some(next) = blocks.front() {
        if next.size_bytes() > max_size {
            break;
        }
        max_size -= next.size_bytes();
        result.push(blocks.pop_front().unwrap());
    }
    result
}

/// This error type should only be returned in the case where an await has been
/// passed but we do not think that the archive canister has received the blocks
pub struct FailedToArchiveBlocks(pub String);
