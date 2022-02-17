use crate::{spawn, EncodedBlock};
use candid::CandidType;
use dfn_core::api::print;
use ic_types::ic00::{Method, IC_00};
use ic_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// Wasm bytecode of an Archive Node
const ARCHIVE_NODE_BYTECODE: &[u8] =
    std::include_bytes!(std::env!("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH"));

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Archive {
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
}

impl Archive {
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
        }
    }

    pub fn nodes(&self) -> &[CanisterId] {
        &self.nodes
    }

    pub async fn send_blocks_to_archive(
        &mut self,
        mut blocks: VecDeque<EncodedBlock>,
        max_ledger_msg_size_bytes: usize,
    ) -> Result<usize, (usize, FailedToArchiveBlocks)> {
        print("[archive] send_blocks_to_archive(): start");
        let max_chunk_size = self.max_message_size_bytes.min(max_ledger_msg_size_bytes);

        let mut num_sent_blocks = 0usize;
        while !blocks.is_empty() {
            print(format!(
                "[archive] send_blocks_to_archive(): number of blocks remaining: {}",
                blocks.len()
            ));

            // Get the CanisterId and remaining capacity of the node that can
            // accept at least the first block
            let (node_canister_id, node_index, remaining_capacity) = self
                .node_and_capacity(blocks[0].size_bytes())
                .await
                .map_err(|e| (num_sent_blocks, e))?;

            // Take as many blocks as can be sent and send those in
            let mut first_blocks: VecDeque<_> = take_prefix(&mut blocks, remaining_capacity).into();
            if first_blocks.is_empty() {
                return Err((num_sent_blocks, FailedToArchiveBlocks("empty chunk".into())));
            }

            print(format!(
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
                print(format!(
                    "[archive] calling append_blocks() with a chunk of size {}",
                    chunk_len
                ));
                match dfn_core::api::call_with_cleanup(
                    node_canister_id,
                    "append_blocks",
                    dfn_candid::candid_one,
                    chunk,
                )
                .await
                {
                    Ok(()) => num_sent_blocks += chunk_len as usize,
                    Err((_, msg)) => return Err((num_sent_blocks, FailedToArchiveBlocks(msg))),
                };

                // Keep track of BlockHeights
                let heights = self.nodes_block_ranges.get_mut(node_index);
                match heights {
                    // We haven't inserted any Blocks into this archive node yet.
                    None => {
                        match self.nodes_block_ranges.last().copied() {
                            // If we haven't recorded any heights yet in any of the
                            // nodes then this is the **first archive node** and it
                            // starts with Block at height 0
                            None => self.nodes_block_ranges.push((0, chunk_len - 1)),
                            // If we haven't recorded any heights for this node but
                            // a previous node exists then the current heights
                            // start one above those in the previous node
                            Some((_, last_height)) => self
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

                print(format!(
                    "[archive] archive node [{}] block heights {:?}",
                    node_index,
                    self.nodes_block_ranges.get(node_index)
                ));
            }
        }

        print("[archive] send_blocks_to_archive() done");
        Ok(num_sent_blocks)
    }

    // Helper function to create a canister and install the node Wasm bytecode.
    async fn create_and_initialize_node_canister(
        &mut self,
    ) -> Result<(CanisterId, usize, usize), FailedToArchiveBlocks> {
        print("[archive] calling create_canister()");
        let node_canister_id: CanisterId =
            spawn::create_canister(self.cycles_for_archive_creation).await;
        let node_block_height_offset: u64 = self
            .nodes_block_ranges
            .last()
            .map(|(_, height_to)| *height_to + 1)
            .unwrap_or(0);
        print("[archive] calling install_code()");

        // We don't inspect the result here because according to MW the install canister
        // code returns an error even after successfully installing the code. We check
        // the existence of the canister immediately afterwards, so it doesn't really
        // matter.
        let _ = spawn::install_code(
            node_canister_id,
            ARCHIVE_NODE_BYTECODE.to_vec(),
            dfn_candid::Candid((
                dfn_core::api::id(),
                node_block_height_offset,
                Some(self.node_max_memory_size_bytes),
            )),
        )
        .await;

        print(format!(
            "[archive] setting controller_id for archive node: {}",
            self.controller_id
        ));
        let res: Result<(), (Option<i32>, String)> = dfn_core::api::call_with_cleanup(
            IC_00,
            &Method::SetController.to_string(),
            dfn_candid::candid_multi_arity,
            (ic_types::ic00::SetControllerArgs::new(
                node_canister_id,
                self.controller_id.into(),
            ),),
        )
        .await;

        res.map_err(|(code, msg)| {
            let s = format!(
                "Setting controller of archive node failed with code {}: {:?}",
                code.unwrap_or_default(),
                msg
            );
            FailedToArchiveBlocks(s)
        })?;

        self.nodes.push(node_canister_id);

        let node_index = self.last_node_index();

        let remaining_capacity: usize = dfn_core::api::call_with_cleanup(
            node_canister_id,
            "remaining_capacity",
            dfn_candid::candid_one,
            (),
        )
        .await
        .map_err(|(_, msg)| FailedToArchiveBlocks(msg))?;

        Ok((node_canister_id, node_index, remaining_capacity))
    }

    /// Helper function to find the CanisterId of the node that can accept
    /// blocks, or create one, and find how many blocks can be accepted.
    async fn node_and_capacity(
        &mut self,
        needed: usize,
    ) -> Result<(CanisterId, usize, usize), FailedToArchiveBlocks> {
        let last_node_canister_id: Option<CanisterId> = self.nodes.last().copied();
        match last_node_canister_id {
            // Not a single archive node exists. Create one.
            None => {
                print("[archive] creating the first archive node");
                let (node_canister_id, node_index, remaining_capacity) =
                    self.create_and_initialize_node_canister().await?;
                print(format!(
                    "[archive] node canister id: {}, index: {}",
                    node_canister_id, node_index
                ));

                Ok((node_canister_id, node_index, remaining_capacity))
            }
            // Some archive node exists. Use it, or, if already full, create a
            // new node.
            Some(last_node_canister_id) => {
                let remaining_capacity: usize = dfn_core::api::call_with_cleanup(
                    last_node_canister_id,
                    "remaining_capacity",
                    dfn_candid::candid,
                    (),
                )
                .await
                .map_err(|(_, msg)| FailedToArchiveBlocks(msg))?;
                if remaining_capacity < needed {
                    print("[archive] last node is full. creating a new archive node");
                    let (node_canister_id, node_index, remaining_capacity) =
                        self.create_and_initialize_node_canister().await?;
                    print(format!(
                        "[archive] node canister id: {}, index: {}",
                        node_canister_id, node_index
                    ));
                    Ok((node_canister_id, node_index, remaining_capacity))
                } else {
                    let node_index = self.last_node_index();
                    print(format!(
                        "[archive] reusing existing last node {} with index {} and capacity {}",
                        last_node_canister_id, node_index, remaining_capacity
                    ));
                    Ok((last_node_canister_id, node_index, remaining_capacity))
                }
            }
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
