use crate::errors::ApiError;

use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_ledger_core::block::EncodedBlock;
use ic_types::CanisterId;
use ledger_canister::protobuf::{ArchiveIndexEntry, ArchiveIndexResponse, TipOfChainRequest};
use ledger_canister::{
    BlockArg, BlockHeight, BlockRes, GetBlocksArgs, GetBlocksRes, TipOfChainRes,
};
use log::{debug, trace, warn};
use on_wire::{FromWire, IntoWire};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::task::{spawn, JoinHandle};
use url::Url;

pub struct CanisterAccess {
    pub agent: Agent,
    pub canister_id: CanisterId,
    archive_list: Arc<tokio::sync::Mutex<Option<ArchiveIndexResponse>>>,
    #[allow(clippy::type_complexity)]
    ongoing_block_queries: tokio::sync::Mutex<
        VecDeque<(
            BlockHeight,
            BlockHeight,
            JoinHandle<Result<Vec<EncodedBlock>, ApiError>>,
        )>,
    >,
}

impl CanisterAccess {
    const BLOCKS_BATCH_LEN: u64 = 2000;
    const MAX_BLOCK_QUERIES: usize = 5;

    pub fn new(url: Url, canister_id: CanisterId, client: HttpClient) -> Self {
        let agent = Agent::new_with_client(client, url, Sender::Anonymous);
        Self {
            agent,
            canister_id,
            archive_list: Arc::new(tokio::sync::Mutex::new(None)),
            ongoing_block_queries: Default::default(),
        }
    }

    pub async fn query<Payload: ToProto, Res: ToProto>(
        &self,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&self.canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_canister<Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_tip(&self) -> Result<TipOfChainRes, ApiError> {
        self.query("tip_of_chain_pb", TipOfChainRequest {})
            .await
            .map_err(|e| ApiError::internal_error(format!("In tip: {}", e)))
    }

    pub async fn query_raw_block(
        &self,
        height: BlockHeight,
    ) -> Result<Option<EncodedBlock>, ApiError> {
        let BlockRes(b) = self
            .query("block_pb", BlockArg(height))
            .await
            .map_err(|e| ApiError::internal_error(format!("In block: {}", e)))?;
        match b {
            // block not found
            None => Ok(None),
            // block in the ledger
            Some(Ok(block)) => Ok(Some(block)),
            // block in the archive
            Some(Err(canister_id)) => {
                let BlockRes(b) = self
                    .query_canister(canister_id, "get_block_pb", BlockArg(height))
                    .await
                    .map_err(|e| ApiError::internal_error(format!("In block: {}", e)))?;
                // get_block() on archive node will never return Ok(Err(canister_id))
                Ok(b.map(|x| x.unwrap()))
            }
        }
    }

    async fn call_query_blocks(
        &self,
        can_id: CanisterId,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<EncodedBlock>, ApiError> {
        let blocks: GetBlocksRes = self
            .query_canister(
                can_id,
                "get_blocks_pb",
                GetBlocksArgs {
                    start,
                    length: (end - start) as usize,
                },
            )
            .await
            .map_err(|e| ApiError::internal_error(format!("In blocks: {}", e)))?;

        blocks
            .0
            .map_err(|e| ApiError::internal_error(format!("In blocks response: {}", e)))
    }

    pub async fn clear_outstanding_queries(&self) {
        let mut handles: VecDeque<_> = self.ongoing_block_queries.lock().await.drain(..).collect();

        while !handles.is_empty() {
            let (a, b, h) = handles.pop_front().unwrap();
            debug!("Ignoring outstanding block query. Idx: {}-{}", a, b);
            h.await.ok();
        }
    }

    pub async fn multi_query_blocks(
        self: &Arc<Self>,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<EncodedBlock>, ApiError> {
        let mut ongoing = self.ongoing_block_queries.lock().await;
        // clean up stale queries
        let a = ongoing.front().map(|(a, _, _)| *a);
        if let Some(a) = a {
            if a != start {
                warn!("Requested for {} ignoring queries at {}.", start, a);
                drop(ongoing);
                self.clear_outstanding_queries().await;
                return Err(ApiError::internal_error("Removed stale block queries"));
            }
        }

        let (a, b, jh) = {
            // schedule queries
            let mut qstart = ongoing.back().map(|(_, b, _)| *b).unwrap_or(start);
            while ongoing.len() < Self::MAX_BLOCK_QUERIES && qstart < end {
                let qend = (qstart + Self::BLOCKS_BATCH_LEN).min(end);
                let slf = self.clone();
                let jh = spawn(async move { slf.query_blocks(qstart, qend).await });
                ongoing.push_back((qstart, qend, jh));
                qstart = qend;
            }

            if ongoing.is_empty() {
                // this can only happen if someone passed start >= end
                return Ok(Vec::new());
            }
            ongoing.pop_front().unwrap()
        };

        let res = jh
            .await
            .map_err(|e| ApiError::internal_error(format!("{}", e)))??;
        let res_end = a + res.len() as u64;
        if res_end < b {
            let slf = self.clone();
            let jh = spawn(async move { slf.query_blocks(res_end, b).await });
            ongoing.push_front((res_end, b, jh));
        }
        Ok(res)
    }

    pub async fn query_blocks(
        self: &Arc<Self>,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<EncodedBlock>, ApiError> {
        // asking for a low number of blocks means we are close to the tip
        // so we can try fetching from ledger first
        if end - start < Self::BLOCKS_BATCH_LEN {
            let blocks = self.call_query_blocks(self.canister_id, start, end).await;
            if blocks.is_ok() {
                return blocks;
            }
            debug!("Failed to get blocks from ledger.. querying for archives");
        }

        fn locate_archive(
            archive_list: &Option<ArchiveIndexResponse>,
            start: BlockHeight,
        ) -> Option<ArchiveIndexEntry> {
            archive_list.as_ref().and_then(|al| {
                al.entries
                    .binary_search_by(|x| {
                        if x.height_from <= start && start <= x.height_to {
                            std::cmp::Ordering::Equal
                        } else if x.height_from < start {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    })
                    .ok()
                    .map(|i| al.entries[i].clone())
            })
        }

        let mut archive_entry;
        {
            let mut alist = self.archive_list.lock().await;
            archive_entry = locate_archive(&*alist, start);
            if archive_entry.is_none() {
                let al: ArchiveIndexResponse =
                    self.query("get_archive_index_pb", ()).await.map_err(|e| {
                        ApiError::internal_error(format!("In get archive index: {}", e))
                    })?;
                trace!("updating archive list to: {:?}", al);
                *alist = Some(al);
                archive_entry = locate_archive(&*alist, start);
            }
        }

        let (can_id, can_end) = match archive_entry {
            Some(entry) => (
                entry
                    .canister_id
                    .and_then(|pid| CanisterId::try_from(pid).ok())
                    .unwrap_or(self.canister_id),
                entry.height_to + 1,
            ),
            None => (self.canister_id, end),
        };

        let end = std::cmp::min(end, can_end);

        self.call_query_blocks(can_id, start, end).await
    }
}
