use std::ops::Range;
use std::sync::Arc;

use async_trait::async_trait;
use ic_ledger_core::block::EncodedBlock;
use ledger_canister::{BlockHeight, TipOfChainRes};

use crate::canister_access::CanisterAccess;

// trait to test sync
#[async_trait]
pub trait BlocksAccess {
    async fn query_raw_block(&self, height: BlockHeight) -> Result<Option<EncodedBlock>, String>;
    async fn query_tip(&self) -> Result<TipOfChainRes, String>;
    async fn multi_query_blocks(
        self: Arc<Self>,
        range: Range<BlockHeight>,
    ) -> Result<Vec<EncodedBlock>, String>;
}

#[async_trait]
impl BlocksAccess for CanisterAccess {
    async fn query_raw_block(&self, height: BlockHeight) -> Result<Option<EncodedBlock>, String> {
        self.query_raw_block(height).await
    }

    async fn query_tip(&self) -> Result<TipOfChainRes, String> {
        self.query_tip().await
    }

    async fn multi_query_blocks(
        self: Arc<Self>,
        range: Range<BlockHeight>,
    ) -> Result<Vec<EncodedBlock>, String> {
        self.multi_query_blocks(range.start, range.end).await
    }
}
