mod construction_combine;
mod construction_derive;
mod construction_hash;
mod construction_metadata;
mod construction_parse;
mod construction_payloads;
mod construction_preprocess;
mod construction_submit;

#[cfg(test)]
mod tests;

use crate::{
    API_VERSION, MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST, NODE_VERSION,
    convert::{self, neuron_account_from_public_key},
    errors::{ApiError, Details},
    ledger_client::{
        LedgerAccess, list_known_neurons_response::ListKnownNeuronsResponse,
        minimum_dissolve_delay_response::MinimumDissolveDelayResponse,
        pending_proposals_response::PendingProposalsResponse,
        proposal_info_response::ProposalInfoResponse,
    },
    models::{
        self, AccountBalanceMetadata, AccountBalanceRequest, AccountBalanceResponse, Allow,
        BalanceAccountType, BlockIdentifier, BlockResponse, BlockTransaction,
        BlockTransactionResponse, CallResponse, Error, NetworkIdentifier, NetworkOptionsResponse,
        NetworkStatusResponse, NeuronInfoResponse, NeuronState, NeuronSubaccountComponents,
        OperationStatus, PartialBlockIdentifier, QueryBlockRangeRequest, QueryBlockRangeResponse,
        SearchTransactionsResponse, Version, amount::tokens_to_amount,
    },
    request_types::{GetProposalInfo, STATUS_COMPLETED},
};
use ic_ledger_canister_blocks_synchronizer::{
    blocks::{HashedBlock, RosettaBlocksMode},
    rosetta_block::RosettaBlock,
};
use ic_ledger_core::block::BlockType;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::manage_neuron::NeuronIdOrSubaccount;
use ic_types::{CanisterId, crypto::DOMAIN_IC_REQUEST, messages::MessageId};
use icp_ledger::{Block, BlockIndex};
use rosetta_core::metrics::RosettaMetrics;
use rosetta_core::{
    objects::ObjectMap,
    response_types::{MempoolResponse, MempoolTransactionResponse, NetworkListResponse},
};
use std::sync::atomic::AtomicBool;
use std::{
    convert::{TryFrom, TryInto},
    num::TryFromIntError,
    sync::Arc,
};
use strum::IntoEnumIterator;
use tracing::log::debug;

/// The maximum amount of blocks to retrieve in a single search.
const MAX_SEARCH_LIMIT: usize = 10_000;

#[derive(Clone)]
pub struct RosettaRequestHandler {
    blockchain: String,
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
    rosetta_metrics: RosettaMetrics,
    initial_sync_complete: Arc<AtomicBool>,
}

// construction requests are implemented in their own module.
impl RosettaRequestHandler {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(
        blockchain: String,
        ledger: Arc<T>,
        rosetta_metrics: RosettaMetrics,
        initial_sync_complete: Arc<AtomicBool>,
    ) -> Self {
        Self {
            blockchain,
            ledger,
            rosetta_metrics,
            initial_sync_complete,
        }
    }

    pub fn new_with_default_blockchain<T: 'static + LedgerAccess + Send + Sync>(
        ledger: Arc<T>,
        initial_sync_complete: Arc<AtomicBool>,
    ) -> Self {
        let canister_id = ledger.ledger_canister_id();
        let canister_id_str = hex::encode(canister_id.get().into_vec());
        Self::new(
            crate::DEFAULT_BLOCKCHAIN.to_string(),
            ledger,
            RosettaMetrics::new(crate::DEFAULT_TOKEN_SYMBOL.to_string(), canister_id_str),
            initial_sync_complete,
        )
    }

    pub fn network_id(&self) -> NetworkIdentifier {
        let canister_id = self.ledger.ledger_canister_id();
        let net_id = hex::encode(canister_id.get().into_vec());
        NetworkIdentifier::new(self.blockchain.clone(), net_id)
    }

    pub fn rosetta_metrics(&self) -> RosettaMetrics {
        self.rosetta_metrics.clone()
    }

    /// Get an Account Balance
    pub async fn account_balance(
        &self,
        msg: AccountBalanceRequest,
    ) -> Result<AccountBalanceResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let neuron_info_request_params = match AccountBalanceMetadata::try_from(
            msg.metadata.clone(),
        )
        .unwrap_or_default()
        .account_type
        {
            BalanceAccountType::Ledger => None,
            BalanceAccountType::Neuron {
                neuron_id,
                subaccount_components,
                verified_query,
            } => {
                let verified = verified_query.unwrap_or(false);

                if let Some(NeuronSubaccountComponents {
                    public_key,
                    neuron_index,
                }) = subaccount_components
                {
                    let addr_from_pk = neuron_account_from_public_key(
                        self.ledger.governance_canister_id(),
                        &public_key,
                        neuron_index,
                    )?;

                    if addr_from_pk != msg.account_identifier {
                        return Err(ApiError::invalid_account_id(
                            "Account identifier does not match the public key + neuron index"
                                .to_string(),
                        ));
                    }
                    if neuron_id.is_some() {
                        return Err(ApiError::invalid_request(
                            "Only one of neuron_id or the combination of public_key and neuron_index must be present",
                        ));
                    }

                    let neuron_subaccount =
                        crate::convert::neuron_subaccount_bytes_from_public_key(
                            &public_key,
                            neuron_index,
                        )?;

                    Some((
                        NeuronIdOrSubaccount::Subaccount(neuron_subaccount.to_vec()),
                        verified,
                    ))
                } else {
                    match neuron_id {
                        Some(id) => {
                            Some((NeuronIdOrSubaccount::NeuronId(NeuronId { id }), verified))
                        }
                        None => {
                            return Err(ApiError::invalid_request(
                                "Invalid neuron account balance request: either neuron_id or public_key must be present",
                            ));
                        }
                    }
                }
            }
        };

        let neuron_info = if let Some((neuron_id, verified)) = neuron_info_request_params {
            Some(self.neuron_info(neuron_id, verified).await?)
        } else {
            None
        };

        let account_id = icp_ledger::AccountIdentifier::from_hex(&msg.account_identifier.address)
            .map_err(|e| {
            ApiError::invalid_account_id(format!(
                "Account {} is not valid address, {}",
                &msg.account_identifier.address, e,
            ))
        })?;
        let block = self.get_block(msg.block_identifier).await?;
        let blocks = self.ledger.read_blocks().await;
        let tokens = blocks.get_account_balance(&account_id, &block.block_identifier.index)?;
        let amount = tokens_to_amount(tokens, self.ledger.token_symbol())?;
        Ok(AccountBalanceResponse {
            block_identifier: block.block_identifier,
            balances: vec![amount],
            metadata: neuron_info.map(|ni| ni.into()),
        })
    }

    /// Get a Block
    pub async fn call(&self, msg: models::CallRequest) -> Result<CallResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        match msg.method_name.as_str() {
            "get_proposal_info" => {
                let get_proposal_info_object = GetProposalInfo::try_from(Some(msg.parameters))?;
                let proposal_info = self
                    .ledger
                    .proposal_info(get_proposal_info_object.proposal_id)
                    .await?;
                let proposal_info_response = ProposalInfoResponse::from(proposal_info);
                Ok(CallResponse::new(
                    ObjectMap::try_from(proposal_info_response)?,
                    true,
                ))
            }
            "get_pending_proposals" => {
                let pending_proposals = self.ledger.pending_proposals().await?;
                let pending_proposals_response = PendingProposalsResponse::from(pending_proposals);
                Ok(CallResponse::new(
                    ObjectMap::try_from(pending_proposals_response)?,
                    false,
                ))
            }
            "get_minimum_dissolve_delay" => {
                let minimum_dissolve_delay = self.ledger.minimum_dissolve_delay().await?;
                let minimum_dissolve_delay_response = MinimumDissolveDelayResponse {
                    neuron_minimum_dissolve_delay_to_vote_seconds: minimum_dissolve_delay,
                };
                Ok(CallResponse::new(
                    ObjectMap::try_from(minimum_dissolve_delay_response)?,
                    false,
                ))
            }
            "list_known_neurons" => {
                let known_neurons = self.ledger.list_known_neurons().await?;
                let list_known_neurons_response = ListKnownNeuronsResponse { known_neurons };
                Ok(CallResponse::new(
                    ObjectMap::try_from(list_known_neurons_response)?,
                    false,
                ))
            }
            "query_block_range" => {
                let query_block_range = QueryBlockRangeRequest::try_from(msg.parameters)
                    .map_err(|err| ApiError::internal_error(format!("{err:?}")))?;
                let mut blocks = vec![];

                let storage = self.ledger.read_blocks().await;
                if query_block_range.number_of_blocks > 0 {
                    let lowest_index = query_block_range.highest_block_index.saturating_sub(
                        std::cmp::min(
                            query_block_range.number_of_blocks,
                            MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                        )
                        .saturating_sub(1),
                    );
                    if storage
                        .contains_block(&lowest_index)
                        .map_err(|err| ApiError::InvalidBlockId(false, format!("{err:?}").into()))?
                    {
                        // TODO: Use block range with rosetta blocks
                        for hb in storage
                            .get_hashed_block_range(
                                lowest_index
                                    ..query_block_range.highest_block_index.saturating_add(1),
                            )
                            .map_err(ApiError::from)?
                            .into_iter()
                        {
                            blocks.push(self.hashed_block_to_rosetta_core_block(hb).await?);
                        }
                    }
                };
                let idempotent = match blocks.last() {
                    // If the block with the highest block index that was retrieved from the database has the same index as the highest block index in the query we return true
                    Some(last_block) => {
                        last_block.block_identifier.index == query_block_range.highest_block_index
                    }
                    // If the database is empty or the requested block range does not exist we return false
                    None => false,
                };
                let block_range_response = QueryBlockRangeResponse { blocks };
                Ok(CallResponse::new(
                    ObjectMap::try_from(block_range_response)
                        .map_err(|err| ApiError::internal_error(format!("{err:?}")))?,
                    idempotent,
                ))
            }
            _ => Err(ApiError::InvalidRequest(
                false,
                Details::from(format!(
                    " Rosetta does not support the method name {} on its call endpoint ",
                    msg.method_name
                )),
            )),
        }
    }

    /// Get a Block
    pub async fn block(&self, msg: models::BlockRequest) -> Result<BlockResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let block = self.get_block(Some(msg.block_identifier)).await?;
        Ok(BlockResponse {
            block: Some(block),
            other_transactions: None,
        })
    }

    async fn is_a_rosetta_block_index(&self, block_index: BlockIndex) -> bool {
        match self.rosetta_blocks_mode().await {
            RosettaBlocksMode::Disabled => false,
            RosettaBlocksMode::Enabled {
                first_rosetta_block_index,
            } => block_index >= first_rosetta_block_index,
        }
    }

    async fn is_rosetta_blocks_mode_enabled(&self) -> bool {
        match self.rosetta_blocks_mode().await {
            RosettaBlocksMode::Disabled => false,
            RosettaBlocksMode::Enabled { .. } => true,
        }
    }

    async fn get_block(
        &self,
        block_id: Option<PartialBlockIdentifier>,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        match block_id {
            Some(PartialBlockIdentifier {
                index: Some(index),
                hash: Some(hash),
            }) => {
                if self.is_a_rosetta_block_index(index).await {
                    self.get_rosetta_block_by_index_and_hash(index, &hash).await
                } else {
                    self.get_verified_block_by_index_and_hash(index, &hash)
                        .await
                }
            }
            Some(PartialBlockIdentifier {
                index: Some(index),
                hash: None,
            }) => {
                if self.is_a_rosetta_block_index(index).await {
                    self.get_rosetta_block_by_index(index).await
                } else {
                    self.get_verified_block_by_index(index).await
                }
            }
            Some(PartialBlockIdentifier {
                index: None,
                hash: Some(hash),
            }) => {
                if self.is_rosetta_blocks_mode_enabled().await {
                    // We cannot tell whether the hash is of a normal block
                    // or a Rosetta block so we need to try both sequentially
                    match self.get_verified_block_by_hash(&hash).await {
                        Ok(block) => Ok(block),
                        Err(ApiError::InvalidBlockId(_, _)) => {
                            todo!("Fetching Rosetta Blocks by hash is not supported yet")
                        }
                        e => e,
                    }
                } else {
                    self.get_verified_block_by_hash(&hash).await
                }
            }
            _ => {
                if self.is_rosetta_blocks_mode_enabled().await {
                    let highest_block_index = self
                        .ledger
                        .read_blocks()
                        .await
                        .get_highest_rosetta_block_index()
                        .map_err(ApiError::from)?
                        .ok_or_else(|| ApiError::BlockchainEmpty(false, Default::default()))?;
                    self.get_rosetta_block_by_index(highest_block_index).await
                } else {
                    self.get_latest_verified_block().await
                }
            }
        }
    }

    async fn create_parent_block_id(
        &self,
        block_index: BlockIndex,
    ) -> Result<BlockIdentifier, ApiError> {
        // For the first block, we return the block itself as its parent
        let parent_block_index = block_index.saturating_sub(1);
        let blocks = self.ledger.read_blocks().await;
        if self.is_a_rosetta_block_index(parent_block_index).await {
            let parent_block = blocks.get_rosetta_block(parent_block_index)?;
            Ok(BlockIdentifier {
                index: parent_block_index,
                hash: hex::encode(parent_block.hash()),
            })
        } else if blocks.is_verified_by_idx(&parent_block_index)? {
            let parent_block = &blocks.get_hashed_block(&parent_block_index)?;
            convert::block_id(parent_block)
        } else {
            Err(ApiError::InvalidBlockId(true, Default::default()))
        }
    }

    async fn hashed_block_to_rosetta_core_block(
        &self,
        block: HashedBlock,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let parent_block_id = self.create_parent_block_id(block.index).await?;

        let token_symbol = self.ledger.token_symbol();
        hashed_block_to_rosetta_core_block(block, parent_block_id, token_symbol)
    }

    async fn get_latest_verified_block(&self) -> Result<rosetta_core::objects::Block, ApiError> {
        let block = {
            let blocks = self.ledger.read_blocks().await;
            blocks
                .get_latest_verified_hashed_block()
                .map_err(ApiError::from)
        }?;
        self.hashed_block_to_rosetta_core_block(block).await
    }

    async fn get_verified_block_by_index(
        &self,
        block_index: BlockIndex,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let block = {
            let blocks = self.ledger.read_blocks().await;
            if !blocks.is_verified_by_idx(&block_index)? {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }
            blocks.get_hashed_block(&block_index)
        }?;
        self.hashed_block_to_rosetta_core_block(block).await
    }

    async fn get_verified_block_by_index_and_hash(
        &self,
        block_index: BlockIndex,
        block_hash: &str,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let block = self.get_verified_block_by_index(block_index).await?;
        if block.block_identifier.hash != block_hash {
            return Err(ApiError::InvalidBlockId(false, Default::default()));
        }
        Ok(block)
    }

    async fn get_verified_block_by_hash(
        &self,
        block_hash: &str,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let hash = convert::to_hash::<ic_ledger_core::block::EncodedBlock>(block_hash)?;
        let block = {
            let blocks = self.ledger.read_blocks().await;
            if !blocks.is_verified_by_hash(&hash)? {
                return Err(ApiError::InvalidBlockId(true, Default::default()));
            }
            let block_index = blocks.get_block_idx_by_block_hash(&hash)?;
            blocks.get_hashed_block(&block_index)
        }?;
        self.hashed_block_to_rosetta_core_block(block).await
    }

    async fn get_rosetta_block_by_index(
        &self,
        block_index: BlockIndex,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let rosetta_block = {
            let blocks = self.ledger.read_blocks().await;
            blocks.get_rosetta_block(block_index)
        }?;
        let parent_block_id = self.create_parent_block_id(block_index).await?;
        let token_symbol = self.ledger.token_symbol();
        rosetta_block_to_rosetta_core_block(rosetta_block, parent_block_id, token_symbol)
    }

    async fn get_rosetta_block_by_index_and_hash(
        &self,
        block_index: BlockIndex,
        block_hash: &str,
    ) -> Result<rosetta_core::objects::Block, ApiError> {
        let rosetta_block = self.get_rosetta_block_by_index(block_index).await?;
        if rosetta_block.block_identifier.hash != block_hash {
            return Err(ApiError::InvalidBlockId(false, Default::default()));
        }
        Ok(rosetta_block)
    }

    /// Get a Block Transfer
    pub async fn block_transaction(
        &self,
        msg: models::BlockTransactionRequest,
    ) -> Result<BlockTransactionResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let block_id = Some(PartialBlockIdentifier {
            index: Some(msg.block_identifier.index),
            hash: Some(msg.block_identifier.hash),
        });
        let mut block = self.get_block(block_id).await?;

        let transaction = match self.rosetta_blocks_mode().await {
            RosettaBlocksMode::Disabled => block.transactions.remove(0),
            RosettaBlocksMode::Enabled { .. } => block
                .transactions
                .into_iter()
                .find(|t| t.transaction_identifier == msg.transaction_identifier)
                .ok_or_else(|| ApiError::InvalidTransactionId(false, Default::default()))?,
        };
        Ok(BlockTransactionResponse::new(transaction))
    }

    /// Get All Mempool Transactions
    pub async fn mempool(&self, msg: models::NetworkRequest) -> Result<MempoolResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        Ok(MempoolResponse::new(vec![]))
    }

    /// Get a Mempool Transfer
    pub async fn mempool_transaction(
        &self,
        msg: models::MempoolTransactionRequest,
    ) -> Result<MempoolTransactionResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        Err(ApiError::MempoolTransactionMissing(
            false,
            Default::default(),
        ))
    }

    /// Get List of Available Networks
    pub async fn network_list(&self) -> Result<NetworkListResponse, ApiError> {
        let net_id = self.network_id();
        Ok(NetworkListResponse::new(vec![net_id]))
    }

    /// Get Network Options
    pub async fn network_options(
        &self,
        msg: models::NetworkRequest,
    ) -> Result<NetworkOptionsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        Ok(NetworkOptionsResponse::new(
            Version::new(
                API_VERSION.to_string(),
                NODE_VERSION.to_string(),
                None,
                None,
            ),
            Allow::new(
                vec![OperationStatus::new("COMPLETED".to_string(), true)],
                models::operation::OperationType::iter()
                    .map(|op| op.to_string())
                    .collect(),
                {
                    let token_name = self.ledger.token_symbol();
                    let mut errs = vec![
                        Error::new(&ApiError::InternalError(true, Default::default())),
                        Error::new(&ApiError::InvalidRequest(false, Default::default())),
                        Error::new(&ApiError::NotAvailableOffline(false, Default::default())),
                        Error::new(&ApiError::InvalidNetworkId(false, Default::default())),
                        Error::new(&ApiError::InvalidAccountId(false, Default::default())),
                        Error::new(&ApiError::InvalidBlockId(false, Default::default())),
                        Error::new(&ApiError::InvalidPublicKey(false, Default::default())),
                        Error::new(&ApiError::InvalidTransactionId(false, Default::default())),
                        Error::new(&ApiError::MempoolTransactionMissing(
                            false,
                            Default::default(),
                        )),
                        Error::new(&ApiError::BlockchainEmpty(false, Default::default())),
                        Error::new(&ApiError::InvalidTransaction(false, Default::default())),
                        Error::new(&ApiError::ICError(Default::default())),
                        Error::new(&ApiError::TransactionRejected(false, Default::default())),
                        Error::new(&ApiError::OperationsErrors(
                            Default::default(),
                            token_name.to_string(),
                        )),
                        Error::new(&ApiError::TransactionExpired),
                    ];

                    // We don't want to return any schema for details.
                    for e in errs.iter_mut() {
                        e.0.details = Default::default();
                    }
                    errs.into_iter()
                        .map(|err| err.0)
                        .collect::<Vec<rosetta_core::miscellaneous::Error>>()
                },
                true,
            ),
        ))
    }

    /// Get Network Status
    pub async fn network_status(
        &self,
        msg: models::NetworkRequest,
    ) -> Result<NetworkStatusResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        if !self
            .initial_sync_complete
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(ApiError::NotAvailableOffline(
                true,
                "The node is still syncing the blocks from the ledger canister. Please wait until the initial sync is complete.".into(),
            ));
        }
        let rosetta_blocks_mode = self.ledger.read_blocks().await.rosetta_blocks_mode;
        let network_status = match rosetta_blocks_mode {
            // If rosetta mode is not enabled we simply fetched the latest verified block
            RosettaBlocksMode::Disabled => {
                let blocks = self.ledger.read_blocks().await;
                let tip_verified_block = blocks.get_latest_verified_hashed_block()?;
                let genesis_block = blocks.get_hashed_block(&0)?;
                let first_verified_block = blocks.get_first_verified_hashed_block()?;
                let oldest_block_id = if first_verified_block.index != 0 {
                    Some(convert::block_id(&first_verified_block)?)
                } else {
                    None
                };
                NetworkStatusResponse::new(
                    convert::block_id(&tip_verified_block)?,
                    models::timestamp::from_system_time(
                        Block::decode(tip_verified_block.block)
                            .unwrap()
                            .timestamp
                            .into(),
                    )?
                    .0
                    .try_into()
                    .map_err(|err: TryFromIntError| {
                        ApiError::InternalError(
                            false,
                            Details::from(format!("Cannot convert timestamp to u64: {err}")),
                        )
                    })?,
                    convert::block_id(&genesis_block)?,
                    oldest_block_id,
                    None,
                    vec![],
                )
            }
            RosettaBlocksMode::Enabled {
                first_rosetta_block_index,
            } => {
                let highest_rosetta_block_index = self
                    .ledger
                    .read_blocks()
                    .await
                    .get_highest_rosetta_block_index()?;
                // If rosetta blocks mode is enabled we have to check whether the rosetta blocks table has been populated
                match highest_rosetta_block_index {
                    // If it has been populated we can return the highest rosetta block
                    Some(highest_rosetta_block_index) => {
                        let highest_rosetta_block = self
                            .get_rosetta_block_by_index(highest_rosetta_block_index)
                            .await?;
                        // If Rosetta Blocks started only after a certain index then the genesis block as well as the first verified block will be the first icp block
                        let genesis_block_id = if first_rosetta_block_index > 0 {
                            let hashed_block =
                                self.ledger.read_blocks().await.get_hashed_block(&0)?;
                            self.hashed_block_to_rosetta_core_block(hashed_block)
                                .await?
                                .block_identifier
                        } else {
                            self.get_rosetta_block_by_index(0).await?.block_identifier
                        };
                        NetworkStatusResponse::new(
                            highest_rosetta_block.block_identifier,
                            highest_rosetta_block.timestamp,
                            genesis_block_id,
                            None,
                            None,
                            vec![],
                        )
                    }
                    None => {
                        return Err(ApiError::BlockchainEmpty(false, "RosettaBlocks was activated and there are no RosettaBlocks in the database yet. The synch is ongoing, please wait until the first RosettaBlock is written to the database.".into()));
                    }
                }
            }
        };

        Ok(network_status)
    }

    pub fn assert_has_indexed_field(
        &self,
        request: &models::SearchTransactionsRequest,
    ) -> Result<(), ApiError> {
        let has_indexed_field =
            request.transaction_identifier.is_some() || request.account_identifier.is_some();
        if !has_indexed_field {
            return Err(ApiError::invalid_request("At least one of transaction_identifier, type_, or account_identifier must be provided to perform an efficient search".to_owned()));
        }
        Ok(())
    }

    /// Search for a transaction given its hash
    pub async fn search_transactions(
        &self,
        request: models::SearchTransactionsRequest,
    ) -> Result<SearchTransactionsResponse, ApiError> {
        verify_network_id(
            self.ledger.ledger_canister_id(),
            &request.network_identifier,
        )?;

        if request.coin_identifier.is_some() {
            return Err(ApiError::invalid_request(
                "Coin identifier not supported in search/transactions endpoint".to_owned(),
            ));
        }

        if request.status.is_some() {
            return Err(ApiError::invalid_request(
                "Status not supported in search/transactions endpoint".to_owned(),
            ));
        }

        if request.operator.is_some() {
            return Err(ApiError::invalid_request(
                "Operator not supported in search/transactions endpoint".to_owned(),
            ));
        }

        if request.address.is_some() {
            return Err(ApiError::invalid_request(
                "Address not supported in search/transactions endpoint".to_owned(),
            ));
        }

        if request.success.is_some() {
            return Err(ApiError::invalid_request(
                "Successful only not supported in search/transactions endpoint".to_owned(),
            ));
        }

        if request.currency.is_some() {
            return Err(ApiError::invalid_request(
                "Currency not supported in search/transactions endpoint".to_owned(),
            ));
        }
        let block_storage = self.ledger.read_blocks().await;

        let block_with_highest_block_index = block_storage
            .get_latest_verified_hashed_block()
            .map_err(|e| ApiError::InvalidBlockId(false, format!("{e:?}").into()))?;

        let max_block: u64 = request
            .max_block
            .unwrap_or(block_with_highest_block_index.index as i64)
            .try_into()
            .map_err(|err| {
                ApiError::invalid_request(format!("Max block has to be a valid u64: {err}"))
            })?;

        let limit: u64 = request
            .limit
            .unwrap_or(MAX_SEARCH_LIMIT as i64)
            .try_into()
            .map_err(|err| {
                ApiError::invalid_request(format!("Limit has to be a valid u64: {err}"))
            })?;

        let offset: u64 = request.offset.unwrap_or(0).try_into().map_err(|err| {
            ApiError::invalid_request(format!("Offset has to be a valid u64: {err}"))
        })?;

        if max_block < offset {
            return Err(ApiError::invalid_request(
                "Max block has to be greater than or equal to offset".to_owned(),
            ));
        }

        let operation_type = request.type_;

        let account_id = request
            .account_identifier
            .map(|acc| {
                icp_ledger::AccountIdentifier::try_from(acc).map_err(|err| {
                    ApiError::invalid_request(format!(
                        "Account identifier has to be a valid AccountIdentifier: {err}"
                    ))
                })
            })
            .transpose()?;

        let start_idx = max_block.min(block_with_highest_block_index.index.saturating_sub(offset));

        if limit == 0 {
            return Ok(SearchTransactionsResponse {
                total_count: 0,
                transactions: vec![],
                next_offset: Some(offset as i64),
            });
        }

        // Base query to fetch the blocks
        let mut command = String::from(
            "SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp
                   FROM blocks WHERE block_idx <= :max_block_idx ",
        );
        let mut parameters: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();

        parameters.push((":max_block_idx", Box::new(start_idx)));

        if let Some(transaction_identifier) = request.transaction_identifier.clone() {
            command.push_str("AND tx_hash = :tx_hash ");
            let tx_hash = serde_bytes::ByteBuf::try_from(transaction_identifier)
                .map_err(|err| {
                    ApiError::invalid_request(format!(
                        "Transaction identifier hash has to be a valid ByteBuf: {err}"
                    ))
                })?
                .as_slice()
                .to_vec();
            parameters.push((":tx_hash", Box::new(tx_hash)));
        }

        if let Some(operation_type) = operation_type {
            command.push_str("AND operation_type = :operation_type ");
            parameters.push((":operation_type", Box::new(operation_type)));
        }

        if let Some(account) = account_id {
            command.push_str("AND (from_account = :account_id OR to_account = :account_id OR spender_account = :account_id) ");
            parameters.push((":account_id", Box::new(account.to_hex())));
        }

        command.push_str("ORDER BY block_idx DESC ");

        command.push_str("LIMIT :limit ");
        parameters.push((":limit", Box::new(limit)));

        let blocks = block_storage
            .get_blocks_by_custom_query(
                command,
                parameters
                    .iter()
                    .map(|(key, param)| {
                        let param_ref: &dyn rusqlite::ToSql = param.as_ref();
                        (key.to_owned(), param_ref)
                    })
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .map_err(|e| ApiError::invalid_block_id(format!("Error fetching blocks: {e:?}")))?;

        let mut transactions = vec![];
        for block in blocks.clone().into_iter() {
            let rosetta_core_block = self.hashed_block_to_rosetta_core_block(block).await?;
            for transaction in rosetta_core_block.transactions.into_iter() {
                transactions.push(BlockTransaction {
                    block_identifier: rosetta_core_block.block_identifier.clone(),
                    transaction,
                });
            }
        }

        transactions.iter_mut().for_each(|tx| {
            tx.transaction.operations.iter_mut().for_each(|op| {
                op.status = Some(STATUS_COMPLETED.to_string());
            })
        });

        // Sort the transactions by block index in descending order
        transactions.sort_by(|a, b| b.block_identifier.index.cmp(&a.block_identifier.index));

        // If rosetta blocks is empty that means the entire blockchain was traversed but no transactions were found that match the search criteria
        let last_traversed_block_index = blocks.iter().map(|block| block.index).min().unwrap_or(0);
        let num_fetched_transactions = transactions.len();

        Ok(SearchTransactionsResponse {
            total_count: num_fetched_transactions as i64,
            transactions,
            // If the traversion of transactions has reached the genesis block we can stop traversing
            next_offset: if last_traversed_block_index == 0 {
                None
            } else {
                // If the transaction hash was provided it means we only want to fetch that transaction
                // If the number of transactions that match the transactionidentifier is less than the limit we can stop traversing --> All transactions with that hash have been fetched
                if request.transaction_identifier.is_some()
                    && num_fetched_transactions < limit as usize
                {
                    None
                } else {
                    Some(
                        max_block.saturating_sub(last_traversed_block_index.saturating_sub(1))
                            as i64,
                    )
                }
            },
        })
    }

    pub async fn neuron_info(
        &self,
        neuron_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfoResponse, ApiError> {
        let res = self.ledger.neuron_info(neuron_id, verified).await?;

        use ic_nns_governance_api::NeuronState as GovernanceNeuronState;
        let state = match GovernanceNeuronState::from_repr(res.state) {
            Some(GovernanceNeuronState::NotDissolving) => NeuronState::NotDissolving,
            Some(GovernanceNeuronState::Spawning) => NeuronState::Spawning,
            Some(GovernanceNeuronState::Dissolving) => NeuronState::Dissolving,
            Some(GovernanceNeuronState::Dissolved) => NeuronState::Dissolved,
            Some(GovernanceNeuronState::Unspecified) | None => {
                return Err(ApiError::internal_error(format!(
                    "unsupported neuron state code: {}",
                    res.state
                )));
            }
        };

        Ok(NeuronInfoResponse {
            verified_query: verified,
            retrieved_at_timestamp_seconds: res.retrieved_at_timestamp_seconds,
            state,
            age_seconds: res.age_seconds,
            dissolve_delay_seconds: res.dissolve_delay_seconds,
            voting_power: res.voting_power,
            created_timestamp_seconds: res.created_timestamp_seconds,
            stake_e8s: res.stake_e8s,
        })
    }

    pub async fn rosetta_blocks_mode(&self) -> RosettaBlocksMode {
        self.ledger.rosetta_blocks_mode().await
    }
}

fn verify_network_id(canister_id: &CanisterId, net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    verify_network_blockchain(net_id)?;
    let id = CanisterId::try_from(net_id).map_err(|err| {
        let err_msg = format!("Invalid network ID ('{net_id:?}'): {err:?}");
        debug!("{err_msg}");
        ApiError::InvalidNetworkId(false, Details::from(err_msg))
    })?;
    if *canister_id != id {
        let err_msg = format!("Invalid canister ID (expected '{canister_id}', received '{id}')");
        debug!("{err_msg}");
        return Err(ApiError::InvalidNetworkId(false, Details::from(err_msg)));
    }
    Ok(())
}

fn verify_network_blockchain(net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    const EXPECTED_BLOCKCHAIN: &str = "Internet Computer";
    match net_id.blockchain.as_str() {
        EXPECTED_BLOCKCHAIN => Ok(()),
        _ => {
            let err_msg = format!(
                "Unknown blockchain (expected '{EXPECTED_BLOCKCHAIN}', received '{}')",
                net_id.blockchain
            );
            debug!("{err_msg}");
            Err(ApiError::InvalidNetworkId(false, Details::from(err_msg)))
        }
    }
}

pub fn make_sig_data(message_id: &MessageId) -> Vec<u8> {
    // Lifted from canister_client::agent::sign_message_id
    let mut sig_data = vec![];
    sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
    sig_data.extend_from_slice(message_id.as_bytes());
    sig_data
}

fn hashed_block_to_rosetta_core_block(
    hashed_block: HashedBlock,
    parent_id: BlockIdentifier,
    token_symbol: &str,
) -> Result<rosetta_core::objects::Block, ApiError> {
    let block = Block::decode(hashed_block.block.clone())
        .map_err(|err| ApiError::internal_error(format!("Cannot decode block: {err}")))?;
    let block_id = convert::block_id(&hashed_block)?;
    let transactions = vec![convert::hashed_block_to_rosetta_core_transaction(
        &hashed_block,
        token_symbol,
    )?];
    Ok(models::Block::new(
        block_id,
        parent_id,
        models::timestamp::from_system_time(block.timestamp.into())?
            .0
            .try_into()?,
        transactions,
    ))
}

fn rosetta_block_to_rosetta_core_block(
    rosetta_block: RosettaBlock,
    parent_id: BlockIdentifier,
    token_symbol: &str,
) -> Result<rosetta_core::objects::Block, ApiError> {
    let block_id = rosetta_core::identifiers::BlockIdentifier {
        index: rosetta_block.index,
        hash: hex::encode(rosetta_block.hash()),
    };
    let timestamp = models::timestamp::from_system_time(rosetta_block.timestamp.into())?
        .0
        .try_into()?;
    let mut transactions = vec![];
    for (index, transaction) in rosetta_block.transactions {
        let transaction = convert::to_rosetta_core_transaction(
            index,
            transaction,
            rosetta_block.timestamp,
            token_symbol,
        )?;
        transactions.push(transaction);
    }

    Ok(models::Block::new(
        block_id,
        parent_id,
        timestamp,
        transactions,
    ))
}
