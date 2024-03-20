mod construction_combine;
mod construction_derive;
mod construction_hash;
mod construction_metadata;
mod construction_parse;
mod construction_payloads;
mod construction_preprocess;
mod construction_submit;

use crate::ledger_client::list_known_neurons_response::ListKnownNeuronsResponse;
use crate::ledger_client::pending_proposals_response::PendingProposalsResponse;
use crate::ledger_client::proposal_info_response::ProposalInfoResponse;
use crate::models::{AccountBalanceMetadata, CallResponse, NetworkIdentifier};
use crate::request_types::GetProposalInfo;
use crate::transaction_id::TransactionIdentifier;
use crate::{convert, models, API_VERSION, NODE_VERSION};
use ic_ledger_canister_blocks_synchronizer::blocks::Blocks;
use ic_ledger_canister_blocks_synchronizer::blocks::HashedBlock;
use ic_ledger_core::block::BlockType;
use ic_nns_common::pb::v1::NeuronId;
use rosetta_core::objects::ObjectMap;

use crate::convert::{from_model_account_identifier, neuron_account_from_public_key};
use crate::errors::{ApiError, Details};
use crate::ledger_client::LedgerAccess;
use crate::models::amount::tokens_to_amount;
use crate::models::{
    AccountBalanceRequest, AccountBalanceResponse, Allow, BalanceAccountType, BlockIdentifier,
    BlockResponse, BlockTransaction, BlockTransactionResponse, Error, NetworkOptionsResponse,
    NetworkStatusResponse, NeuronInfoResponse, NeuronState, NeuronSubaccountComponents,
    OperationStatus, Operator, PartialBlockIdentifier, SearchTransactionsResponse, SyncStatus,
    Version,
};
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_types::crypto::DOMAIN_IC_REQUEST;
use ic_types::messages::MessageId;
use ic_types::CanisterId;
use icp_ledger::{Block, BlockIndex};
use rosetta_core::request_types::MetadataRequest;
use rosetta_core::response_types::NetworkListResponse;
use rosetta_core::response_types::{MempoolResponse, MempoolTransactionResponse};
use std::convert::{TryFrom, TryInto};
use std::num::TryFromIntError;
use std::sync::Arc;
use strum::IntoEnumIterator;

/// The maximum amount of blocks to retrieve in a single search.
const MAX_SEARCH_LIMIT: usize = 10_000;

#[derive(Clone)]
pub struct RosettaRequestHandler {
    blockchain: String,
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
}

// construction requests are implemented in their own module.
impl RosettaRequestHandler {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(
        blockchain: String,
        ledger: Arc<T>,
    ) -> Self {
        Self { blockchain, ledger }
    }

    pub fn new_with_default_blockchain<T: 'static + LedgerAccess + Send + Sync>(
        ledger: Arc<T>,
    ) -> Self {
        Self::new(crate::DEFAULT_BLOCKCHAIN.to_string(), ledger)
    }

    pub fn network_id(&self) -> NetworkIdentifier {
        let canister_id = self.ledger.ledger_canister_id();
        let net_id = hex::encode(canister_id.get().into_vec());
        NetworkIdentifier::new(self.blockchain.clone(), net_id)
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
        let blocks = self.ledger.read_blocks().await;
        let block = get_block(&blocks, msg.block_identifier)?;

        let tokens = blocks.get_account_balance(&account_id, &block.index)?;
        let amount = tokens_to_amount(tokens, self.ledger.token_symbol())?;
        let b = convert::block_id(&block)?;
        Ok(AccountBalanceResponse {
            block_identifier: b,
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
                Ok(CallResponse::new(ObjectMap::try_from(
                    proposal_info_response,
                )?))
            }
            "get_pending_proposals" => {
                let pending_proposals = self.ledger.pending_proposals().await?;
                let pending_proposals_response = PendingProposalsResponse::from(pending_proposals);
                Ok(CallResponse::new(ObjectMap::try_from(
                    pending_proposals_response,
                )?))
            }
            "list_known_neurons" => {
                let known_neurons = self.ledger.list_known_neurons().await?;
                let list_known_neurons_response = ListKnownNeuronsResponse { known_neurons };
                Ok(CallResponse::new(ObjectMap::try_from(
                    list_known_neurons_response,
                )?))
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

        let blocks = self.ledger.read_blocks().await;
        let hb = get_block(&blocks, Some(msg.block_identifier))?;
        let block = Block::decode(hb.block.clone())
            .map_err(|err| ApiError::internal_error(format!("Cannot decode block: {}", err)))?;
        let b_id = convert::block_id(&hb)?;
        let parent_id = create_parent_block_id(&blocks, &hb)?;

        let transactions = vec![convert::block_to_transaction(
            &hb,
            self.ledger.token_symbol(),
        )?];
        let block = Some(models::Block::new(
            b_id,
            parent_id,
            models::timestamp::from_system_time(block.timestamp.into())?
                .0
                .try_into()?,
            transactions,
        ));

        Ok(BlockResponse {
            block,
            other_transactions: None,
        })
    }

    /// Get a Block Transfer
    pub async fn block_transaction(
        &self,
        msg: models::BlockTransactionRequest,
    ) -> Result<BlockTransactionResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let blocks = self.ledger.read_blocks().await;
        let b_id = Some(PartialBlockIdentifier {
            index: Some(msg.block_identifier.index),
            hash: Some(msg.block_identifier.hash),
        });
        let hb = get_block(&blocks, b_id)?;
        let transaction = convert::block_to_transaction(&hb, self.ledger.token_symbol())?;
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
    pub async fn network_list(
        &self,
        _metadata_request: MetadataRequest,
    ) -> Result<NetworkListResponse, ApiError> {
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
        let blocks = self.ledger.read_blocks().await;
        let first = blocks.get_first_verified_hashed_block()?;
        let tip = blocks.get_latest_verified_hashed_block()?;
        let tip_id = convert::block_id(&tip)?;
        let tip_timestamp = models::timestamp::from_system_time(
            Block::decode(tip.block).unwrap().timestamp.into(),
        )?;

        let genesis_block = blocks.get_hashed_block(&0)?;
        let genesis_block_id = convert::block_id(&genesis_block)?;
        let peers = vec![];
        let oldest_block_id = if first.index != 0 {
            Some(convert::block_id(&first)?)
        } else {
            None
        };

        let mut sync_status = SyncStatus::new(tip.index as i64, None);
        let target = crate::rosetta_server::TARGET_HEIGHT.get();
        if target != 0 {
            sync_status.target_index = Some(crate::rosetta_server::TARGET_HEIGHT.get());
        }

        Ok(NetworkStatusResponse::new(
            tip_id,
            tip_timestamp.0.try_into().map_err(|err: TryFromIntError| {
                ApiError::InternalError(
                    false,
                    Details::from(format!("Cannot convert timestamp to u64: {}", err)),
                )
            })?,
            genesis_block_id,
            oldest_block_id,
            sync_status,
            peers,
        ))
    }

    async fn get_blocks_range(
        &self,
        max_block: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<SearchTransactionsResponse, ApiError> {
        let blocks = self.ledger.read_blocks().await;

        // Note: the Rosetta API specifies that the transactions should be sorted from
        // the most recent to oldest: https://www.rosetta-api.org/docs/models/SearchTransactionsResponse.html.
        // This means that query offset is computed from the end of the search
        // result.
        //
        // Let's look at an example: max_block = 3, offset = 2, limit = 2
        //
        //                                    max_block
        //                                    V
        // +---------+--------------+---------+---------+
        // | Block 1 |    Block 2   | Block 3 | Block 4 |
        // |----+----+----+----+----+----+----+----+----|
        // | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 | T9 | <- Transactions
        // |----+----+----+----+----+----+----+----+----|
        // | ** |    | ** | ** |    | ** | ** | ** | ** | <- ** = matches the criteria
        // |  4 |    |  3 |  2 |    |  1 |  0 |    |    | <- Offsets
        //           ^---------^
        //           Select these transactions
        //
        // Currently, we only support "match all" search criteria, and each block only
        // contains one transaction. We only need to compute block range
        // correctly to produce the requested transaction range.

        let last_idx = blocks
            .get_latest_verified_hashed_block()
            .map_err(ApiError::from)?
            .index;
        let mut first_idx = blocks
            .get_first_verified_hashed_block()
            .map_err(ApiError::from)?
            .index;
        first_idx = if first_idx == 1 { 0 } else { first_idx };
        let max_block = max_block.unwrap_or(last_idx);
        let end = max_block
            .checked_sub(offset as u64)
            .ok_or_else(|| ApiError::invalid_request("max_block < offset"))?
            .saturating_add(1);
        let start = end.saturating_sub(limit as u64).max(first_idx);

        let block_range = blocks
            .get_hashed_block_range(start..end)
            .map_err(ApiError::from)?;
        let mut txs: Vec<BlockTransaction> = Vec::new();

        for hb in block_range.into_iter().rev() {
            txs.push(BlockTransaction {
                block_identifier: convert::block_id(&hb)?,
                transaction: convert::block_to_transaction(&hb, self.ledger.token_symbol())?,
            });
        }

        let next_offset = if start == first_idx {
            None
        } else {
            Some((max_block - start + 1) as i64)
        };

        Ok(SearchTransactionsResponse {
            transactions: txs,
            total_count: (end - first_idx) as i64,
            next_offset,
        })
    }

    /// Search for a transaction given its hash
    pub async fn search_transactions(
        &self,
        msg: models::SearchTransactionsRequest,
    ) -> Result<SearchTransactionsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        if let Some(Operator::Or) = msg.operator {
            return Err(ApiError::invalid_request("Operator OR not supported"));
        }

        if msg.coin_identifier.is_some() {
            return Err(ApiError::invalid_request("coin_identifier not supported"));
        }

        if msg.currency.is_some() {
            return Err(ApiError::invalid_request("currency not supported"));
        }

        if msg.status.is_some() {
            return Err(ApiError::invalid_request("status not supported"));
        }

        if msg.type_.is_some() {
            return Err(ApiError::invalid_request("type not supported"));
        }

        if msg.address.is_some() {
            return Err(ApiError::invalid_request("address not supported"));
        }

        if msg.success.is_some() {
            return Err(ApiError::invalid_request("success not supported"));
        }

        let max_block = match msg.max_block {
            Some(x) => Some(
                u64::try_from(x)
                    .map_err(|e| ApiError::invalid_request(format!("Invalid max_block: {}", e)))?,
            ),
            None => None,
        };

        let offset = match msg.offset {
            Some(x) => usize::try_from(x)
                .map_err(|e| ApiError::invalid_request(format!("Invalid offset: {}", e)))?,
            None => 0,
        };

        let limit = match msg.limit {
            Some(x) => usize::try_from(x)
                .map_err(|e| ApiError::invalid_request(format!("Invalid limit: {}", e)))?,
            None => usize::MAX,
        };
        let limit = std::cmp::min(limit, MAX_SEARCH_LIMIT);

        if msg.transaction_identifier.is_none() && msg.account_identifier.is_none() {
            return self.get_blocks_range(max_block, offset, limit).await;
        }

        let blocks = self.ledger.read_blocks().await;

        let last_idx = blocks.get_latest_verified_hashed_block()?.index;

        let mut heights = Vec::new();
        let mut total_count = 0;

        if let Some(tid) = &msg.transaction_identifier {
            if msg.account_identifier.is_some() {
                return Err(ApiError::invalid_request(
                    "Only one of transaction_identitier and account_identifier should be populated",
                ));
            }

            let tid = ic_ledger_hash_of::HashOf::try_from(&TransactionIdentifier(tid.clone()))
                .map_err(|_| {
                    ApiError::InvalidTransactionId(
                        false,
                        Details::from(format!(
                            "Could not calculate hash of transaction identifier: {:?}",
                            tid
                        )),
                    )
                })?;

            if let Ok(indices) = blocks.get_block_idxs_by_transaction_hash(&tid) {
                for idx in indices {
                    heights.push(idx);
                    total_count += 1;
                }
            }
        }

        let mut next_offset = None;

        if let Some(aid) = &msg.account_identifier {
            let acc = from_model_account_identifier(aid)
                .map_err(|e| ApiError::InvalidAccountId(false, e.into()))?;

            let hist = blocks.get_account_balance_history(&acc, max_block)?;
            heights = hist
                .iter()
                .map(|(h, _)| *h)
                .rev()
                .filter(|h| *h <= last_idx)
                .skip(offset)
                .collect();

            let cnt = offset
                .checked_add(heights.len())
                .ok_or_else(|| ApiError::internal_error("total count overflow"))?;
            total_count = i64::try_from(cnt).map_err(|e| {
                ApiError::internal_error(format!("Total count does not fit in i64: {}", e))
            })?;

            if heights.len() > limit {
                let next = offset
                    .checked_add(limit)
                    .ok_or_else(|| ApiError::internal_error("offset + limit overflow"))?;
                next_offset = Some(i64::try_from(next).map_err(|e| {
                    ApiError::internal_error(format!("Next offset cannot fit in i64: {}", e))
                })?);
            }
            heights.truncate(limit);
        }

        let mut txs: Vec<BlockTransaction> = Vec::new();
        for i in heights {
            if i <= last_idx {
                let hb = blocks.get_hashed_block(&i)?;
                txs.push(BlockTransaction {
                    block_identifier: convert::block_id(&hb)?,
                    transaction: convert::block_to_transaction(&hb, self.ledger.token_symbol())?,
                });
            } else {
                return Err(ApiError::InvalidBlockId(true, Default::default()));
            }
        }
        Ok(SearchTransactionsResponse {
            transactions: txs,
            total_count,
            next_offset,
        })
    }

    pub async fn neuron_info(
        &self,
        neuron_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfoResponse, ApiError> {
        let res = self.ledger.neuron_info(neuron_id, verified).await?;

        use ic_nns_governance::pb::v1::NeuronState as PbNeuronState;
        let state = match PbNeuronState::try_from(res.state).ok() {
            Some(PbNeuronState::NotDissolving) => NeuronState::NotDissolving,
            Some(PbNeuronState::Spawning) => NeuronState::Spawning,
            Some(PbNeuronState::Dissolving) => NeuronState::Dissolving,
            Some(PbNeuronState::Dissolved) => NeuronState::Dissolved,
            Some(PbNeuronState::Unspecified) | None => {
                return Err(ApiError::internal_error(format!(
                    "unsupported neuron state code: {}",
                    res.state
                )))
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
}

fn create_parent_block_id(
    blocks: &Blocks,
    block: &HashedBlock,
) -> Result<BlockIdentifier, ApiError> {
    // For the first block, we return the block itself as its parent
    let idx = std::cmp::max(0, block_height_to_index(block.index) - 1);
    if blocks.is_verified_by_idx(&(idx as u64))? {
        let parent = blocks.get_hashed_block(&(idx as u64))?;
        convert::block_id(&parent)
    } else {
        Err(ApiError::InvalidBlockId(true, Default::default()))
    }
}

fn block_height_to_index(height: BlockIndex) -> i128 {
    i128::from(height)
}

fn get_block(
    blocks: &Blocks,
    block_id: Option<PartialBlockIdentifier>,
) -> Result<HashedBlock, ApiError> {
    match block_id {
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: Some(block_hash),
        }) => {
            let hash: ic_ledger_hash_of::HashOf<ic_ledger_core::block::EncodedBlock> =
                convert::to_hash(&block_hash)?;

            let idx = block_height as usize;
            if !blocks.is_verified_by_idx(&(idx as u64))? {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }
            let block = blocks.get_hashed_block(&(idx as u64))?;
            if block.hash != hash {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }

            Ok(block)
        }
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: None,
        }) => {
            let idx = block_height as usize;
            if blocks.is_verified_by_idx(&(idx as u64))? {
                Ok(blocks.get_hashed_block(&(idx as u64))?)
            } else {
                Err(ApiError::InvalidBlockId(true, Default::default()))
            }
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: Some(block_hash),
        }) => {
            let hash: ic_ledger_hash_of::HashOf<ic_ledger_core::block::EncodedBlock> =
                convert::to_hash(&block_hash)?;
            if blocks.is_verified_by_hash(&hash)? {
                let idx = blocks.get_block_idx_by_block_hash(&hash)?;
                Ok(blocks.get_hashed_block(&idx)?)
            } else {
                Err(ApiError::InvalidBlockId(true, Default::default()))
            }
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: None,
        })
        | None => blocks
            .get_latest_verified_hashed_block()
            .map_err(ApiError::from),
    }
}

fn verify_network_id(canister_id: &CanisterId, net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    verify_network_blockchain(net_id)?;
    let id: CanisterId = net_id
        .try_into()
        .map_err(|err| ApiError::InvalidNetworkId(false, format!("{:?}", err).into()))?;
    if *canister_id != id {
        return Err(ApiError::InvalidNetworkId(false, "unknown network".into()));
    }
    Ok(())
}

fn verify_network_blockchain(net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    match net_id.blockchain.as_str() {
        "Internet Computer" => Ok(()),
        _ => Err(ApiError::InvalidNetworkId(
            false,
            "unknown blockchain".into(),
        )),
    }
}

pub fn make_sig_data(message_id: &MessageId) -> Vec<u8> {
    // Lifted from canister_client::agent::sign_message_id
    let mut sig_data = vec![];
    sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
    sig_data.extend_from_slice(message_id.as_bytes());
    sig_data
}
