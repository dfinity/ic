pub mod blocks; // made pub for tests.
mod canister_access;
mod handle_add_hotkey;
mod handle_disburse;
mod handle_follow;
mod handle_merge_maturity;
mod handle_neuron_info;
mod handle_remove_hotkey;
mod handle_send;
mod handle_set_dissolve_timestamp;
mod handle_spawn;
mod handle_stake;
mod handle_start_dissolve;
mod handle_stop_dissolve;
mod neuron_response;

use core::ops::Deref;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use reqwest::Client;
use tokio::sync::RwLock;

use dfn_candid::CandidOne;
use ic_canister_client::HttpClient;
use ic_nns_governance::pb::v1::{manage_neuron::NeuronIdOrSubaccount, GovernanceError, NeuronInfo};
use ic_types::messages::{HttpCallContent, MessageId};
use ic_types::CanisterId;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, messages::SignedRequestBytes};
use ledger_canister::{
    BlockHeight, Symbol, TipOfChainRes, TransferFee, TransferFeeArgs, DEFAULT_TRANSFER_FEE,
};
use on_wire::{FromWire, IntoWire};

use crate::certification::verify_block_hash;
use crate::convert;
use crate::errors::{ApiError, Details, ICError};
use crate::ledger_client::blocks::Blocks;
use crate::ledger_client::canister_access::CanisterAccess;
use crate::ledger_client::neuron_response::NeuronResponse;
use crate::ledger_client::{
    handle_add_hotkey::handle_add_hotkey, handle_disburse::handle_disburse,
    handle_follow::handle_follow, handle_merge_maturity::handle_merge_maturity,
    handle_neuron_info::handle_neuron_info, handle_remove_hotkey::handle_remove_hotkey,
    handle_send::handle_send, handle_set_dissolve_timestamp::handle_set_dissolve_timestamp,
    handle_spawn::handle_spawn, handle_stake::handle_stake,
    handle_start_dissolve::handle_start_dissolve, handle_stop_dissolve::handle_stop_dissolve,
};
use crate::models::{EnvelopePair, Object, SignedTransaction};
use crate::request::request_result::RequestResult;
use crate::request::transaction_results::TransactionResults;
use crate::request::Request;
use crate::request_types::{RequestType, Status};
use crate::store::{BlockStoreError, HashedBlock};
use crate::transaction_id::TransactionIdentifier;

// If pruning is enabled, instead of pruning after each new block
// we'll wait for PRUNE_DELAY blocks to accumulate and prune them in one go
const PRUNE_DELAY: u64 = 10000;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn governance_canister_id(&self) -> &CanisterId;
    fn token_symbol(&self) -> &str;
    async fn submit(&self, _envelopes: SignedTransaction) -> Result<TransactionResults, ApiError>;
    async fn cleanup(&self);
    async fn neuron_info(
        &self,
        acc_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfo, ApiError>;
    async fn transfer_fee(&self) -> Result<TransferFee, ApiError>;
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
    canister_access: Option<Arc<CanisterAccess>>,
    ic_url: Url,
    token_symbol: String,
    store_max_blocks: Option<u64>,
    offline: bool,
    root_key: Option<ThresholdSigPublicKey>,
}

pub enum OperationOutput {
    BlockIndex(BlockHeight),
    NeuronId(u64),
    NeuronResponse(NeuronResponse),
}

impl LedgerClient {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        ic_url: Url,
        canister_id: CanisterId,
        token_symbol: String,
        governance_canister_id: CanisterId,
        store_location: Option<&std::path::Path>,
        store_max_blocks: Option<u64>,
        offline: bool,
        root_key: Option<ThresholdSigPublicKey>,
    ) -> Result<LedgerClient, ApiError> {
        let mut blocks = match store_location {
            Some(loc) => Blocks::new_persistent(loc),
            None => Blocks::new_in_memory(),
        };
        let canister_access = if offline {
            None
        } else {
            let http_client = HttpClient::new();
            let canister_access = Arc::new(CanisterAccess::new(
                ic_url.clone(),
                canister_id,
                http_client,
            ));
            Self::verify_store(&blocks, &canister_access).await?;

            if root_key.is_some() {
                // verify if we have the right certificate/we are connecting to the right
                // canister
                let TipOfChainRes {
                    tip_index,
                    certification,
                } = canister_access.query_tip().await?;

                let tip_block = canister_access
                    .query_raw_block(tip_index)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                verify_block_hash(&certification, tip_block.hash(), &root_key, &canister_id)
                    .map_err(ApiError::internal_error)?;
            }

            let arg = CandidOne(())
                .into_bytes()
                .map_err(|e| ApiError::internal_error(format!("Serialization failed: {:?}", e)))?;

            let symbol_res: Result<Symbol, String> = canister_access
                .agent
                .execute_query(&canister_access.canister_id, "symbol", arg)
                .await
                .and_then(|bytes| {
                    CandidOne::from_bytes(
                        bytes.ok_or_else(|| "symbol reply payload was empty".to_string())?,
                    )
                    .map(|c| c.0)
                });

            match symbol_res {
                Ok(Symbol { symbol }) => {
                    if symbol != token_symbol {
                        return Err(ApiError::internal_error(format!(
                            "The ledger serves a different token ({}) than specified ({})",
                            symbol, token_symbol
                        )));
                    }
                }
                Err(e) => {
                    if e.contains("has no query method") || e.contains("not found") {
                        log::warn!("Symbol endpoint not present in the ledger canister. Couldn't verify token symbol.");
                    } else {
                        return Err(ApiError::internal_error(format!(
                            "Failed to fetch symbol name from the ledger: {}",
                            e
                        )));
                    }
                }
            };

            Some(canister_access)
        };

        info!("Loading blocks from store");
        let num_loaded = blocks.load_from_store()?;

        info!(
            "Ledger client is up. Loaded {} blocks from store. First block at {}, last at {}",
            num_loaded,
            blocks
                .first()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string()),
            blocks
                .last()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string())
        );
        if let Some(x) = blocks.last()? {
            crate::rosetta_server::SYNCED_HEIGHT.set(x.index as i64);
        }
        if let Some(x) = blocks.block_store.last_verified() {
            crate::rosetta_server::VERIFIED_HEIGHT.set(x as i64);
        }

        blocks.try_prune(&store_max_blocks, PRUNE_DELAY)?;

        Ok(Self {
            blockchain: RwLock::new(blocks),
            canister_id,
            token_symbol,
            governance_canister_id,
            canister_access,
            ic_url,
            store_max_blocks,
            offline,
            root_key,
        })
    }

    async fn verify_store(
        blocks: &Blocks,
        canister_access: &CanisterAccess,
    ) -> Result<(), ApiError> {
        debug!("Verifying store...");
        let first_block = blocks.block_store.first()?;

        match blocks.block_store.get_at(0) {
            Ok(store_genesis) => {
                let genesis = canister_access
                    .query_raw_block(0)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                if store_genesis.hash != genesis.hash() {
                    let msg = format!(
                        "Genesis block from the store is different than \
                        in the ledger canister. Store hash: {}, canister hash: {}",
                        store_genesis.hash,
                        genesis.hash()
                    );
                    error!("{}", msg);
                    return Err(ApiError::internal_error(msg));
                }
            }
            Err(BlockStoreError::NotFound(0)) => {
                if first_block.is_some() {
                    let msg = "Snapshot found, but genesis block not present in the store";
                    error!("{}", msg);
                    return Err(ApiError::internal_error(msg));
                }
            }
            Err(e) => {
                let msg = format!("Error loading genesis block: {:?}", e);
                error!("{}", msg);
                return Err(ApiError::internal_error(msg));
            }
        }

        if first_block.is_some() && first_block.as_ref().unwrap().index > 0 {
            let first_block = first_block.unwrap();
            let queried_block = canister_access.query_raw_block(first_block.index).await?;
            if queried_block.is_none() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Block with this index not found: {}",
                    first_block.index
                );
                error!("{}", msg);
                return Err(ApiError::internal_error(msg));
            }
            let queried_block = queried_block.unwrap();
            if first_block.hash != queried_block.hash() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Index: {}, snapshot hash: {}, canister hash: {}",
                    first_block.index,
                    first_block.hash,
                    queried_block.hash()
                );
                error!("{}", msg);
                return Err(ApiError::internal_error(msg));
            }
        }
        debug!("Verifying store done");
        Ok(())
    }
}

#[async_trait]
impl LedgerAccess for LedgerClient {
    async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let canister = self.canister_access.as_ref().unwrap();
        let TipOfChainRes {
            tip_index,
            certification,
        } = canister.query_tip().await?;
        crate::rosetta_server::TARGET_HEIGHT.set(tip_index as i64);

        let chain_length = tip_index + 1;

        if chain_length == 0 {
            return Ok(());
        }

        let mut blockchain = self.blockchain.write().await;

        let (mut last_block_hash, next_block_index) = match blockchain.synced_to() {
            Some((hash, index)) => (Some(hash), index + 1),
            None => (None, 0),
        };

        if next_block_index < chain_length {
            trace!(
                "Sync from: {}, chain_length: {}",
                next_block_index,
                chain_length
            );
        } else {
            if next_block_index > chain_length {
                trace!("Tip received from IC lower than what we already have (queried lagging replica?),
                 new chain length: {}, our {}", chain_length, next_block_index);
            }
            return Ok(());
        }

        let print_progress = if chain_length - next_block_index >= 1000 {
            info!(
                "Syncing {} blocks. New tip at {}",
                chain_length - next_block_index,
                chain_length - 1
            );
            true
        } else {
            false
        };

        let mut i = next_block_index;
        while i < chain_length {
            if stopped.load(Relaxed) {
                return Err(ApiError::internal_error("Interrupted"));
            }

            debug!("Asking for blocks {}-{}", i, chain_length);
            let batch = canister.multi_query_blocks(i, chain_length).await?;

            debug!("Got batch of len: {}", batch.len());
            if batch.is_empty() {
                return Err(ApiError::internal_error(
                    "Couldn't fetch new blocks (batch result empty)".to_string(),
                ));
            }

            let mut hashed_batch = Vec::new();
            hashed_batch.reserve_exact(batch.len());
            for raw_block in batch {
                let block = raw_block.decode().map_err(|err| {
                    ApiError::internal_error(format!("Cannot decode block: {}", err))
                })?;
                if block.parent_hash != last_block_hash {
                    let err_msg = format!(
                        "Block at {}: parent hash mismatch. Expected: {:?}, got: {:?}",
                        i, last_block_hash, block.parent_hash
                    );
                    error!("{}", err_msg);
                    return Err(ApiError::internal_error(err_msg));
                }
                let hb = HashedBlock::hash_block(raw_block, last_block_hash, i);
                if i == chain_length - 1 {
                    verify_block_hash(&certification, hb.hash, &self.root_key, &self.canister_id)
                        .map_err(ApiError::internal_error)?;
                }
                last_block_hash = Some(hb.hash);
                hashed_batch.push(hb);
                i += 1;
            }

            blockchain.add_blocks_batch(hashed_batch)?;
            crate::rosetta_server::SYNCED_HEIGHT.set(i as i64 - 1);

            if print_progress && (i - next_block_index) % 10000 == 0 {
                info!("Synced up to {}", i - 1);
            }
        }

        blockchain
            .block_store
            .mark_last_verified(chain_length - 1)?;
        crate::rosetta_server::VERIFIED_HEIGHT.set(chain_length as i64 - 1);

        if next_block_index != chain_length {
            info!(
                "You are all caught up to block {}",
                blockchain.last()?.unwrap().index
            );
        }

        blockchain.try_prune(&self.store_max_blocks, PRUNE_DELAY)?;
        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn governance_canister_id(&self) -> &CanisterId {
        &self.governance_canister_id
    }

    fn token_symbol(&self) -> &str {
        &self.token_symbol
    }

    async fn submit(&self, envelopes: SignedTransaction) -> Result<TransactionResults, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let start_time = Instant::now();
        let http_client = reqwest::Client::new();

        let mut results: TransactionResults = envelopes
            .iter()
            .map(|e| {
                Request::try_from(e).map(|_type| RequestResult {
                    _type,
                    block_index: None,
                    neuron_id: None,
                    transaction_identifier: None,
                    status: crate::request_types::Status::NotAttempted,
                    response: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into();

        for ((request_type, request), result) in
            envelopes.into_iter().zip(results.operations.iter_mut())
        {
            if let Err(e) = self
                .do_request(&http_client, start_time, request_type, request, result)
                .await
            {
                result.status = Status::Failed(e);
                return Err(convert::transaction_results_to_api_error(
                    results,
                    &self.token_symbol,
                ));
            }
        }

        Ok(results)
    }

    async fn cleanup(&self) {
        if let Some(ca) = &self.canister_access {
            ca.clear_outstanding_queries().await;
        }
    }

    async fn neuron_info(
        &self,
        acc_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfo, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }

        let agent = &self.canister_access.as_ref().unwrap().agent;

        let arg = CandidOne(acc_id)
            .into_bytes()
            .map_err(|e| ApiError::internal_error(format!("Serialization failed: {:?}", e)))?;
        let bytes = if verified {
            let nonce = Vec::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    .to_be_bytes(),
            );
            agent
                .execute_update(
                    &self.governance_canister_id,
                    "get_neuron_info_by_id_or_subaccount",
                    arg,
                    nonce,
                )
                .await
        } else {
            agent
                .execute_query(
                    &self.governance_canister_id,
                    "get_neuron_info_by_id_or_subaccount",
                    arg,
                )
                .await
        }
        .map_err(ApiError::internal_error)?
        .ok_or_else(|| {
            ApiError::internal_error("neuron_info reply payload was empty".to_string())
        })?;
        let ninfo: Result<Result<NeuronInfo, GovernanceError>, _> =
            CandidOne::from_bytes(bytes).map(|c| c.0);
        let ninfo = ninfo.map_err(|e| {
            ApiError::internal_error(format!(
                "Deserialization of get_neuron_info response failed: {:?}",
                e
            ))
        })?;

        // TODO consider adding new error types to ApiError to match error codes from
        // GovernanceError::error_type (e.g. NotFound)
        // (this may be more useful for management, since that's when we want to
        // communicate errors clearly)
        let ninfo = ninfo.map_err(|e| {
            ApiError::ICError(ICError {
                retriable: false,
                error_message: format!("{}", e),
                ic_http_status: 0,
            })
        })?;

        Ok(ninfo)
    }

    async fn transfer_fee(&self) -> Result<TransferFee, ApiError> {
        let agent = &self.canister_access.as_ref().unwrap().agent;
        let arg = CandidOne(TransferFeeArgs {})
            .into_bytes()
            .map_err(|e| ApiError::internal_error(format!("Serialization failed: {:?}", e)))?;

        let res = agent
            .execute_query(&self.canister_id, "transfer_fee", arg)
            .await;

        // Older Ledger versions may not have the transfer_fee method. Ideally
        // this method should return the default DEFAULT_TRANSFER_FEE as transfer_fee
        // only if the IC returns an error saying that the canister doesn't have
        // the method. canister-client's agent does not return the error code
        // with the error so there is no way to know if the error was 302
        // CanisterMethodNotFound or something else. As a workaround, we always
        // return the default transfer fee if there was an error in calling the
        // Ledger transfer_fee method.
        // see https://dfinity.atlassian.net/browse/NET-833
        match res {
            Err(e) => {
                warn!(
                    "Error while calling transfer_fee, returning the default one {}. Error was: {}",
                    DEFAULT_TRANSFER_FEE, e
                );
                Ok(TransferFee {
                    transfer_fee: DEFAULT_TRANSFER_FEE,
                })
            }
            Ok(None) => Err(ApiError::internal_error(
                "conf reply payload was empty".to_string(),
            )),
            Ok(Some(bytes)) => CandidOne::from_bytes(bytes).map(|c| c.0).map_err(|e| {
                ApiError::internal_error(format!("Error querying transfer_fee: {}", e))
            }),
        }
    }
}

impl LedgerClient {
    // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
    const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
    const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
    const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;
    const TIMEOUT: Duration = Duration::from_secs(20);

    async fn do_request(
        &self,
        http_client: &Client,
        start_time: Instant,
        request_type: RequestType,
        request: Vec<EnvelopePair>,
        result: &mut RequestResult,
    ) -> Result<(), ApiError> {
        // Pick the update/read-start message that is currently valid.
        let now = ic_types::time::current_time();
        let deadline = start_time + Self::TIMEOUT;

        let EnvelopePair { update, read_state } = request
            .clone()
            .into_iter()
            .find(|EnvelopePair { update, .. }| {
                let ingress_expiry =
                    ic_types::Time::from_nanos_since_unix_epoch(update.content.ingress_expiry());
                let ingress_start = ingress_expiry
                    - (ic_constants::MAX_INGRESS_TTL - ic_constants::PERMITTED_DRIFT);
                ingress_start <= now && ingress_expiry > now
            })
            .ok_or(ApiError::TransactionExpired)?;

        let canister_id = match &update.content {
            HttpCallContent::Call { update } => CanisterId::try_from(update.canister_id.0.clone())
                .map_err(|e| {
                    ApiError::internal_error(format!(
                        "Cannot parse canister ID found in submit call: {}",
                        e
                    ))
                })?,
        };

        let request_id = MessageId::from(update.content.representation_independent_hash());
        let txn_id = TransactionIdentifier::try_from_envelope(request_type.clone(), &update)?;

        if txn_id.is_transfer() {
            result.transaction_identifier = Some(txn_id.clone());
        }

        let http_body = SignedRequestBytes::try_from(update).map_err(|e| {
            ApiError::internal_error(format!(
                "Cannot serialize the submit request in CBOR format because of: {}",
                e
            ))
        })?;

        let read_state_http_body = SignedRequestBytes::try_from(read_state).map_err(|e| {
            ApiError::internal_error(format!(
                "Cannot serialize the read state request in CBOR format because of: {}",
                e
            ))
        })?;

        let url = self
            .ic_url
            .join(&ic_canister_client::update_path(canister_id))
            .expect("URL join failed");

        // Submit the update call (with retry).
        let mut poll_interval = Self::MIN_POLL_INTERVAL;

        while Instant::now() + poll_interval < deadline {
            let wait_timeout = Self::TIMEOUT - start_time.elapsed();

            match send_post_request(
                http_client,
                url.as_str(),
                http_body.clone().into(),
                wait_timeout,
            )
            .await
            {
                Err(err) => {
                    // Retry client-side errors.
                    error!("Error while submitting transaction: {}.", err);
                }
                Ok((body, status)) => {
                    if status.is_success() {
                        break;
                    }
                    // Retry on 5xx errors. We don't want to retry on
                    // e.g. authentication errors.
                    let body =
                        String::from_utf8(body).unwrap_or_else(|_| "<undecodable>".to_owned());
                    if status.is_server_error() {
                        error!(
                            "HTTP error {} while submitting transaction: {}.",
                            status, body
                        );
                    } else {
                        return Err(ApiError::ICError(ICError {
                            retriable: false,
                            ic_http_status: status.as_u16(),
                            error_message: body,
                        }));
                    }
                }
            }

            // Bump the poll interval and compute the next poll time (based on current wall
            // time, so we don't spin without delay after a slow poll).
            poll_interval = poll_interval
                .mul_f32(Self::POLL_INTERVAL_MULTIPLIER)
                .min(Self::MAX_POLL_INTERVAL);
        }

        /* Only return a non-200 result in case of an error from the
         * ledger canister. Otherwise just log the error and return a
         * 200 result with no block index. */
        match self
            .wait_for_result(
                canister_id,
                request_id,
                request_type,
                start_time,
                deadline,
                http_client,
                read_state_http_body,
            )
            .await
        {
            // Success
            Ok(Ok(Some(output))) => {
                match output {
                    OperationOutput::BlockIndex(block_height) => {
                        result.block_index = Some(block_height);
                    }
                    OperationOutput::NeuronId(neuron_id) => {
                        result.neuron_id = Some(neuron_id);
                    }
                    OperationOutput::NeuronResponse(response) => {
                        result.response = Some(Object::from(response));
                    }
                }
                result.status = Status::Completed;
                Ok(())
            }
            Ok(Ok(None)) => {
                result.status = Status::Completed;
                Ok(())
            }
            // Error from ledger canister
            Ok(Err(err)) => Err(err),
            // Some other error, transaction might still be processed by the IC
            Err(err) => {
                let e_msg = format!("Error submitting transaction {:?}: {}.", txn_id, err);
                error!("{}", e_msg);
                // We can't continue with the next request since
                // we don't know if the previous one succeeded.
                result.status = Status::Failed(ApiError::internal_error(e_msg));
                Ok(())
            }
        }
    }

    // Do read-state calls until the result becomes available.
    async fn wait_for_result(
        &self,
        canister_id: CanisterId,
        request_id: MessageId,
        request_type: RequestType,
        start_time: Instant,
        deadline: Instant,
        http_client: &Client,
        read_state_http_body: SignedRequestBytes,
    ) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
        // Cut&paste from canister_client Agent.
        let mut poll_interval = Self::MIN_POLL_INTERVAL;
        while Instant::now() + poll_interval < deadline {
            debug!("Waiting {} ms for response", poll_interval.as_millis());
            actix_rt::time::sleep(poll_interval).await;
            let wait_timeout = Self::TIMEOUT - start_time.elapsed();
            let url = self
                .ic_url
                .join(&ic_canister_client::read_state_path(canister_id))
                .expect("URL join failed");

            match send_post_request(
                http_client,
                url.as_str(),
                read_state_http_body.clone().into(),
                wait_timeout,
            )
            .await
            {
                Err(err) => {
                    // Retry client-side errors.
                    error!("Error while reading the IC state: {}.", err);
                }
                Ok((body, status)) => {
                    if status.is_success() {
                        let cbor: serde_cbor::Value = serde_cbor::from_slice(&body)
                            .map_err(|err| format!("While parsing the status body: {}", err))?;

                        let status =
                            ic_canister_client::parse_read_state_response(&request_id, cbor)
                                .map_err(|err| {
                                    format!("While parsing the read state response: {}", err)
                                })?;

                        debug!("Read state response: {:?}", status);

                        match status.status.as_ref() {
                            "replied" => match status.reply {
                                Some(bytes) => {
                                    return self.handle_reply(&request_type, bytes);
                                }
                                None => {
                                    return Err("Send returned with no result.".to_owned());
                                }
                            },
                            "unknown" | "received" | "processing" => {}
                            "rejected" => {
                                return Ok(Err(ApiError::TransactionRejected(
                                    false,
                                    status
                                        .reject_message
                                        .unwrap_or_else(|| "(no message)".to_owned())
                                        .into(),
                                )));
                            }
                            "done" => {
                                return Err(
                                        "The call has completed but the reply/reject data has been pruned."
                                            .to_string(),
                                    );
                            }
                            _ => {
                                return Err(format!(
                                    "Send returned unexpected result: {:?} - {:?}",
                                    status.status, status.reject_message
                                ))
                            }
                        }
                    } else {
                        let body =
                            String::from_utf8(body).unwrap_or_else(|_| "<undecodable>".to_owned());
                        let err = format!(
                            "HTTP error {} while reading the IC state: {}.",
                            status, body
                        );
                        if status.is_server_error() {
                            // Retry on 5xx errors.
                            error!("{}", err);
                        } else {
                            return Err(err);
                        }
                    }
                }
            };

            // Bump the poll interval and compute the next poll time (based on current
            // wall time, so we don't spin without delay after a
            // slow poll).
            poll_interval = poll_interval
                .mul_f32(Self::POLL_INTERVAL_MULTIPLIER)
                .min(Self::MAX_POLL_INTERVAL);
        }

        // We didn't get a response in 30 seconds. Let the client handle it.
        Err(format!(
            "Operation took longer than {:?} to complete.",
            Self::TIMEOUT
        ))
    }

    /// Handle the replied data.
    fn handle_reply(
        &self,
        request_type: &RequestType,
        bytes: Vec<u8>,
    ) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
        match request_type.clone() {
            RequestType::AddHotKey { .. } => handle_add_hotkey(bytes),
            RequestType::Disburse { .. } => handle_disburse(bytes),
            RequestType::Follow { .. } => handle_follow(bytes),
            RequestType::MergeMaturity { .. } => handle_merge_maturity(bytes),
            RequestType::NeuronInfo { .. } => handle_neuron_info(bytes),
            RequestType::RemoveHotKey { .. } => handle_remove_hotkey(bytes),
            RequestType::Send => handle_send(bytes),
            RequestType::SetDissolveTimestamp { .. } => handle_set_dissolve_timestamp(bytes),
            RequestType::Spawn { .. } => handle_spawn(bytes),
            RequestType::Stake { .. } => handle_stake(bytes),
            RequestType::StartDissolve { .. } => handle_start_dissolve(bytes, request_type),
            RequestType::StopDissolve { .. } => handle_stop_dissolve(bytes, request_type),
        }
    }
}

async fn send_post_request(
    http_client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<(Vec<u8>, reqwest::StatusCode), String> {
    let resp = http_client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| format!("sending post request failed with {}: ", err))?;
    let resp_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|err| format!("receive post response failed with {}: ", err))?
        .to_vec();
    Ok((resp_body, resp_status))
}
