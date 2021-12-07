use core::ops::Deref;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use reqwest::Client;
use tokio::sync::RwLock;
use tokio::task::{spawn, JoinHandle};
use url::Url;

use dfn_candid::CandidOne;
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_nns_governance::pb::v1::manage_neuron_response::DisburseResponse;
use ic_nns_governance::pb::v1::{
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
    governance_error, manage_neuron::NeuronIdOrSubaccount, manage_neuron_response,
    ClaimOrRefreshNeuronFromAccountResponse, GovernanceError, ManageNeuronResponse, NeuronInfo,
};
use ic_types::messages::{HttpSubmitContent, MessageId};
use ic_types::CanisterId;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, messages::SignedRequestBytes};
use ledger_canister::protobuf::{ArchiveIndexEntry, ArchiveIndexResponse};
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountIdentifier, BlockArg, BlockHeight, BlockRes, EncodedBlock,
    GetBlocksArgs, GetBlocksRes, HashOf, TipOfChainRes, Tokens, Transaction,
};
use on_wire::{FromWire, IntoWire};

use crate::balance_book::BalanceBook;
use crate::certification::verify_block_hash;
use crate::errors::{ApiError, Details, ICError};
use crate::models::{EnvelopePair, SignedTransaction};
use crate::request_types::START_DISSOLVE;
use crate::request_types::STOP_DISSOLVE;
use crate::request_types::{Request, RequestResult, RequestType, Status, TransactionResults};
use crate::store::{BlockStore, BlockStoreError, HashedBlock, SQLiteStore};
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
    async fn submit(&self, _envelopes: SignedTransaction) -> Result<TransactionResults, ApiError>;
    async fn cleanup(&self);
    async fn neuron_info(
        &self,
        acc_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfo, ApiError>;
}

pub struct SubmitResult {
    pub transaction_identifier: TransactionIdentifier,
    pub block_index: Option<BlockHeight>,
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
    canister_access: Option<Arc<CanisterAccess>>,
    ic_url: Url,
    store_max_blocks: Option<u64>,
    offline: bool,
    root_key: Option<ThresholdSigPublicKey>,
}

impl LedgerClient {
    pub async fn new(
        ic_url: Url,
        canister_id: CanisterId,
        governance_canister_id: CanisterId,
        block_store: SQLiteStore,
        store_max_blocks: Option<u64>,
        offline: bool,
        root_key: Option<ThresholdSigPublicKey>,
    ) -> Result<LedgerClient, ApiError> {
        let mut blocks = Blocks::new(block_store);
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

#[async_trait]
impl LedgerAccess for LedgerClient {
    async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    async fn cleanup(&self) {
        if let Some(ca) = &self.canister_access {
            ca.clear_outstanding_queries().await;
        }
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
                return Err(ApiError::from(results));
            }
        }

        Ok(results)
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
                    - (ic_types::ingress::MAX_INGRESS_TTL - ic_types::ingress::PERMITTED_DRIFT);
                ingress_start <= now && ingress_expiry > now
            })
            .ok_or(ApiError::TransactionExpired)?;

        let canister_id = match &update.content {
            HttpSubmitContent::Call { update } => {
                CanisterId::try_from(update.canister_id.0.clone()).map_err(|e| {
                    ApiError::internal_error(format!(
                        "Cannot parse canister ID found in submit call: {}",
                        e
                    ))
                })?
            }
        };

        let request_id = MessageId::from(update.content.representation_independent_hash());
        let txn_id = TransactionIdentifier::try_from_envelope(request_type, &update)?;

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

        // Do read-state calls until the result becomes available.
        let wait_for_result = || {
            async {
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
                                    .map_err(|err| {
                                        format!("While parsing the status body: {}", err)
                                    })?;

                                let status = ic_canister_client::parse_read_state_response(
                                    &request_id,
                                    cbor,
                                )
                                .map_err(|err| {
                                    format!("While parsing the read state response: {}", err)
                                })?;

                                debug!("Read state response: {:?}", status);

                                match status.status.as_ref() {
                                    "replied" => match status.reply {
                                        Some(bytes) => {
                                            match request_type {
                                                RequestType::Send => {
                                                    let block_index: BlockHeight =
                                                        ProtoBuf::from_bytes(bytes)
                                                        .map(|c| c.0)
                                                        .map_err(|err| {
                                                            format!(
                                                                "While parsing the reply of the send call: {}",
                                                                err
                                                            )
                                                        })?;
                                                    return Ok(Ok(Some(block_index)));
                                                }
                                                RequestType::Stake { .. } => {
                                                    let res: ClaimOrRefreshNeuronFromAccountResponse = candid::decode_one(&bytes)
                                                        .map_err(|err| {
                                                            format!(
                                                                "While parsing the reply of the stake creation call: {}",
                                                                err
                                                            )
                                                        })?;
                                                    match res.result.unwrap() {
                                                        ClaimOrRefreshResult::Error(err) => {
                                                            return Ok(Err(ApiError::TransactionRejected(
                                                                false,
                                                                format!("Could not claim neuron: {}", err).into())));
                                                        }
                                                        ClaimOrRefreshResult::NeuronId(nid) => {
                                                            return Ok(Ok(Some(nid.id)));
                                                        }
                                                    };
                                                }
                                                RequestType::SetDissolveTimestamp { .. } => {
                                                    let response: ManageNeuronResponse =
                                                        candid::decode_one(bytes.as_ref())
                                                            .map_err(|err| {
                                                                format!(
                                                                    "Could not set dissolve timestamp: {}",
                                                                    err
                                                                )
                                                            })?;
                                                    match &response.command {
                                                        Some(manage_neuron_response::Command::Configure(_)) => { return Ok(Ok(None)); }
                                                        Some(manage_neuron_response::Command::Error(err)) => {
                                                            if err.error_message == "Can't set a dissolve delay that is smaller than the current dissolve delay." {
                                                                return Ok(Ok(None));
                                                            } else {
                                                                return Ok(Err(ApiError::TransactionRejected(
                                                                    false,
                                                                    format!("Could not set dissolve delay timestamp: {}", err).into()
                                                                )));
                                                            }
                                                        }
                                                        _ => panic!("unexpected set dissolve delay timestamp result: {:?}", response.command),
                                                    }
                                                }
                                                RequestType::StartDissolve { .. }
                                                | RequestType::StopDissolve { .. } => {
                                                    let response: ManageNeuronResponse =
                                                        candid::decode_one(bytes.as_ref())
                                                            .map_err(|err| {
                                                                format!(
                                                                    "Could not set dissolve: {}",
                                                                    err
                                                                )
                                                            })?;
                                                    match &response.command {
                                                        Some(manage_neuron_response::Command::Configure(_)) => {
                                                            return Ok(Ok(None));
                                                        }
                                                        Some(manage_neuron_response::Command::Error(err)) => {
                                                            if (request_type.into_str() ==  START_DISSOLVE
                                                                && err.error_type == governance_error::ErrorType::RequiresNotDissolving as i32)
                                                                || (request_type.into_str() == STOP_DISSOLVE
                                                                    && err.error_type == governance_error::ErrorType::RequiresDissolving as i32)
                                                            {
                                                                return Ok(Ok(None));
                                                            } else {
                                                                return Ok(Err(ApiError::TransactionRejected(
                                                                    false,
                                                                    format!("Could not start/stop dissolving: {}", err).into(),
                                                                )));
                                                            }
                                                        }
                                                        _ => panic!(
                                                            "unexpected start/stop dissolve result: {:?}",
                                                            response.command
                                                        ),
                                                    }
                                                }
                                                RequestType::Disburse { .. } => {
                                                    let response: ManageNeuronResponse =
                                                        candid::decode_one(bytes.as_ref())
                                                            .map_err(|err| {
                                                                format!(
                                                                    "Could not disburse : {}",
                                                                    err
                                                                )
                                                            })?;

                                                    match &response.command {
                                                        Some(manage_neuron_response::Command::Disburse(DisburseResponse {transfer_block_height})) => {
                                                            return Ok(Ok(Some(*transfer_block_height)));
                                                        }
                                                        Some(manage_neuron_response::Command::Error(err)) => {
                                                                return Ok(Err(ApiError::TransactionRejected(
                                                                    false,
                                                                    format!("Could not disburse: {}", err).into(),
                                                                )));
                                                        }
                                                        _ => panic!(
                                                            "unexpected disburse result: {:?}", response.command)}
                                                }
                                                RequestType::AddHotKey { .. } => {
                                                    let response: ManageNeuronResponse =
                                                        candid::decode_one(bytes.as_ref())
                                                            .map_err(|err| {
                                                                format!(
                                                                    "Could not decode ADD_HOTKEY request: {}",
                                                                    err
                                                                )
                                                            })?;
                                                    match &response.command {
                                                        Some(manage_neuron_response::Command::Configure(_)) => {
                                                            return Ok(Ok(None));
                                                        }
                                                        Some(manage_neuron_response::Command::Error(err)) => {
                                                            if err.error_message.contains("Hot key duplicated") {
                                                                 return Ok(Ok(None));
                                                            } else {
                                                                return Ok(Err(ApiError::TransactionRejected(
                                                                            false,
                                                                            format!("Could not add hot key: {}", err).into()
                                                                        )
                                                                    )
                                                                );
                                                            }
                                                        }
                                                        _ => panic!(
                                                            "unexpected add hot key result: {:?}",

                                                            response.command
                                                        ),
                                                    }
                                                }
                                            }
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
                                    _ => {
                                        return Err(format!(
                                            "Send returned unexpected result: {:?} - {:?}",
                                            status.status, status.reject_message
                                        ))
                                    }
                                }
                            } else {
                                let body = String::from_utf8(body)
                                    .unwrap_or_else(|_| "<undecodable>".to_owned());
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
                return Err(format!(
                    "Block submission took longer than {:?} to complete.",
                    Self::TIMEOUT
                ));
            }
        };

        /* Only return a non-200 result in case of an error from the
         * ledger canister. Otherwise just log the error and return a
         * 200 result with no block index. */
        match wait_for_result().await {
            // Success
            Ok(Ok(id)) => {
                if let Request::Stake(_) = result._type {
                    result.neuron_id = id;
                } else {
                    result.block_index = id;
                }
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
}

pub struct CanisterAccess {
    agent: Agent,
    canister_id: CanisterId,
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

    async fn multi_query_blocks(
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
                    .map(|pid| CanisterId::try_from(pid).ok())
                    .flatten()
                    .unwrap_or(self.canister_id),
                entry.height_to + 1,
            ),
            None => (self.canister_id, end),
        };

        let end = std::cmp::min(end, can_end);

        self.call_query_blocks(can_id, start, end).await
    }
}

pub struct Blocks {
    pub balance_book: BalanceBook,
    hash_location: HashMap<HashOf<EncodedBlock>, BlockHeight>,
    pub tx_hash_location: HashMap<HashOf<Transaction>, BlockHeight>,
    pub block_store: SQLiteStore,
    last_hash: Option<HashOf<EncodedBlock>>,
}

impl Default for Blocks {
    fn default() -> Self {
        Blocks::new_in_memory()
    }
}

impl Blocks {
    const LOAD_FROM_STORE_BLOCK_BATCH_LEN: u64 = 10000;

    pub fn new(block_store: SQLiteStore) -> Self {
        Self {
            balance_book: BalanceBook::default(),
            hash_location: HashMap::default(),
            tx_hash_location: HashMap::default(),
            block_store,
            last_hash: None,
        }
    }

    pub fn new_in_memory() -> Self {
        let store =
            SQLiteStore::new_in_memory().expect("Failed to initialize sql store for ledger");
        Self::new(store)
    }

    pub fn load_from_store(&mut self) -> Result<u64, ApiError> {
        assert!(self.last()?.is_none(), "Blocks is not empty");
        assert!(
            self.balance_book.store.acc_to_hist.is_empty(),
            "Blocks is not empty"
        );
        assert!(self.hash_location.is_empty(), "Blocks is not empty");
        assert!(self.tx_hash_location.is_empty(), "Blocks is not empty");

        if let Ok(genesis) = self.block_store.get_at(0) {
            self.process_block(genesis)?;
        } else {
            return Ok(0);
        }

        if let Some((first, balances_snapshot)) = self.block_store.first_snapshot() {
            self.balance_book = balances_snapshot;

            self.hash_location.insert(first.hash, first.index);

            let tx = first.block.decode().unwrap().transaction;
            self.tx_hash_location.insert(tx.hash(), first.index);
            self.last_hash = Some(first.hash);
        }

        let mut n = 1; // one block loaded so far (genesis or first from snapshot)
        let mut next_idx = self.last()?.map(|hb| hb.index + 1).unwrap();
        loop {
            let batch = self
                .block_store
                .get_range(next_idx..next_idx + Self::LOAD_FROM_STORE_BLOCK_BATCH_LEN)?;
            if batch.is_empty() {
                break;
            }
            for hb in batch {
                self.process_block(hb).map_err(|e| {
                    error!(
                        "Processing block retrieved from store failed. Block idx: {}, error: {:?}",
                        next_idx, e
                    );
                    e
                })?;

                next_idx += 1;
                n += 1;
                if n % 30000 == 0 {
                    info!("Loading... {} blocks processed", n);
                }
            }
        }

        Ok(n)
    }

    fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        Ok(self.block_store.get_at(index)?)
    }

    pub fn get_verified_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if index as i128 > last_verified_idx {
            Err(BlockStoreError::NotFound(index).into())
        } else {
            self.get_at(index)
        }
    }

    pub fn get_balance(&self, acc: &AccountIdentifier, h: BlockHeight) -> Result<Tokens, ApiError> {
        if let Ok(Some(b)) = self.first_verified() {
            if h < b.index {
                return Err(ApiError::invalid_block_id(format!(
                    "Block at height: {} not available for query",
                    h
                )));
            }
        }
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if h as i128 > last_verified_idx {
            Err(ApiError::invalid_block_id(format!(
                "Block not found at height: {}",
                h
            )))
        } else {
            self.balance_book.store.get_at(*acc, h)
        }
    }

    fn get(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| ApiError::invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_at(index)
    }

    pub fn get_verified(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| ApiError::invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_verified_at(index)
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub fn add_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        self.block_store.push(hb.clone())?;
        self.process_block(hb)?;
        Ok(())
    }

    pub fn add_blocks_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), ApiError> {
        self.block_store.push_batch(batch.clone())?;
        for hb in batch {
            self.process_block(hb)?;
        }
        Ok(())
    }

    pub fn process_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        let HashedBlock {
            block,
            hash,
            parent_hash,
            index,
        } = hb.clone();
        let last = self.last()?;
        let last_hash = last.clone().map(|hb| hb.hash);
        let last_index = last.map(|hb| hb.index);
        assert_eq!(
            &parent_hash, &last_hash,
            "When adding a block the parent_hash must match the last added block"
        );

        let block = block.decode().unwrap();

        match last_index {
            Some(i) => assert_eq!(i + 1, index),
            None => assert_eq!(0, index),
        }

        let mut bb = &mut self.balance_book;
        bb.store.transaction_context = Some(index);
        bb.add_payment(&block.transaction.operation).unwrap();
        bb.store.transaction_context = None;

        self.hash_location.insert(hash, index);

        let tx = block.transaction;
        self.tx_hash_location.insert(tx.hash(), index);

        self.last_hash = Some(hb.hash);

        Ok(())
    }

    fn first(&self) -> Result<Option<HashedBlock>, ApiError> {
        Ok(self.block_store.first()?)
    }

    pub fn first_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        let first_block = self.block_store.first()?;
        if let Some(fb) = first_block.as_ref() {
            if fb.index as i128 > last_verified_idx {
                return Ok(None);
            }
        }
        Ok(first_block)
    }

    fn last(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.last_hash {
            Some(last_hash) => {
                let last = self.get(last_hash)?;
                Ok(Some(last))
            }
            None => Ok(None),
        }
    }

    pub fn last_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.block_store.last_verified() {
            Some(h) => Ok(Some(self.block_store.get_at(h)?)),
            None => Ok(None),
        }
    }

    fn synced_to(&self) -> Option<(HashOf<EncodedBlock>, u64)> {
        self.last().ok().flatten().map(|hb| (hb.hash, hb.index))
    }

    pub fn try_prune(
        &mut self,
        max_blocks: &Option<u64>,
        prune_delay: u64,
    ) -> Result<(), ApiError> {
        if let Some(block_limit) = max_blocks {
            let first_idx = self.first()?.map(|hb| hb.index).unwrap_or(0);
            let last_idx = self.last()?.map(|hb| hb.index).unwrap_or(0);
            if first_idx + block_limit + prune_delay < last_idx {
                let new_first_idx = last_idx - block_limit;
                let prune_start_idx = first_idx.max(1).min(new_first_idx);
                for i in prune_start_idx..new_first_idx {
                    let hb = self.block_store.get_at(i)?;
                    self.hash_location
                        .remove(&hb.hash)
                        .expect("failed to remove block by hash");
                    let tx_hash = hb
                        .block
                        .decode()
                        .expect("failed to decode block")
                        .transaction
                        .hash();
                    self.tx_hash_location
                        .remove(&tx_hash)
                        .expect("failed to remove transaction by hash");
                }

                let hb = self.block_store.get_at(new_first_idx)?;
                self.balance_book.store.prune_at(hb.index);
                self.block_store
                    .prune(&hb, &self.balance_book)
                    .map_err(ApiError::internal_error)?
            }
        }
        Ok(())
    }
}
