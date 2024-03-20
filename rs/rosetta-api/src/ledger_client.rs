mod handle_add_hotkey;
mod handle_change_auto_stake_maturity;
mod handle_disburse;
mod handle_follow;
mod handle_list_neurons;
mod handle_merge_maturity;
mod handle_neuron_info;
mod handle_register_vote;
mod handle_remove_hotkey;
mod handle_send;
mod handle_set_dissolve_timestamp;
mod handle_spawn;
mod handle_stake;
mod handle_stake_maturity;
mod handle_start_dissolve;
mod handle_stop_dissolve;
pub mod list_known_neurons_response;
pub mod list_neurons_response;
mod neuron_response;
pub mod pending_proposals_response;
pub mod proposal_info_response;

use candid::{Decode, Encode};
use core::ops::Deref;
use ic_agent::agent::{RejectCode, RejectResponse};
use ic_nns_governance::pb::v1::{KnownNeuron, ListKnownNeuronsResponse, ProposalInfo};
use std::convert::TryFrom;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{thread, time};
use url::Url;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use tracing::{debug, error, warn};

use dfn_candid::CandidOne;
use ic_ledger_canister_blocks_synchronizer::blocks::Blocks;
use ic_ledger_canister_blocks_synchronizer::canister_access::CanisterAccess;
use ic_ledger_canister_blocks_synchronizer::certification::VerificationInfo;
use ic_ledger_canister_blocks_synchronizer::ledger_blocks_sync::{
    LedgerBlocksSynchronizer, LedgerBlocksSynchronizerMetrics,
};
use ic_nns_governance::pb::v1::{manage_neuron::NeuronIdOrSubaccount, GovernanceError, NeuronInfo};
use ic_types::messages::{HttpCallContent, MessageId};
use ic_types::CanisterId;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, messages::SignedRequestBytes};
use icp_ledger::{BlockIndex, Symbol, TransferFee, TransferFeeArgs, DEFAULT_TRANSFER_FEE};
use on_wire::{FromWire, IntoWire};

use crate::convert;
use crate::errors::{ApiError, Details, ICError};
use crate::ledger_client::neuron_response::NeuronResponse;
use crate::ledger_client::{
    handle_add_hotkey::handle_add_hotkey,
    handle_change_auto_stake_maturity::handle_change_auto_stake_maturity,
    handle_disburse::handle_disburse, handle_follow::handle_follow,
    handle_merge_maturity::handle_merge_maturity, handle_neuron_info::handle_neuron_info,
    handle_register_vote::handle_register_vote, handle_remove_hotkey::handle_remove_hotkey,
    handle_send::handle_send, handle_set_dissolve_timestamp::handle_set_dissolve_timestamp,
    handle_spawn::handle_spawn, handle_stake::handle_stake,
    handle_stake_maturity::handle_stake_maturity, handle_start_dissolve::handle_start_dissolve,
    handle_stop_dissolve::handle_stop_dissolve,
};
use crate::models::{EnvelopePair, SignedTransaction};
use crate::request::request_result::RequestResult;
use crate::request::transaction_results::TransactionResults;
use crate::request::Request;
use crate::request_types::{RequestType, Status};
use crate::transaction_id::TransactionIdentifier;
use rosetta_core::objects::ObjectMap;

use self::handle_list_neurons::handle_list_neurons;
use self::list_neurons_response::ListNeuronsResponse;
use self::proposal_info_response::ProposalInfoResponse;

struct LedgerBlocksSynchronizerMetricsImpl {}

impl LedgerBlocksSynchronizerMetrics for LedgerBlocksSynchronizerMetricsImpl {
    fn set_target_height(&self, height: u64) {
        crate::rosetta_server::TARGET_HEIGHT.set(height as i64);
    }

    fn set_synced_height(&self, height: u64) {
        crate::rosetta_server::SYNCED_HEIGHT.set(height as i64);
    }

    fn set_verified_height(&self, height: u64) {
        crate::rosetta_server::VERIFIED_HEIGHT.set(height as i64);
    }
}

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
    async fn proposal_info(&self, proposal_id: u64) -> Result<ProposalInfo, ApiError>;
    async fn pending_proposals(&self) -> Result<Vec<ProposalInfo>, ApiError>;
    async fn list_known_neurons(&self) -> Result<Vec<KnownNeuron>, ApiError>;
    async fn transfer_fee(&self) -> Result<TransferFee, ApiError>;
}

pub struct LedgerClient {
    ledger_blocks_synchronizer: LedgerBlocksSynchronizer<CanisterAccess>,
    canister_id: CanisterId,
    root_key: Option<ThresholdSigPublicKey>,
    governance_canister_id: CanisterId,
    canister_access: Option<Arc<CanisterAccess>>,
    ic_url: Url,
    token_symbol: String,
    offline: bool,
}

pub enum OperationOutput {
    BlockIndex(BlockIndex),
    NeuronId(u64),
    NeuronResponse(NeuronResponse),
    ProposalInfoResponse(ProposalInfoResponse),
    ListNeuronsResponse(ListNeuronsResponse),
}

fn public_key_to_der(key: ThresholdSigPublicKey) -> Result<Vec<u8>, ApiError> {
    ic_crypto_utils_threshold_sig_der::public_key_to_der(&key.into_bytes())
        .map_err(ApiError::internal_error)
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
        let canister_access = if offline {
            None
        } else {
            let canister_access = CanisterAccess::new(
                ic_url.clone(),
                canister_id,
                root_key.map(public_key_to_der).transpose()?,
            )
            .await
            .map_err(|e| ApiError::internal_error(format!("{}", e)))?;
            LedgerClient::check_ledger_symbol(&token_symbol, &canister_access).await?;
            Some(Arc::new(canister_access))
        };
        let verification_info = root_key.map(|root_key| VerificationInfo {
            root_key,
            canister_id,
        });
        let ledger_blocks_synchronizer = LedgerBlocksSynchronizer::new(
            canister_access.clone(),
            store_location,
            store_max_blocks,
            verification_info,
            Box::new(LedgerBlocksSynchronizerMetricsImpl {}),
        )
        .await?;

        Ok(Self {
            ledger_blocks_synchronizer,
            canister_id,
            root_key,
            token_symbol,
            governance_canister_id,
            canister_access,
            ic_url,
            offline,
        })
    }

    async fn check_ledger_symbol(
        token_symbol: &str,
        canister_access: &CanisterAccess,
    ) -> Result<(), ApiError> {
        let arg = CandidOne(())
            .into_bytes()
            .map_err(|e| ApiError::internal_error(format!("Serialization failed: {:?}", e)))?;

        let symbol_res: Result<Symbol, String> = canister_access
            .agent
            .query(&canister_access.canister_id.get().0, "symbol")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| format!("{}", e))
            .and_then(|bytes| CandidOne::from_bytes(bytes).map(|c| c.0));

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
                    tracing::warn!("Symbol endpoint not present in the ledger canister. Couldn't verify token symbol.");
                } else {
                    return Err(ApiError::internal_error(format!(
                        "Failed to fetch symbol name from the ledger: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LedgerAccess for LedgerClient {
    async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        self.ledger_blocks_synchronizer.read_blocks().await
    }

    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        self.ledger_blocks_synchronizer
            .sync_blocks(stopped, None)
            .await
            .map_err(ApiError::from)
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

    async fn submit(
        &self,
        signed_transaction: SignedTransaction,
    ) -> Result<TransactionResults, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let start_time = Instant::now();
        let http_client = reqwest::Client::new();

        let mut results: TransactionResults = signed_transaction
            .requests
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

        for ((request_type, request), result) in signed_transaction
            .requests
            .into_iter()
            .zip(results.operations.iter_mut())
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

    async fn proposal_info(&self, proposal_id: u64) -> Result<ProposalInfo, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let agent = &self.canister_access.as_ref().unwrap().agent;

        let arg = CandidOne(proposal_id)
            .into_bytes()
            .map_err(|e| ApiError::internal_error(format!("Serialization failed: {:?}", e)))?;
        let bytes = agent
            .query(&self.governance_canister_id.get().0, "get_proposal_info")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| ApiError::invalid_request(format!("{}", e)))?;
        let proposal_info_response =
            Decode!(bytes.as_slice(), Option<ProposalInfo>).map_err(|err| {
                ApiError::InvalidRequest(
                    false,
                    Details::from(format!("Could not decode ProposalInfo response: {}", err)),
                )
            })?;
        match proposal_info_response {
            Some(pinf) => Ok(pinf),
            None => Err(ApiError::InvalidRequest(
                false,
                Details::from(
                    "Get Proposal Info returned no ProposalInfo --> No Proposal Info found by that Id",
                ),
            )),
        }
    }
    async fn pending_proposals(&self) -> Result<Vec<ProposalInfo>, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let agent = &self.canister_access.as_ref().unwrap().agent;
        let arg = Encode!().unwrap();
        let bytes = agent
            .query(
                &self.governance_canister_id.get().0,
                "get_pending_proposals",
            )
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| ApiError::invalid_request(format!("{}", e)))?;
        Decode!(bytes.as_slice(), Vec<ProposalInfo>).map_err(|err| {
            ApiError::InvalidRequest(
                false,
                Details::from(format!(
                    "Could not decode PendingProposals response: {}",
                    err
                )),
            )
        })
    }
    async fn list_known_neurons(&self) -> Result<Vec<KnownNeuron>, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, Details::default()));
        }
        let agent = &self.canister_access.as_ref().unwrap().agent;
        let arg = Encode!().unwrap();
        let bytes = agent
            .query(&self.governance_canister_id.get().0, "list_known_neurons")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| ApiError::invalid_request(format!("{}", e)))?;
        Decode!(bytes.as_slice(), ListKnownNeuronsResponse)
            .map_err(|err| {
                ApiError::InvalidRequest(
                    false,
                    Details::from(format!(
                        "Could not decode ListKnownNeuronsResponse response: {}",
                        err
                    )),
                )
            })
            .map(|res| res.known_neurons)
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
            agent
                .update(
                    &self.governance_canister_id.get().0,
                    "get_neuron_info_by_id_or_subaccount",
                )
                .with_arg(arg)
                .call_and_wait()
                .await
        } else {
            agent
                .query(
                    &self.governance_canister_id.get().0,
                    "get_neuron_info_by_id_or_subaccount",
                )
                .with_arg(arg)
                .call()
                .await
        }
        .map_err(|e| ApiError::invalid_request(format!("{}", e)))?;
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
            .query(&self.canister_id.get().0, "transfer_fee")
            .with_arg(arg)
            .call()
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
            Ok(bytes) => CandidOne::from_bytes(bytes).map(|c| c.0).map_err(|e| {
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
                let ingress_start = ingress_expiry.saturating_sub(
                    ic_constants::MAX_INGRESS_TTL.saturating_sub(ic_constants::PERMITTED_DRIFT),
                );
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
                    match status {
                        StatusCode::ACCEPTED => {
                            break;
                        }
                        // Status code 200 means there is a CBOR encoded RejectResponse encoded in the body.
                        StatusCode::OK => {
                            let reject_response: Result<RejectResponse, _> =
                                serde_cbor::from_slice(&body);

                            let (retriable, error_message) = reject_response
                                .map(|response| {
                                    let retriable =
                                        response.reject_code != RejectCode::DestinationInvalid;
                                    (retriable, response.reject_message)
                                })
                                .unwrap_or((true, "<undecodable>".to_owned()));

                            return Err(ApiError::ICError(ICError {
                                retriable,
                                ic_http_status: status.as_u16(),
                                error_message,
                            }));
                        }
                        _ => {
                            let body = String::from_utf8(body)
                                .unwrap_or_else(|_| "<undecodable>".to_owned());

                            // Retry on 5xx errors. We don't want to retry on
                            // e.g. authentication errors.
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
                }
            }

            // Sleep for 100 milliseconds to avoid spamming the ICP ledger in case of repeated errors
            thread::sleep(time::Duration::from_millis(100));
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
                        result.response = Some(ObjectMap::try_from(response)?);
                    }
                    OperationOutput::ProposalInfoResponse(response) => {
                        result.response = Some(ObjectMap::try_from(response)?);
                    }
                    OperationOutput::ListNeuronsResponse(response) => {
                        result.response = Some(ObjectMap::try_from(response)?)
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

                        let status = ic_canister_client::parse_read_state_response(
                            &request_id,
                            &canister_id,
                            self.root_key.as_ref(),
                            cbor,
                        )
                        .map_err(|err| format!("While parsing the read state response: {}", err))?;

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
            RequestType::RegisterVote { .. } => handle_register_vote(bytes),
            RequestType::StakeMaturity { .. } => handle_stake_maturity(bytes),
            RequestType::NeuronInfo { .. } => handle_neuron_info(bytes),
            RequestType::ListNeurons { .. } => handle_list_neurons(bytes),
            RequestType::RemoveHotKey { .. } => handle_remove_hotkey(bytes),
            RequestType::Send => handle_send(bytes),
            RequestType::SetDissolveTimestamp { .. } => handle_set_dissolve_timestamp(bytes),
            RequestType::ChangeAutoStakeMaturity { .. } => handle_change_auto_stake_maturity(bytes),
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
