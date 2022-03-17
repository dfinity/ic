pub mod balance_book;
pub mod certification;
pub mod convert;
pub mod errors;
pub mod ledger_client;
pub mod models;
pub mod request_types;
pub mod rosetta_server;
pub mod store;
pub mod time;
pub mod transaction_id;

use crate::convert::{
    account_from_public_key, from_arg, from_hex, from_model_account_identifier, from_public_key,
    make_read_state_from_update, neuron_account_from_public_key,
    neuron_subaccount_bytes_from_public_key, principal_id_from_public_key,
    principal_id_from_public_key_or_principal, to_model_account_identifier,
};
use crate::ledger_client::LedgerAccess;
use crate::request_types::{
    AddHotKey, Disburse, MergeMaturity, NeuronInfo, PublicKeyOrPrincipal, Request, RequestType,
    SetDissolveTimestamp, Spawn, Stake, StartDissolve, StopDissolve, TransactionOperationResults,
};
use crate::store::HashedBlock;
use crate::time::Seconds;

use convert::to_arg;
use dfn_candid::CandidOne;
use errors::ApiError;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, configure, Command, NeuronIdOrSubaccount},
    ClaimOrRefreshNeuronFromAccount, ManageNeuron,
};
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpReadStateContent, HttpRequestEnvelope,
};
use ic_types::{messages::MessageId, CanisterId, PrincipalId};
use on_wire::IntoWire;
use strum::IntoEnumIterator;

use models::*;

use ledger_canister::{BlockHeight, Memo, Operation, SendArgs};
use serde_json::map::Map;
use std::convert::TryFrom;
use transaction_id::TransactionIdentifier;

use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, warn};

pub const API_VERSION: &str = "1.4.10";
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_TOKEN_SYMBOL: &str = "ICP";

fn to_index(height: BlockHeight) -> Result<i128, ApiError> {
    i128::try_from(height).map_err(|e| ApiError::InternalError(true, e.to_string().into()))
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

fn verify_network_id(canister_id: &CanisterId, net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    verify_network_blockchain(net_id)?;

    let id: CanisterId = net_id.try_into()?;

    if *canister_id != id {
        return Err(ApiError::InvalidNetworkId(false, "unknown network".into()));
    }

    Ok(())
}

// For the first block, we return the block itself as its parent
fn create_parent_block_id(
    blocks: &ledger_client::Blocks,
    block: &HashedBlock,
) -> Result<BlockIdentifier, ApiError> {
    let idx = std::cmp::max(0, to_index(block.index)? - 1);

    let parent = blocks.get_verified_at(idx as u64)?;
    convert::block_id(&parent)
}

fn get_block(
    blocks: &ledger_client::Blocks,
    block_id: Option<PartialBlockIdentifier>,
) -> Result<HashedBlock, ApiError> {
    let block = match block_id {
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: Some(block_hash),
        }) => {
            let hash: ledger_canister::HashOf<ledger_canister::EncodedBlock> =
                convert::to_hash(&block_hash)?;
            if block_height < 0 {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }
            let block = blocks.get_verified_at(block_height as u64)?;

            if block.hash != hash {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }

            block
        }
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: None,
        }) => {
            if block_height < 0 {
                return Err(ApiError::InvalidBlockId(false, Default::default()));
            }
            let idx = block_height as usize;
            blocks.get_verified_at(idx as u64)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: Some(block_hash),
        }) => {
            let hash: ledger_canister::HashOf<ledger_canister::EncodedBlock> =
                convert::to_hash(&block_hash)?;
            blocks.get_verified(hash)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: None,
        })
        | None => blocks
            .last_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(false, Default::default()))?,
    };

    Ok(block)
}

#[derive(Clone)]
pub struct RosettaRequestHandler {
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
}

impl RosettaRequestHandler {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(ledger: Arc<T>) -> Self {
        Self { ledger }
    }

    pub fn network_id(&self) -> NetworkIdentifier {
        let canister_id = self.ledger.ledger_canister_id();
        let net_id = hex::encode(canister_id.get().into_vec());
        NetworkIdentifier::new("Internet Computer".to_string(), net_id)
    }

    /// Get an Account Balance
    pub async fn account_balance(
        &self,
        msg: models::AccountBalanceRequest,
    ) -> Result<AccountBalanceResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let neuron_info_request_params = match msg.metadata.clone().unwrap_or_default().account_type
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

        let account_id = ledger_canister::AccountIdentifier::from_hex(
            &msg.account_identifier.address,
        )
        .map_err(|e| {
            ApiError::invalid_account_id(format!(
                "Account {} is not valid address, {}",
                &msg.account_identifier.address, e,
            ))
        })?;
        let blocks = self.ledger.read_blocks().await;
        let block = get_block(&blocks, msg.block_identifier)?;

        let tokens = blocks.get_balance(&account_id, block.index)?;
        let amount = convert::amount_(tokens, self.ledger.token_symbol())?;
        let b = convert::block_id(&block)?;
        Ok(AccountBalanceResponse {
            block_identifier: b,
            balances: vec![amount],
            metadata: neuron_info,
        })
    }

    /// Get a Block
    pub async fn block(&self, msg: models::BlockRequest) -> Result<BlockResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let blocks = self.ledger.read_blocks().await;
        let hb = get_block(&blocks, Some(msg.block_identifier))?;
        let block = hb
            .block
            .decode()
            .map_err(|err| ApiError::internal_error(format!("Cannot decode block: {}", err)))?;
        let b_id = convert::block_id(&hb)?;
        let parent_id = create_parent_block_id(&blocks, &hb)?;

        let transactions = vec![convert::transaction(&hb, self.ledger.token_symbol())?];
        let block = Some(models::Block::new(
            b_id,
            parent_id,
            convert::timestamp(block.timestamp.into())?,
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

        let transaction = convert::transaction(&hb, self.ledger.token_symbol())?;

        Ok(BlockTransactionResponse::new(transaction))
    }

    /// Create Network Transfer from Signatures
    // This returns Envelopes encoded in a CBOR string
    pub async fn construction_combine(
        &self,
        msg: models::ConstructionCombineRequest,
    ) -> Result<ConstructionCombineResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let mut signatures_by_sig_data: HashMap<Vec<u8>, _> = HashMap::new();

        for sig in &msg.signatures {
            let sig_data = from_hex(&sig.signing_payload.hex_bytes)?;
            signatures_by_sig_data.insert(sig_data, sig);
        }

        let unsigned_transaction = msg.unsigned_transaction()?;

        let mut envelopes: SignedTransaction = vec![];

        for (request_type, update) in unsigned_transaction.updates {
            let mut request_envelopes = vec![];

            for ingress_expiry in &unsigned_transaction.ingress_expiries {
                let mut update = update.clone();
                update.ingress_expiry = *ingress_expiry;

                let read_state = make_read_state_from_update(&update);

                let transaction_signature = signatures_by_sig_data
                    .get(&make_sig_data(&update.id()))
                    .ok_or_else(|| {
                        ApiError::internal_error(
                            "Could not find signature for transaction".to_string(),
                        )
                    })?;
                let read_state_signature = signatures_by_sig_data
                    .get(&make_sig_data(&MessageId::from(
                        read_state.representation_independent_hash(),
                    )))
                    .ok_or_else(|| {
                        ApiError::internal_error(
                            "Could not find signature for read-state".to_string(),
                        )
                    })?;

                assert_eq!(transaction_signature.signature_type, SignatureType::Ed25519);
                assert_eq!(read_state_signature.signature_type, SignatureType::Ed25519);

                let envelope = HttpRequestEnvelope::<HttpCallContent> {
                    content: HttpCallContent::Call { update },
                    sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
                        from_public_key(&transaction_signature.public_key)?,
                    ))),
                    sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes)?)),
                    sender_delegation: None,
                };

                let read_state_envelope = HttpRequestEnvelope::<HttpReadStateContent> {
                    content: HttpReadStateContent::ReadState { read_state },
                    sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
                        from_public_key(&read_state_signature.public_key)?,
                    ))),
                    sender_sig: Some(Blob(from_hex(&read_state_signature.hex_bytes)?)),
                    sender_delegation: None,
                };

                request_envelopes.push(EnvelopePair {
                    update: envelope,
                    read_state: read_state_envelope,
                });
            }

            envelopes.push((request_type, request_envelopes));
        }

        let envelopes = hex::encode(serde_cbor::to_vec(&envelopes).map_err(|_| {
            ApiError::InternalError(false, "Serialization of envelope failed".into())
        })?);

        Ok(ConstructionCombineResponse {
            signed_transaction: envelopes,
        })
    }

    /// Derive an AccountIdentifier from a PublicKey
    pub async fn construction_derive(
        &self,
        msg: models::ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let account_identifier = Some(match msg.metadata {
            Some(ConstructionDeriveRequestMetadata {
                account_type: AccountType::Neuron { neuron_index },
                ..
            }) => neuron_account_from_public_key(
                self.ledger.governance_canister_id(),
                &msg.public_key,
                neuron_index,
            )?,
            _ => account_from_public_key(&msg.public_key)?,
        });

        Ok(ConstructionDeriveResponse {
            account_identifier,
            address: None,
            metadata: None,
        })
    }

    /// Get the Hash of a Signed Transfer
    pub async fn construction_hash(
        &self,
        msg: models::ConstructionHashRequest,
    ) -> Result<ConstructionHashResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let envelopes = msg.signed_transaction()?;

        let transaction_identifier = if let Some((request_type, envelope_pairs)) =
            envelopes.iter().rev().find(|(rt, _)| rt.is_transfer())
        {
            TransactionIdentifier::try_from_envelope(
                request_type.clone(),
                &envelope_pairs[0].update,
            )
        } else if envelopes.iter().all(|(r, _)| r.is_neuron_management()) {
            Ok(TransactionIdentifier {
                hash: transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH.to_owned(),
            })
        } else {
            Err(ApiError::invalid_request(
                "There is no hash for this transaction",
            ))
        }?;

        Ok(ConstructionHashResponse {
            transaction_identifier,
            metadata: Map::new(),
        })
    }

    /// Get Metadata for Transfer Construction
    pub async fn construction_metadata(
        &self,
        msg: models::ConstructionMetadataRequest,
    ) -> Result<ConstructionMetadataResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let suggested_fee = match msg.options {
            Some(opts)
                if opts
                    .request_types
                    .iter()
                    .all(RequestType::is_neuron_management) =>
            {
                None
            }
            _ => {
                let transfer_fee = self.ledger.transfer_fee().await?.transfer_fee;
                Some(vec![convert::amount_(
                    transfer_fee,
                    self.ledger.token_symbol(),
                )?])
            }
        };
        Ok(ConstructionMetadataResponse {
            metadata: ConstructionPayloadsRequestMetadata::default(),
            suggested_fee,
        })
    }

    /// Parse a Transfer
    pub async fn construction_parse(
        &self,
        msg: models::ConstructionParseRequest,
    ) -> Result<ConstructionParseResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let updates: Vec<_> = match msg.transaction()? {
            ParsedTransaction::Signed(envelopes) => envelopes
                .iter()
                .map(
                    |(request_type, updates)| match updates[0].update.content.clone() {
                        HttpCallContent::Call { update } => (request_type.clone(), update),
                    },
                )
                .collect(),
            ParsedTransaction::Unsigned(unsigned_transaction) => unsigned_transaction.updates,
        };

        let mut requests = vec![];
        let mut from_ai = vec![];

        for (request_type, HttpCanisterUpdate { arg, sender, .. }) in updates {
            let from = PrincipalId::try_from(sender.0)
                .map_err(|e| ApiError::internal_error(e.to_string()))?
                .into();
            if msg.signed {
                from_ai.push(from);
            }

            match request_type {
                RequestType::Send => {
                    let SendArgs {
                        amount, fee, to, ..
                    } = from_arg(arg.0)?;
                    requests.push(Request::Transfer(Operation::Transfer {
                        from,
                        to,
                        amount,
                        fee,
                    }));
                }
                RequestType::Stake { neuron_index } => {
                    let _: ClaimOrRefreshNeuronFromAccount = candid::decode_one(arg.0.as_ref())
                        .map_err(|e| {
                            ApiError::internal_error(format!(
                                "Could not decode Create Stake argument: {}",
                                e
                            ))
                        })?;
                    requests.push(Request::Stake(Stake {
                        account: from,
                        neuron_index,
                    }));
                }
                RequestType::SetDissolveTimestamp { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode Set Dissolve Timestamp argument: {}",
                            e
                        ))
                    })?;
                    let timestamp = Seconds(match manage.command {
                        Some(Command::Configure(manage_neuron::Configure {
                            operation:
                                Some(manage_neuron::configure::Operation::SetDissolveTimestamp(d)),
                        })) => Ok(d.dissolve_timestamp_seconds),
                        Some(e) => Err(ApiError::internal_error(format!(
                            "Incompatible manage_neuron command: {:?}",
                            e
                        ))),
                        None => Err(ApiError::internal_error(
                            "Missing manage_neuron command".to_string(),
                        )),
                    }?);

                    requests.push(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                        account: from,
                        neuron_index,
                        timestamp,
                    }));
                }
                RequestType::StartDissolve { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode Start Dissolve argument: {}",
                            e
                        ))
                    })?;
                    if !matches!(
                        manage.command,
                        Some(Command::Configure(manage_neuron::Configure {
                            operation: Some(manage_neuron::configure::Operation::StartDissolving(
                                manage_neuron::StartDissolving {},
                            )),
                        }))
                    ) {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                    requests.push(Request::StartDissolve(StartDissolve {
                        account: from,
                        neuron_index,
                    }));
                }
                RequestType::StopDissolve { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode Stop Dissolve argument: {}",
                            e
                        ))
                    })?;
                    if !matches!(
                        manage.command,
                        Some(Command::Configure(manage_neuron::Configure {
                            operation: Some(manage_neuron::configure::Operation::StopDissolving(
                                manage_neuron::StopDissolving {},
                            )),
                        }))
                    ) {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                    requests.push(Request::StopDissolve(StopDissolve {
                        account: from,
                        neuron_index,
                    }));
                }
                RequestType::Disburse { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode ManageNeuron argument: {}",
                            e
                        ))
                    })?;
                    if let ManageNeuron {
                        command:
                            Some(manage_neuron::Command::Disburse(manage_neuron::Disburse {
                                to_account,
                                amount,
                            })),
                        ..
                    } = manage
                    {
                        requests.push(Request::Disburse(Disburse {
                            account: from,
                            amount: amount.map(|a| ledger_canister::Tokens::from_e8s(a.e8s)),
                            recipient: to_account.map_or(Ok(None), |a| {
                                ledger_canister::AccountIdentifier::try_from(&a)
                                    .map_err(|e| {
                                        ApiError::internal_error(format!(
                                            "Could not parse recipient AccountIdentifier {:?}",
                                            e
                                        ))
                                    })
                                    .map(Some)
                            })?,
                            neuron_index,
                        }));
                    } else {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                }
                RequestType::AddHotKey { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode Stop Dissolve argument: {}",
                            e
                        ))
                    })?;
                    if let Some(Command::Configure(manage_neuron::Configure {
                        operation:
                            Some(manage_neuron::configure::Operation::AddHotKey(
                                manage_neuron::AddHotKey {
                                    new_hot_key: Some(pid),
                                },
                            )),
                    })) = manage.command
                    {
                        requests.push(Request::AddHotKey(AddHotKey {
                            account: from,
                            neuron_index,
                            key: PublicKeyOrPrincipal::Principal(pid),
                        }));
                    } else {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                }

                RequestType::Spawn { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode ManageNeuron argument: {}",
                            e
                        ))
                    })?;
                    if let Some(Command::Spawn(manage_neuron::Spawn {
                        new_controller,
                        nonce,
                        percentage_to_spawn,
                    })) = manage.command
                    {
                        if let Some(spawned_neuron_index) = nonce {
                            requests.push(Request::Spawn(Spawn {
                                account: from,
                                spawned_neuron_index,
                                controller: new_controller,
                                percentage_to_spawn,
                                neuron_index,
                            }));
                        } else {
                            return Err(ApiError::internal_error(
                                "Incompatible manage_neuron command (spawned neuron index is required).",
                            ));
                        }
                    } else {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    }
                }

                RequestType::MergeMaturity { neuron_index } => {
                    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not decode ManageNeuron argument: {}",
                            e
                        ))
                    })?;
                    if let Some(Command::MergeMaturity(manage_neuron::MergeMaturity {
                        percentage_to_merge,
                    })) = manage.command
                    {
                        requests.push(Request::MergeMaturity(MergeMaturity {
                            account: from,
                            percentage_to_merge,
                            neuron_index,
                        }));
                    } else {
                        return Err(ApiError::internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    }
                }

                RequestType::NeuronInfo {
                    neuron_index,
                    controller,
                } => {
                    let _: NeuronIdOrSubaccount =
                        candid::decode_one(arg.0.as_ref()).map_err(|e| {
                            ApiError::internal_error(format!(
                                "Could not decode neuron info argument: {}",
                                e
                            ))
                        })?;

                    match controller
                        .clone()
                        .map(|pkp| principal_id_from_public_key_or_principal(pkp))
                    {
                        None => {
                            requests.push(Request::NeuronInfo(NeuronInfo {
                                account: from,
                                controller: None,
                                neuron_index,
                            }));
                        }
                        Some(Ok(pid)) => {
                            requests.push(Request::NeuronInfo(NeuronInfo {
                                account: from,
                                controller: Some(pid),
                                neuron_index,
                            }));
                        }
                        _ => {
                            return Err(ApiError::invalid_request("Invalid neuron info request."));
                        }
                    }
                }
            }
        }

        from_ai.sort();
        from_ai.dedup();
        let from_ai = from_ai.iter().map(to_model_account_identifier).collect();

        Ok(ConstructionParseResponse {
            operations: Request::requests_to_operations(&requests, self.ledger.token_symbol())?,
            signers: None,
            account_identifier_signers: Some(from_ai),
            metadata: None,
        })
    }

    /// Generate an Unsigned Transfer and Signing Payloads. The
    /// unsigned_transaction returned from this function is a CBOR
    /// serialized UnsignedTransaction. The data to be signed is a
    /// single hex encoded MessageId.
    pub async fn construction_payloads(
        &self,
        msg: models::ConstructionPayloadsRequest,
    ) -> Result<ConstructionPayloadsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let ops = msg.operations.clone();

        let pks = msg.public_keys.clone().ok_or_else(|| {
            ApiError::internal_error("Expected field 'public_keys' to be populated")
        })?;
        let transactions = convert::from_operations(&ops, false, self.ledger.token_symbol())?;

        let interval = ic_constants::MAX_INGRESS_TTL
            - ic_constants::PERMITTED_DRIFT
            - Duration::from_secs(120);

        let meta = msg.metadata.as_ref();

        let ingress_start = meta
            .and_then(|meta| meta.ingress_start)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(ic_types::time::current_time);

        let ingress_end = meta
            .and_then(|meta| meta.ingress_end)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| ingress_start + interval);

        let created_at_time: ledger_canister::TimeStamp = meta
            .and_then(|meta| meta.created_at_time)
            .map(ledger_canister::TimeStamp::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| std::time::SystemTime::now().into());

        // FIXME: the memo field needs to be associated with the operation
        let memo: Memo = meta
            .and_then(|meta| meta.memo)
            .map(Memo)
            .unwrap_or_else(|| Memo(rand::thread_rng().gen()));

        let mut ingress_expiries = vec![];
        let mut now = ingress_start;
        while now < ingress_end {
            let ingress_expiry = (now + ic_constants::MAX_INGRESS_TTL
                - ic_constants::PERMITTED_DRIFT)
                .as_nanos_since_unix_epoch();
            ingress_expiries.push(ingress_expiry);
            now += interval;
        }

        let mut updates = vec![];
        let mut payloads = vec![];

        let pks_map = pks
            .iter()
            .map(|pk| {
                let pid: PrincipalId = convert::principal_id_from_public_key(pk)?;
                let account: ledger_canister::AccountIdentifier = pid.into();
                Ok((account, pk))
            })
            .collect::<Result<HashMap<_, _>, ApiError>>()?;

        fn add_payloads(
            payloads: &mut Vec<SigningPayload>,
            ingress_expiries: &[u64],
            account_identifier: &AccountIdentifier,
            update: &HttpCanisterUpdate,
        ) {
            for ingress_expiry in ingress_expiries {
                let mut update = update.clone();
                update.ingress_expiry = *ingress_expiry;

                let message_id = update.id();

                let transaction_payload = SigningPayload {
                    address: None,
                    account_identifier: Some(account_identifier.clone()),
                    hex_bytes: hex::encode(make_sig_data(&message_id)),
                    signature_type: Some(SignatureType::Ed25519),
                };

                payloads.push(transaction_payload);

                let read_state = make_read_state_from_update(&update);

                let read_state_message_id =
                    MessageId::from(read_state.representation_independent_hash());

                let read_state_payload = SigningPayload {
                    address: None,
                    account_identifier: Some(account_identifier.clone()),
                    hex_bytes: hex::encode(make_sig_data(&read_state_message_id)),
                    signature_type: Some(SignatureType::Ed25519),
                };

                payloads.push(read_state_payload);
            }
        }

        let add_neuron_management_payload =
            |request_type: RequestType,
             account: ledger_canister::AccountIdentifier,
             neuron_index: u64,
             command: Command,
             payloads: &mut Vec<SigningPayload>,
             updates: &mut Vec<(RequestType, HttpCanisterUpdate)>|
             -> Result<(), ApiError> {
                let pk = pks_map.get(&account).ok_or_else(|| {
                    ApiError::internal_error(format!(
                        "Cannot find public key for account identifier {}",
                        account,
                    ))
                })?;

                let neuron_subaccount = neuron_subaccount_bytes_from_public_key(pk, neuron_index)?;

                let manage_neuron = ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(manage_neuron::NeuronIdOrSubaccount::Subaccount(
                        neuron_subaccount.to_vec(),
                    )),
                    command: Some(command),
                };

                let update = HttpCanisterUpdate {
                    canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
                    method_name: "manage_neuron".to_string(),
                    arg: Blob(
                        CandidOne(manage_neuron)
                            .into_bytes()
                            .expect("Serialization failed"),
                    ),
                    nonce: Some(Blob(
                        CandidOne(neuron_index)
                            .into_bytes()
                            .expect("Serialization of neuron_index failed"),
                    )),
                    sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
                    ingress_expiry: 0,
                };

                add_payloads(
                    payloads,
                    &ingress_expiries,
                    &to_model_account_identifier(&account),
                    &update,
                );

                updates.push((request_type, update));
                Ok(())
            };

        for t in transactions {
            match t {
                Request::NeuronInfo(NeuronInfo {
                    account,
                    controller,
                    neuron_index,
                }) => {
                    let neuron_subaccount = match controller {
                        Some(neuron_controller) => {
                            // Hotkey (or any explicit controller).
                            crate::convert::neuron_subaccount_bytes_from_principal(
                                &neuron_controller,
                                neuron_index,
                            )
                        }
                        None => {
                            // Default controller.
                            let pk = pks_map.get(&account).ok_or_else(|| {
                                ApiError::internal_error(format!(
                                    "NeuronInfo - Cannot find public key for account {}",
                                    account,
                                ))
                            })?;
                            crate::convert::neuron_subaccount_bytes_from_public_key(
                                pk,
                                neuron_index,
                            )?
                        }
                    };

                    // In the case of an hotkey, account will be derived from the hotkey so
                    // we can use the same logic for controller or hotkey.
                    let pk = pks_map.get(&account).ok_or_else(|| {
                        ApiError::internal_error(format!(
                            "NeuronInfo - Cannot find public key for account {}",
                            account,
                        ))
                    })?;
                    let sender = convert::principal_id_from_public_key(pk)?;

                    // Argument for the method called on the governance canister.
                    let args = NeuronIdOrSubaccount::Subaccount(neuron_subaccount.to_vec());
                    let update = HttpCanisterUpdate {
                        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
                        method_name: "get_full_neuron_by_id_or_subaccount".to_string(),
                        arg: Blob(CandidOne(args).into_bytes().expect("Serialization failed")),
                        nonce: None,
                        sender: Blob(sender.into_vec()), // Sender is controller or hotkey.
                        ingress_expiry: 0,
                    };
                    add_payloads(
                        &mut payloads,
                        &ingress_expiries,
                        &to_model_account_identifier(&account),
                        &update,
                    );
                    updates.push((
                        RequestType::NeuronInfo {
                            neuron_index,
                            controller: controller.map(|pid| PublicKeyOrPrincipal::Principal(pid)),
                        },
                        update,
                    ));
                }
                Request::Transfer(Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                }) => {
                    let pk = pks_map.get(&from).ok_or_else(|| {
                        ApiError::internal_error(format!(
                            "Cannot find public key for account identifier {}",
                            from,
                        ))
                    })?;

                    // The argument we send to the canister
                    let send_args = SendArgs {
                        memo,
                        amount,
                        fee,
                        from_subaccount: None,
                        to,
                        created_at_time: Some(created_at_time),
                    };

                    let update = HttpCanisterUpdate {
                        canister_id: Blob(self.ledger.ledger_canister_id().get().to_vec()),
                        method_name: "send_pb".to_string(),
                        arg: Blob(to_arg(send_args)),
                        // This nonce allows you to send two otherwise identical requests to the IC.
                        // We don't use a it here because we never want two transactions with
                        // identical tx IDs to both land on chain.
                        nonce: None,
                        sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
                        ingress_expiry: 0,
                    };

                    add_payloads(
                        &mut payloads,
                        &ingress_expiries,
                        &to_model_account_identifier(&from),
                        &update,
                    );
                    updates.push((RequestType::Send, update));
                }
                Request::Stake(Stake {
                    account,
                    neuron_index,
                }) => {
                    let pk = pks_map.get(&account).ok_or_else(|| {
                        ApiError::internal_error(format!(
                            "Cannot find public key for account identifier {}",
                            account,
                        ))
                    })?;

                    // What we send to the governance canister
                    let args = ClaimOrRefreshNeuronFromAccount {
                        controller: None,
                        memo: neuron_index,
                    };

                    let update = HttpCanisterUpdate {
                        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
                        method_name: "claim_or_refresh_neuron_from_account".to_string(),
                        arg: Blob(CandidOne(args).into_bytes().expect("Serialization failed")),
                        // TODO work out whether Rosetta will accept us generating a nonce here
                        // If we don't have a nonce it could cause one of those nasty bugs that
                        // doesn't show it's face until you try to do two
                        // identical transactions at the same time

                        // We reuse the nonce field for neuron_index,
                        // since neuron management commands lack an equivalent to the ledgers memo.
                        // If we also need a real nonce, we'll concatenate it to the
                        // neuron_index.
                        nonce: Some(Blob(
                            CandidOne(neuron_index)
                                .into_bytes()
                                .expect("Serialization of neuron_index failed"),
                        )),
                        sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
                        ingress_expiry: 0,
                    };

                    add_payloads(
                        &mut payloads,
                        &ingress_expiries,
                        &to_model_account_identifier(&account),
                        &update,
                    );
                    updates.push((RequestType::Stake { neuron_index }, update));
                }
                Request::StartDissolve(StartDissolve {
                    account,
                    neuron_index,
                })
                | Request::StopDissolve(StopDissolve {
                    account,
                    neuron_index,
                }) => {
                    let command = Command::Configure(manage_neuron::Configure {
                        operation: Some(if let Request::StartDissolve(_) = t {
                            manage_neuron::configure::Operation::StartDissolving(
                                manage_neuron::StartDissolving {},
                            )
                        } else {
                            manage_neuron::configure::Operation::StopDissolving(
                                manage_neuron::StopDissolving {},
                            )
                        }),
                    });

                    add_neuron_management_payload(
                        if let Request::StartDissolve(_) = t {
                            RequestType::StartDissolve { neuron_index }
                        } else {
                            RequestType::StopDissolve { neuron_index }
                        },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account,
                    neuron_index,
                    timestamp,
                }) => {
                    let command = Command::Configure(manage_neuron::Configure {
                        operation: Some(configure::Operation::SetDissolveTimestamp(
                            manage_neuron::SetDissolveTimestamp {
                                dissolve_timestamp_seconds: Duration::from(timestamp).as_secs(),
                            },
                        )),
                    });

                    add_neuron_management_payload(
                        RequestType::SetDissolveTimestamp { neuron_index },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::AddHotKey(AddHotKey {
                    account,
                    key,
                    neuron_index,
                }) => {
                    let pid = match key {
                        PublicKeyOrPrincipal::Principal(p) => p,
                        PublicKeyOrPrincipal::PublicKey(pk) => principal_id_from_public_key(&pk)?,
                    };
                    let command = Command::Configure(manage_neuron::Configure {
                        operation: Some(configure::Operation::AddHotKey(
                            manage_neuron::AddHotKey {
                                new_hot_key: Some(pid),
                            },
                        )),
                    });

                    add_neuron_management_payload(
                        RequestType::AddHotKey { neuron_index },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::Disburse(Disburse {
                    account,
                    amount,
                    recipient,
                    neuron_index,
                }) => {
                    let command = Command::Disburse(manage_neuron::Disburse {
                        amount: amount.map(|amount| manage_neuron::disburse::Amount {
                            e8s: amount.get_e8s(),
                        }),
                        to_account: recipient.map(From::from),
                    });

                    add_neuron_management_payload(
                        RequestType::Disburse { neuron_index },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::Transfer(Operation::Burn { .. }) => {
                    return Err(ApiError::invalid_request(
                        "Burn operations are not supported through rosetta",
                    ))
                }
                Request::Transfer(Operation::Mint { .. }) => {
                    return Err(ApiError::invalid_request(
                        "Mint operations are not supported through rosetta",
                    ))
                }
                Request::Spawn(Spawn {
                    account,
                    spawned_neuron_index,
                    controller,
                    percentage_to_spawn,
                    neuron_index,
                }) => {
                    let command = Command::Spawn(manage_neuron::Spawn {
                        new_controller: controller,
                        percentage_to_spawn,
                        nonce: Some(spawned_neuron_index),
                    });
                    add_neuron_management_payload(
                        RequestType::Spawn { neuron_index },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::MergeMaturity(MergeMaturity {
                    account,
                    percentage_to_merge,
                    neuron_index,
                }) => {
                    let command = Command::MergeMaturity(manage_neuron::MergeMaturity {
                        percentage_to_merge,
                    });
                    add_neuron_management_payload(
                        RequestType::MergeMaturity { neuron_index },
                        account,
                        neuron_index,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
            }
        }

        Ok(models::ConstructionPayloadsResponse::new(
            &UnsignedTransaction {
                updates,
                ingress_expiries,
            },
            payloads,
        ))
    }

    /// Create a Request to Fetch Metadata
    pub async fn construction_preprocess(
        &self,
        msg: models::ConstructionPreprocessRequest,
    ) -> Result<ConstructionPreprocessResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let transfers =
            convert::from_operations(&msg.operations, true, self.ledger.token_symbol())?;
        let options = Some(ConstructionMetadataRequestOptions {
            request_types: transfers
                .iter()
                .map(|r| r.request_type())
                .collect::<Result<_, _>>()?,
        });

        let required_public_keys: Result<HashSet<ledger_canister::AccountIdentifier>, ApiError> =
            transfers
                .into_iter()
                .map(|transfer| match transfer {
                    Request::Transfer(Operation::Transfer { from, .. }) => Ok(from),
                    Request::Stake(Stake { account, .. })
                    | Request::SetDissolveTimestamp(SetDissolveTimestamp { account, .. })
                    | Request::StartDissolve(StartDissolve { account, .. })
                    | Request::StopDissolve(StopDissolve { account, .. })
                    | Request::Disburse(Disburse { account, .. })
                    | Request::AddHotKey(AddHotKey { account, .. })
                    | Request::Spawn(Spawn { account, .. })
                    | Request::MergeMaturity(MergeMaturity { account, .. })
                    | Request::NeuronInfo(NeuronInfo { account, .. }) => Ok(account),
                    Request::Transfer(Operation::Burn { .. }) => Err(ApiError::invalid_request(
                        "Burn operations are not supported through rosetta",
                    )),
                    Request::Transfer(Operation::Mint { .. }) => Err(ApiError::invalid_request(
                        "Mint operations are not supported through rosetta",
                    )),
                })
                .collect();

        let required_public_keys: Vec<_> = required_public_keys?
            .into_iter()
            .map(|x| to_model_account_identifier(&x))
            .collect();

        Ok(ConstructionPreprocessResponse {
            required_public_keys: Some(required_public_keys),
            options,
        })
    }

    /// Submit a Signed Transfer
    // Normally we'd just use the canister client Agent for this but because this
    // request is constructed in such an odd way it's easier to just do it from
    // scratch
    pub async fn construction_submit(
        &self,
        msg: models::ConstructionSubmitRequest,
    ) -> Result<ConstructionSubmitResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let envelopes = msg.signed_transaction()?;
        let results = self.ledger.submit(envelopes).await?;
        let transaction_identifier = results
            .last_transaction_id()
            .cloned()
            .map(From::from)
            .unwrap_or_else(|| {
                assert!(results
                    .operations
                    .iter()
                    .all(|r| r._type.is_neuron_management()));
                TransactionIdentifier {
                    hash: transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH.to_owned(),
                }
            });
        let results = TransactionOperationResults::from_transaction_results(
            results,
            self.ledger.token_symbol(),
        )?;
        Ok(ConstructionSubmitResponse {
            transaction_identifier,
            metadata: results,
        })
    }

    /// Wait until a new block appears that contains the specified
    /// transaction.
    pub async fn wait_for_transaction(
        &self,
        transaction_identifier: &TransactionIdentifier,
        mut prev_chain_length: BlockHeight,
        deadline: std::time::Instant,
    ) -> Result<Option<BlockHeight>, ApiError> {
        debug!(
            "Waiting for transaction {:?} to appear...",
            transaction_identifier
        );

        loop {
            let cur_chain_length = self
                .ledger
                .read_blocks()
                .await
                .last_verified()?
                .map(|hb| hb.index + 1)
                .unwrap_or(0);

            for idx in prev_chain_length..cur_chain_length {
                debug!("Looking at block {}", idx);
                let blocks = self.ledger.read_blocks().await;
                let hb = get_block(
                    &blocks,
                    Some(PartialBlockIdentifier {
                        index: Some(idx as i64),
                        hash: None,
                    }),
                )?;
                let block = hb.block.decode().map_err(|err| {
                    ApiError::internal_error(format!("Cannot decode block: {}", err))
                })?;
                let hash = block.transaction.hash();
                if TransactionIdentifier::from(&hash) == *transaction_identifier {
                    return Ok(Some(idx));
                }
            }

            prev_chain_length = cur_chain_length;

            if Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        warn!(
            "Transaction {:?} did not appear within the deadline",
            transaction_identifier
        );

        Ok(None)
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
        _metadata_request: models::MetadataRequest,
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
                OperationType::iter().map(|op| op.to_string()).collect(),
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
                        e.details = Default::default();
                    }
                    errs
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
        let first = blocks
            .first_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(true, Default::default()))?;
        let tip = blocks
            .last_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(true, Default::default()))?;
        let tip_id = convert::block_id(&tip)?;
        let tip_timestamp = convert::timestamp(tip.block.decode().unwrap().timestamp.into())?;
        // Block at index 0 has to be there if tip was present
        let genesis_block = blocks.get_verified_at(0)?;
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
            tip_timestamp,
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
            .last_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(true, Default::default()))?
            .index;
        let first_idx = blocks
            .first_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(true, Default::default()))?
            .index;

        let max_block = max_block.unwrap_or(last_idx);
        let end = max_block
            .checked_sub(offset as u64)
            .ok_or_else(|| ApiError::invalid_request("max_block < offset"))?
            .saturating_add(1);
        let start = end.saturating_sub(limit as u64).max(first_idx);

        let block_range = blocks.block_store.get_range(start..end)?;

        let mut txs: Vec<BlockTransaction> = Vec::new();

        for hb in block_range.into_iter().rev() {
            txs.push(BlockTransaction::new(
                convert::block_id(&hb)?,
                convert::transaction(&hb, self.ledger.token_symbol())?,
            ));
        }

        let next_offset = if start == first_idx {
            None
        } else {
            Some((max_block - start + 1) as i64)
        };

        Ok(SearchTransactionsResponse::new(
            txs,
            (end - first_idx) as i64,
            next_offset,
        ))
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

        if msg._type.is_some() {
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
        let limit = std::cmp::min(limit, 10_000);

        if msg.transaction_identifier.is_none() && msg.account_identifier.is_none() {
            return self.get_blocks_range(max_block, offset, limit).await;
        }

        let blocks = self.ledger.read_blocks().await;

        let last_idx = blocks
            .last_verified()?
            .ok_or_else(|| ApiError::BlockchainEmpty(true, Default::default()))?
            .index;

        let mut heights = Vec::new();
        let mut total_count = 0;

        if let Some(tid) = &msg.transaction_identifier {
            if msg.account_identifier.is_some() {
                return Err(ApiError::invalid_request(
                    "Only one of transaction_identitier and account_identifier should be populated",
                ));
            }

            let tid = ledger_canister::HashOf::try_from(tid)
                .map_err(|e| ApiError::InvalidTransactionId(false, e.into()))?;

            if let Some(i) = blocks.tx_hash_location.get(&tid) {
                heights.push(*i);
                total_count += 1;
            }
        }

        let mut next_offset = None;

        if let Some(aid) = &msg.account_identifier {
            let acc = from_model_account_identifier(aid)
                .map_err(|e| ApiError::InvalidAccountId(false, e.into()))?;

            let hist = blocks.balance_book.store.get_history(&acc, max_block);
            heights = hist
                .iter()
                .rev()
                .map(|(h, _)| *h)
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
            let hb = blocks.get_verified_at(i)?;
            txs.push(BlockTransaction::new(
                convert::block_id(&hb)?,
                convert::transaction(&hb, self.ledger.token_symbol())?,
            ));
        }

        Ok(SearchTransactionsResponse::new(
            txs,
            total_count,
            next_offset,
        ))
    }

    pub async fn neuron_info(
        &self,
        neuron_id: NeuronIdOrSubaccount,
        verified: bool,
    ) -> Result<NeuronInfoResponse, ApiError> {
        let res = self.ledger.neuron_info(neuron_id, verified).await?;

        use ic_nns_governance::pb::v1::NeuronState as PbNeuronState;
        let state = match PbNeuronState::from_i32(res.state) {
            Some(PbNeuronState::NotDissolving) => NeuronState::NotDissolving,
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
        })
    }
}

pub fn make_sig_data(message_id: &MessageId) -> Vec<u8> {
    // Lifted from canister_client::agent::sign_message_id
    let mut sig_data = vec![];
    sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
    sig_data.extend_from_slice(message_id.as_bytes());
    sig_data
}

pub enum CyclesResponse {
    CanisterCreated(CanisterId),
    CanisterToppedUp(),
    Refunded(String, Option<BlockHeight>),
}
