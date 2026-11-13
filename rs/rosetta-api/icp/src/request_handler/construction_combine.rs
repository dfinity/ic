use crate::convert::{from_hex, make_read_state_from_update};
use crate::errors::{ApiError, Details};
use crate::models::{
    ConstructionCombineResponse, EnvelopePair, SignatureType, SignedTransaction,
    UnsignedTransaction,
};
use crate::request_handler::construction_payloads::{
    validate_request_ingress_expiry_pairs, validate_update_size,
};
use crate::request_handler::{RosettaRequestHandler, make_sig_data, verify_network_id};
use crate::{convert, models};
use ic_types::messages::{
    Blob, HttpCallContent, HttpReadStateContent, HttpRequestEnvelope, MessageId,
};
use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair, Secp256k1KeyPair};
use std::collections::HashMap;
use std::str::FromStr;

/// Maximum permitted size of a signature: Ed25519 and secp256k1 signatures
/// are both 64 bytes.
const MAX_SIGNATURE_BYTES: usize = 64;

/// Maximum permitted size of a public key: Ed25519 public keys are 32 bytes,
/// secp256k1 public keys 33 (compressed) or 65 (uncompressed) bytes.
const MAX_PUBLIC_KEY_BYTES: usize = 65;

/// Validate the size of a signature and its public key before they are decoded
/// for every envelope they are used in.
fn validate_signature_size(signature: &models::Signature) -> Result<(), ApiError> {
    if signature.hex_bytes.len() > 2 * MAX_SIGNATURE_BYTES {
        return Err(ApiError::invalid_request(format!(
            "A signature must not be larger than {MAX_SIGNATURE_BYTES} bytes."
        )));
    }
    if signature.public_key.hex_bytes.len() > 2 * MAX_PUBLIC_KEY_BYTES {
        return Err(ApiError::invalid_request(format!(
            "A public key must not be larger than {MAX_PUBLIC_KEY_BYTES} bytes."
        )));
    }
    Ok(())
}

impl RosettaRequestHandler {
    /// Create Network Transaction from Signatures.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructioncombine
    // This returns Envelopes encoded in a CBOR string
    pub fn construction_combine(
        &self,
        msg: models::ConstructionCombineRequest,
    ) -> Result<ConstructionCombineResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let mut signatures_by_sig_data: HashMap<Vec<u8>, _> = HashMap::new();

        for sig in &msg.signatures {
            validate_signature_size(sig)?;
            let sig_data = convert::from_hex(&sig.signing_payload.hex_bytes)?;
            signatures_by_sig_data.insert(sig_data, sig);
        }

        let unsigned_transaction = UnsignedTransaction::from_str(&msg.unsigned_transaction)
            .map_err(|e| {
                ApiError::invalid_request(format!(
                    "Cannot deserialize signed transaction in /construction/combine response: {e}"
                ))
            })?;
        validate_request_ingress_expiry_pairs(
            unsigned_transaction.updates.len(),
            unsigned_transaction.ingress_expiries.len(),
        )?;
        for (_, update) in &unsigned_transaction.updates {
            validate_update_size(update)?;
        }
        // `/construction/payloads` builds strictly increasing ingress expiries.
        // Repeated expiries would let a single signature be reused for many
        // envelopes.
        if !unsigned_transaction
            .ingress_expiries
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ApiError::invalid_request(
                "The ingress expiries must be strictly increasing.".to_string(),
            ));
        }

        let mut requests = vec![];

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
                let envelope = match transaction_signature.signature_type {
                    SignatureType::Ed25519 => Ok(HttpRequestEnvelope::<HttpCallContent> {
                        content: HttpCallContent::Call { update },
                        sender_pubkey: Some(Blob(
                            Ed25519KeyPair::der_encode_pk(
                                Ed25519KeyPair::hex_decode_pk(
                                    &transaction_signature.public_key.hex_bytes,
                                )
                                .map_err(|err| {
                                    ApiError::InvalidPublicKey(
                                        false,
                                        Details::from(format!("{err:?}")),
                                    )
                                })?,
                            )
                            .map_err(|err| {
                                ApiError::InvalidPublicKey(false, Details::from(format!("{err:?}")))
                            })?,
                        )),
                        sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes)?)),
                        sender_delegation: None,
                    }),
                    SignatureType::Ecdsa => Ok(HttpRequestEnvelope::<HttpCallContent> {
                        content: HttpCallContent::Call { update },
                        sender_pubkey: Some(Blob(
                            Secp256k1KeyPair::der_encode_pk(
                                Secp256k1KeyPair::hex_decode_pk(
                                    &transaction_signature.public_key.hex_bytes,
                                )
                                .map_err(|err| {
                                    ApiError::InvalidPublicKey(
                                        false,
                                        Details::from(format!("{err:?}")),
                                    )
                                })?,
                            )
                            .map_err(|err| {
                                ApiError::InvalidPublicKey(false, Details::from(format!("{err:?}")))
                            })?,
                        )),
                        sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes)?)),
                        sender_delegation: None,
                    }),
                    sig_type => Err(ApiError::InvalidRequest(
                        false,
                        format!("Sginature Type {sig_type} not supported byt rosetta").into(),
                    )),
                }?;

                let read_state_envelope = match read_state_signature.signature_type {
                    SignatureType::Ed25519 => Ok(HttpRequestEnvelope::<HttpReadStateContent> {
                        content: HttpReadStateContent::ReadState { read_state },
                        sender_pubkey: Some(Blob(
                            Ed25519KeyPair::der_encode_pk(
                                Ed25519KeyPair::hex_decode_pk(
                                    &read_state_signature.public_key.hex_bytes,
                                )
                                .map_err(|err| {
                                    ApiError::InvalidPublicKey(
                                        false,
                                        Details::from(format!("{err:?}")),
                                    )
                                })?,
                            )
                            .map_err(|err| {
                                ApiError::InvalidPublicKey(false, Details::from(format!("{err:?}")))
                            })?,
                        )),
                        sender_sig: Some(Blob(from_hex(&read_state_signature.hex_bytes)?)),
                        sender_delegation: None,
                    }),
                    SignatureType::Ecdsa => Ok(HttpRequestEnvelope::<HttpReadStateContent> {
                        content: HttpReadStateContent::ReadState { read_state },
                        sender_pubkey: Some(Blob(
                            Secp256k1KeyPair::der_encode_pk(
                                Secp256k1KeyPair::hex_decode_pk(
                                    &transaction_signature.public_key.hex_bytes,
                                )
                                .map_err(|err| {
                                    ApiError::InvalidPublicKey(
                                        false,
                                        Details::from(format!("{err:?}")),
                                    )
                                })?,
                            )
                            .map_err(|err| {
                                ApiError::InvalidPublicKey(false, Details::from(format!("{err:?}")))
                            })?,
                        )),

                        sender_sig: Some(Blob(from_hex(&read_state_signature.hex_bytes)?)),
                        sender_delegation: None,
                    }),
                    sig_type => Err(ApiError::InvalidRequest(
                        false,
                        format!("Sginature Type {sig_type} not supported byt rosetta").into(),
                    )),
                }?;
                request_envelopes.push(EnvelopePair {
                    update: envelope,
                    read_state: read_state_envelope,
                });
            }

            requests.push((request_type, request_envelopes));
        }
        let signed_transaction = SignedTransaction { requests };

        Ok(ConstructionCombineResponse {
            signed_transaction: hex::encode(serde_cbor::to_vec(&signed_transaction).map_err(
                |err| {
                    ApiError::InternalError(
                        false,
                        format!(
                            "Serialization of signed transaction {signed_transaction:?} failed: {err:?}"
                        )
                        .into(),
                    )
                },
            )?),
        })
    }
}
