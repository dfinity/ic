use crate::convert::{from_hex, make_read_state_from_update};
use crate::errors::ApiError;
use crate::models::{ConstructionCombineResponse, EnvelopePair, SignatureType, SignedTransaction};
use crate::request_handler::{make_sig_data, verify_network_id, RosettaRequestHandler};
use crate::{convert, models};
use ic_types::messages::{
    Blob, HttpCallContent, HttpReadStateContent, HttpRequestEnvelope, MessageId,
};
use std::collections::HashMap;

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
            let sig_data = convert::from_hex(&sig.signing_payload.hex_bytes)?;
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
                        convert::from_public_key(&transaction_signature.public_key)?,
                    ))),
                    sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes)?)),
                    sender_delegation: None,
                };

                let read_state_envelope = HttpRequestEnvelope::<HttpReadStateContent> {
                    content: HttpReadStateContent::ReadState { read_state },
                    sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
                        convert::from_public_key(&read_state_signature.public_key)?,
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
}
