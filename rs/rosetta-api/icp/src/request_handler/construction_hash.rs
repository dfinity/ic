use crate::errors::ApiError;
use crate::models::{ConstructionHashRequest, ConstructionHashResponse, SignedTransaction};
use crate::request_handler::{RosettaRequestHandler, verify_network_id};
use crate::signed_target::verify_signed_envelopes;
use crate::transaction_id::{self, TransactionIdentifier};
use serde_json::map::Map;
use std::str::FromStr;

impl RosettaRequestHandler {
    /// Get the Hash of a Signed Transaction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionhash
    pub fn construction_hash(
        &self,
        msg: ConstructionHashRequest,
    ) -> Result<ConstructionHashResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let signed_transaction = SignedTransaction::from_str(&msg.signed_transaction)
            .map_err(|err| ApiError::invalid_transaction(format!("{err:?}")))?;

        // Which hash is reported is decided by the unsigned wrapper, and which
        // message that hash describes is decided by the envelope picked out of
        // the request. Both have to agree with the signed payload, or the
        // identifier returned here is not the identifier of the transaction
        // the caller is about to submit.
        for (request_type, envelopes) in &signed_transaction.requests {
            verify_signed_envelopes(
                request_type,
                envelopes,
                self.ledger.ledger_canister_id(),
                self.ledger.governance_canister_id(),
            )?;
        }

        let transaction_identifier = if let Some((request_type, envelope_pairs)) =
            signed_transaction
                .requests
                .iter()
                .rev()
                .find(|(rt, _)| rt.is_transfer())
        {
            let envelope = envelope_pairs.first().ok_or_else(|| {
                ApiError::invalid_transaction("A request carries no envelope to hash.")
            })?;
            TransactionIdentifier::try_from_envelope(request_type.clone(), &envelope.update)
        } else if signed_transaction
            .requests
            .iter()
            .all(|(r, _)| r.is_neuron_management())
        {
            Ok(TransactionIdentifier::from(
                transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH.to_owned(),
            ))
        } else {
            Err(ApiError::invalid_request(
                "There is no hash for this transaction",
            ))
        }?;

        Ok(ConstructionHashResponse {
            transaction_identifier: transaction_identifier.into(),
            metadata: Map::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        models::{
            ConstructionHashRequest, ConstructionPayloadsRequest, NetworkIdentifier,
            SignedTransaction,
        },
        request_handler::{
            RosettaRequestHandler,
            tests::construction::{
                setup_handler, setup_transfer_test, sign_and_combine, signed_disburse,
            },
        },
        request_types::RequestType,
        transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH,
    };
    use std::str::FromStr;

    /// Builds and genuinely signs the shared ICP transfer fixture.
    fn signed_transfer() -> (RosettaRequestHandler, NetworkIdentifier, String) {
        let (handler, network_identifier, operations, pub_key, key) = setup_transfer_test();
        let payloads = handler
            .construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations,
                metadata: None,
                public_keys: Some(vec![pub_key.clone()]),
            })
            .unwrap();
        let signed = sign_and_combine(&handler, &network_identifier, &pub_key, &key, payloads);
        (handler, network_identifier, signed)
    }

    /// A genuine transfer still hashes, and to the identifier of the transfer
    /// it actually carries.
    #[test]
    fn a_genuine_transfer_is_hashed() {
        let (handler, network_identifier, signed) = signed_transfer();
        let hash = handler
            .construction_hash(ConstructionHashRequest {
                network_identifier,
                signed_transaction: signed,
            })
            .expect("a genuine transfer must hash");
        assert_ne!(
            hash.transaction_identifier.hash, NEURON_MANAGEMENT_PSEUDO_HASH,
            "a transfer must not be reported with the neuron management hash"
        );
    }

    /// Which hash is reported is decided by the unsigned wrapper alone:
    /// relabelling a transfer as neuron management used to replace the real
    /// transfer hash with the neuron management pseudo hash, leaving the caller
    /// unable to recognise the transaction they were about to broadcast.
    #[test]
    fn a_transfer_relabelled_as_neuron_management_is_rejected() {
        let (handler, network_identifier, signed) = signed_transfer();
        let mut relabelled = SignedTransaction::from_str(&signed).unwrap();
        for (request_type, _) in relabelled.requests.iter_mut() {
            *request_type = RequestType::StartDissolve { neuron_index: 0 };
        }

        handler
            .construction_hash(ConstructionHashRequest {
                network_identifier,
                signed_transaction: relabelled.to_string(),
            })
            .expect_err("a relabelled transfer must not be hashed");
    }

    /// The hash describes the first envelope, but the submit path broadcasts
    /// whichever envelope is currently valid, so envelopes that disagree must
    /// not be hashed either.
    #[test]
    fn divergent_envelopes_are_rejected() {
        let (handler, network_identifier, pub_key, key) = setup_handler();
        let (_, _, displayed) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 0);
        let (_, _, hidden) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 7);

        let displayed = SignedTransaction::from_str(&displayed).unwrap();
        let hidden = SignedTransaction::from_str(&hidden).unwrap();
        let spliced = SignedTransaction {
            requests: vec![(
                RequestType::Disburse { neuron_index: 0 },
                vec![
                    displayed.requests[0].1[0].clone(),
                    hidden.requests[0].1[0].clone(),
                ],
            )],
        };

        handler
            .construction_hash(ConstructionHashRequest {
                network_identifier,
                signed_transaction: spliced.to_string(),
            })
            .expect_err("envelopes that disagree must not be hashed");
    }

    /// A signed transaction is attacker-supplied, and nothing requires a
    /// request in it to carry any envelope at all. Hashing the first one must
    /// therefore not assume there is one.
    #[test]
    fn a_request_without_envelopes_is_rejected() {
        let (handler, network_identifier, _pub_key, _key) = setup_handler();
        let transaction = SignedTransaction {
            requests: vec![(RequestType::Send, vec![])],
        };

        handler
            .construction_hash(ConstructionHashRequest {
                network_identifier,
                signed_transaction: transaction.to_string(),
            })
            .expect_err("a request without envelopes has no hash");
    }
}
