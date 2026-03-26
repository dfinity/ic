use ic_interfaces::{
    batch_payload::PastPayload,
    chain_key::{ChainKeyPayloadValidationFailure, InvalidChainKeyPayloadReason},
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    validation::ValidationError,
};
use ic_logger::{ReplicaLogger, error};
use ic_protobuf::types::v1 as pb;
use ic_types::crypto::canister_threshold_sig::{ThresholdEcdsaSigShare, ThresholdSchnorrSigShare};
use ic_types::crypto::vetkd::VetKdEncryptedKeyShare;
use ic_types::{NodeId, batch::slice_to_messages, consensus::idkg::SigShare, messages::CallbackId};
use std::collections::{BTreeMap, HashSet};

pub(super) fn validation_failed_err(
    err: ChainKeyPayloadValidationFailure,
) -> Result<(), PayloadValidationError> {
    Err(validation_failed(err))
}

pub(super) fn invalid_artifact_err(
    reason: InvalidChainKeyPayloadReason,
) -> Result<(), PayloadValidationError> {
    Err(invalid_artifact(reason))
}

pub(super) fn validation_failed(err: ChainKeyPayloadValidationFailure) -> PayloadValidationError {
    ValidationError::ValidationFailed(PayloadValidationFailure::ChainKeyPayloadValidationFailed(
        err,
    ))
}

pub(super) fn invalid_artifact(reason: InvalidChainKeyPayloadReason) -> PayloadValidationError {
    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidChainKeyPayload(reason))
}

#[derive(Default)]
pub(super) struct Shares {
    pub(crate) vetkd_shares: BTreeMap<CallbackId, BTreeMap<NodeId, VetKdEncryptedKeyShare>>,
    pub(crate) ecdsa_shares: BTreeMap<CallbackId, BTreeMap<NodeId, ThresholdEcdsaSigShare>>,
    pub(crate) schnorr_shares: BTreeMap<CallbackId, BTreeMap<NodeId, ThresholdSchnorrSigShare>>,
}

pub(super) fn group_shares_by_callback_id<ShareIter: Iterator<Item = SigShare>>(
    shares_iter: ShareIter,
) -> Shares {
    let mut grouped_shares = Shares::default();
    for share in shares_iter {
        match share {
            SigShare::VetKd(share) => {
                grouped_shares
                    .vetkd_shares
                    .entry(share.request_id.callback_id)
                    .or_default()
                    .insert(share.signer_id, share.share);
            }
            SigShare::Ecdsa(share) => {
                grouped_shares
                    .ecdsa_shares
                    .entry(share.request_id.callback_id)
                    .or_default()
                    .insert(share.signer_id, share.share);
            }
            SigShare::Schnorr(share) => {
                grouped_shares
                    .schnorr_shares
                    .entry(share.request_id.callback_id)
                    .or_default()
                    .insert(share.signer_id, share.share);
            }
        }
    }
    grouped_shares
}

pub(super) fn parse_past_payload_ids(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            slice_to_messages::<pb::ChainKeyAgreement>(payload.payload).unwrap_or_else(|err| {
                error!(
                    log,
                    "Failed to parse chain key past payload for height {}. Error: {}",
                    payload.height,
                    err
                );
                vec![]
            })
        })
        .map(|msg| CallbackId::new(msg.callback_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use core::{convert::From, iter::Iterator};
    use ic_logger::no_op_logger;

    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_parse_past_payload_ids() {
        let payloads = [
            as_bytes(make_chain_key_agreements(0, 1, 2)),
            as_bytes(make_chain_key_agreements(2, 3, 4)),
            as_bytes(make_chain_key_agreements(4, 4, 5)),
        ];
        let past_payloads = payloads
            .iter()
            .map(|p| as_past_payload(p))
            .collect::<Vec<_>>();
        let past_payload_ids = parse_past_payload_ids(&past_payloads, &no_op_logger());
        let expected = HashSet::from_iter((0..=5).map(CallbackId::from));
        assert_eq!(past_payload_ids, expected);
    }
}
