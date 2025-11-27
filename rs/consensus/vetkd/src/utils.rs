use ic_interfaces::{
    batch_payload::PastPayload,
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    validation::ValidationError,
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_logger::{ReplicaLogger, error};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    NodeId, batch::slice_to_messages, consensus::idkg::VetKdKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShare, messages::CallbackId,
};
use std::collections::{BTreeMap, HashSet};

pub(super) fn validation_failed_err(
    err: VetKdPayloadValidationFailure,
) -> Result<(), PayloadValidationError> {
    Err(validation_failed(err))
}

pub(super) fn invalid_artifact_err(
    reason: InvalidVetKdPayloadReason,
) -> Result<(), PayloadValidationError> {
    Err(invalid_artifact(reason))
}

pub(super) fn validation_failed(err: VetKdPayloadValidationFailure) -> PayloadValidationError {
    ValidationError::ValidationFailed(PayloadValidationFailure::VetKdPayloadValidationFailed(err))
}

pub(super) fn invalid_artifact(reason: InvalidVetKdPayloadReason) -> PayloadValidationError {
    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(reason))
}

pub(super) fn group_shares_by_callback_id<Shares: Iterator<Item = VetKdKeyShare>>(
    shares: Shares,
) -> BTreeMap<CallbackId, BTreeMap<NodeId, VetKdEncryptedKeyShare>> {
    let mut map: BTreeMap<CallbackId, BTreeMap<NodeId, VetKdEncryptedKeyShare>> = BTreeMap::new();
    for share in shares {
        map.entry(share.request_id.callback_id)
            .or_default()
            .insert(share.signer_id, share.share);
    }
    map
}

pub(super) fn parse_past_payload_ids(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            slice_to_messages::<pb::VetKdAgreement>(payload.payload).unwrap_or_else(|err| {
                error!(
                    log,
                    "Failed to parse VetKD past payload for height {}. Error: {}",
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
            as_bytes(make_vetkd_agreements(0, 1, 2)),
            as_bytes(make_vetkd_agreements(2, 3, 4)),
            as_bytes(make_vetkd_agreements(4, 4, 5)),
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
