use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationError};
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_interfaces::validation::{ValidationError, ValidationResult};
use ic_types::batch::{UpgradePayload, ValidationContext};
use ic_types::{Height, NumBytes};

pub struct UpgradePayloadBuilderImpl;

impl BatchPayloadBuilder for UpgradePayloadBuilderImpl {
    fn build_payload(
        &self,
        _height: Height,
        _max_size: NumBytes,
        _past_payloads: &[PastPayload],
        _context: &ValidationContext,
    ) -> Vec<u8> {
        // TODO: implement payload building
        vec![]
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> ValidationResult<PayloadValidationError> {
        // TODO: implement proper validation
        UpgradePayload::deserialize(payload)
            .map(|_| ())
            .map_err(|e| {
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidUpgradePayload(
                    InvalidUpgradePayloadReason::DecodeFailed(format!("{e:?}")),
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::RegistryVersion;
    use ic_types::time::UNIX_EPOCH;
    use ic_types_test_utils::ids::node_test_id;

    fn validation_context() -> ValidationContext {
        ValidationContext {
            registry_version: RegistryVersion::from(1),
            certified_height: Height::from(0),
            time: UNIX_EPOCH,
        }
    }

    #[test]
    fn test_build_payload_is_empty() {
        let context = validation_context();
        assert!(
            UpgradePayloadBuilderImpl
                .build_payload(Height::from(1), NumBytes::new(u64::MAX), &[], &context)
                .is_empty()
        );
    }

    #[test]
    fn test_validate_payload_rejects_undecodable_bytes() {
        let context = validation_context();
        let proposal_context = ProposalContext {
            proposer: node_test_id(1),
            validation_context: &context,
        };
        assert!(matches!(
            UpgradePayloadBuilderImpl.validate_payload(
                Height::from(1),
                &proposal_context,
                &[0xFF, 0xFF],
                &[]
            ),
            Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::InvalidUpgradePayload(
                    InvalidUpgradePayloadReason::DecodeFailed(_)
                )
            ))
        ));
    }

    #[test]
    fn test_validate_payload_accepts_empty_payload() {
        let context = validation_context();
        let proposal_context = ProposalContext {
            proposer: node_test_id(1),
            validation_context: &context,
        };
        assert!(
            UpgradePayloadBuilderImpl
                .validate_payload(Height::from(1), &proposal_context, &[], &[])
                .is_ok()
        );
    }
}
