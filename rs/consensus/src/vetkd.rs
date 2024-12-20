//! This module provides the component responsible for generating and validating
//! payloads relevant to VetKD.

use crate::idkg::metrics::timed_call;

use ic_interfaces::validation::{ValidationError, ValidationResult};
use ic_types::consensus::vetkd::VetKdPayload;
use ic_types::consensus::BlockPayload;
use prometheus::HistogramVec;

#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
/// Possible failures which could occur while validating an VetKd payload. They don't imply that the
/// payload is invalid.
pub(crate) enum VetKdPayloadValidationFailure {}

#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
/// Reasons for why a VetKD payload might be invalid.
pub(crate) enum InvalidVetKdPayloadReason {
    SummaryPayloadMismatch,
    DataPayloadMismatch,
    VetKdNotSupportedYet,
}

impl From<InvalidVetKdPayloadReason> for VetKdValidationError {
    fn from(err: InvalidVetKdPayloadReason) -> Self {
        ValidationError::InvalidArtifact(err)
    }
}

impl From<VetKdPayloadValidationFailure> for VetKdValidationError {
    fn from(err: VetKdPayloadValidationFailure) -> Self {
        ValidationError::ValidationFailed(err)
    }
}

pub(crate) type VetKdValidationError =
    ValidationError<InvalidVetKdPayloadReason, VetKdPayloadValidationFailure>;

pub(crate) fn validate_payload(
    payload: &BlockPayload,
    metrics: &HistogramVec,
) -> ValidationResult<VetKdValidationError> {
    if payload.is_summary() {
        if payload.as_summary().supports_vetkd_payload {
            return Err(InvalidVetKdPayloadReason::VetKdNotSupportedYet.into());
        }
        timed_call(
            "verify_summary_payload",
            || validate_summary_payload(payload.as_summary().vetkd.as_ref()),
            metrics,
        )
    } else {
        timed_call(
            "verify_data_payload",
            || validate_data_payload(payload.as_data().vetkd.as_ref()),
            metrics,
        )
    }
}

/// Validates a VetKD summary payload.
fn validate_summary_payload(
    summary_payload: Option<&VetKdPayload>,
) -> ValidationResult<VetKdValidationError> {
    if summary_payload.is_none() {
        Ok(())
    } else {
        Err(InvalidVetKdPayloadReason::SummaryPayloadMismatch.into())
    }
}

/// Validates a VetKD data payload.
fn validate_data_payload(
    data_payload: Option<&VetKdPayload>,
) -> ValidationResult<VetKdValidationError> {
    if data_payload.is_none() {
        Ok(())
    } else {
        Err(InvalidVetKdPayloadReason::DataPayloadMismatch.into())
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use ic_types::consensus::{dkg::Summary, SummaryPayload};
    use prometheus::HistogramOpts;

    use super::*;

    #[test]
    fn test_some_data_payload_should_be_invalid() {
        let payload = VetKdPayload {
            vet_key_agreements: BTreeMap::new(),
        };
        assert!(validate_data_payload(Some(&payload)).is_err())
    }

    #[test]
    fn test_some_summary_payload_should_be_invalid() {
        let payload = VetKdPayload {
            vet_key_agreements: BTreeMap::new(),
        };
        assert!(validate_summary_payload(Some(&payload)).is_err())
    }

    #[test]
    fn test_vetkd_payload_not_supported_yet() {
        let payload = BlockPayload::Summary(SummaryPayload {
            dkg: Summary::default(),
            idkg: None,
            vetkd: None,
            supports_vetkd_payload: true,
        });
        let vec = HistogramVec::new(
            HistogramOpts::new("test_histogram_vec", "test histogram vec help"),
            &["l1", "l2"],
        )
        .unwrap();
        assert!(validate_payload(&payload, &vec).is_err())
    }

    #[test]
    fn test_none_data_payload_should_be_valid() {
        assert!(validate_data_payload(None).is_ok())
    }

    #[test]
    fn test_none_summary_payload_should_be_valid() {
        assert!(validate_summary_payload(None).is_ok())
    }
}
