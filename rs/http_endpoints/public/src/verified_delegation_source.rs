//! Source of the NNS delegation to serve, verified against the certified state it is served with.

use crate::{HttpError, common::LOG_EVERY_N_SECONDS, metrics::HttpHandlerMetrics};
use hyper::StatusCode;
use ic_logger::{ReplicaLogger, warn};
use ic_nns_delegation_manager::{
    CanisterRangesCheck, DelegationVerificationError, NNSDelegationReader,
};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CertificateDelegation;

/// Serves an endpoint with the NNS delegation, after verifying it against the certified
/// state which the certificate it is attached to is built from.
#[derive(Clone)]
pub(crate) struct VerifiedDelegationSource {
    nns_delegation_reader: NNSDelegationReader,
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    /// The endpoint served, for logging and metrics.
    endpoint_type: &'static str,
}

impl VerifiedDelegationSource {
    pub(crate) fn new(
        nns_delegation_reader: NNSDelegationReader,
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        endpoint_type: &'static str,
    ) -> Self {
        Self {
            nns_delegation_reader,
            log,
            metrics,
            endpoint_type,
        }
    }

    /// Wrapper around `NNSDelegationReader::get_delegation` to log and record metrics on
    /// verification failures.
    pub(crate) fn get_delegation(
        &self,
        canister_ranges_check: CanisterRangesCheck,
        certified_state: &ReplicatedState,
    ) -> Result<Option<CertificateDelegation>, DelegationVerificationError> {
        self.nns_delegation_reader
            .get_delegation(canister_ranges_check, certified_state)
            .inspect_err(|err| {
                warn!(
                    every_n_seconds => LOG_EVERY_N_SECONDS,
                    self.log,
                    "Failed to verify the NNS delegation (endpoint: {}): {err}",
                    self.endpoint_type
                );
                self.metrics
                    .observe_delegation_verification_failure(self.endpoint_type, err);
            })
    }
}

/// The `503 Service Unavailable` error to reply with when the NNS delegation fails verification,
/// suggesting that the client retry once the replica has fetched a new delegation.
pub(crate) fn delegation_verification_failure_error(
    err: &DelegationVerificationError,
) -> HttpError {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let message = match err {
        DelegationVerificationError::Inconsistent => {
            "This replica's delegation is inconsistent with its state. Please try again."
        }
        DelegationVerificationError::Validation(_) => {
            "This replica has an invalid delegation. Please try again."
        }
    }
    .to_string();

    HttpError { status, message }
}
