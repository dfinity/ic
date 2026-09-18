//! Source of the NNS delegation to serve, verified against the certified state it is served with.

use crate::{HttpError, common::LOG_EVERY_N_SECONDS, metrics::HttpHandlerMetrics};
use hyper::StatusCode;
use ic_interfaces_state_manager::CertifiedStateSnapshot;
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

    /// Returns the most recent NNS delegation known to the replica, verified (according to
    /// `canister_ranges_check`) to be consistent with the given certified state, or `None`
    /// if there is no delegation (i.e. on the NNS subnet).
    ///
    /// If the delegation cannot be verified, the failure is logged and recorded in the
    /// metrics, and the HTTP error to reply with is returned.
    pub(crate) fn get_delegation(
        &self,
        certified_state_reader: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
        canister_ranges_check: CanisterRangesCheck,
    ) -> Result<Option<CertificateDelegation>, HttpError> {
        let network_topology = &certified_state_reader.get_state().metadata.network_topology;

        self.nns_delegation_reader
            .get_delegation(
                canister_ranges_check,
                network_topology.routing_table_for_certification(),
                |subnet_id| {
                    network_topology
                        .subnets_for_certification()
                        .get(&subnet_id)
                        .map(|subnet_topology| subnet_topology.public_key.as_slice())
                },
            )
            .map_err(|err| {
                warn!(
                    every_n_seconds => LOG_EVERY_N_SECONDS,
                    self.log,
                    "Failed to verify the NNS delegation (endpoint: {}): {err:?}",
                    self.endpoint_type
                );
                self.metrics
                    .observe_delegation_verification_failure(self.endpoint_type, &err);

                delegation_verification_failure_error(err)
            })
    }
}

fn delegation_verification_failure_error(err: DelegationVerificationError) -> HttpError {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let message = match err {
        DelegationVerificationError::Inconsistent => {
            "This replica has an outdated delegation. Please try again."
        }
        DelegationVerificationError::Validation(_) => {
            "This replica has an invalid delegation. Please try again."
        }
    }
    .to_string();

    HttpError { status, message }
}
