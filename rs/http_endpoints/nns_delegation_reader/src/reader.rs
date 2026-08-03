use ic_types::messages::{
    CertificateDelegation, CertificateDelegationFormat, CertificateDelegationMetadata,
};
use tokio::sync::watch;

use crate::{CanisterRangesFilter, builder::NNSDelegationBuilder};

#[derive(Clone)]
/// Wrapper around [`tokio::sync::watch::Receiver`] with some utility methods.
// TODO(CON-1487): Consider caching the delegations per canister range.
pub struct NNSDelegationReader {
    receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
}

impl NNSDelegationReader {
    pub fn new(receiver: watch::Receiver<Option<NNSDelegationBuilder>>) -> Self {
        Self { receiver }
    }

    /// Returns the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.build_unverified(canister_ranges_filter))
    }

    /// Returns the most recent NNS delegation known to the replica together with some metadata.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation_with_metadata(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<(CertificateDelegation, CertificateDelegationMetadata)> {
        let metadata = CertificateDelegationMetadata {
            format: match canister_ranges_filter {
                CanisterRangesFilter::Flat => CertificateDelegationFormat::Flat,
                CanisterRangesFilter::Tree(_canister_id) => CertificateDelegationFormat::Tree,
                CanisterRangesFilter::None => CertificateDelegationFormat::Pruned,
            },
        };

        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| (builder.build_unverified(canister_ranges_filter), metadata))
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
