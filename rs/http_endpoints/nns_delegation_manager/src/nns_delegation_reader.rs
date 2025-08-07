use ic_types::messages::CertificateDelegation;
use tokio::sync::watch;

#[derive(Copy, Clone)]
/// Enum representing the format of canister ranges in the delegation.
// TODO(CON-1487): Add support for the new canister ranges format.
pub enum CanisterRangesFormat {
    /// Canister ranges are represented as a flat list of canister ranges.
    /// Corresponds to the /subnet/{subnet_id}/canister_ranges path in the state tree.
    Flat,
    //// Canister ranges are represented as a tree of canister ranges.
    //// Corresponds to the /canister_ranges/{subnet_id} subtree in the state tree.
    // Tree(CanisterId),
    //// Both canister ranges subtrees are going to be pruned out.
    // Pruned
}

#[derive(Clone)]
// TODO(CON-1487): Consider caching the delegations.
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<CertificateDelegation>>,
}

impl NNSDelegationReader {
    pub fn new(receiver: watch::Receiver<Option<CertificateDelegation>>) -> Self {
        Self { receiver }
    }

    /// Returns the most recent NNS delegation.
    /// Depending on the specified canister ranges format, either /subnet/{subnet_id}/canister_ranges,
    /// or /canister_ranges/{subnet_id}, or both will be pruned from the state tree.
    pub fn get_delegation(
        &self,
        canister_ranges_format: CanisterRangesFormat,
    ) -> Option<CertificateDelegation> {
        let delegation = self.receiver.borrow().clone()?;

        match canister_ranges_format {
            // At the moment, we only request /subnet/{subnet_id}/canister_ranges from the NNS,
            // so there is nothing to prune.
            CanisterRangesFormat::Flat => Some(delegation),
        }
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
