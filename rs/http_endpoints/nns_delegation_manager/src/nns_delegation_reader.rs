use ic_types::{messages::CertificateDelegation, CanisterId};
use tokio::sync::watch;

#[derive(Copy, Clone)]
/// Enum representing the format of canister ranges in the delegation.
// TODO(CON-1487): Add support for the new canister ranges format.
pub enum CanisterRangesFormat {
    /// Canister ranges are represented as a flat list of canister ranges.
    /// Corresponds to the /subnet/{subnet_id}/canister_ranges path in the state tree.
    Flat,
    //// Canister ranges are represented as a tree of canister ranges.
    //// Corresponds to the /canister_ranges/{subnet_id} path in the state tree.
    // Tree,
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

    /// Returns the most recent NNS delegation with the canister ranges in the specified format.
    /// If canister_id is given, canister ranges subtrees are pruned in such a way that it's
    /// still possible to prove that the specified canister id is assigned to the subnet.
    /// Otherwise, the entire delegation is returned.
    pub fn get_delegation(
        &self,
        canister_ranges_format: CanisterRangesFormat,
        _canister_id: Option<CanisterId>,
    ) -> Option<CertificateDelegation> {
        let delegation = self.receiver.borrow().clone()?;

        match canister_ranges_format {
            CanisterRangesFormat::Flat => Some(delegation),
        }
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
