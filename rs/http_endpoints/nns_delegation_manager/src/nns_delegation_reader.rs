use ic_types::messages::CertificateDelegation;
use tokio::sync::watch;

#[derive(Clone)]
// TODO(CON-1487): Consider caching the delegations.
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<CertificateDelegation>>,
}

// TODO(CON-1487): allow getting the delegation with both canister ranges pruned
// TODO(CON-1487): allow getting the delegation with only the /canister_ranges/{subnet_id} subtree in it.
impl NNSDelegationReader {
    pub fn new(receiver: watch::Receiver<Option<CertificateDelegation>>) -> Self {
        Self { receiver }
    }

    /// Returns the most recent NNS delegation with the canister id ranges in the flat format,
    /// i.e. the state tree in the delegation will have the /subnet/{subnet_id}/canister_ranges path
    /// and the /canister_ranges/{subnet_id} subtree will be pruned out.
    pub fn get_delegation_with_flat_canister_ranges(&self) -> Option<CertificateDelegation> {
        // At the moment the delegation we get from the nns doesn't have the
        // /canister_ranges/{subnet_id} subtree yet, so we don't have to do anything.
        self.receiver.borrow().clone()
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
