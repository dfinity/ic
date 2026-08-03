use std::sync::Arc;
use tokio::sync::watch;

use crate::builder::NNSDelegationBuilder;

#[derive(Clone)]
/// Wrapper around [`tokio::sync::watch::Receiver`].
// TODO(CON-1487): Consider caching the delegations per canister range.
pub struct NNSDelegationReader {
    receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>,
}

impl NNSDelegationReader {
    pub fn new(receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>) -> Self {
        Self { receiver }
    }

    /// Returns a snapshot of the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    ///
    /// The snapshot is immutable, so it can be used to verify the delegation against a
    /// certified state and to build exactly the verified delegation (see
    /// [`NNSDelegationBuilder::build_verified`]), without having to worry about the
    /// delegation being concurrently replaced.
    pub fn builder(&self) -> Option<Arc<NNSDelegationBuilder>> {
        self.receiver.borrow().clone()
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
