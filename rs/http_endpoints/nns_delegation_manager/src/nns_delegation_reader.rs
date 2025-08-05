use ic_types::messages::CertificateDelegation;
use tokio::sync::watch;

#[derive(Clone)]
pub struct NNSDelegationReader {
    receiver: watch::Receiver<Option<CertificateDelegation>>,
}

impl NNSDelegationReader {
    pub(crate) fn new(receiver: watch::Receiver<Option<CertificateDelegation>>) -> Self {
        Self { receiver }
    }

    pub fn get_delegation(&self) -> Option<CertificateDelegation> {
        self.receiver.borrow().clone()
    }

    pub async fn wait_for_delegation(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}
