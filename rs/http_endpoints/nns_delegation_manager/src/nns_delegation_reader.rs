use ic_types::{messages::CertificateDelegation, CanisterId};
use tokio::sync::watch;

#[derive(Copy, Clone)]
pub enum CanisterRangesFormat {
    Flat,
    // Tree,
}
#[derive(Clone)]
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<CertificateDelegation>>,
    is_nns: bool,
}

impl NNSDelegationReader {
    pub(crate) fn new(
        receiver: watch::Receiver<Option<CertificateDelegation>>,
        is_nns: bool,
    ) -> Self {
        Self { receiver, is_nns }
    }

    pub fn get_delegation(
        &self,
        canister_ranges_format: CanisterRangesFormat,
        _canister_id: CanisterId,
    ) -> Option<CertificateDelegation> {
        if self.is_nns {
            return None;
        }

        let Some(delegation) = self.receiver.borrow().clone() else {
            return None;
        };

        match canister_ranges_format {
            CanisterRangesFormat::Flat => Some(delegation),
        }
    }

    pub fn get_full_delegation(
        &self,
        canister_ranges_format: CanisterRangesFormat,
    ) -> Option<CertificateDelegation> {
        if self.is_nns {
            return None;
        }

        let Some(delegation) = self.receiver.borrow().clone() else {
            return None;
        };

        match canister_ranges_format {
            CanisterRangesFormat::Flat => Some(delegation),
        }
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        if self.is_nns {
            Ok(())
        } else {
            self.receiver.changed().await
        }
    }

    // DO NOT USE IN PRODUCTION CODE
    pub fn new_for_test_only(delegation: Option<CertificateDelegation>) -> Self {
        let (_sender, receiver) = watch::channel(delegation);
        Self {
            receiver,
            is_nns: false,
        }
    }
}
