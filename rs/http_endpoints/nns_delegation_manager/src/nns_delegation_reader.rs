use ic_registry_client_helpers::routing_table;
use ic_types::{
    messages::{CertificateDelegation, RoutingTableFormat},
    CanisterId,
};
use tokio::sync::watch;

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
        routing_table_format: RoutingTableFormat,
        _canister_id: CanisterId,
    ) -> Option<CertificateDelegation> {
        if self.is_nns {
            return None;
        }

        let Some(delegation) = self.receiver.borrow().clone() else {
            return None;
        };

        match routing_table_format {
            RoutingTableFormat::Flat => Some(delegation),
        }
    }

    pub fn get_full_delegation(
        &self,
        routing_table_format: RoutingTableFormat,
    ) -> Option<CertificateDelegation> {
        if self.is_nns {
            return None;
        }

        let Some(delegation) = self.receiver.borrow().clone() else {
            return None;
        };

        match routing_table_format {
            RoutingTableFormat::Flat => Some(delegation),
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
