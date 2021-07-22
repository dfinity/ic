//! This module implements the `IngressMessageFilter` trait.
use std::sync::Arc;

use crate::ExecutionEnvironmentImpl;
use ic_interfaces::execution_environment::{IngressMessageFilter, MessageAcceptanceError};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::SignedIngressContent;

pub(crate) struct IngressMessageFilterImpl {
    exec_env: Arc<ExecutionEnvironmentImpl>,
}

impl IngressMessageFilter for IngressMessageFilterImpl {
    type State = ReplicatedState;

    fn should_accept_ingress_message(
        &self,
        state: Arc<ReplicatedState>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngressContent,
    ) -> Result<(), MessageAcceptanceError> {
        self.exec_env
            .should_accept_ingress_message(state, provisional_whitelist, ingress)
    }
}

impl IngressMessageFilterImpl {
    pub(crate) fn new(exec_env: Arc<ExecutionEnvironmentImpl>) -> Self {
        Self { exec_env }
    }
}
