//! Finding the operator canister of this node's own engine.
//!
//! The engine management canister knows for each engine the canister ID of
//! the corresponding operator canister.

use super::{
    agent,
    error::{CloudEngineError, CloudEngineResult},
};
use crate::registry_helper::RegistryHelper;
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_logger::{ReplicaLogger, info};
use ic_types::{CanisterId, PrincipalId, RegistryVersion, SubnetId};
use serde::Deserialize;
use std::sync::Arc;

#[derive(CandidType)]
struct GetEngineOperatorBySubnetArgs {
    subnet_id: Option<Principal>,
}

#[derive(CandidType, Deserialize)]
struct GetEngineOperatorBySubnetResult {
    engine_operator_id: Option<Principal>,
}

pub(super) struct Discovery {
    registry: Arc<RegistryHelper>,
    engine_management_canister_id: CanisterId,
    resolved: Option<CanisterId>,
    logger: ReplicaLogger,
}

impl Discovery {
    pub(super) fn new(
        registry: Arc<RegistryHelper>,
        engine_management_canister_id: CanisterId,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            engine_management_canister_id,
            resolved: None,
            logger,
        }
    }

    /// The operator canister of `own_subnet`, from memory or by asking the
    /// engine management canister.
    ///
    /// The engine management canister is only contacted (and the agent to it
    /// only built) if the operator canister id is not in memory.
    pub(super) async fn resolve(
        &mut self,
        own_subnet: SubnetId,
        version: RegistryVersion,
    ) -> CloudEngineResult<CanisterId> {
        if let Some(operator) = self.resolved {
            return Ok(operator);
        }

        let agent = agent::anonymous_via_api_boundary_node(
            self.registry.get_registry_client(),
            version,
            &self.logger,
        )?;
        let operator = self.lookup_operator(&agent, own_subnet).await?;
        info!(self.logger, "Resolved the engine operator: {}", operator);
        self.resolved = Some(operator);

        Ok(operator)
    }

    /// Forgets the resolved id, so the next [`Self::resolve`] asks the engine
    /// management canister again.
    pub(super) fn invalidate(&mut self) {
        self.resolved = None;
    }

    /// The operator canister the engine management canister has on file for
    /// `own_subnet`.
    async fn lookup_operator(
        &self,
        agent: &Agent,
        own_subnet: SubnetId,
    ) -> CloudEngineResult<CanisterId> {
        let arg = Encode!(&GetEngineOperatorBySubnetArgs {
            subnet_id: Some(own_subnet.get().0),
        })
        .map_err(|err| {
            CloudEngineError::failed(format!("could not encode getEngineOperatorBySubnet: {err}"))
        })?;

        let response = agent
            .query(
                &self.engine_management_canister_id.get().0,
                "getEngineOperatorBySubnet",
            )
            .with_arg(arg)
            .call()
            .await
            .map_err(|err| {
                CloudEngineError::failed(format!("getEngineOperatorBySubnet failed: {err}"))
            })?;

        Decode!(&response, GetEngineOperatorBySubnetResult)
            .map_err(|err| {
                CloudEngineError::failed(format!(
                    "could not decode getEngineOperatorBySubnet: {err}"
                ))
            })?
            .engine_operator_id
            .map(PrincipalId::from)
            .ok_or_else(|| {
                CloudEngineError::failed(
                    "the engine management canister does not know an operator for this subnet",
                )
            })
            .and_then(as_canister_id)
    }
}

/// Lets the tests of the parent module observe whether a resolved operator id
/// survives an outcome.
#[cfg(test)]
impl Discovery {
    pub(super) fn remembered(&self) -> Option<CanisterId> {
        self.resolved
    }

    pub(super) fn remember(&mut self, operator: CanisterId) {
        self.resolved = Some(operator);
    }
}

/// The engine management canister answers with a plain principal, which does
/// not have to be a canister id.
fn as_canister_id(candidate: PrincipalId) -> CloudEngineResult<CanisterId> {
    CanisterId::try_from_principal_id(candidate).map_err(|err| {
        CloudEngineError::failed(format!("operator candidate is not a canister id: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_logger::no_op_logger;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::NODE_1;

    fn discovery_for_test() -> Discovery {
        let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(
            ProtoRegistryDataProvider::new(),
        )));
        registry_client.update_to_latest_version();
        let registry = Arc::new(RegistryHelper::new(NODE_1, registry_client, no_op_logger()));

        Discovery::new(registry, CanisterId::from_u64(1000), no_op_logger())
    }

    #[test]
    fn non_canister_principal_is_rejected() {
        let user = PrincipalId::new_self_authenticating(&[1, 2, 3]);

        assert_matches!(
            as_canister_id(user),
            Err(CloudEngineError::Failed(msg)) if msg.contains("not a canister id")
        );
    }

    #[test]
    fn invalidate_forgets_the_resolved_id() {
        let mut discovery = discovery_for_test();
        discovery.remember(CanisterId::from_u64(3));

        discovery.invalidate();

        assert_eq!(discovery.remembered(), None);
    }
}
