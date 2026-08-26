//! Finding the operator canister of this node's own engine.
//!
//! The engine management canister knows the mapping, but it lives on another
//! subnet and is reached over the network, so its answer is treated as a hint
//! and checked against the local, NNS-verified registry before it is used.

use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registry_helper::RegistryHelper,
};
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{CanisterId, PrincipalId, RegistryVersion, SubnetId};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

/// File under the orchestrator data directory that caches the resolved operator
/// id, so a restart does not have to wait for the engine management canister.
const CACHE_FILE_NAME: &str = "engine-operator-canister-id";

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
    cache_file: PathBuf,
    resolved: Option<CanisterId>,
    logger: ReplicaLogger,
}

impl Discovery {
    pub(super) fn new(
        registry: Arc<RegistryHelper>,
        engine_management_canister_id: CanisterId,
        data_directory: &Path,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            engine_management_canister_id,
            cache_file: data_directory.join(CACHE_FILE_NAME),
            resolved: None,
            logger,
        }
    }

    /// The operator canister of `own_subnet`, from memory, from the on-disk
    /// cache, or by asking the engine management canister.
    ///
    /// `agent` has to point at the subnet hosting the engine management
    /// canister; [`Self::management_subnet`] says which one that is.
    pub(super) async fn resolve(
        &mut self,
        agent: &Agent,
        own_subnet: SubnetId,
        version: RegistryVersion,
    ) -> OrchestratorResult<CanisterId> {
        if let Some(operator) = self.resolved {
            return Ok(operator);
        }

        if let Some(operator) = self.read_cache() {
            // Validate before trusting the cache: the subnet's admins may have
            // changed while this node was down.
            match self.validate(operator.get(), own_subnet, version) {
                Ok(operator) => {
                    self.resolved = Some(operator);
                    return Ok(operator);
                }
                Err(err) => warn!(self.logger, "Discarding the cached operator id: {}", err),
            }
        }

        let candidate = self.ask_management_canister(agent, own_subnet).await?;
        let operator = self.validate(candidate, own_subnet, version)?;
        info!(self.logger, "Resolved the engine operator: {}", operator);
        self.write_cache(operator);
        self.resolved = Some(operator);

        Ok(operator)
    }

    /// Forgets the resolved id, so the next [`Self::resolve`] asks again. Called
    /// when the operator stops answering in a way that suggests we have the
    /// wrong canister rather than a cold cache.
    pub(super) fn invalidate(&mut self) {
        self.resolved = None;
    }

    /// The subnet hosting the engine management canister.
    pub(super) fn management_subnet(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<SubnetId> {
        self.registry
            .get_subnet_of_canister(self.engine_management_canister_id, version)
    }

    async fn ask_management_canister(
        &self,
        agent: &Agent,
        own_subnet: SubnetId,
    ) -> OrchestratorResult<PrincipalId> {
        let arg = Encode!(&GetEngineOperatorBySubnetArgs {
            subnet_id: Some(own_subnet.get().0),
        })
        .map_err(|err| {
            OrchestratorError::cloud_engine_error(format!(
                "could not encode getEngineOperatorBySubnet: {err}"
            ))
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
                OrchestratorError::cloud_engine_error(format!(
                    "getEngineOperatorBySubnet failed: {err}"
                ))
            })?;

        Decode!(&response, GetEngineOperatorBySubnetResult)
            .map_err(|err| {
                OrchestratorError::cloud_engine_error(format!(
                    "could not decode getEngineOperatorBySubnet: {err}"
                ))
            })?
            .engine_operator_id
            .map(PrincipalId::from)
            .ok_or_else(|| {
                OrchestratorError::cloud_engine_error(
                    "the engine management canister does not know an operator for this subnet",
                )
            })
    }

    /// Accepts `candidate` only if the local registry independently confirms it
    /// is a canister on `own_subnet` and an admin of it. This is what keeps a
    /// hostile node of the management subnet from pointing us at an arbitrary
    /// canister.
    fn validate(
        &self,
        candidate: PrincipalId,
        own_subnet: SubnetId,
        version: RegistryVersion,
    ) -> OrchestratorResult<CanisterId> {
        let candidate = CanisterId::try_from_principal_id(candidate).map_err(|err| {
            OrchestratorError::cloud_engine_error(format!(
                "operator candidate is not a canister id: {err}"
            ))
        })?;

        if !self
            .registry
            .get_subnet_canister_ranges(own_subnet, version)?
            .iter()
            .any(|range| range.contains(&candidate))
        {
            return Err(OrchestratorError::cloud_engine_error(format!(
                "operator candidate {candidate} is not hosted by subnet {own_subnet}"
            )));
        }

        if !self
            .registry
            .get_subnet_admins(own_subnet, version)?
            .contains(&candidate.get())
        {
            return Err(OrchestratorError::cloud_engine_error(format!(
                "operator candidate {candidate} is not an admin of subnet {own_subnet}"
            )));
        }

        Ok(candidate)
    }

    fn read_cache(&self) -> Option<CanisterId> {
        let contents = fs::read_to_string(&self.cache_file).ok()?;
        match CanisterId::from_str(contents.trim()) {
            Ok(canister_id) => Some(canister_id),
            Err(err) => {
                warn!(
                    self.logger,
                    "Ignoring the malformed operator id cache at {}: {}",
                    self.cache_file.display(),
                    err
                );
                None
            }
        }
    }

    fn write_cache(&self, operator: CanisterId) {
        if let Err(err) = fs::write(&self.cache_file, operator.to_string()) {
            warn!(
                self.logger,
                "Could not cache the operator id in {}: {}",
                self.cache_file.display(),
                err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_logger::no_op_logger;
    use ic_protobuf::registry::{
        routing_table::v1::RoutingTable as PbRoutingTable, subnet::v1::SubnetRecord,
    };
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{make_canister_ranges_key, make_subnet_record_key};
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2};
    use tempfile::{TempDir, tempdir};

    const VERSION: RegistryVersion = RegistryVersion::new(1);

    /// The operator as a well-behaved engine would have it: a canister in the
    /// subnet's own range that is also one of its admins.
    fn operator() -> CanisterId {
        CanisterId::from_u64(3)
    }

    /// Builds a registry where `SUBNET_1` owns canisters 0..=99 and has
    /// `admins` as its subnet admins, and `SUBNET_2` owns 100..=199.
    ///
    /// The returned `TempDir` backs the id cache and has to stay alive for as
    /// long as the `Discovery`.
    fn discovery_for_test(admins: &[PrincipalId]) -> (Discovery, TempDir) {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        let mut routing_table = RoutingTable::new();
        for (subnet_id, start, end) in [(SUBNET_1, 0, 99), (SUBNET_2, 100, 199)] {
            routing_table
                .insert(
                    CanisterIdRange {
                        start: CanisterId::from_u64(start),
                        end: CanisterId::from_u64(end),
                    },
                    subnet_id,
                )
                .unwrap();
        }
        data_provider
            .add(
                &make_canister_ranges_key(CanisterId::from_u64(0)),
                VERSION,
                Some(PbRoutingTable::from(routing_table)),
            )
            .unwrap();
        data_provider
            .add(
                &make_subnet_record_key(SUBNET_1),
                VERSION,
                Some(SubnetRecord {
                    subnet_admins: admins.iter().copied().map(Into::into).collect(),
                    ..Default::default()
                }),
            )
            .unwrap();

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();
        let registry = Arc::new(RegistryHelper::new(
            ic_test_utilities_types::ids::NODE_1,
            registry_client,
            no_op_logger(),
        ));

        let data_directory = tempdir().unwrap();
        let discovery = Discovery::new(
            registry,
            CanisterId::from_u64(1000),
            data_directory.path(),
            no_op_logger(),
        );

        (discovery, data_directory)
    }

    #[test]
    fn own_subnet_admin_canister_is_accepted() {
        let (discovery, _data_directory) = discovery_for_test(&[operator().get()]);

        assert_matches!(
            discovery.validate(operator().get(), SUBNET_1, VERSION),
            Ok(accepted) if accepted == operator()
        );
    }

    #[test]
    fn canister_of_another_subnet_is_rejected() {
        // In `subnet_admins`, but outside this subnet's canister ranges: the
        // engine management canister itself would look like this.
        let foreign = CanisterId::from_u64(150);
        let (discovery, _data_directory) = discovery_for_test(&[foreign.get()]);

        assert_matches!(
            discovery.validate(foreign.get(), SUBNET_1, VERSION),
            Err(OrchestratorError::CloudEngineError(msg)) if msg.contains("not hosted by")
        );
    }

    #[test]
    fn canister_that_is_not_a_subnet_admin_is_rejected() {
        // On this subnet, but not an admin of it: any canister an engine's users
        // happen to deploy.
        let (discovery, _data_directory) = discovery_for_test(&[operator().get()]);
        let bystander = CanisterId::from_u64(7);

        assert_matches!(
            discovery.validate(bystander.get(), SUBNET_1, VERSION),
            Err(OrchestratorError::CloudEngineError(msg)) if msg.contains("not an admin")
        );
    }

    #[test]
    fn non_canister_principal_is_rejected() {
        let user = PrincipalId::new_self_authenticating(&[1, 2, 3]);
        let (discovery, _data_directory) = discovery_for_test(&[user]);

        assert_matches!(
            discovery.validate(user, SUBNET_1, VERSION),
            Err(OrchestratorError::CloudEngineError(msg)) if msg.contains("not a canister id")
        );
    }

    #[test]
    fn cached_id_round_trips() {
        let (discovery, _data_directory) = discovery_for_test(&[operator().get()]);
        assert_eq!(discovery.read_cache(), None);

        discovery.write_cache(operator());

        assert_eq!(discovery.read_cache(), Some(operator()));
    }

    #[test]
    fn malformed_cached_id_is_ignored() {
        let (discovery, _data_directory) = discovery_for_test(&[operator().get()]);
        fs::write(&discovery.cache_file, "not-a-canister-id").unwrap();

        assert_eq!(discovery.read_cache(), None);
    }
}
