use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_agent::agent::AgentBuilder;
use ic_agent::identity::AnonymousIdentity;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::{
    apply_mutations_for_test, get_changes_since_as_registry_records, get_latest_version, get_value,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_registry_transport::{delete, upsert};
use pocket_ic::PocketIcBuilder;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

use crate::common::test_helpers::upgrade_registry_canister;

mod common;

trait DataMigrationAssert {
    async fn assert_expected_changes(&self, new_mutations: &Vec<RegistryMutation>);
}

struct TestScenario {
    name: String,
    on_hash: String,
    asserts: Vec<Box<dyn DataMigrationAssert>>,
}

struct Setup {
    pocket_ic: PocketIc,
    mainnet_mutation_batches: Vec<Vec<RegistryMutation>>,
    mainnet_module_hash: String,
}

impl Setup {
    async fn new() -> Self {
        Self {
            mainnet_mutation_batches: Self::fetch_all_mainnet_changes().await,
            pocket_ic: PocketIcBuilder::new().with_nns_subnet().build_async().await,
            mainnet_module_hash: Self::fetch_current_module_hash().await,
        }
    }

    async fn fetch_all_mainnet_changes() -> Vec<Vec<RegistryMutation>> {
        let mut mutation_batches = vec![];
        let mainnet_registry = RegistryCanister::new(vec!["https://ic0.app".parse().unwrap()]);

        let latest_version_on_mainnet = mainnet_registry.get_latest_version().await.unwrap();

        let mut local_version = ZERO_REGISTRY_VERSION;

        loop {
            match local_version.get().cmp(&latest_version_on_mainnet) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => break,
                std::cmp::Ordering::Greater => panic!(
                    "Impossible, the local version was in front of the registry on mainnet. Local {local_version}, remote {latest_version_on_mainnet}"
                ),
            }

            // The registry itself maps the limit of deltas to
            // fit into the message, so we just need to send
            // them in the exact same batches, mapped.
            let (records, _) = mainnet_registry
                .get_changes_since_as_registry_records(local_version.get())
                .await
                .unwrap();

            let new_version = records.last().map(|r| r.version);
            mutation_batches.push(
                records
                    .into_iter()
                    .map(|r| match r.value {
                        None => delete(r.key.as_bytes()),
                        Some(val) => upsert(r.key.as_bytes(), val.as_slice()),
                    })
                    .collect(),
            );

            local_version = match new_version {
                Some(v) => v,
                None => break,
            }
        }

        mutation_batches
    }

    async fn fetch_current_module_hash() -> String {
        let agent = AgentBuilder::default()
            .with_url("https://ic0.app")
            .with_identity(AnonymousIdentity {})
            .build()
            .unwrap();

        std::str::from_utf8(
            &agent
                .read_state_canister_module_hash(REGISTRY_CANISTER_ID.get().0)
                .await
                .unwrap(),
        )?
        .trim()
        .to_string()
    }

    async fn upgrade(&self) -> Vec<RegistryMutation> {
        let version_before_upgrade = get_latest_version(&self.pocket_ic).await.unwrap();

        upgrade_registry_canister(&pocket_ic, true).await;

        let version_after_upgrade = get_latest_version(&self.pocket_ic).await.unwrap();

        println!(
            "Version before upgrade {version_before_upgrade} : {version_after_upgrade} Version after upgrade"
        );

        let (records_since_upgrade, _) =
            get_changes_since_as_registry_records(&pocket_ic, version_before_upgrade)
                .await
                .unwrap();

        records_since_upgrade
            .into_iter()
            .map(|r| match &r.value {
                Some(val) => upsert(r.key.as_bytes(), val),
                None => delete(r.key.as_bytes()),
            })
            .collect()
    }
}

#[tokio::test]
async fn test_mainnet_data() {
    let setup = Setup::new().await;

    let new_mutations = setup.upgrade().await;
}
