use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_agent::agent::AgentBuilder;
use ic_agent::identity::AnonymousIdentity;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::{
    apply_mutations_for_test, get_changes_since_as_registry_records, get_latest_version,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_registry_transport::{delete, upsert};
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::common::test_helpers::upgrade_registry_canister;

mod common;

#[async_trait::async_trait]
trait DataMigrationAssert: Send + Sync {
    async fn assert_expected_changes(&self, new_mutations: &[RegistryMutation]);
}

struct Setup {
    pocket_ic: PocketIc,
    mainnet_module_hash: String,
}

thread_local! {
    /// Registry Data Migration Scenarios
    ///
    /// This map links a **Mainnet Module Hash** (the state of production before upgrade)
    /// to a specific **Migration Assertion** strategy.
    ///
    /// # Purpose
    /// To verify that post-upgrade hooks strictly perform the expected data migrations
    /// (and nothing else) when applied to real-world Mainnet data.
    ///
    /// # Logic
    /// 1. The test fetches the current WASM module hash from Mainnet.
    /// 2. It queries this map using that hash.
    /// 3. **Match Found:** Executes the specific `DataMigrationAssert` logic defined here.
    /// 4. **No Match:** Executes `EmptyDataAssertion`, which asserts that **zero** changes occur.
    ///
    /// # How to Add a Migration Test
    /// If you are introducing a registry migration:
    /// 1. Implement `DataMigrationAssert` for a new struct.
    /// 2. Obtain the current Mainnet WASM hash (via dashboard or `dfx`).
    /// 3. Add an entry below mapping that hash to your new assertion struct.
    ///
    /// # Example
    /// ```rust
    /// // 1. Define expectations
    /// struct VerifyNodeFix;
    /// #[async_trait::async_trait]
    /// impl DataMigrationAssert for VerifyNodeFix {
    ///     async fn assert_expected_changes(&self, changes: &Vec<RegistryMutation>) {
    ///         assert_eq!(changes.len(), 1);
    ///         assert_eq!(changes[0].key, b"node_operator_xyz");
    ///     }
    /// }
    /// ...
    /// thread_local! {
    ///     static MIGRATION_SCENARIOS: RefCell<BTreeMap<String, Arc<dyn DataMigrationAssert>>> =
    ///     RefCell::new({
    ///         let mut map = BTreeMap::new();
    ///
    ///         map.insert("<current-module-hash>", Arc::new(VerifyNodeFix {});
    ///         map.insert("<old-hash-that-wont-run>", Arc::new(OldFix {});
    ///
    ///         map
    ///     }),
    /// }
    static MIGRATION_SCENARIOS: RefCell<BTreeMap<String, Arc<dyn DataMigrationAssert>>> = RefCell::new({
        #[allow(unused_mut)]
        let mut map: BTreeMap<String, Arc<dyn DataMigrationAssert>> = BTreeMap::new();

        // Insert your assertions here like the following example
        //
        // map.insert(
        //     "4842f2cb8fbe9b57d08edf5c66608be7a56eec27bced313c3ed194da263d36c0".to_string(),
        //     Arc::new(EmptyDataAssertion{})
        // );

        map
    });
}

#[tokio::test]
async fn test_mainnet_data() {
    let setup = Setup::new().await;

    let new_mutations = setup.upgrade().await;

    setup.assert(new_mutations).await;
}

impl Setup {
    async fn new() -> Self {
        let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let mainnet_mutations = Self::fetch_all_mainnet_changes().await;

        let builder = RegistryCanisterInitPayloadBuilder::new();

        install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

        for batch in &mainnet_mutations {
            apply_mutations_for_test(&pocket_ic, batch).await.unwrap();
        }

        Self {
            pocket_ic,
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

        let hash = agent
            .read_state_canister_module_hash(REGISTRY_CANISTER_ID.get().0)
            .await
            .unwrap();

        let encoded = hex::encode(hash);
        println!("Mainnet hash {encoded}");
        encoded
    }

    async fn upgrade(&self) -> Vec<RegistryMutation> {
        let version_before_upgrade = get_latest_version(&self.pocket_ic).await.unwrap();

        upgrade_registry_canister(&self.pocket_ic, true).await;

        let version_after_upgrade = get_latest_version(&self.pocket_ic).await.unwrap();

        println!(
            "Version before upgrade {version_before_upgrade} : {version_after_upgrade} Version after upgrade"
        );

        let (records_since_upgrade, _) =
            get_changes_since_as_registry_records(&self.pocket_ic, version_before_upgrade)
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

    async fn assert(&self, new_mutations: Vec<RegistryMutation>) {
        let default_assertion = Arc::new(EmptyDataAssertion {}) as Arc<dyn DataMigrationAssert>;
        let batch_to_run = MIGRATION_SCENARIOS
            .with_borrow(|scenarios| scenarios.get(&self.mainnet_module_hash).cloned());

        let assertion = batch_to_run.unwrap_or(default_assertion);

        assertion.assert_expected_changes(&new_mutations).await;
    }
}

#[derive(Clone)]
struct EmptyDataAssertion {}

#[async_trait::async_trait]
impl DataMigrationAssert for EmptyDataAssertion {
    async fn assert_expected_changes(&self, new_mutations: &[RegistryMutation]) {
        assert!(new_mutations.is_empty())
    }
}
