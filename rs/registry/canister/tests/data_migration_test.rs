use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::apply_mutations_for_test;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_registry_transport::{delete, upsert};
use pocket_ic::PocketIcBuilder;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

mod common;

#[tokio::test]
async fn test_mainnet_data() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
    let builder = RegistryCanisterInitPayloadBuilder::new();

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let mutations = fetch_all_mainnet_changes().await;
    println!("Fetched {} mutations", mutations.len());

    for batch in &mutations {
        apply_mutations_for_test(&pocket_ic, batch).await.unwrap();
    }
}

async fn fetch_all_mainnet_changes() -> Vec<Vec<RegistryMutation>> {
    let registry_canister = ic_registry_nns_data_provider::registry::RegistryCanister::new(vec![
        "https://ic0.app".parse().unwrap(),
    ]);

    let mut mutations = vec![];

    let latest_version_on_mainnet = registry_canister.get_latest_version().await.unwrap();

    let mut local_version = ZERO_REGISTRY_VERSION;

    loop {
        match local_version.get().cmp(&latest_version_on_mainnet) {
            // Still need to sync
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => break,
        }

        // The registry itself maps the limit of deltas to
        // fit into the message, so we just need to send
        // them in the exact same batches, mapped.
        let (records, _) = registry_canister
            .get_changes_since_as_registry_records(local_version.get())
            .await
            .unwrap();

        let new_version = records.last().map(|r| r.version.increment());
        mutations.push(
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

    mutations
}
