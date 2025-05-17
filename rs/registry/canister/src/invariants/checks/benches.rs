use crate::registry::Registry;
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_protobuf::registry::routing_table::v1::routing_table::Entry;
use ic_registry_keys::make_canister_range_key;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_transport::pb::v1::RegistryValue;
use ic_registry_transport::upsert;
use prost::Message;

fn pb_subnet_id(subnet_id: SubnetId) -> ic_protobuf::types::v1::SubnetId {
    ic_protobuf::types::v1::SubnetId {
        principal_id: Some(ic_protobuf::types::v1::PrincipalId {
            raw: subnet_id.get().as_slice().to_vec(),
        }),
    }
}

fn setup_registry_with_entries(number_entries: u64) -> Registry {
    let mut registry = Registry::new();

    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(0));

    let mut mutations = vec![];

    for i in 0..number_entries {
        let entry = Entry {
            range: Some(
                ic_protobuf::registry::routing_table::v1::CanisterIdRange::from(CanisterIdRange {
                    start: CanisterId::from_u64(i),
                    end: CanisterId::from_u64(i),
                }),
            ),
            subnet_id: Some(pb_subnet_id(subnet_id)),
        };
        mutations.push(upsert(
            make_canister_range_key(CanisterId::from(i), subnet_id)
                .as_bytes()
                .to_vec(),
            entry.encode_to_vec(),
        ));

        // every 10_000 mutations, apply and clear the mutation vec
        if i % 10_000 == 0 {
            registry.apply_mutations_for_test(mutations.clone());
            mutations.clear();
        }
    }

    registry.apply_mutations_for_test(mutations);

    registry
}

fn benchmark_snapshot_creation_with_entries(number_entries: u64) -> BenchResult {
    let registry = setup_registry_with_entries(number_entries);

    bench_fn(|| {
        registry.take_latest_snapshot();
    })
}

#[bench(raw)]
fn measure_snapshot_creation_with_1000() -> BenchResult {
    benchmark_snapshot_creation_with_entries(1000)
}

#[bench(raw)]
fn measure_snapshot_creation_with_10_000() -> BenchResult {
    benchmark_snapshot_creation_with_entries(10_000)
}

#[bench(raw)]
fn measure_snapshot_creation_with_100_000() -> BenchResult {
    benchmark_snapshot_creation_with_entries(100_000)
}
