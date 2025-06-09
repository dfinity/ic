use crate::registry::Registry;
use canbench_rs::{bench, bench_fn, BenchResult};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_protobuf::registry::routing_table::v1::routing_table::Entry;
use ic_protobuf::registry::routing_table::v1::RoutingTable;
use ic_registry_keys::make_canister_ranges_key;
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

fn setup_registry_with_rt_segments_with_x_entries_each(
    number_segments: u64,
    entries_per_segment: u64,
) -> Registry {
    let mut registry = Registry::new();

    let mut mutations = vec![];

    let mut segment = RoutingTable { entries: vec![] };

    for i in 0..(number_segments * entries_per_segment) {
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(i));
        segment.entries.push(Entry {
            range: Some(
                ic_protobuf::registry::routing_table::v1::CanisterIdRange::from(CanisterIdRange {
                    start: CanisterId::from_u64(i),
                    end: CanisterId::from_u64(i),
                }),
            ),
            subnet_id: Some(pb_subnet_id(subnet_id)),
        });

        if i % entries_per_segment == 0 && i > 0 {
            mutations.push(upsert(
                make_canister_ranges_key(CanisterId::from(i))
                    .as_bytes()
                    .to_vec(),
                segment.encode_to_vec(),
            ));
            // every segment has a new routing table
            segment = RoutingTable { entries: vec![] };
        }

        // every 10_000 mutations, apply and clear the mutation vec
        if i % 10_000 == 0 {
            registry.apply_mutations_for_test(mutations.clone());
            mutations.clear();
        }
    }

    if !segment.entries.is_empty() {
        mutations.push(upsert(
            make_canister_ranges_key(CanisterId::from(number_segments * entries_per_segment))
                .as_bytes()
                .to_vec(),
            segment.encode_to_vec(),
        ));
    }

    registry.apply_mutations_for_test(mutations);

    registry
}

fn benchmark_snapshot_creation_with_entries(
    number_segments: u64,
    entries_per_segment: u64,
) -> BenchResult {
    let registry =
        setup_registry_with_rt_segments_with_x_entries_each(number_segments, entries_per_segment);

    // TODO DO NOT MERGE - benchmark for different shard sizes for snapshot creation
    bench_fn(|| {
        registry.take_latest_snapshot();
    })
}

// TODO DO NOT MERGE - what's the cost to build a routing table from 100 versus 1000 shards?

// TODO DO NOT MERGE- what's the invariant check cost for RoutingTable with 100 versus 1000 shards?

#[bench(raw)]
fn measure_snapshot_creation_with_1000_individual_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(1000, 1)
}

#[bench(raw)]
fn measure_snapshot_creation_with_10_000_individual_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(10_000, 1)
}

#[bench(raw)]
fn measure_snapshot_creation_with_100_000_individual_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(100_000, 1)
}

#[bench(raw)]
fn measure_snapshot_creation_with_1_segment_of_1000_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(1, 1000)
}

#[bench(raw)]
fn measure_snapshot_creation_with_10_segments_of_1000_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(10, 1000)
}

#[bench(raw)]
fn measure_snapshot_creation_with_100_segments_of_1000_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(100, 1000)
}

#[bench(raw)]
fn measure_snapshot_creation_with_1000_segments_of_1000_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(1000, 1000)
}
