use crate::flags::temporarily_enable_chunkifying_large_values;
use crate::invariants::routing_table::check_routing_table_invariants;
use crate::registry::Registry;
use canbench_rs::{BenchResult, bench, bench_fn};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_protobuf::registry::routing_table::v1::RoutingTable;
use ic_protobuf::registry::routing_table::v1::routing_table::Entry;
use ic_registry_keys::make_canister_ranges_key;
use ic_registry_routing_table::CanisterIdRange;
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
    let make_entry = |i: u64| Entry {
        range: Some(
            ic_protobuf::registry::routing_table::v1::CanisterIdRange::from(CanisterIdRange {
                start: CanisterId::from_u64(i),
                end: CanisterId::from_u64(i),
            }),
        ),
        subnet_id: Some(pb_subnet_id(SubnetId::from(
            PrincipalId::new_subnet_test_id(i),
        ))),
    };

    let mutations: Vec<_> = (0..(number_segments * entries_per_segment))
        .map(make_entry)
        .collect::<Vec<_>>()
        .chunks(entries_per_segment.try_into().unwrap())
        .enumerate()
        .map(|(i, entries_chunk)| {
            let entries = entries_chunk.to_vec();
            let segment_start = CanisterId::from_u64(i as u64 * entries_per_segment);
            let rt = RoutingTable { entries };
            upsert(
                make_canister_ranges_key(segment_start).as_bytes(),
                rt.encode_to_vec(),
            )
        })
        .collect::<Vec<_>>();

    let mut registry = Registry::new();

    for mutation in mutations {
        // If we break this into chunks, we have to figure out how many mutations we can apply
        // based on the size of each segment... so we just do one at a time.
        registry.apply_mutations_for_test(vec![mutation]);
    }

    registry
}

fn benchmark_snapshot_creation_with_entries(
    number_segments: u64,
    entries_per_segment: u64,
) -> BenchResult {
    let registry =
        setup_registry_with_rt_segments_with_x_entries_each(number_segments, entries_per_segment);

    bench_fn(|| {
        registry.take_latest_snapshot();
    })
}

#[bench(raw)]
fn measure_snapshot_creation_with_1000_individual_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(1000, 1)
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
fn measure_snapshot_creation_with_100_segments_of_1000_entries() -> BenchResult {
    benchmark_snapshot_creation_with_entries(100, 1000)
}

/// 20k entries costs 250m instructions to validate
#[bench(raw)]
fn measure_routing_table_invariant_checks_shards_and_unsharded() -> BenchResult {
    let _feature = temporarily_enable_chunkifying_large_values();
    let registry = setup_registry_with_rt_segments_with_x_entries_each(1000, 20);

    let snapshot = registry.take_latest_snapshot();

    bench_fn(|| check_routing_table_invariants(&snapshot))
}
