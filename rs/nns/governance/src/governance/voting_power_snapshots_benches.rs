use super::*;

use canbench_rs::{BenchResult, bench, bench_fn};
use ic_stable_structures::{
    VectorMemory,
    memory_manager::{MemoryId, MemoryManager},
};
use std::collections::HashMap;

fn set_up_snapshots() -> VotingPowerSnapshots {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    VotingPowerSnapshots::new(
        memory_manager.get(MemoryId::new(0)),
        memory_manager.get(MemoryId::new(1)),
    )
}

fn populate_snapshots(snapshots: &mut VotingPowerSnapshots, num_neurons: u64) {
    let voting_power_map: HashMap<u64, u64> = (0..num_neurons).map(|i| (i, 1)).collect();
    for i in 0..MAX_VOTING_POWER_SNAPSHOTS {
        snapshots.record_voting_power_snapshot(
            i,
            VotingPowerSnapshot::new_for_test(voting_power_map.clone(), num_neurons),
        );
    }
}

// The following benchmarks make sure that more neurons does not cause the tested functionality
// (based on voting power snapshots) to cost more.

#[bench(raw)]
fn voting_power_snapshots_is_latest_snapshot_a_spike_false() -> BenchResult {
    let mut snapshots = set_up_snapshots();
    populate_snapshots(&mut snapshots, 100_000);

    bench_fn(|| {
        snapshots.is_latest_snapshot_a_spike(MAX_VOTING_POWER_SNAPSHOTS);
    })
}

#[bench(raw)]
fn voting_power_snapshots_is_latest_snapshot_a_spike_true() -> BenchResult {
    let mut snapshots = set_up_snapshots();
    populate_snapshots(&mut snapshots, 100_000);

    let voting_power_map_spike = (0..200_000).map(|i| (i, 1)).collect();
    snapshots.record_voting_power_snapshot(
        MAX_VOTING_POWER_SNAPSHOTS - 1,
        VotingPowerSnapshot::new_for_test(voting_power_map_spike, 200_000),
    );

    bench_fn(|| {
        snapshots.is_latest_snapshot_a_spike(MAX_VOTING_POWER_SNAPSHOTS);
    })
}

#[bench(raw)]
fn voting_power_snapshots_latest_snapshot_timestamp_seconds() -> BenchResult {
    let mut snapshots = set_up_snapshots();
    populate_snapshots(&mut snapshots, 100_000);

    bench_fn(|| {
        snapshots.latest_snapshot_timestamp_seconds();
    })
}
