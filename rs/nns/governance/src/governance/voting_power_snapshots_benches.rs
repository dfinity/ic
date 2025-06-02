use super::*;

use canbench_rs::{bench, bench_fn, BenchResult};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    VectorMemory,
};
use std::collections::HashMap;

#[bench(raw)]
fn voting_power_snapshots_is_latest_snapshot_a_spike() -> BenchResult {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let mut snapshots = VotingPowerSnapshots::new(
        memory_manager.get(MemoryId::new(0)),
        memory_manager.get(MemoryId::new(1)),
    );

    let voting_power_map: HashMap<u64, u64> = (0..100_000).map(|i| (i, 1)).collect();
    for i in 0..MAX_VOTING_POWER_SNAPSHOTS {
        snapshots.record_voting_power_snapshot(
            i,
            VotingPowerSnapshot::new_for_test(voting_power_map.clone(), 100_000),
        );
    }

    bench_fn(|| {
        snapshots.is_latest_snapshot_a_spike(MAX_VOTING_POWER_SNAPSHOTS);
    })
}
