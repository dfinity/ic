use super::*;
use ic_base_types::CanisterId;
use ic_config::state_manager::lsmt_config_default;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    PageMap,
    page_map::{
        MergeCandidate, PAGE_SIZE, PageIndex, StorageMetrics, TestPageAllocatorFileDescriptorImpl,
    },
};
use ic_state_layout::{CheckpointLayout, ReadOnly, WriteOnly};
use std::sync::Arc;

/// Imported overlays must never shadow writes made after recovery, regardless
/// of which subnet halted at the greater height.
#[test]
fn writes_after_merge_survive_reload_with_different_halting_heights() {
    for (source_height, destination_height) in
        [(20_000, 10_000), (10_000, 20_000), (20_000, 20_000)]
    {
        let source_height = Height::new(source_height);
        let destination_height = Height::new(destination_height);
        let merged_height = merged_recovery_height(source_height, destination_height);
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let destination = tmp.path().join("destination");
        let merged = tmp.path().join(StateLayout::checkpoint_name(merged_height));
        let config = lsmt_config_default();
        let metrics = StorageMetrics::new(&MetricsRegistry::new());
        let original = [1; PAGE_SIZE];
        let updated = [2; PAGE_SIZE];
        let canisters = [CanisterId::from_u64(1), CanisterId::from_u64(2)];

        // One canister from each subnet, each with an overlay at its halting
        // height. The merge preserves these filenames.
        for (path, height, canister_id) in [
            (&source, source_height, canisters[0]),
            (&destination, destination_height, canisters[1]),
        ] {
            let checkpoint =
                CheckpointLayout::<WriteOnly>::new_untracked(path.clone(), height).unwrap();
            let memory = checkpoint.canister(&canister_id).unwrap().vmemory_0();
            let mut page_map = PageMap::new_for_testing();
            page_map.update(&[(PageIndex::new(0), &original)]);
            page_map
                .persist_unflushed_delta(&memory, height, &config, &metrics)
                .unwrap();
        }

        state_tool_helper::merge_checkpoints(&destination, &source, &merged).unwrap();
        let checkpoint =
            CheckpointLayout::<ReadOnly>::new_untracked(merged, merged_height).unwrap();
        let tip =
            CheckpointLayout::<WriteOnly>::new_untracked(tmp.path().join("tip"), merged_height)
                .unwrap();
        let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());

        for canister_id in canisters {
            let memory = checkpoint.canister(&canister_id).unwrap().vmemory_0();
            let tip_canister = tip.canister(&canister_id).unwrap();
            let tip_memory = tip_canister.vmemory_0();
            for overlay in memory.existing_overlays().unwrap() {
                std::fs::hard_link(
                    &overlay,
                    tip_canister.raw_path().join(overlay.file_name().unwrap()),
                )
                .unwrap();
            }

            // Startup compaction leaves a single overlay untouched.
            assert!(
                MergeCandidate::new(&tip_memory, merged_height, 1, &config, &metrics)
                    .unwrap()
                    .is_empty()
            );
            let mut page_map = PageMap::open(Box::new(memory), fd_factory.clone()).unwrap();
            assert_eq!(page_map.get_page(PageIndex::new(0)), &original);
            page_map.update(&[(PageIndex::new(0), &updated)]);
            page_map
                .persist_unflushed_delta(&tip_memory, merged_height.increment(), &config, &metrics)
                .unwrap();

            let reloaded = PageMap::open(Box::new(tip_memory), fd_factory.clone()).unwrap();
            assert_eq!(
                reloaded.get_page(PageIndex::new(0))[0],
                updated[0],
                "write lost after merging {source_height} into {destination_height} at {merged_height}"
            );
        }
    }
}
