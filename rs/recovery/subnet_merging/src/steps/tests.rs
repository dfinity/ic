use super::*;
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::state_manager::lsmt_config_default;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::CHECKPOINTS;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
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

/// Writes the manifest of a checkpoint holding a single file with `contents`
/// to `manifest_path`.
fn write_manifest(tmp: &Path, name: &str, contents: &str, manifest_path: &Path) {
    let checkpoint = tmp.join(name);
    std::fs::create_dir(&checkpoint).unwrap();
    std::fs::write(checkpoint.join("file.bin"), contents).unwrap();
    state_tool_helper::compute_manifest(&checkpoint, manifest_path).unwrap();
}

#[test]
fn merged_state_hash_is_the_root_hash_of_the_expected_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::for_test(tmp.path().join("recovery"));
    std::fs::create_dir(tmp.path().join("recovery")).unwrap();
    let manifest = layout.merged_state_manifest_file();
    let expected_manifest = layout.expected_merged_state_manifest_file();

    // No merged state yet.
    assert!(merged_state_hash(&layout).is_err());

    write_manifest(tmp.path(), "merged", "merged", &manifest);
    // No expected manifest to check the merged state against.
    assert!(merged_state_hash(&layout).is_err());

    write_manifest(tmp.path(), "expected", "merged", &expected_manifest);
    let state_hash = merged_state_hash(&layout).unwrap();
    assert_eq!(
        state_hash,
        state_tool_helper::verify_manifest(&manifest).unwrap()
    );

    write_manifest(tmp.path(), "other", "other", &expected_manifest);
    let expected_state_hash = state_tool_helper::verify_manifest(&expected_manifest).unwrap();
    assert_ne!(state_hash, expected_state_hash);
    let err = merged_state_hash(&layout).unwrap_err().to_string();
    assert!(err.contains(&state_hash), "{err}");
    assert!(err.contains(&expected_state_hash), "{err}");
}

#[test]
fn recovery_cup_time_must_be_past_both_halting_times() {
    let subnet_id = |id| SubnetId::from(ic_base_types::PrincipalId::new_subnet_test_id(id));
    let (source, destination) = (subnet_id(1), subnet_id(2));
    let time = |nanos| UNIX_EPOCH + Duration::from_nanos(nanos);
    let halting_times = |source_nanos, destination_nanos| {
        [
            (source, Time::from_nanos_since_unix_epoch(source_nanos)),
            (
                destination,
                Time::from_nanos_since_unix_epoch(destination_nanos),
            ),
        ]
    };

    assert!(check_time_is_past_halting_times(time(101), &halting_times(100, 50)).is_ok());
    assert!(check_time_is_past_halting_times(time(101), &halting_times(50, 100)).is_ok());

    // Not past the halting time of one of the two subnets, whichever it is.
    for (halting_times, behind) in [
        (halting_times(100, 50), source),
        (halting_times(50, 100), destination),
        (halting_times(101, 50), source),
        (halting_times(50, 101), destination),
    ] {
        let err = check_time_is_past_halting_times(time(100), &halting_times)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("subnet {behind} halted at")), "{err}");
    }
}

/// The copy of the merged state that is moved into place on the node of the
/// destination subnet shares no files with the downloaded states, even though
/// the merged state does.
#[test]
fn copy_of_merged_state_shares_no_files() {
    use std::os::unix::fs::MetadataExt;

    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::for_test(tmp.path().to_path_buf());
    let downloaded = layout.checkpoint_dir(TargetSubnet::Destination, Height::new(100));
    let merged = layout.merged_checkpoint_dir(Height::new(101));
    std::fs::create_dir_all(&downloaded).unwrap();
    std::fs::create_dir_all(&merged).unwrap();
    std::fs::write(downloaded.join("system_metadata.pbuf"), "metadata").unwrap();
    std::fs::hard_link(
        downloaded.join("system_metadata.pbuf"),
        merged.join("system_metadata.pbuf"),
    )
    .unwrap();
    // A stale copy from an earlier run of the step is replaced.
    let stale = layout.merged_ic_state_copy_dir().join("stale");
    std::fs::create_dir_all(&stale).unwrap();

    let step = UploadMergedStateStep {
        node: DataLocation::Local,
        layout: layout.clone(),
        require_confirmation: false,
        key_file: None,
        logger: Logger::root(slog::Discard, slog::o!()),
    };
    step.copy_merged_state().unwrap();

    assert!(!stale.exists());
    let copied = layout
        .merged_ic_state_copy_dir()
        .join(CHECKPOINTS)
        .join(StateLayout::checkpoint_name(Height::new(101)))
        .join("system_metadata.pbuf");
    assert_eq!(std::fs::read_to_string(&copied).unwrap(), "metadata");
    assert_eq!(std::fs::metadata(&copied).unwrap().nlink(), 1);
}

#[test]
fn only_a_subnet_whose_record_was_deleted_is_deleted() {
    let subnet_id = |id| SubnetId::from(PrincipalId::new_subnet_test_id(id));
    let (deleted, remaining, unknown) = (subnet_id(1), subnet_id(2), subnet_id(3));
    let (before, after) = (RegistryVersion::from(1), RegistryVersion::from(2));

    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    for subnet_id in [deleted, remaining] {
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                before,
                Some(SubnetRecord::default()),
            )
            .unwrap();
    }
    data_provider
        .add::<SubnetRecord>(&make_subnet_record_key(deleted), after, None)
        .unwrap();
    let registry_client = FakeRegistryClient::new(data_provider);
    registry_client.update_to_latest_version();

    assert!(ensure_subnet_deleted(&registry_client, deleted, after).is_ok());

    // Neither a subnet whose record is still there, nor one that never had a
    // record, nor the deleted subnet as of a version that still holds it.
    for (subnet_id, registry_version) in [(remaining, after), (unknown, after), (deleted, before)] {
        let err = ensure_subnet_deleted(&registry_client, subnet_id, registry_version)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not record"), "{err}");
        assert!(err.contains(&subnet_id.to_string()), "{err}");
    }

    // A version the registry client has not seen cannot confirm the deletion.
    let err = ensure_subnet_deleted(&registry_client, deleted, RegistryVersion::from(3))
        .unwrap_err()
        .to_string();
    assert!(err.contains("Failed to check"), "{err}");
}
