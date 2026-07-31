use candid::{Principal, Reserved};
use ic_management_canister_types_private::{
    Global, GlobalTimer, OnLowWasmMemoryHookStatus, ReadCanisterSnapshotMetadataResponse,
    SnapshotSource,
};
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const T: u128 = 1_000_000_000_000;

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

/// Returns the paths of all files in the directory `dir` (recursively)
/// relative to `dir` (using `/` as the path separator) in sorted order.
fn list_files(dir: &Path) -> Vec<String> {
    fn visit(dir: &Path, prefix: &str, files: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = format!("{}{}", prefix, entry.file_name().to_string_lossy());
            if entry.file_type().unwrap().is_dir() {
                visit(&entry.path(), &format!("{path}/"), files);
            } else {
                files.push(path);
            }
        }
    }

    let mut files = vec![];
    visit(dir, "", &mut files);
    files.sort();
    files
}

/// Returns the size of the file at `path` or `None` if the file does not exist.
fn file_size(path: &Path) -> Option<u64> {
    path.try_exists()
        .unwrap()
        .then(|| std::fs::metadata(path).unwrap().len())
}

/// Downloads a snapshot of the canister `canister_id` using PocketIC and checks that
/// the downloaded snapshot consists of exactly the files `expected_files` (paths relative
/// to the snapshot directory) with the expected contents (files mapped to `None` are
/// checked separately). Then the downloaded snapshot is uploaded again and downloaded
/// once more to check that the round trip does not change the snapshot.
fn test_canister_snapshot_download_upload(
    pic: &PocketIc,
    canister_id: Principal,
    expected_files: BTreeMap<String, Option<Vec<u8>>>,
) {
    // Take a snapshot to download later.
    // The canister should be stopped before taking a snapshot.
    pic.stop_canister(canister_id, None).unwrap();
    let time_before_snapshot = pic.get_time().as_nanos_since_unix_epoch();
    let snapshot_id = pic
        .take_canister_snapshot(canister_id, None, None)
        .unwrap()
        .id;
    let time_after_snapshot = pic.get_time().as_nanos_since_unix_epoch();

    // Download the canister snapshot using PocketIC.
    let downloaded_snapshot_temp_dir = tempfile::tempdir().unwrap();
    let downloaded_snapshot_dir = downloaded_snapshot_temp_dir.path().to_path_buf();
    pic.canister_snapshot_download(
        canister_id,
        Principal::anonymous(),
        snapshot_id.clone(),
        downloaded_snapshot_dir.clone(),
    );

    // Check that the downloaded snapshot consists of exactly the expected files.
    assert_eq!(
        list_files(&downloaded_snapshot_dir),
        expected_files.keys().cloned().collect::<Vec<_>>()
    );

    // Check the contents of the downloaded files
    // (the files mapped to `None` are checked separately).
    for (path, expected_contents) in &expected_files {
        let Some(expected_contents) = expected_contents else {
            continue;
        };
        let contents = std::fs::read(downloaded_snapshot_dir.join(path)).unwrap();
        // We do not use `assert_eq!` on the contents
        // to avoid dumping the (potentially large) contents.
        assert_eq!(
            contents.len(),
            expected_contents.len(),
            "Unexpected size of {}",
            path
        );
        if let Some(offset) = contents
            .iter()
            .zip(expected_contents)
            .position(|(byte, expected_byte)| byte != expected_byte)
        {
            panic!(
                "Unexpected contents of {} at offset {}: {} instead of the expected {}",
                path, offset, contents[offset], expected_contents[offset]
            );
        }
    }

    // Upload the canister snapshot downloaded before.
    let uploaded_snapshot_id = pic.canister_snapshot_upload(
        canister_id,
        Principal::anonymous(),
        None,
        downloaded_snapshot_dir.clone(),
    );

    // Download the uploaded snapshot to compare it against the originally downloaded snapshot.
    let uploaded_snapshot_temp_dir = tempfile::tempdir().unwrap();
    let uploaded_snapshot_dir = uploaded_snapshot_temp_dir.path().to_path_buf();
    pic.canister_snapshot_download(
        canister_id,
        Principal::anonymous(),
        uploaded_snapshot_id.clone(),
        uploaded_snapshot_dir.clone(),
    );

    // Check that the uploaded snapshot is equal to the originally downloaded snapshot.
    // We compare snapshot metadata separately because it is expected that some fields differ.
    let diff = Command::new("diff")
        .arg("-r")
        .arg("--exclude")
        .arg("metadata.json")
        .arg(downloaded_snapshot_dir.clone())
        .arg(uploaded_snapshot_dir.clone())
        .output()
        .expect("Failed to execute diff");
    match diff.status.code() {
        Some(0) => (),
        _ => panic!(
            "Snapshots differ (uploaded snapshot: {}): {}",
            uploaded_snapshot_dir.display(),
            String::from_utf8(diff.stdout).unwrap()
        ),
    };

    // Compare snapshot metadata.
    // The source and timestamps are expected to differ and
    // thus they are overwritten before comparision.
    let downloaded_metadata_path = downloaded_snapshot_dir.join("metadata.json");
    let downloaded_metadata_bytes = std::fs::read(downloaded_metadata_path).unwrap();
    let downloaded_metadata: ReadCanisterSnapshotMetadataResponse =
        serde_json::from_slice(&downloaded_metadata_bytes).unwrap();

    let uploaded_metadata_path = uploaded_snapshot_dir.join("metadata.json");
    let uploaded_metadata_bytes = std::fs::read(uploaded_metadata_path).unwrap();
    let mut uploaded_metadata: ReadCanisterSnapshotMetadataResponse =
        serde_json::from_slice(&uploaded_metadata_bytes).unwrap();

    assert_eq!(
        downloaded_metadata.source,
        SnapshotSource::TakenFromCanister(Reserved)
    );
    assert_eq!(
        uploaded_metadata.source,
        SnapshotSource::MetadataUpload(Reserved)
    );

    uploaded_metadata.source = downloaded_metadata.source;
    uploaded_metadata.taken_at_timestamp = downloaded_metadata.taken_at_timestamp;
    assert_eq!(downloaded_metadata, uploaded_metadata);

    // Check the contents of the metadata of the originally downloaded snapshot.
    assert!(downloaded_metadata.taken_at_timestamp >= time_before_snapshot);
    assert!(downloaded_metadata.taken_at_timestamp <= time_after_snapshot);
    assert_eq!(
        downloaded_metadata.wasm_module_size,
        test_canister_wasm().len() as u64
    );
    // The values of the globals depend on how the test canister WASM is compiled
    // and thus we only check that there is a single global of type `i32`.
    assert_eq!(downloaded_metadata.globals.len(), 1);
    assert!(matches!(downloaded_metadata.globals[0], Global::I32(_)));
    // The contents of the WASM memory are hard to reproduce and thus we only check
    // the WASM memory size against the size of the downloaded WASM memory file.
    assert_eq!(
        Some(downloaded_metadata.wasm_memory_size),
        file_size(&downloaded_snapshot_dir.join("wasm_memory.bin"))
    );
    // The stable memory file is missing if and only if the stable memory is empty.
    assert_eq!(
        downloaded_metadata.stable_memory_size,
        file_size(&downloaded_snapshot_dir.join("stable_memory.bin")).unwrap_or(0)
    );
    // Every WASM chunk is stored in a file named after its hash
    // in the WASM chunk store directory (which is missing
    // if and only if the WASM chunk store is empty).
    let chunk_store_files: Vec<String> = downloaded_metadata
        .wasm_chunk_store
        .iter()
        .map(|chunk_hash| format!("wasm_chunk_store/{}.bin", hex::encode(&chunk_hash.hash)))
        .collect();
    assert_eq!(
        chunk_store_files,
        expected_files
            .keys()
            .filter(|path| path.starts_with("wasm_chunk_store/"))
            .cloned()
            .collect::<Vec<_>>()
    );
    // The canister version after creating, installing, and stopping the canister.
    assert_eq!(downloaded_metadata.canister_version, 4);
    assert!(downloaded_metadata.certified_data.is_empty());
    assert_eq!(
        downloaded_metadata.global_timer,
        Some(GlobalTimer::Inactive)
    );
    assert_eq!(
        downloaded_metadata.on_low_wasm_memory_hook_status,
        Some(OnLowWasmMemoryHookStatus::ConditionNotSatisfied)
    );
}

#[test]
fn test_canister_snapshot_download_empty_stable_memory_and_chunk_store() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // Create and install a test canister.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // Ensure that the canister has empty stable memory.
    let stable_size = update_candid::<_, (u64,)>(&pic, canister_id, "stable_size", ())
        .unwrap()
        .0;
    assert_eq!(stable_size, 0);

    // Ensure that the canister has empty WASM chunk store.
    let chunks = pic.stored_chunks(canister_id, None).unwrap();
    assert!(chunks.is_empty());

    // Neither a file for the (empty) stable memory nor a directory
    // for the (empty) WASM chunk store is expected.
    let expected_files = BTreeMap::from([
        // The metadata is checked separately after parsing it.
        ("metadata.json".to_string(), None),
        // The contents of the WASM memory are hard to reproduce.
        ("wasm_memory.bin".to_string(), None),
        ("wasm_module.bin".to_string(), Some(test_canister_wasm())),
    ]);

    test_canister_snapshot_download_upload(&pic, canister_id, expected_files);
}

#[test]
fn test_canister_snapshot_download_nonempty_stable_memory_and_chunk_store() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // Create and install a test canister.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // Ensure that the canister has non-empty stable memory
    // and that it takes more than one call to download/upload stable memory.
    let stable_memory_pages = 42;
    let stable_memory_bytes = stable_memory_pages << 16;
    assert!(stable_memory_bytes > 2_000_000); // snapshot data chunks have size 2MB
    update_candid::<_, ()>(&pic, canister_id, "stable_grow_and_fill", (42_u64,)).unwrap();
    // The test canister fills the stable memory with the bytes 0, 1, ..., 255 repeated
    // (the stable memory page size is a multiple of 256).
    let expected_stable_memory: Vec<u8> = (0..stable_memory_bytes)
        .map(|byte| (byte % 256) as u8)
        .collect();

    // Ensure that the canister has non-empty WASM chunk store.
    let mut expected_chunk_files = vec![];
    for chunk in [vec![0_u8; 1 << 20], vec![1_u8; 1 << 19]] {
        let chunk_hash = pic.upload_chunk(canister_id, None, chunk.clone()).unwrap();
        expected_chunk_files.push((
            format!("wasm_chunk_store/{}.bin", hex::encode(chunk_hash)),
            Some(chunk),
        ));
    }

    // A file for the stable memory and one file per WASM chunk
    // in the WASM chunk store directory are expected in addition.
    let mut expected_files = BTreeMap::from([
        // The metadata is checked separately after parsing it.
        ("metadata.json".to_string(), None),
        (
            "stable_memory.bin".to_string(),
            Some(expected_stable_memory),
        ),
        // The contents of the WASM memory are hard to reproduce.
        ("wasm_memory.bin".to_string(), None),
        ("wasm_module.bin".to_string(), Some(test_canister_wasm())),
    ]);
    expected_files.extend(expected_chunk_files);

    test_canister_snapshot_download_upload(&pic, canister_id, expected_files);
}
