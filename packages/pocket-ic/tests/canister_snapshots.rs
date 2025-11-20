use candid::Principal;
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid};
use std::process::Command;

const T: u128 = 1_000_000_000_000;

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

fn test_canister_snapshot_download(pic: &mut PocketIc, canister_id: Principal) {
    // Take a snapshot to download later.
    // The canister should be stopped before taking a snapshot
    // (checked by dfx).
    pic.stop_canister(canister_id, None).unwrap();
    let snapshot_id = pic
        .take_canister_snapshot(canister_id, None, None)
        .unwrap()
        .id;

    // Download canister snapshot using PocketIC.
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path().to_path_buf();
    pic.canister_snapshot_download(
        canister_id,
        Principal::anonymous(),
        snapshot_id.clone(),
        snapshot_dir.clone(),
    );

    // We skip the rest of the test on Windows
    // since there's no Windows build of dfx
    // and we don't want to use WSL here
    // for the sake of simplicity.
    if cfg!(target_os = "windows") {
        return;
    }

    // We need to make the PocketIC instance live for dfx to work.
    let url = pic.make_live(None);

    // Create a home directory for dfx (that contains a configuration file)
    // and a snapshot directory for the snapshot downloaded using dfx.
    let dfx_temp_dir = tempfile::tempdir().unwrap();
    let dfx_home_dir = dfx_temp_dir.path().to_path_buf();
    let dfx_snapshot_dir = dfx_home_dir.join("snapshot");

    // We need to turn off telemetry explicitly,
    // otherwise dfx panics.
    std::fs::create_dir_all(dfx_home_dir.join(".config/dfx")).unwrap();
    std::fs::write(
        dfx_home_dir.join(".config/dfx/config.json"),
        "{\"telemetry\": \"off\"}",
    )
    .unwrap();

    // dfx expects the snapshot directory to exist.
    std::fs::create_dir_all(dfx_snapshot_dir.clone()).unwrap();

    // Download canister snapshot using dfx.
    let relative_dfx_path = std::env::var_os("DFX").expect("Missing dfx binary");
    let absolute_dfx_path = std::env::current_dir().unwrap().join(relative_dfx_path);
    Command::new(absolute_dfx_path)
        .arg("canister")
        .arg("snapshot")
        .arg("download")
        .arg(canister_id.to_string())
        .arg(hex::encode(snapshot_id))
        .arg("--dir")
        .arg(dfx_snapshot_dir.clone())
        .arg("--network")
        .arg(url.to_string())
        .arg("--identity")
        .arg("anonymous")
        .current_dir(dfx_home_dir.clone())
        .env("HOME", dfx_home_dir.clone())
        .output()
        .unwrap();

    // Check that the snapshots downloaded using PocketIC and dfx are equal.
    let diff = Command::new("diff")
        .arg("-r")
        .arg(snapshot_dir.clone())
        .arg(dfx_snapshot_dir.clone())
        .output()
        .expect("Failed to execute diff");
    match diff.status.code() {
        Some(0) => (),
        _ => panic!(
            "Snapshots differ (dfx snapshot: {}): {}",
            dfx_snapshot_dir.display(),
            String::from_utf8(diff.stdout).unwrap()
        ),
    };
}

#[test]
fn test_canister_snapshot_download_empty_stable_memory_and_chunk_store() {
    let mut pic = PocketIcBuilder::new().with_application_subnet().build();

    // Create and install a test canister.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // Ensure that the canister has empty stable memory.
    let stable_size = update_candid::<_, (u64,)>(&pic, canister_id, "stable_size", ())
        .unwrap()
        .0;
    assert_eq!(stable_size, 0);

    // Ensure that the canister has non-empty WASM chunk store.
    let chunks = pic.stored_chunks(canister_id, None).unwrap();
    assert!(chunks.is_empty());

    test_canister_snapshot_download(&mut pic, canister_id);
}

#[test]
fn test_canister_snapshot_download_nonempty_stable_memory_and_chunk_store() {
    let mut pic = PocketIcBuilder::new().with_application_subnet().build();

    // Create and install a test canister.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // Ensure that the canister has non-empty stable memory.
    update_candid::<_, ()>(&pic, canister_id, "stable_grow_and_fill", (42_u64,)).unwrap();

    // Ensure that the canister has non-empty WASM chunk store.
    pic.upload_chunk(canister_id, None, vec![0; 1 << 20])
        .unwrap();
    pic.upload_chunk(canister_id, None, vec![1; 1 << 19])
        .unwrap();

    test_canister_snapshot_download(&mut pic, canister_id);
}
