use super::*;

/// `std::env::temp_dir()` alone is not enough: it always returns the same
/// (shared) directory, so callers still need to make a unique subdirectory
/// within it to avoid colliding with other test runs. This wraps that in one
/// place, and creates the directory too.
fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dfx-core-vendored-network-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_shared_networks_json(config_root: &Path, contents: &str) {
    let dfx_dir = config_root.join(".config").join("dfx");
    std::fs::create_dir_all(&dfx_dir).unwrap();
    std::fs::write(dfx_dir.join("networks.json"), contents).unwrap();
}

#[test]
fn project_dfx_json_without_networks_falls_back_to_shared_network() {
    // Step 1: Prepare the world.
    let project_dir = unique_temp_dir("project-no-networks-key");
    std::fs::write(project_dir.join("dfx.json"), r#"{"canisters": {}}"#).unwrap();

    let config_root = unique_temp_dir("shared-config");
    write_shared_networks_json(&config_root, r#"{"local": {"bind": "shared:2718"}}"#);

    // Step 2: Run the code under test.
    let result = resolve_local_network_with(Some(&project_dir), Some(&config_root)).unwrap();

    // Step 3: Verify result(s).
    assert_eq!(result.providers, vec!["http://shared:2718".to_string()]);
}

#[test]
fn project_dfx_json_with_its_own_local_network_takes_precedence() {
    // Step 1: Prepare the world.
    let project_dir = unique_temp_dir("project-with-local");
    std::fs::write(
        project_dir.join("dfx.json"),
        r#"{"networks": {"local": {"bind": "dfx-json:9999"}}}"#,
    )
    .unwrap();

    // The shared network is configured too, with a distinct bind address, so
    // this test proves the project's own network takes precedence over an
    // actually configured shared network -- not merely over the shared
    // default.
    let config_root = unique_temp_dir("shared-config-for-precedence-test");
    write_shared_networks_json(&config_root, r#"{"local": {"bind": "shared:1111"}}"#);

    // Step 2: Run the code under test.
    let result = resolve_local_network_with(Some(&project_dir), Some(&config_root)).unwrap();

    // Step 3: Verify result(s).
    assert_eq!(result.providers, vec!["http://dfx-json:9999".to_string()]);
}

#[test]
fn shared_network_without_local_entry_uses_default_shared_address() {
    // Step 1: Prepare the world.
    //
    // Both dfx.json and networks.json exist, but neither declares a "local"
    // network, so they should be skipped over (not merely absent).
    let project_dir = unique_temp_dir("project-without-local-network");
    std::fs::write(project_dir.join("dfx.json"), r#"{"canisters": {}}"#).unwrap();

    let config_root = unique_temp_dir("shared-config-without-local-network");
    write_shared_networks_json(&config_root, r#"{"unrelated": {"bind": "shared:4444"}}"#);

    // Step 2: Run the code under test.
    let result = resolve_local_network_with(Some(&project_dir), Some(&config_root)).unwrap();

    // Step 3: Verify result(s).
    assert_eq!(
        result.providers,
        vec![format!("http://{DEFAULT_SHARED_LOCAL_ADDRESS}")]
    );
}
