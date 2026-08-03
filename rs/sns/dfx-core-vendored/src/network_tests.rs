use super::*;

fn write_shared_networks_json(config_root: &Path, contents: &str) {
    let dfx_dir = config_root.join(".config").join("dfx");
    std::fs::create_dir_all(&dfx_dir).unwrap();
    std::fs::write(dfx_dir.join("networks.json"), contents).unwrap();
}

#[test]
fn project_dfx_json_without_networks_falls_back_to_shared_network() {
    // Step 1: Prepare the world.
    let project_dir = tempfile::tempdir().unwrap();
    std::fs::write(project_dir.path().join("dfx.json"), r#"{"canisters": {}}"#).unwrap();

    let config_root = tempfile::tempdir().unwrap();
    write_shared_networks_json(config_root.path(), r#"{"local": {"bind": "shared:2718"}}"#);

    // Step 2: Run the code under test.
    let result = resolve_local_network_with(project_dir.path(), Some(config_root.path())).unwrap();

    // Step 3: Verify result(s).
    assert_eq!(result.providers, vec!["http://shared:2718".to_string()]);
}

#[test]
fn project_dfx_json_with_its_own_local_network_takes_precedence() {
    // Step 1: Prepare the world.
    let project_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        project_dir.path().join("dfx.json"),
        r#"{"networks": {"local": {"bind": "dfx-json:9999"}}}"#,
    )
    .unwrap();

    // The shared network is configured too, with a distinct bind address, so
    // this test proves the project's own network takes precedence over an
    // actually configured shared network -- not merely over the shared
    // default.
    let config_root = tempfile::tempdir().unwrap();
    write_shared_networks_json(config_root.path(), r#"{"local": {"bind": "shared:1111"}}"#);

    // Step 2: Run the code under test.
    let result = resolve_local_network_with(project_dir.path(), Some(config_root.path())).unwrap();

    // Step 3: Verify result(s).
    assert_eq!(result.providers, vec!["http://dfx-json:9999".to_string()]);
}

#[test]
fn shared_network_without_local_entry_uses_default_shared_address() {
    // Step 1: Prepare the world.
    //
    // Both dfx.json and networks.json exist, but neither declares a "local"
    // network, so they should be skipped over (not merely absent).
    let project_dir = tempfile::tempdir().unwrap();
    std::fs::write(project_dir.path().join("dfx.json"), r#"{"canisters": {}}"#).unwrap();

    let config_root = tempfile::tempdir().unwrap();
    write_shared_networks_json(
        config_root.path(),
        r#"{"unrelated": {"bind": "shared:4444"}}"#,
    );

    // Step 2: Run the code under test, and verify the result.
    assert_eq!(
        resolve_local_network_with(project_dir.path(), Some(config_root.path())).unwrap(),
        NetworkDescriptor {
            providers: vec![format!("http://{DEFAULT_SHARED_LOCAL_ADDRESS}")],
            is_ic: false,
        }
    );
}
