use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
};
use serde_json::json;
use slog::info;
use std::fs;

pub fn configure_local_network(env: &TestEnv) {
    let log = env.logger();
    info!(
        log,
        "Configure dfx 'local' network to connect to testenv subnet nodes"
    );

    let node_urls = env
        .topology_snapshot()
        .subnets()
        .flat_map(|subnet| subnet.nodes())
        .map(|node| node.get_public_url())
        .collect::<Vec<_>>();
    let config = json!({
        "local": {
            "providers": node_urls
        }
    });
    let config = serde_json::to_string_pretty(&config).unwrap();

    let home = fs::canonicalize(env.base_path()).unwrap();
    let config_dir = home.join(".config").join("dfx");
    let networks_json_path = config_dir.join("networks.json");

    info!(
        log,
        "Writing dfx network configuration to {}:",
        networks_json_path.display()
    );
    info!(log, "Configuration: {config}");

    fs::create_dir_all(&config_dir).unwrap();
    fs::write(networks_json_path, config).unwrap();
}
