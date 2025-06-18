use anyhow::Result;
use bitcoincore_rpc::RpcApi;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on},
};
use ic_tests_ckbtc::{
    adapter::AdapterProxy,
    adapter_test_setup, subnet_sys,
    utils::{ensure_wallet, get_btc_client},
};
use slog::info;

fn test_received_blocks(env: TestEnv) {
    let log = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    // Setup client
    let client = get_btc_client(&env);
    ensure_wallet(&client, &log);
    assert_eq!(0, client.get_blockchain_info().unwrap().blocks);
    info!(log, "Set up bitcoind wallet");

    // Mine 150 blocks
    let address = client.get_new_address(None, None).unwrap().assume_checked();
    client.generate_to_address(150, &address).unwrap();
    info!(log, "Generated 150");

    // Instruct the adapter to sync the blocks
    let anchor = client.get_block_hash(0).unwrap()[..].to_vec();
    let blocks = block_on(async {
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let adapter_proxy = AdapterProxy::new(&agent).await;
        adapter_proxy
            .sync_blocks(&mut vec![], anchor, 150, 15)
            .await
            .expect("Failed to syncronize blocks")
    });

    assert_eq!(blocks.len(), 150);
    for (h, block) in blocks.iter().enumerate() {
        assert_eq!(
            block.block_hash(),
            client.get_block_hash((h + 1) as u64).unwrap()
        );
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(adapter_test_setup)
        .add_test(systest!(test_received_blocks))
        .execute_from_args()?;
    Ok(())
}
