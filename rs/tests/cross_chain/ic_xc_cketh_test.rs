use anyhow::{anyhow, bail, Context, Result};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::universal_vm::DeployedUniversalVm;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasTopologySnapshot, IcNodeContainer, NnsCustomizations,
            SshSession,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
    util::block_on,
};
use reqwest::Client;
use serde_json::json;
use std::env;

const UNIVERSAL_VM_NAME: &str = "foundry";
const DOCKER_NETWORK_NAME: &str = "ethereum";
const FOUNDRY_PORT: u16 = 8545;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_system_and_application_subnets)
        .add_test(systest!(ic_xc_cketh_test))
        .execute_from_args()?;
    Ok(())
}

fn setup_with_system_and_application_subnets(env: TestEnv) {
    setup_anvil(&env);
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

fn setup_anvil(env: &TestEnv) {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            env::var("CKETH_UVM_CONFIG_PATH").expect("CKETH_UVM_CONFIG_PATH not set"),
        ))
        .enable_ipv4() //forge needs to download the version of the solidity compiler indicated in the smart contracts that are being deployed
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();

    println!(
        "{}",
        deployed_universal_vm
            .block_on_bash_script(&format!(
                r#"
# Run nginx auto proxy
docker load -i /config/foundry.tar
docker network create {DOCKER_NETWORK_NAME}
docker run --net {DOCKER_NETWORK_NAME} --detach --rm --name anvil -p {FOUNDRY_PORT}:{FOUNDRY_PORT} foundry:latest "anvil --host 0.0.0.0"
docker logs anvil
"#
            ))
            .unwrap()
    );
}

fn ic_xc_cketh_test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let docker_host = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let docker_host_ip = docker_host.get_vm().unwrap().ipv6;
    let client = Client::new();

    let url = format!("http://[{:?}]:{:?}", docker_host_ip, 8545);

    block_on(async {
        let response = client
            .post(&url)
            .body(r#"{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}"#)
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("failed to get the zone");

        let response_json: serde_json::Value = response
            .json()
            .await
            .expect("failed to decode the response");
        assert_eq!(
            response_json,
            json!({"jsonrpc":"2.0","id":1,"result":"0x0"})
        )
    });

    let minter_address = "0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80";

    let eth_deposit_helper_contract_address = deploy_smart_contract(
        &docker_host,
        "EthDepositHelper.sol",
        "CkEthDeposit",
        minter_address,
    );
    assert_eq!(
        call_smart_contract(
            &docker_host,
            &eth_deposit_helper_contract_address,
            "getMinterAddress()(address)"
        ),
        minter_address
    );

    let erc20_deposit_helper_contract_address = deploy_smart_contract(
        &docker_host,
        "ERC20DepositHelper.sol",
        "CkErc20Deposit",
        minter_address,
    );
    assert_eq!(
        call_smart_contract(
            &docker_host,
            &erc20_deposit_helper_contract_address,
            "getMinterAddress()(address)"
        ),
        minter_address
    );
}

fn deploy_smart_contract(
    foundry: &DeployedUniversalVm,
    filename: &str,
    contract_name: &str,
    constructor_args: &str,
) -> String {
    let json_output = foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm -v /config/{filename}:/contracts/{filename} foundry "forge create --json --rpc-url http://anvil:{FOUNDRY_PORT} --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 /contracts/{filename}:{contract_name} --constructor-args {constructor_args}""#)).unwrap();
    println!(
        "Deployed {filename} with constructor args {constructor_args}: {}",
        json_output
    );
    let parsed_output: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    parsed_output["deployedTo"].as_str().unwrap().to_string()
}

fn call_smart_contract(
    foundry: &DeployedUniversalVm,
    contract_address: &str,
    method: &str,
) -> String {
    foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast call {contract_address} '{method}' --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string()
}
