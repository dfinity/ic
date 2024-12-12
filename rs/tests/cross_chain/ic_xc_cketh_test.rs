use anyhow::{anyhow, bail, Context, Result};
use candid::{Encode, Nat};
use canister_test::{Canister, Runtime, Wasm};
use ic_cketh_minter::endpoints::CandidBlockTag;
use ic_cketh_minter::lifecycle::{init::InitArg as MinterInitArgs, EthereumNetwork, MinterArg};
use ic_icrc1_ledger::{ArchiveOptions, FeatureFlags, InitArgsBuilder, LedgerArgument};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::universal_vm::DeployedUniversalVm;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsCustomizations, SshSession,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
    util::{block_on, runtime_from_url},
};
use icrc_ledger_types::icrc1::account::Account;
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
    let application_subnet_runtime = {
        let application_subnet = topology_snapshot
            .subnets()
            .find(|s| s.subnet_type() == SubnetType::Application)
            .expect("missing application subnet");
        let application_node = application_subnet.nodes().next().unwrap();
        runtime_from_url(
            application_node.get_public_url(),
            application_node.effective_canister_id(),
        )
    };

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

    block_on(async {
        let mut minter_canister = create_canister(&application_subnet_runtime).await;
        let minter = minter_canister.canister_id().get().0;

        let mut ledger_canister = create_canister(&application_subnet_runtime).await;
        let ledger_init_args = LedgerArgument::Init(
            // See proposal 126309
            InitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
                .with_minting_account(minter)
                .with_transfer_fee(2_000_000_000_000_u64)
                .with_feature_flags(FeatureFlags { icrc2: true })
                .with_fee_collector_account(Account {
                    owner: minter,
                    subaccount: Some([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0x0f, 0xee,
                    ]),
                })
                .with_decimals(18)
                .with_max_memo_length(80)
                .with_archive_options(ArchiveOptions {
                    trigger_threshold: 2_000,
                    num_blocks_to_archive: 1_0000,
                    node_max_memory_size_bytes: None,
                    max_message_size_bytes: Some(3_221_225_472),
                    controller_id: minter.into(),
                    more_controller_ids: None,
                    cycles_for_archive_creation: Some(100_000_000_000_000),
                    max_transactions_per_response: None,
                })
                .build(),
        );
        let ledger_wasm =
            Wasm::from_file(env::var("LEDGER_WASM_PATH").expect("LEDGER_WASM_PATH not set"));
        ledger_wasm
            .install_with_retries_onto_canister(
                &mut ledger_canister,
                Some(Encode!(&ledger_init_args).unwrap()),
                None,
            )
            .await
            .unwrap();

        let minter_init_args = MinterArg::InitArg(MinterInitArgs {
            ethereum_network: EthereumNetwork::Mainnet,
            ecdsa_key_name: "key_1".to_string(),
            ethereum_contract_address: None,
            ledger_id: ledger_canister.canister_id().get().0,
            ethereum_block_height: CandidBlockTag::Finalized,
            minimum_withdrawal_amount: Nat::from(30_000_000_000_000_000_u64),
            next_transaction_nonce: Nat::from(0_u8),
            last_scraped_block_number: Nat::from(0_u8),
        });
        let minter_wasm = Wasm::from_file(
            env::var("CKETH_MINTER_WASM_PATH").expect("CKETH_MINTER_WASM_PATH not set"),
        );
        minter_wasm
            .install_with_retries_onto_canister(
                &mut minter_canister,
                Some(Encode!(&minter_init_args).unwrap()),
                None,
            )
            .await
            .unwrap();
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

pub async fn create_canister(runtime: &Runtime) -> Canister<'_> {
    runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister")
}
