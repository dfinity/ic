use anyhow::{anyhow, bail, Result};
use candid::{Encode, Nat, Principal};
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use futures::future::FutureExt;
use ic_cketh_minter::endpoints::{CandidBlockTag, MinterInfo};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg as MinterUpgradeArg;
use ic_cketh_minter::lifecycle::{init::InitArg as MinterInitArgs, EthereumNetwork, MinterArg};
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing, get_public_key_and_test_signature, make_key,
};
use ic_ethereum_types::Address;
use ic_icrc1_ledger::{ArchiveOptions, FeatureFlags, InitArgsBuilder, LedgerArgument};
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, LedgerInitArg, ManagedCanisterIds, OrchestratorArg,
    UpgradeArg as LedgerSuiteOrchestratorUpgradeArg,
};
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::test_env_api::SubnetSnapshot;
use ic_system_test_driver::driver::universal_vm::DeployedUniversalVm;
use ic_system_test_driver::util::MessageCanister;
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
use ic_types::Height;
use icrc_ledger_types::icrc1::account::Account;
use reqwest::Client;
use serde_json::json;
use slog::{info, Logger};
use std::env;
use std::future::Future;
use std::time::Duration;

const UNIVERSAL_VM_NAME: &str = "foundry";
const DOCKER_NETWORK_NAME: &str = "ethereum";
const FOUNDRY_PORT: u16 = 8545;
const ENCODED_PRINCIPAL: &str =
    "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000";

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
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(1)
                .with_dkg_interval_length(Height::from(10)),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );

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
        .start(env)
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
    let nns_subnet = topology_snapshot.root_subnet();
    let application_subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("missing application subnet");

    let system_subnet_runtime = {
        let nns_node = nns_subnet.nodes().next().unwrap();
        runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id())
    };
    let governance_canister = Canister::new(&system_subnet_runtime, GOVERNANCE_CANISTER_ID);

    let ecdsa_key_id = block_on(async {
        activate_threshold_ecdsa(&governance_canister, &application_subnet, &logger).await
    });

    let application_subnet_runtime = {
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

    let (_cketh_ledger, mut minter) = block_on(async {
        let minter_canister = create_canister(&application_subnet_runtime).await;
        let minter = minter_canister.canister_id().get().0;
        let cketh_ledger_canister = install_cketh_ledger(&application_subnet_runtime, minter).await;
        let ledger_id = cketh_ledger_canister.canister.canister_id().get().0;
        let minter_canister = install_cketh_minter(minter_canister, &ecdsa_key_id, ledger_id).await;
        (cketh_ledger_canister, minter_canister)
    });

    let minter_address: Address = block_on(async { minter.minter_address().await })
        .parse()
        .unwrap();

    let eth_deposit_helper_contract_address =
        deploy_eth_deposit_helper_contract(&docker_host, &minter_address);

    block_on(async {
        minter
            .upgrade(MinterUpgradeArg {
                ethereum_contract_address: Some(eth_deposit_helper_contract_address),
                ..Default::default()
            })
            .await
    });

    block_on(async { test_cketh_deposit(&docker_host, &minter, &logger).await });

    let erc20_contract_address = deploy_erc20_contract(&docker_host);
    let erc20_deposit_helper_contract_address =
        deploy_erc20_helper_contract(&docker_host, &minter_address);
    let mut ledger_orchestrator = block_on(async {
        let mut lso =
            install_ledger_suite_orchestrator(&application_subnet_runtime, minter.principal())
                .await;
        lso.register_embedded_wasms().await;
        minter
            .upgrade(MinterUpgradeArg {
                ledger_suite_orchestrator_id: Some(lso.principal()),
                erc20_helper_contract_address: Some(erc20_deposit_helper_contract_address),
                last_erc20_scraped_block_number: Some(Nat::from(0_u8)), //TODO: XC-256 get block number from contract creation
                ..Default::default()
            })
            .await;
        lso
    });
    let ckexl_token = block_on(async {
        ledger_orchestrator
            .add_erc20(
                AddErc20Arg {
                    contract: Erc20Contract {
                        chain_id: Nat::from(1_u8),
                        address: erc20_contract_address.clone(),
                    },
                    ledger_init_arg: LedgerInitArg {
                        transfer_fee: 1_u8.into(),
                        decimals: 18,
                        token_name: "ckEXL".to_string(),
                        token_symbol: "ckEXL".to_string(),
                        token_logo: "".to_string(),
                    },
                },
                &logger,
            )
            .await;
        try_async("minter supports ckEXL", &logger, || {
            minter.get_minter_info().map(|info| {
                info.supported_ckerc20_tokens
                    .clone()
                    .into_iter()
                    .flatten()
                    .find(|t| t.ckerc20_token_symbol == "ckEXL")
                    .ok_or(format!(
                        "ckEXL not found. Supported ckERC20: {:?}",
                        info.supported_ckerc20_tokens
                    ))
            })
        })
        .await
    });
    assert_eq!(ckexl_token.erc20_contract_address, erc20_contract_address);

    block_on(async {
        test_cketh_deposit(&docker_host, &minter, &logger).await;
        test_ckerc20_deposit(&docker_host, &minter, &erc20_contract_address, &logger).await;
    });
}

async fn activate_threshold_ecdsa(
    governance: &Canister<'_>,
    subnet: &SubnetSnapshot,
    logger: &Logger,
) -> EcdsaKeyId {
    let ecdsa_key_id = make_key("some_key");
    let key_id = MasterPublicKeyId::Ecdsa(ecdsa_key_id.clone());
    enable_chain_key_signing(governance, subnet.subnet_id, vec![key_id.clone()], logger).await;
    let app_node = subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent_async().await;
    let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
    get_public_key_and_test_signature(&key_id, &msg_can, false, logger)
        .await
        .expect("Should successfully create and verify the signature");
    ecdsa_key_id
}

async fn install_cketh_ledger(runtime: &Runtime, minter: Principal) -> LedgerCanister {
    let mut cketh_ledger_canister = create_canister(runtime).await;
    let ledger_init_args = LedgerArgument::Init(
        // See proposal 126309
        InitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
            .with_minting_account(minter)
            .with_transfer_fee(2_000_000_000_000_u64)
            .with_feature_flags(FeatureFlags { icrc2: true })
            .with_fee_collector_account(Account {
                owner: minter,
                subaccount: Some([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0x0f, 0xee,
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
            &mut cketh_ledger_canister,
            Some(Encode!(&ledger_init_args).unwrap()),
            None,
        )
        .await
        .unwrap();
    LedgerCanister {
        canister: cketh_ledger_canister,
    }
}

async fn install_cketh_minter<'a>(
    mut minter_canister: Canister<'a>,
    ecdsa_key_id: &EcdsaKeyId,
    cketh_ledger: Principal,
) -> CkEthMinterCanister<'a> {
    let minter_init_args = MinterArg::InitArg(MinterInitArgs {
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: ecdsa_key_id.name.clone(),
        ethereum_contract_address: None,
        ledger_id: cketh_ledger,
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

    CkEthMinterCanister {
        canister: minter_canister,
    }
}

async fn install_ledger_suite_orchestrator(
    runtime: &Runtime,
    minter: Principal,
) -> LedgerSuiteOrchestratorCanister {
    let mut lso_canister = create_canister(runtime).await;
    let lso_init_args = OrchestratorArg::InitArg(InitArg {
        more_controller_ids: vec![ROOT_CANISTER_ID.get().0],
        minter_id: Some(minter),
        cycles_management: None,
    });
    let lso_wasm = Wasm::from_file(
        env::var("LEDGER_SUITE_ORCHESTRATOR_WASM_PATH")
            .expect("LEDGER_SUITE_ORCHESTRATOR_WASM_PATH not set"),
    );
    lso_wasm
        .install_with_retries_onto_canister(
            &mut lso_canister,
            Some(Encode!(&lso_init_args).unwrap()),
            None,
        )
        .await
        .unwrap();

    LedgerSuiteOrchestratorCanister {
        canister: lso_canister,
    }
}

fn deploy_eth_deposit_helper_contract(
    docker_host: &DeployedUniversalVm,
    minter_address: &Address,
) -> String {
    let eth_deposit_helper_contract_address = deploy_smart_contract(
        docker_host,
        &EthereumAccount::HelperContractDeployer,
        "EthDepositHelper.sol",
        "CkEthDeposit",
        &minter_address.to_string(),
    );
    assert_eq!(
        call_smart_contract(
            docker_host,
            &eth_deposit_helper_contract_address,
            "getMinterAddress()(address)",
            &[]
        ),
        minter_address.to_string()
    );
    eth_deposit_helper_contract_address
}

async fn test_cketh_deposit(
    foundry: &DeployedUniversalVm,
    minter: &CkEthMinterCanister<'_>,
    logger: &slog::Logger,
) {
    let minter_info = minter.get_minter_info().await;
    let minter_address = minter_info.minter_address.unwrap();
    // retrieve helper contract address from minter to ensure ABI does not change
    let eth_deposit_helper_contract_address = minter_info.eth_helper_contract_address.unwrap();
    let deposit_amount: u128 = 42_000;
    assert!(eth_balance_of(foundry, EthereumAccount::User.address()) > deposit_amount);

    let minter_balance_before = eth_balance_of(foundry, &minter_address);
    info!(
        logger,
        "Depositing {} wei to ETH helper contract {}",
        deposit_amount,
        eth_deposit_helper_contract_address,
    );
    let _cketh_deposit_tx_hash = send_smart_contract(
        foundry,
        &EthereumAccount::User,
        &eth_deposit_helper_contract_address,
        "deposit(bytes32)",
        &[ENCODED_PRINCIPAL],
        Some(&deposit_amount.to_string()),
    );
    let minter_balance_after = eth_balance_of(foundry, &minter_address);

    assert_eq!(minter_balance_after - minter_balance_before, deposit_amount);
}

async fn test_ckerc20_deposit(
    foundry: &DeployedUniversalVm,
    minter: &CkEthMinterCanister<'_>,
    erc20_contract_address: &str,
    logger: &slog::Logger,
) {
    let minter_info = minter.get_minter_info().await;
    let minter_address = minter_info.minter_address.unwrap();
    let minter_balance_before = erc20_balance_of(foundry, erc20_contract_address, &minter_address);
    // retrieve helper contract address from minter to ensure ABI does not change
    let erc20_deposit_helper_contract_address = minter_info.erc20_helper_contract_address.unwrap();
    let deposit_amount: u128 = 1000;
    assert!(
        erc20_balance_of(
            foundry,
            erc20_contract_address,
            EthereumAccount::User.address()
        ) > deposit_amount
    );

    info!(
        logger,
        "Approving helper smart contract {} to use {} ckEXL",
        erc20_deposit_helper_contract_address,
        deposit_amount
    );
    send_smart_contract(
        foundry,
        &EthereumAccount::User,
        erc20_contract_address,
        "approve(address,uint256)",
        &[
            &erc20_deposit_helper_contract_address,
            &deposit_amount.to_string(),
        ],
        None,
    );
    info!(
        logger,
        "Depositing {} ckEXL to ERC-20 helper contract {}",
        deposit_amount,
        erc20_deposit_helper_contract_address,
    );
    send_smart_contract(
        foundry,
        &EthereumAccount::User,
        &erc20_deposit_helper_contract_address,
        "deposit(address,uint256,bytes32)",
        &[
            erc20_contract_address,
            &deposit_amount.to_string(),
            ENCODED_PRINCIPAL,
        ],
        None,
    );

    let minter_balance_after = erc20_balance_of(foundry, erc20_contract_address, &minter_address);
    assert_eq!(minter_balance_after - minter_balance_before, deposit_amount);
}

fn deploy_erc20_helper_contract(
    docker_host: &DeployedUniversalVm,
    minter_address: &Address,
) -> String {
    let erc20_deposit_helper_contract_address = deploy_smart_contract(
        docker_host,
        &EthereumAccount::HelperContractDeployer,
        "ERC20DepositHelper.sol",
        "CkErc20Deposit",
        &minter_address.to_string(),
    );
    assert_eq!(
        call_smart_contract(
            docker_host,
            &erc20_deposit_helper_contract_address,
            "getMinterAddress()(address)",
            &[]
        ),
        minter_address.to_string()
    );
    erc20_deposit_helper_contract_address
}

fn deploy_erc20_contract(foundry: &DeployedUniversalVm) -> String {
    let initial_supply: u128 = 1_000_000_000_000_000_000_000;
    let erc20_address = deploy_smart_contract(
        foundry,
        &EthereumAccount::Erc20Deployer,
        "ERC20.sol",
        "EXLToken",
        &format!("0x{:x}", initial_supply),
    );
    //deployer has initial supply, transfer some ERC-20 tokens to user to play with
    let user_initial_balance = initial_supply / 1_000;
    let user_address = EthereumAccount::User.address();
    let _transfer_tx = send_smart_contract(
        foundry,
        &EthereumAccount::Erc20Deployer,
        &erc20_address,
        "transfer(address,uint256)",
        &[user_address, &user_initial_balance.to_string()],
        None,
    );
    assert_eq!(
        erc20_balance_of(foundry, &erc20_address, user_address),
        user_initial_balance
    );
    erc20_address
}

fn erc20_balance_of(
    foundry: &DeployedUniversalVm,
    contract_address: &str,
    user_address: &str,
) -> u128 {
    let user_balance = call_smart_contract(
        foundry,
        contract_address,
        "balanceOf(address)(uint256)",
        &[user_address],
    ); //Output is formatted as "1000000000000000000 [1e18]"
    let user_balance = user_balance.split_ascii_whitespace().next().unwrap();
    user_balance.parse::<u128>().unwrap()
}

fn eth_balance_of(foundry: &DeployedUniversalVm, user_address: &str) -> u128 {
    foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast balance {user_address} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string().parse::<u128>().unwrap()
}

fn deploy_smart_contract(
    foundry: &DeployedUniversalVm,
    sender: &EthereumAccount,
    filename: &str,
    contract_name: &str,
    constructor_args: &str,
) -> String {
    let sender_private_key = sender.private_key();
    let json_output = foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm -v /config/{filename}:/contracts/{filename} foundry "forge create --json --rpc-url http://anvil:{FOUNDRY_PORT} --private-key {sender_private_key} /contracts/{filename}:{contract_name} --constructor-args {constructor_args}""#)).unwrap();
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
    args: &[&str],
) -> String {
    let arg = args.join(" ");
    foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast call {contract_address} '{method}' {arg} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string()
}

fn send_smart_contract(
    foundry: &DeployedUniversalVm,
    sender: &EthereumAccount,
    contract_address: &str,
    method: &str,
    args: &[&str],
    eth: Option<&str>,
) -> String {
    let value = eth.unwrap_or("0");
    let sender_private_key = sender.private_key();
    let arg = args.join(" ");
    let json_output = foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast send --json {contract_address} '{method}' {arg} --value {value} --private-key {sender_private_key} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string();
    let parsed_output: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    assert_eq!(parsed_output["status"].as_str().unwrap(), "0x1");
    parsed_output["transactionHash"]
        .as_str()
        .unwrap()
        .to_string()
}

pub async fn create_canister(runtime: &Runtime) -> Canister<'_> {
    runtime
        .create_canister(Some(u128::MAX))
        .await
        .expect("Unable to create canister")
}

struct LedgerCanister<'a> {
    canister: Canister<'a>,
}

struct CkEthMinterCanister<'a> {
    canister: Canister<'a>,
}

impl<'a> CkEthMinterCanister<'a> {
    async fn minter_address(&self) -> String {
        self.canister
            .update_("minter_address", candid, ())
            .await
            .unwrap()
    }

    async fn get_minter_info(&self) -> MinterInfo {
        self.canister
            .update_("get_minter_info", candid, ())
            .await
            .unwrap()
    }

    async fn upgrade(&mut self, arg: MinterUpgradeArg) {
        self.canister
            .upgrade_to_self_binary(Encode!(&MinterArg::UpgradeArg(arg)).unwrap())
            .await
            .unwrap();
    }

    fn principal(&self) -> Principal {
        self.canister.canister_id().get().0
    }
}

struct LedgerSuiteOrchestratorCanister<'a> {
    canister: Canister<'a>,
}

impl<'a> LedgerSuiteOrchestratorCanister<'a> {
    async fn upgrade(&mut self, arg: LedgerSuiteOrchestratorUpgradeArg) {
        self.canister
            .upgrade_to_self_binary(Encode!(&OrchestratorArg::UpgradeArg(arg)).unwrap())
            .await
            .unwrap();
    }

    async fn register_embedded_wasms(&mut self) {
        self.upgrade(LedgerSuiteOrchestratorUpgradeArg {
            git_commit_hash: Some("6a8e5fca2c6b4e12966638c444e994e204b42989".to_string()),
            ..Default::default()
        })
        .await;
    }

    async fn add_erc20(&mut self, arg: AddErc20Arg, logger: &slog::Logger) {
        self.canister
            .upgrade_to_self_binary(Encode!(&OrchestratorArg::AddErc20Arg(arg.clone())).unwrap())
            .await
            .unwrap();
        let created_canister_ids = ic_system_test_driver::retry_with_msg_async!(
            "checking if all canisters are created",
            logger,
            Duration::from_secs(100),
            Duration::from_secs(1),
            || async {
                let managed_canister_ids = self.canister_ids(arg.contract.clone()).await;
                match managed_canister_ids {
                    None => bail!("No managed canister IDs yet"),
                    Some(x) if x.ledger.is_some() && x.index.is_some() => Ok(x),
                    _ => bail!(
                        "Not all canisters were created yet: {:?}",
                        managed_canister_ids
                    ),
                }
            }
        )
        .await
        .unwrap_or_else(|e| panic!("Canisters for ERC-20 {:?} were not created: {}", arg, e));
        info!(
            &logger,
            "Created canister IDs: {} for ERC-20 {:?}", created_canister_ids, arg
        );
    }

    async fn canister_ids(&self, contract: Erc20Contract) -> Option<ManagedCanisterIds> {
        self.canister
            .query_("canister_ids", candid, (contract,))
            .await
            .expect("Error while calling canister_ids endpoint")
    }

    fn principal(&self) -> Principal {
        self.canister.canister_id().get().0
    }
}

/// Accounts created by Anvil on startup
enum EthereumAccount {
    Erc20Deployer,
    HelperContractDeployer,
    User,
}

impl EthereumAccount {
    const ACCOUNT_0: (&str, &str) = (
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    const ACCOUNT_1: (&str, &str) = (
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    const ACCOUNT_2: (&str, &str) = (
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    );
    fn account(&self) -> (&str, &str) {
        match self {
            EthereumAccount::Erc20Deployer => Self::ACCOUNT_0,
            EthereumAccount::HelperContractDeployer => Self::ACCOUNT_1,
            EthereumAccount::User => Self::ACCOUNT_2,
        }
    }
    pub fn address(&self) -> &str {
        self.account().0
    }

    pub fn private_key(&self) -> &str {
        self.account().1
    }
}

async fn try_async<S: AsRef<str>, F, Fut, R>(msg: S, logger: &slog::Logger, f: F) -> R
where
    Fut: Future<Output = Result<R, String>>,
    F: Fn() -> Fut,
{
    ic_system_test_driver::retry_with_msg_async!(
        msg.as_ref(),
        logger,
        Duration::from_secs(100),
        Duration::from_secs(1),
        || async { f().await.map_err(|e| anyhow!(e)) }
    )
    .await
    .expect("failed despite retries")
}
