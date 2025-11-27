use anyhow::{Result, anyhow, bail};
use candid::{Encode, Nat, Principal};
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use futures::future::FutureExt;
use hex_literal::hex;
use ic_cketh_minter::endpoints::{CandidBlockTag, MinterInfo};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg as MinterUpgradeArg;
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_cketh_minter::numeric::BlockNumber;
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
use ic_management_canister_types_private::{EcdsaKeyId, MasterPublicKeyId};
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
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsCustomizations, SshSession,
            get_dependency_path,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
    util::{block_on, runtime_from_url},
};
use ic_types::Height;
use icrc_ledger_types::icrc1::account::Account;
use reqwest::Client;
use slog::{Logger, info};
use std::env;
use std::future::Future;
use std::time::Duration;

const FOUNDRY_VM_NAME: &str = "foundry";
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
    std::thread::scope(|s| {
        s.spawn(|| {
            setup_anvil(&env);
        });
        s.spawn(|| {
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
        });
    });
}

fn setup_anvil(env: &TestEnv) {
    UniversalVm::new(String::from(FOUNDRY_VM_NAME))
        .with_config_img(get_dependency_path(
            env::var("CKETH_UVM_CONFIG_PATH").expect("CKETH_UVM_CONFIG_PATH not set"),
        ))
        .enable_ipv4() //forge needs to download the version of the solidity compiler indicated in the smart contracts that are being deployed
        .start(env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(FOUNDRY_VM_NAME).unwrap();

    deployed_universal_vm
            .block_on_bash_script(&format!(
                r#"
docker load -i /config/foundry.tar
docker network create {DOCKER_NETWORK_NAME}
docker run --net {DOCKER_NETWORK_NAME} --detach --rm --name anvil -p {FOUNDRY_PORT}:{FOUNDRY_PORT} foundry:latest "anvil --host 0.0.0.0"
"#
            ))
            .unwrap();
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

    let foundry = env.get_deployed_universal_vm(FOUNDRY_VM_NAME).unwrap();
    assert_eq!(
        block_on(async { eth_block_number(&foundry).await }),
        BlockNumber::ZERO
    );

    let (cketh_ledger, mut minter) = block_on(async {
        let minter_canister = create_canister(&application_subnet_runtime).await;
        let minter = minter_canister.canister_id().get().0;
        let cketh_ledger_canister = install_cketh_ledger(&application_subnet_runtime, minter).await;
        info!(
            logger,
            "Installed ckETH ledger at {}",
            cketh_ledger_canister.principal()
        );

        let minter_canister = install_cketh_minter(
            minter_canister,
            &ecdsa_key_id,
            cketh_ledger_canister.principal(),
        )
        .await;
        info!(
            logger,
            "Installed ckETH minter at {}",
            minter_canister.principal()
        );
        (cketh_ledger_canister, minter_canister)
    });

    info!(
        logger,
        "Supporting deposit of ETH and testing deposit flows."
    );
    block_on(async {
        support_eth_deposit(
            &foundry,
            &mut minter,
            &ecdsa_key_id,
            cketh_ledger.principal(),
            &logger,
        )
        .await;

        test_cketh_deposit(&foundry, &minter, &logger).await
    });

    let (erc20_contract_address, _contract_creation_block_number) =
        deploy_erc20_contract(&foundry, &logger);
    info!(
        logger,
        "Deployed ERC20 contract EXL at {}", erc20_contract_address
    );
    let mut ledger_orchestrator = block_on(async {
        install_ledger_suite_orchestrator(&application_subnet_runtime, minter.principal()).await
    });
    info!(
        logger,
        "Ledger suite orchestrator installed at {}",
        ledger_orchestrator.principal()
    );

    info!(
        logger,
        "Supporting deposit of ERC-20 and testing deposit flows."
    );
    block_on(async {
        support_erc20_deposit(
            &foundry,
            &mut minter,
            &mut ledger_orchestrator,
            &erc20_contract_address,
            &logger,
        )
        .await;

        test_cketh_deposit(&foundry, &minter, &logger).await;
        test_ckerc20_deposit(&foundry, &minter, &erc20_contract_address, &logger).await;
    });

    info!(
        logger,
        "Supporting deposit with subaccounts and testing deposit flows."
    );
    block_on(async {
        support_deposit_with_subaccount(&foundry, &mut minter, &logger).await;

        test_cketh_deposit(&foundry, &minter, &logger).await;
        test_ckerc20_deposit(&foundry, &minter, &erc20_contract_address, &logger).await;
        test_deposit_with_subaccount(&foundry, &minter, &erc20_contract_address, &logger).await;
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

// TODO: XC-258: setup EVM RPC canister to target anvil via IPv6
async fn eth_block_number(foundry: &DeployedUniversalVm) -> BlockNumber {
    let foundry_ip = foundry.get_vm().unwrap().ipv6;
    let client = Client::new();

    let url = format!("http://[{foundry_ip:?}]:{FOUNDRY_PORT:?}");

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

    serde_json::from_value(response_json["result"].clone()).unwrap()
}

async fn install_cketh_ledger(runtime: &Runtime, minter: Principal) -> LedgerCanister<'_> {
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
    let minter_init_args = MinterArg::InitArg(minter_init_args(ecdsa_key_id, cketh_ledger));
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

fn minter_init_args(ecdsa_key_id: &EcdsaKeyId, cketh_ledger: Principal) -> MinterInitArgs {
    MinterInitArgs {
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: ecdsa_key_id.name.clone(),
        ethereum_contract_address: None,
        ledger_id: cketh_ledger,
        ethereum_block_height: CandidBlockTag::Finalized,
        minimum_withdrawal_amount: Nat::from(30_000_000_000_000_000_u64),
        next_transaction_nonce: Nat::from(0_u8),
        last_scraped_block_number: Nat::from(0_u8),
        evm_rpc_id: None,
    }
}

async fn install_ledger_suite_orchestrator(
    runtime: &Runtime,
    minter: Principal,
) -> LedgerSuiteOrchestratorCanister<'_> {
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
    logger: &slog::Logger,
) -> (Address, BlockNumber) {
    let (contract_address, block_number) = deploy_smart_contract(
        docker_host,
        &EthereumAccount::HelperContractDeployer,
        "EthDepositHelper.sol",
        "CkEthDeposit",
        &minter_address.to_string(),
        logger,
    );
    assert_eq!(
        call_smart_contract(
            docker_host,
            &contract_address,
            "getMinterAddress()(address)",
            &[]
        ),
        minter_address.to_string()
    );
    (contract_address, block_number)
}

async fn support_eth_deposit(
    foundry: &DeployedUniversalVm,
    minter: &mut CkEthMinterCanister<'_>,
    ecdsa_key_id: &EcdsaKeyId,
    cketh_ledger: Principal,
    logger: &slog::Logger,
) {
    let minter_address = minter.minter_address().await.parse().unwrap();
    info!(logger, "Retrieved ckETH minter address {minter_address}");

    let (eth_deposit_helper_contract_address, eth_deposit_contract_creation_block_number) =
        deploy_eth_deposit_helper_contract(foundry, &minter_address, logger);
    minter
        .reinstall(MinterInitArgs {
            ethereum_contract_address: Some(eth_deposit_helper_contract_address.to_string()),
            last_scraped_block_number: Nat::from(eth_deposit_contract_creation_block_number),
            ..minter_init_args(ecdsa_key_id, cketh_ledger)
        })
        .await;
    info!(
        logger,
        "ckETH minter re-installed to set `last_scraped_block_number`"
    );
}

async fn test_cketh_deposit(
    foundry: &DeployedUniversalVm,
    minter: &CkEthMinterCanister<'_>,
    logger: &slog::Logger,
) {
    let minter_info = minter.get_minter_info().await;
    let minter_address: Address = minter_info.minter_address.unwrap().parse().unwrap();
    // retrieve helper contract address from minter to ensure ABI does not change
    let eth_deposit_helper_contract_address: Address = minter_info
        .eth_helper_contract_address
        .unwrap()
        .parse()
        .unwrap();
    let deposit_amount: u128 = 42_000;
    assert!(eth_balance_of(foundry, &EthereumAccount::User.address()) > deposit_amount);

    test_eth_deposit(
        foundry,
        &minter_address,
        &eth_deposit_helper_contract_address,
        "deposit(bytes32)",
        &[ENCODED_PRINCIPAL],
        logger,
    );
}

fn test_eth_deposit(
    foundry: &DeployedUniversalVm,
    minter_address: &Address,
    helper_contract_address: &Address,
    helper_contract_method: &str,
    helper_contract_args: &[&str],
    logger: &slog::Logger,
) {
    let deposit_amount: u128 = 42_000;
    assert!(eth_balance_of(foundry, &EthereumAccount::User.address()) > deposit_amount);

    let minter_balance_before = eth_balance_of(foundry, minter_address);
    info!(
        logger,
        "Depositing {} wei to helper contract {}", deposit_amount, helper_contract_address,
    );
    let _cketh_deposit_tx_hash = send_smart_contract(
        foundry,
        &EthereumAccount::User,
        helper_contract_address,
        helper_contract_method,
        helper_contract_args,
        Some(&deposit_amount.to_string()),
    );
    let minter_balance_after = eth_balance_of(foundry, minter_address);

    assert_eq!(minter_balance_after - minter_balance_before, deposit_amount);
}

async fn support_erc20_deposit(
    foundry: &DeployedUniversalVm,
    minter: &mut CkEthMinterCanister<'_>,
    ledger_orchestrator: &mut LedgerSuiteOrchestratorCanister<'_>,
    erc20_contract_address: &Address,
    logger: &slog::Logger,
) {
    let minter_address = minter.minter_address().await.parse().unwrap();
    let (erc20_deposit_helper_contract_address, erc20_contract_creation_block_number) =
        deploy_erc20_helper_contract(foundry, &minter_address, logger);

    ledger_orchestrator.register_embedded_wasms().await;
    minter
        .upgrade(MinterUpgradeArg {
            ledger_suite_orchestrator_id: Some(ledger_orchestrator.principal()),
            erc20_helper_contract_address: Some(erc20_deposit_helper_contract_address.to_string()),
            last_erc20_scraped_block_number: Some(Nat::from(erc20_contract_creation_block_number)),
            ..Default::default()
        })
        .await;

    ledger_orchestrator
        .add_erc20(
            AddErc20Arg {
                contract: Erc20Contract {
                    chain_id: Nat::from(1_u8),
                    address: erc20_contract_address.to_string(),
                },
                ledger_init_arg: LedgerInitArg {
                    transfer_fee: 1_u8.into(),
                    decimals: 18,
                    token_name: "ckEXL".to_string(),
                    token_symbol: "ckEXL".to_string(),
                    token_logo: "".to_string(),
                },
            },
            logger,
        )
        .await;
    let ckexl_token = try_async("minter supports ckEXL", logger, || {
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
    .await;
    assert_eq!(
        &ckexl_token
            .erc20_contract_address
            .parse::<Address>()
            .unwrap(),
        erc20_contract_address
    );
}

async fn test_ckerc20_deposit(
    foundry: &DeployedUniversalVm,
    minter: &CkEthMinterCanister<'_>,
    erc20_contract_address: &Address,
    logger: &slog::Logger,
) {
    let minter_info = minter.get_minter_info().await;
    let minter_address: Address = minter_info.minter_address.unwrap().parse().unwrap();
    // retrieve helper contract address from minter to ensure ABI does not change
    let erc20_deposit_helper_contract_address: Address = minter_info
        .erc20_helper_contract_address
        .unwrap()
        .parse()
        .unwrap();
    let deposit_amount: u128 = 1000;

    test_erc20_deposit(
        foundry,
        &minter_address,
        erc20_contract_address,
        &erc20_deposit_helper_contract_address,
        "deposit(address,uint256,bytes32)",
        &[
            &erc20_contract_address.to_string(),
            &deposit_amount.to_string(),
            ENCODED_PRINCIPAL,
        ],
        deposit_amount,
        logger,
    );
}

fn test_erc20_deposit(
    foundry: &DeployedUniversalVm,
    minter_address: &Address,
    erc20_contract_address: &Address,
    helper_contract_address: &Address,
    helper_contract_method: &str,
    helper_contract_args: &[&str],
    deposit_amount: u128,
    logger: &slog::Logger,
) {
    assert!(
        erc20_balance_of(
            foundry,
            erc20_contract_address,
            &EthereumAccount::User.address()
        ) > deposit_amount
    );

    let minter_balance_before = erc20_balance_of(foundry, erc20_contract_address, minter_address);
    info!(
        logger,
        "Approving helper smart contract {} to use {} ckEXL",
        helper_contract_address,
        deposit_amount
    );
    send_smart_contract(
        foundry,
        &EthereumAccount::User,
        erc20_contract_address,
        "approve(address,uint256)",
        &[
            &helper_contract_address.to_string(),
            &deposit_amount.to_string(),
        ],
        None,
    );
    info!(
        logger,
        "Depositing {} ckEXL to helper contract {}", deposit_amount, helper_contract_address,
    );
    send_smart_contract(
        foundry,
        &EthereumAccount::User,
        helper_contract_address,
        helper_contract_method,
        helper_contract_args,
        None,
    );

    let minter_balance_after = erc20_balance_of(foundry, erc20_contract_address, minter_address);
    assert_eq!(minter_balance_after - minter_balance_before, deposit_amount);
}

async fn support_deposit_with_subaccount(
    foundry: &DeployedUniversalVm,
    minter: &mut CkEthMinterCanister<'_>,
    logger: &slog::Logger,
) {
    let minter_address = minter.minter_address().await.parse().unwrap();
    let (
        deposit_with_subaccount_helper_contract_address,
        deposit_with_subaccount_contract_creation_block_number,
    ) = deploy_deposit_with_subaccount_helper_contract(foundry, &minter_address, logger);
    info!(
        logger,
        "Deposit with subaccount helper smart contract deployed at {} in block {}",
        deposit_with_subaccount_helper_contract_address,
        deposit_with_subaccount_contract_creation_block_number
    );
    minter
        .upgrade(MinterUpgradeArg {
            deposit_with_subaccount_helper_contract_address: Some(
                deposit_with_subaccount_helper_contract_address.to_string(),
            ),
            last_deposit_with_subaccount_scraped_block_number: Some(Nat::from(
                deposit_with_subaccount_contract_creation_block_number,
            )),
            ..Default::default()
        })
        .await
}

async fn test_deposit_with_subaccount(
    foundry: &DeployedUniversalVm,
    minter: &CkEthMinterCanister<'_>,
    erc20_contract_address: &Address,
    logger: &slog::Logger,
) {
    const ENCODED_NO_SUBACCOUNT: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
    const ENCODED_SUBACCOUNT: &str =
        "0xff00000000000000000000000000000000000000000000000000000000000000";

    let minter_info = minter.get_minter_info().await;
    let minter_address: Address = minter_info.minter_address.unwrap().parse().unwrap();
    // retrieve helper contract address from minter to ensure ABI does not change
    let deposit_with_subaccount_helper_contract_address: Address = minter_info
        .deposit_with_subaccount_helper_contract_address
        .unwrap()
        .parse()
        .unwrap();
    let erc20_deposit_amount: u128 = 1000;

    for subaccount in [ENCODED_NO_SUBACCOUNT, ENCODED_SUBACCOUNT] {
        test_eth_deposit(
            foundry,
            &minter_address,
            &deposit_with_subaccount_helper_contract_address,
            "depositEth(bytes32,bytes32)",
            &[ENCODED_PRINCIPAL, subaccount],
            logger,
        );

        test_erc20_deposit(
            foundry,
            &minter_address,
            erc20_contract_address,
            &deposit_with_subaccount_helper_contract_address,
            "depositErc20(address,uint256,bytes32,bytes32)",
            &[
                &erc20_contract_address.to_string(),
                &erc20_deposit_amount.to_string(),
                ENCODED_PRINCIPAL,
                subaccount,
            ],
            erc20_deposit_amount,
            logger,
        );
    }
}

fn deploy_erc20_helper_contract(
    docker_host: &DeployedUniversalVm,
    minter_address: &Address,
    logger: &slog::Logger,
) -> (Address, BlockNumber) {
    let (erc20_deposit_helper_contract_address, block_number) = deploy_smart_contract(
        docker_host,
        &EthereumAccount::HelperContractDeployer,
        "ERC20DepositHelper.sol",
        "CkErc20Deposit",
        &minter_address.to_string(),
        logger,
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
    (erc20_deposit_helper_contract_address, block_number)
}

fn deploy_erc20_contract(
    foundry: &DeployedUniversalVm,
    logger: &slog::Logger,
) -> (Address, BlockNumber) {
    let initial_supply: u128 = 1_000_000_000_000_000_000_000;
    let (erc20_address, block_number) = deploy_smart_contract(
        foundry,
        &EthereumAccount::Erc20Deployer,
        "ERC20.sol",
        "EXLToken",
        &format!("0x{initial_supply:x}"),
        logger,
    );
    //deployer has initial supply, transfer some ERC-20 tokens to user to play with
    let user_initial_balance = initial_supply / 1_000;
    let user_address = EthereumAccount::User.address();
    let _transfer_tx = send_smart_contract(
        foundry,
        &EthereumAccount::Erc20Deployer,
        &erc20_address,
        "transfer(address,uint256)",
        &[&user_address.to_string(), &user_initial_balance.to_string()],
        None,
    );
    assert_eq!(
        erc20_balance_of(foundry, &erc20_address, &user_address),
        user_initial_balance
    );
    (erc20_address, block_number)
}

fn deploy_deposit_with_subaccount_helper_contract(
    docker_host: &DeployedUniversalVm,
    minter_address: &Address,
    logger: &slog::Logger,
) -> (Address, BlockNumber) {
    let (deposit_helper_contract_with_subaccount_address, block_number) = deploy_smart_contract(
        docker_host,
        &EthereumAccount::HelperContractDeployer,
        "DepositHelperWithSubaccount.sol",
        "CkDeposit",
        &minter_address.to_string(),
        logger,
    );
    assert_eq!(
        call_smart_contract(
            docker_host,
            &deposit_helper_contract_with_subaccount_address,
            "getMinterAddress()(address)",
            &[]
        ),
        minter_address.to_string()
    );
    (
        deposit_helper_contract_with_subaccount_address,
        block_number,
    )
}

fn erc20_balance_of(
    foundry: &DeployedUniversalVm,
    contract_address: &Address,
    user_address: &Address,
) -> u128 {
    let user_balance = call_smart_contract(
        foundry,
        contract_address,
        "balanceOf(address)(uint256)",
        &[&user_address.to_string()],
    ); //Output is formatted as "1000000000000000000 [1e18]"
    let user_balance = user_balance.split_ascii_whitespace().next().unwrap();
    user_balance.parse::<u128>().unwrap()
}

fn eth_balance_of(foundry: &DeployedUniversalVm, user_address: &Address) -> u128 {
    foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast balance {user_address} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string().parse::<u128>().unwrap()
}

fn deploy_smart_contract(
    foundry: &DeployedUniversalVm,
    sender: &EthereumAccount,
    filename: &str,
    contract_name: &str,
    constructor_args: &str,
    logger: &slog::Logger,
) -> (Address, BlockNumber) {
    let sender_private_key = sender.private_key();
    let cmd = format!(
        "\
        docker run --net {DOCKER_NETWORK_NAME} --rm \
        -v /config/{filename}:/contracts/{filename} \
        foundry \"forge create --json --rpc-url http://anvil:{FOUNDRY_PORT} --broadcast --private-key {sender_private_key} /contracts/{filename}:{contract_name} --constructor-args {constructor_args}\"\
    "
    );
    let json_output = foundry.block_on_bash_script(&cmd).unwrap();
    info!(
        logger,
        "Deployed {filename} with constructor args {constructor_args}: {}", json_output
    );
    let parsed_output: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    let tx_hash = parsed_output["transactionHash"].as_str().unwrap();
    let tx_receipt_json = foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast receipt --json {tx_hash} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap();
    let parsed_tx_receipt: serde_json::Value = serde_json::from_str(&tx_receipt_json).unwrap();
    let contract_address =
        serde_json::from_value(parsed_tx_receipt["contractAddress"].clone()).unwrap();
    let block_number = serde_json::from_value(parsed_tx_receipt["blockNumber"].clone()).unwrap();
    (contract_address, block_number)
}

fn call_smart_contract(
    foundry: &DeployedUniversalVm,
    contract_address: &Address,
    method: &str,
    args: &[&str],
) -> String {
    let arg = args.join(" ");
    foundry.block_on_bash_script(&format!(r#"docker run --net {DOCKER_NETWORK_NAME} --rm foundry "cast call {contract_address} '{method}' {arg} --rpc-url http://anvil:{FOUNDRY_PORT}""#)).unwrap().trim().to_string()
}

fn send_smart_contract(
    foundry: &DeployedUniversalVm,
    sender: &EthereumAccount,
    contract_address: &Address,
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

impl LedgerCanister<'_> {
    fn principal(&self) -> Principal {
        self.canister.canister_id().get().0
    }
}

struct CkEthMinterCanister<'a> {
    canister: Canister<'a>,
}

impl CkEthMinterCanister<'_> {
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

    async fn reinstall(&mut self, arg: MinterInitArgs) {
        self.canister
            .reinstall_with_self_binary(Encode!(&MinterArg::InitArg(arg)).unwrap())
            .await
            .unwrap();
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

impl LedgerSuiteOrchestratorCanister<'_> {
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
        .unwrap_or_else(|e| panic!("Canisters for ERC-20 {arg:?} were not created: {e}"));
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
    const ACCOUNT_0: (Address, &str) = (
        Address::new(hex!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")),
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    const ACCOUNT_1: (Address, &str) = (
        Address::new(hex!("70997970C51812dc3A010C7d01b50e0d17dc79C8")),
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    const ACCOUNT_2: (Address, &str) = (
        Address::new(hex!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")),
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    );
    fn account(&self) -> (Address, &str) {
        match self {
            EthereumAccount::Erc20Deployer => Self::ACCOUNT_0,
            EthereumAccount::HelperContractDeployer => Self::ACCOUNT_1,
            EthereumAccount::User => Self::ACCOUNT_2,
        }
    }
    pub fn address(&self) -> Address {
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
