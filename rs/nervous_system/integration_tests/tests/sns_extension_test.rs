use candid::Nat;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::Sns;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_common::ledger::compute_distribution_subaccount_bytes;
use ic_nervous_system_common::E8;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nervous_system_integration_tests::pocket_ic_helpers::add_wasms_to_sns_wasm;
use ic_nervous_system_integration_tests::pocket_ic_helpers::cycles_ledger;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_with_controllers;
use ic_nervous_system_integration_tests::pocket_ic_helpers::load_registry_mutations;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns;
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_sns_cli::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use ic_sns_cli::register_extension;
use ic_sns_cli::register_extension::RegisterExtensionArgs;
use ic_sns_cli::register_extension::RegisterExtensionInfo;
use ic_sns_governance::governance::TREASURY_SUBACCOUNT_NONCE;
use ic_sns_swap::pb::v1::Lifecycle;
use icp_ledger::{Tokens, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::icrc1::account::Account;
use maplit::btreemap;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use pretty_assertions::assert_eq;
use sns_treasury_manager;
use sns_treasury_manager::Asset;
use sns_treasury_manager::AuditTrailRequest;
use sns_treasury_manager::BalancesRequest;
use sns_treasury_manager::{Accounts, Balance, WithdrawRequest};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

mod src {
    pub use ic_nns_governance_api::create_service_nervous_system::initial_token_distribution::{
        developer_distribution::NeuronDistribution, DeveloperDistribution, SwapDistribution,
        TreasuryDistribution,
    };
    pub use ic_nns_governance_api::create_service_nervous_system::InitialTokenDistribution;
} // end mod src

const ICP_FEE: u64 = DEFAULT_TRANSFER_FEE.get_e8s();
const SNS_FEE: u64 = 11143;

#[tokio::test]
async fn test() {
    test_treasury_manager().await
}

async fn test_treasury_manager() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let _sns_subnet_id = topology.get_sns().unwrap();

    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();

    println!(">>> Fiduciary subnet ID: {}", fiduciary_subnet_id);

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    {
        let registry_proto_path = state_dir.join("registry.proto");
        let initial_mutations = load_registry_mutations(registry_proto_path);

        let mut nns_installer = NnsInstaller::default();
        nns_installer
            .with_current_nns_canister_versions()
            .with_test_governance_canister()
            .with_cycles_minting_canister()
            .with_cycles_ledger()
            .with_custom_registry_mutations(vec![initial_mutations]);
        nns_installer.install(&pocket_ic).await;
    }

    let sns = deploy_sns(&pocket_ic, false).await;

    // Install KongSwap
    let _kong_backend_canister_id = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");

        let kong_backend_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![PrincipalId::new_user_test_id(42)];

        // Canister ID from the mainnet.
        // See https://dashboard.internetcomputer.org/canister/2ipq2-uqaaa-aaaar-qailq-cai
        let canister_id = CanisterId::try_from_principal_id(
            PrincipalId::from_str("2ipq2-uqaaa-aaaar-qailq-cai").unwrap(),
        )
        .unwrap();

        install_canister_with_controllers(
            &pocket_ic,
            "KongSwap Backend Canister",
            canister_id,
            vec![],
            kong_backend_wasm,
            controllers,
        )
        .await;

        canister_id
    };

    let sns_ledger_canister_id = CanisterId::try_from_principal_id(sns.ledger.canister_id).unwrap();
    let sns_root_canister_id = CanisterId::try_from_principal_id(sns.root.canister_id).unwrap();

    let sns_token = Asset::Token {
        symbol: "Kanye".to_string(),
        ledger_canister_id: sns_ledger_canister_id.get().0,
        ledger_fee_decimals: Nat::from(SNS_FEE),
    };

    let icp_token = Asset::Token {
        symbol: "ICP".to_string(),
        ledger_canister_id: LEDGER_CANISTER_ID.get().0,
        ledger_fee_decimals: Nat::from(ICP_FEE),
    };

    let initial_icp_balance_e8s = 64_999_999_990_000;
    let initial_sns_balance_e8s = 40_000_000_000;

    validate_treasury_balances(
        "Before registering KongSwapAdaptor",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s,
        initial_sns_balance_e8s,
    )
    .await
    .unwrap();

    let adaptor_canister_id = {
        let (neuron_id, sender) = sns::governance::find_neuron_with_majority_voting_power(
            &pocket_ic,
            sns.governance.canister_id,
        )
        .await
        .expect("cannot find SNS neuron with dissolve delay over 6 months.");

        let agent = PocketIcAgent::new(&pocket_ic, sender);

        let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
            .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

        let wasm_path = PathBuf::from(wasm_path);

        let icp = Tokens::from_tokens(10).unwrap();
        cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

        let RegisterExtensionInfo {
            proposal_id,
            extension_canister_id,
            wasm_module_hash: _,
        } = register_extension::exec(
            RegisterExtensionArgs {
                sns_neuron_id: Some(ParsedSnsNeuron(neuron_id)),
                sns_root_canister_id,
                fiduciary_subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
                wasm_path,
                proposal_url: Url::try_from("https://example.com").unwrap(),
                summary: "Register KongSwap Adaptor".to_string(),
                treasury_allocation_icp_e8s: Some(150 * E8 + 2 * ICP_FEE),
                treasury_allocation_sns_e8s: Some(350 * E8 + 2 * SNS_FEE),
            },
            &agent,
        )
        .await
        .unwrap();

        let proposal_id = proposal_id.unwrap();

        let _proposal_data = sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            proposal_id,
        )
        .await
        .unwrap();

        extension_canister_id.get()
    };

    for _ in 0..100 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(100)).await;
    }

    validate_treasury_balances(
        "After registering KongSwapAdaptor",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s - 150 * E8 - 3 * ICP_FEE,
        initial_sns_balance_e8s - 350 * E8 - 3 * SNS_FEE,
    )
    .await
    .unwrap();

    {
        let request = BalancesRequest {};
        let response = pocket_ic
            .call(adaptor_canister_id, request)
            .await
            .unwrap()
            .unwrap();

        println!(">>> Balances: {:#?}", response);
    }

    {
        let request = AuditTrailRequest {};
        let response = pocket_ic.call(adaptor_canister_id, request).await.unwrap();

        // println!(">>> AuditTrail: {:#?}", response);
    }

    let treasury_sns_account = sns_treasury_manager::Account {
        owner: sns.governance.canister_id.0,
        subaccount: Some(compute_distribution_subaccount_bytes(
            sns.governance.canister_id,
            TREASURY_SUBACCOUNT_NONCE,
        )),
    };

    let treasury_icp_account = sns_treasury_manager::Account {
        owner: sns.governance.canister_id.0,
        subaccount: None,
    };

    let _withdrawn_amounts = {
        let ledger_id_to_account = btreemap! {
            sns.ledger.canister_id.0 => treasury_sns_account,
            LEDGER_CANISTER_ID.get().0 => treasury_icp_account,
        };

        let request = WithdrawRequest {
            withdraw_accounts: Some(Accounts {
                ledger_id_to_account,
            }),
        };

        let response = PocketIcAgent::new(&pocket_ic, sns.root.canister_id)
            .call(adaptor_canister_id, request)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            response.balances,
            btreemap! {
                sns_token => Balance {
                    amount_decimals: Nat::from(350 * E8 - 2 * SNS_FEE),
                    owner_account: treasury_sns_account,
                },
                icp_token => Balance {
                    amount_decimals: Nat::from(150 * E8 - 2 * ICP_FEE),
                    owner_account: treasury_icp_account,
                },
            },
        );
    };

    validate_treasury_balances(
        "After withdrawing.",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s - 5 * ICP_FEE,
        initial_sns_balance_e8s - 5 * SNS_FEE,
    )
    .await
    .unwrap();

    // let audit_trail = adaptor_canister_id.audit_trail();

    // println!("{:#?}", audit_trail.transactions());

    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 0).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 1).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 2).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 3).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 4).await;

    panic!("  Directed by\nROBERT B. WEIDE.");
}

async fn dbg_print_block(
    pocket_ic: &PocketIc,
    sns_ledger_canister_id: PrincipalId,
    block_index: u64,
) {
    let block =
        sns::ledger::get_all_blocks(pocket_ic, sns_ledger_canister_id, block_index, 1).await;

    let Value::Map(block_details) = block.blocks[0].clone() else {
        panic!("Expected a block with details, got: {:?}", block.blocks[0]);
    };

    let Value::Map(tx_details) = block_details.get("tx").clone().unwrap() else {
        panic!(
            "Expected a transaction in the block details, got: {:?}",
            block_details.get("tx")
        );
    };

    let from = tx_details.get("from");
    let to = tx_details.get("to");
    let spender = tx_details.get("spender");
    let amt = tx_details.get("amt").unwrap();
    let op = tx_details.get("op").unwrap();

    println!("SNS Ledger block {} details.", block_index);
    println!("    amt = {:?}", amt);
    println!("     op = {:?}", op);
    println!("   from = {:?}", from);
    println!("     to = {:?}", to);
    println!("spender = {:?}", spender);
}

async fn deploy_sns(pocket_ic: &PocketIc, with_mainnet_sns_canisters: bool) -> Sns {
    use ic_nervous_system_proto::pb::v1::{self as pb};

    add_wasms_to_sns_wasm(pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
    create_service_nervous_system.initial_token_distribution =
        Some(src::InitialTokenDistribution {
            developer_distribution: Some(src::DeveloperDistribution {
                developer_neurons: vec![src::NeuronDistribution {
                    controller: Some(PrincipalId::new_user_test_id(830947)),
                    dissolve_delay: Some(pb::Duration {
                        seconds: Some(ONE_MONTH_SECONDS * 6),
                    }),
                    memo: Some(763535),
                    stake: Some(pb::Tokens { e8s: Some(756575) }),
                    vesting_period: Some(pb::Duration { seconds: Some(0) }),
                }],
            }),
            treasury_distribution: Some(src::TreasuryDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(400 * E8),
                }),
            }),
            swap_distribution: Some(src::SwapDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(1_840_880_000),
                }),
            }),
        });

    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();

    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    sns::swap::await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();
    sns::swap::smoke_test_participate_and_finalize(
        pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    sns
}

async fn validate_treasury_balances(
    lebel: &str,
    sns: &Sns,
    pocket_ic: &PocketIc,
    icp_balance_e8s: u64,
    sns_balance_e8s: u64,
) -> Result<(), String> {
    let sns_treasury_subaccount = compute_distribution_subaccount_bytes(
        sns.governance.canister_id,
        TREASURY_SUBACCOUNT_NONCE,
    );

    let owner = sns.governance.canister_id.0;

    for (token_name, ledger_canister_id, subaccount, expected_balance_e8s) in [
        ("ICP", LEDGER_CANISTER_ID.get(), None, icp_balance_e8s),
        (
            "SNS",
            sns.ledger.canister_id,
            Some(sns_treasury_subaccount),
            sns_balance_e8s,
        ),
    ] {
        let account = Account { owner, subaccount };

        let observed_balance_e8s =
            sns::ledger::icrc1_balance_of(pocket_ic, ledger_canister_id, account).await;

        let expected_balance_e8s = Nat::from(expected_balance_e8s);

        if observed_balance_e8s != expected_balance_e8s {
            return Err(format!(
                "[{}] Expected treasury {} balance of {}, got {}.",
                lebel, token_name, expected_balance_e8s, observed_balance_e8s
            ));
        }
    }

    Ok(())
}
