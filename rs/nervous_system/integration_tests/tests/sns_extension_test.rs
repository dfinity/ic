use std::str::FromStr;
use std::time::Duration;
use candid::Nat;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_nervous_system_agent::{pocketic_impl::PocketIcAgent, CallCanisters};
use ic_nervous_system_common::E8;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_with_controllers;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_canister_on_subnet, sns};
use ic_nns_constants::LEDGER_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Tokens, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::approve::ApproveArgs,
};
use itertools::{Either, Itertools};
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use sns_treasury_manager::Allowance;
use sns_treasury_manager::Asset;
use sns_treasury_manager::DepositRequest;
use sns_treasury_manager::TreasuryManagerResult;
use sns_treasury_manager::{TreasuryManagerArg, TreasuryManagerInit};

// TODO
// use thiserror::Error

pub const MAX_SYMBOL_BYTES: usize = 10;

#[tokio::test]
async fn test() {
    test_custom_upgrade_path_for_sns().await
}

#[track_caller]
async fn test_custom_upgrade_path_for_sns() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();
    let sns_subnet_id = topology.get_sns().unwrap();

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    // Step 0.1: Publish (master) SNS Wasms to SNS-W.
    // let with_mainnet_sns_canisters = false;
    // add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
    //     .await
    //     .unwrap();
    // let initial_sns_version = nns::sns_wasm::get_latest_sns_version(&pocket_ic).await;

    // Step 0.2: Deploy an SNS instance via proposal.
    // let sns = {
    //     let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
    //     let swap_parameters = create_service_nervous_system
    //         .swap_parameters
    //         .clone()
    //         .unwrap();

    //     let sns_instance_label = "1";
    //     let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
    //         &pocket_ic,
    //         create_service_nervous_system,
    //         sns_instance_label,
    //     )
    //     .await;

    //     sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
    //         .await
    //         .unwrap();
    //     sns::swap::smoke_test_participate_and_finalize(
    //         &pocket_ic,
    //         sns.swap.canister_id,
    //         swap_parameters,
    //     )
    //     .await;

    //     sns
    // };

    let lp_adaptor_canister_id = PrincipalId::new_user_test_id(444);
    let lp_adaptor_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: lp_adaptor_canister_id.0,
    };

    let sns_root_canister_id = PrincipalId::new_user_test_id(123);

    // Install the SNS ledger (normally, this is part of the SNS deployment).
    let sns_ledger_canister_id = {
        let wasm_path = std::env::var("IC_ICRC1_LEDGER_WASM_PATH")
            .expect("IC_ICRC1_LEDGER_WASM_PATH must be set.");

        let icrc1_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![sns_root_canister_id];

        let arg = InitArgsBuilder::with_symbol_and_name("SNS", "My DAO Token")
            .with_minting_account(Account {
                owner: sns_root_canister_id.0,
                subaccount: None,
            })
            .build();

        let arg = LedgerArgument::Init(arg);

        let arg = candid::encode_one(&arg).unwrap();

        install_canister_on_subnet(
            &pocket_ic,
            sns_subnet_id,
            arg,
            Some(icrc1_wasm),
            controllers,
        )
        .await
        .get()
    };

    // Install KongSwap
    let kong_backend_canister_id = {
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

    let lp_adaptor_icp_account = AccountIdentifier::new(lp_adaptor_canister_id, None);

    let lp_adaptor_sns_account = Account {
        owner: lp_adaptor_canister_id.0,
        subaccount: None,
    };

    let assert_dao_balances = async |pocket_ic: &PocketIc, icp: u64, sns: u64| {
        {
            let observed_icp_tokens =
                nns::ledger::account_balance(pocket_ic, &lp_adaptor_icp_account).await;
            let expected_icp_tokens = Tokens::from_e8s(icp);
            assert_eq!(
                observed_icp_tokens, expected_icp_tokens,
                "Unexpected ICP balance."
            );
        }
        {
            let observed_sns_tokens = sns::ledger::icrc1_balance_of(
                pocket_ic,
                sns_ledger_canister_id,
                lp_adaptor_sns_account,
            )
            .await;
            let expected_sns_tokens = Nat::from(sns);
            assert_eq!(
                observed_sns_tokens, expected_sns_tokens,
                "Unexpected SNS balance."
            );
        }
    };

    // Approve some ICP from the LP Adaptor.
    nns::ledger::mint_icp(
        &pocket_ic,
        lp_adaptor_icp_account,
        Tokens::from_tokens(100).unwrap(),
        None,
    )
    .await;

    assert_dao_balances(&pocket_ic, 100 * E8, 0).await;

    // Approve some SNS tokens from the LP Adaptor.
    sns::ledger::icrc1_transfer(
        &pocket_ic,
        sns_ledger_canister_id,
        sns_root_canister_id,
        TransferArg {
            from_subaccount: None,
            to: lp_adaptor_sns_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(350 * E8),
        },
    )
    .await
    .unwrap();

    assert_dao_balances(&pocket_ic, 100 * E8, 350 * E8).await;

    // Set up the ICP allowance.
    lp_adaptor_agent
        .call(
            LEDGER_CANISTER_ID,
            ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: kong_backend_canister_id.get().0,
                    subaccount: None,
                },
                amount: Nat::from(u64::MAX),
                expected_allowance: Some(Nat::from(0u8)),
                expires_at: Some(u64::MAX),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_dao_balances(
        &pocket_ic,
        100 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
        350 * E8,
    )
    .await;

    // Set up the SNS allowance.
    lp_adaptor_agent
        .call(
            sns_ledger_canister_id,
            ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: kong_backend_canister_id.get().0,
                    subaccount: None,
                },
                amount: Nat::from(3500 * E8 + DEFAULT_TRANSFER_FEE.get_e8s()),
                expected_allowance: Some(Nat::from(0u8)),
                expires_at: Some(u64::MAX),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_dao_balances(
        &pocket_ic,
        100 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
        350 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
    )
    .await;

    let sns_token = Asset::new_token("SNS", sns_ledger_canister_id).unwrap();
    let icp_token = Asset::new_token("ICP", LEDGER_CANISTER_ID).unwrap();

    let kong_swap_adaptor = {
        let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
            .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

        let kongswap_adaptor_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![PrincipalId::new_user_test_id(42)];

        let arg = TreasuryManagerArg::Init(TreasuryManagerInit {
            allowances: vec![
                Allowance {
                    amount_decimals: Nat::from(0_u64),
                    asset: sns_token,
                },
                Allowance {
                    amount_decimals: Nat::from(0_u64),
                    asset: icp_token,
                },
            ],
        });

        let arg = candid::encode_one(&arg).unwrap();

        install_canister_on_subnet(
            &pocket_ic,
            fiduciary_subnet_id,
            arg,
            Some(kongswap_adaptor_wasm),
            controllers,
        )
        .await
    };
    
    for _ in 0..100 {
        pocket_ic.advance_time(Duration::from_secs(1)).await;
        pocket_ic.tick().await;
    }

    {
        let response = pocket_ic
            .call(
                kong_swap_adaptor,
                DepositRequest {
                    allowances: vec![
                        Allowance {
                            amount_decimals: Nat::from(200 * E8),
                            asset: sns_token,
                        },
                        Allowance {
                            amount_decimals: Nat::from(50 * E8),
                            asset: icp_token,
                        },
                    ]
                }
            )
            .await
            .unwrap();

        println!("response = {:#?}", response);

        assert_dao_balances(
            &pocket_ic,
            50 * E8 - 2 * DEFAULT_TRANSFER_FEE.get_e8s(),
            150 * E8 - 2 * DEFAULT_TRANSFER_FEE.get_e8s(),
        )
        .await;
    }

    // let err = kong_swap_adaptor.refresh_balances().await.unwrap_err();
    // assert_eq!(err, TransactionError::Backend("User not found".to_string()));

    

    // assert_eq!(
    //     kong_swap_adaptor.refresh_balances().await,
    //     Ok(btreemap! {
    //         sns_token => Nat::from(200 * E8),
    //         icp_token => Nat::from(50 * E8),
    //     }),
    // );

    // // Kong-specific assertion.
    // let response = lp_adaptor_agent
    //     .call(kong_backend_canister_id, TokensArgs { symbol: None })
    //     .await
    //     .unwrap()
    //     .unwrap();
    // println!("second tokens response = {:#?}", response);

    // // Kong-specific assertion.
    // let response = lp_adaptor_agent
    //     .call(kong_backend_canister_id, PoolsArgs { symbol: None })
    //     .await
    //     .unwrap()
    //     .unwrap();
    // println!("second pools response = {:#?}", response);

    // // Step 2: Increase the liquidity allocation.
    // kong_swap_adaptor
    //     .deposit(vec![
    //         Allowance {
    //             amount_decimals: Nat::from(140 * E8),
    //             ledger_canister_id: sns_ledger_canister_id,
    //         },
    //         Allowance {
    //             amount_decimals: Nat::from(35 * E8),
    //             ledger_canister_id: LEDGER_CANISTER_ID,
    //         },
    //     ])
    //     .await
    //     .unwrap();

    // assert_dao_balances(
    //     &pocket_ic,
    //     15 * E8 - 3 * DEFAULT_TRANSFER_FEE.get_e8s(),
    //     10 * E8 - 3 * DEFAULT_TRANSFER_FEE.get_e8s(),
    // )
    // .await;

    // // Debugging: Print the SNS Ledger block details.

    // assert_eq!(
    //     kong_swap_adaptor.refresh_balances().await,
    //     Ok(btreemap! {
    //         sns_token => Nat::from(340 * E8),
    //         icp_token => Nat::from(85 * E8),
    //     }),
    // );

    // // Kong-specific assertion.
    // let response = lp_adaptor_agent
    //     .call(kong_backend_canister_id, PoolsArgs { symbol: None })
    //     .await
    //     .unwrap()
    //     .unwrap();
    // println!("third pools response = {:#?}", response);

    // let withdrawn_amounts = kong_swap_adaptor.withdraw().await.unwrap();

    // println!("withdrawn_amounts = {:#?}", withdrawn_amounts);

    // assert_eq!(
    //     kong_swap_adaptor.refresh_balances().await,
    //     Ok(btreemap! {
    //         sns_token => Nat::from(0_u8),
    //         icp_token => Nat::from(0_u8),
    //     }),
    // );

    // assert_dao_balances(
    //     &pocket_ic,
    //     100 * E8 - 4 * DEFAULT_TRANSFER_FEE.get_e8s(),
    //     350 * E8 - 4 * DEFAULT_TRANSFER_FEE.get_e8s(),
    // )
    // .await;

    // let audit_trail = kong_swap_adaptor.audit_trail();

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
