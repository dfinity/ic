use candid::Nat;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_agent::sns::governance::GovernanceCanister;
use ic_nervous_system_agent::sns::index::IndexCanister;
use ic_nervous_system_agent::sns::ledger::LedgerCanister;
use ic_nervous_system_agent::sns::root::RootCanister;
use ic_nervous_system_agent::sns::swap::SwapCanister;
use ic_nervous_system_agent::sns::Sns;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_common::E8;
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nervous_system_integration_tests::pocket_ic_helpers::add_wasms_to_sns_wasm;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_with_controllers;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_canister_on_subnet, sns};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_sns_swap::pb::v1::Lifecycle;
use icp_ledger::{AccountIdentifier, Tokens, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use maplit::btreemap;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use pretty_assertions::assert_eq;
use sns_treasury_manager::Allowance;
use sns_treasury_manager::Asset;
use sns_treasury_manager::BalancesRequest;
use sns_treasury_manager::DepositRequest;
use sns_treasury_manager::WithdrawRequest;
use sns_treasury_manager::{TreasuryManagerArg, TreasuryManagerInit};
use std::str::FromStr;

const FEE: u64 = DEFAULT_TRANSFER_FEE.get_e8s();

#[tokio::test]
async fn test() {
    test_treasury_manager().await
}

async fn test_treasury_manager() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let sns_subnet_id = topology.get_sns().unwrap();

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    // let sns = deploy_sns(&pocket_ic, false).await;

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

    let sns = Sns {
        root: RootCanister {
            canister_id: sns_root_canister_id,
        },
        ledger: LedgerCanister {
            canister_id: sns_ledger_canister_id,
        },
        governance: GovernanceCanister {
            canister_id: PrincipalId::new_user_test_id(111),
        },
        index: IndexCanister {
            canister_id: PrincipalId::new_user_test_id(222),
        },
        swap: SwapCanister {
            canister_id: PrincipalId::new_user_test_id(333),
        },
        archive: vec![],
    };

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

    let sns_token = Asset::new_token("SNS", sns_ledger_canister_id).unwrap();
    let icp_token = Asset::new_token("ICP", LEDGER_CANISTER_ID).unwrap();

    let adaptor_canister_id = deploy_kong_adaptor(&pocket_ic, &sns).await;

    topup_liquidity(
        &pocket_ic,
        &sns,
        adaptor_canister_id,
        100 * E8 + 2 * FEE,
        350 * E8 + 2 * FEE,
        2 * FEE,
        2 * FEE,
    )
    .await;

    topup_liquidity(
        &pocket_ic,
        &sns,
        adaptor_canister_id,
        50 * E8 + 2 * FEE,
        175 * E8 + 2 * FEE,
        2 * FEE,
        2 * FEE,
    )
    .await;

    {
        let request = BalancesRequest {};
        let response = pocket_ic
            .call(adaptor_canister_id, request)
            .await
            .unwrap()
            .unwrap();

        println!(">>> Balances: {:#?}", response);
    }

    let _withdrawn_amounts = {
        let response = PocketIcAgent::new(&pocket_ic, sns.root.canister_id)
            .call(adaptor_canister_id, WithdrawRequest {})
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            response,
            btreemap! {
                icp_token => Nat::from(150 * E8),
                sns_token => Nat::from(525 * E8),
            },
        );
    };

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
    add_wasms_to_sns_wasm(pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
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

async fn validate_balances(
    lebel: &str,
    sns: &Sns,
    pocket_ic: &PocketIc,
    owner: PrincipalId,
    icp_balance_e8s: u64,
    sns_balance_e8s: u64,
) -> Result<(AccountIdentifier, Account), String> {
    let icp_account = {
        let icp_account = AccountIdentifier::new(owner, None);

        let observed_icp_tokens = nns::ledger::account_balance(pocket_ic, &icp_account).await;

        let expected_icp_tokens = Tokens::from_e8s(icp_balance_e8s);

        if observed_icp_tokens != expected_icp_tokens {
            return Err(format!(
                "[{}] Expected ICP balance of {} = {}, got {}.",
                lebel, owner, expected_icp_tokens, observed_icp_tokens
            ));
        }

        icp_account
    };

    let sns_account = {
        let sns_account = Account {
            owner: owner.0,
            subaccount: None,
        };

        let observed_sns_tokens =
            sns::ledger::icrc1_balance_of(pocket_ic, sns.ledger.canister_id, sns_account).await;

        let expected_sns_tokens = Nat::from(sns_balance_e8s);

        if observed_sns_tokens != expected_sns_tokens {
            return Err(format!(
                "[{}] Expected SNS balance of {} = {}, got {}.",
                lebel, owner, expected_sns_tokens, observed_sns_tokens
            ));
        }

        sns_account
    };

    Ok((icp_account, sns_account))
}

async fn deploy_kong_adaptor(pocket_ic: &PocketIc, sns: &Sns) -> PrincipalId {
    // First, the SNS creates the Adaptor canister without installing the Wasm yet.
    let topology = pocket_ic.topology().await;
    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();

    let adaptor_canister_id = install_canister_on_subnet(
        &pocket_ic,
        fiduciary_subnet_id,
        vec![],
        None,
        vec![sns.root.canister_id],
    )
    .await
    .get();

    // Second, the SNS installs the Treasury Manager Wasm, specifying the initial allowances.
    let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
        .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

    let wasm = Wasm::from_file(wasm_path);

    let sns_token = Asset::new_token("SNS", sns.ledger.canister_id).unwrap();
    let icp_token = Asset::new_token("ICP", LEDGER_CANISTER_ID).unwrap();

    let arg = TreasuryManagerArg::Init(TreasuryManagerInit {
        assets: vec![sns_token, icp_token],
    });
    let arg = candid::encode_one(&arg).unwrap();

    pocket_ic
        .install_canister(
            adaptor_canister_id.0,
            wasm.bytes(),
            arg,
            Some(sns.root.canister_id.0),
        )
        .await;

    adaptor_canister_id
}

async fn topup_liquidity(
    pocket_ic: &PocketIc,
    sns: &Sns,
    adaptor_canister_id: PrincipalId,
    icp_token_allowance_e8s: u64,
    sns_token_allowance_e8s: u64,
    expected_icp_fees_e8s: u64,
    expected_sns_fees_e8s: u64,
) {
    let sns_token = Asset::new_token("SNS", sns.ledger.canister_id).unwrap();
    let icp_token = Asset::new_token("ICP", LEDGER_CANISTER_ID).unwrap();

    let (icp_account, sns_account) = validate_balances(
        "topup_liquidity-0",
        sns,
        pocket_ic,
        adaptor_canister_id,
        0,
        0,
    )
    .await
    .unwrap();

    nns::ledger::mint_icp(
        &pocket_ic,
        icp_account,
        Tokens::from_e8s(icp_token_allowance_e8s),
        None,
    )
    .await;

    sns::ledger::icrc1_transfer(
        &pocket_ic,
        sns.ledger.canister_id,
        sns.root.canister_id,
        TransferArg {
            from_subaccount: None,
            to: sns_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(sns_token_allowance_e8s),
        },
    )
    .await
    .unwrap();

    validate_balances(
        "topup_liquidity-1",
        sns,
        pocket_ic,
        adaptor_canister_id,
        icp_token_allowance_e8s,
        sns_token_allowance_e8s,
    )
    .await
    .unwrap();

    let request = DepositRequest {
        allowances: vec![
            Allowance {
                amount_decimals: Nat::from(sns_token_allowance_e8s),
                asset: sns_token,
                expected_ledger_fee_decimals: Nat::from(FEE),
            },
            Allowance {
                amount_decimals: Nat::from(icp_token_allowance_e8s),
                asset: icp_token,
                expected_ledger_fee_decimals: Nat::from(FEE),
            },
        ],
    };

    let response = PocketIcAgent::new(&pocket_ic, sns.root.canister_id)
        .call(adaptor_canister_id, request)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        response,
        btreemap! {
            sns_token => Nat::from(sns_token_allowance_e8s) - expected_sns_fees_e8s,
            icp_token => Nat::from(icp_token_allowance_e8s) - expected_icp_fees_e8s,
        }
    );

    validate_balances(
        "topup_liquidity-2",
        sns,
        pocket_ic,
        adaptor_canister_id,
        0,
        0,
    )
    .await
    .unwrap();
}
