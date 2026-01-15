use candid::Nat;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, add_wasms_to_sns_wasm, install_canister, nns,
        sns::{self, governance::set_automatically_advance_target_version_flag},
        upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::{self, GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm,
    create_modified_sns_wasm,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::SnsCanisterType;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::{allowance::AllowanceArgs, approve::ApproveArgs, transfer_from::TransferFromArgs},
};
use pocket_ic::PocketIcBuilder;
use rust_decimal::prelude::ToPrimitive;

#[tokio::test]
async fn test_upgrade_existing_sns() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();
    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();

    let dapp_canister_ids: Vec<_> = create_service_nervous_system
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();

    let transaction_fee_sns_e8s = create_service_nervous_system
        .ledger_parameters
        .as_ref()
        .unwrap()
        .transaction_fee
        .unwrap()
        .e8s
        .unwrap();

    eprintln!("1. Prepare the world (use mainnet WASMs for all NNS and SNS canisters) ...");
    let pocket_ic = {
        let pocket_ic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_sns_subnet()
            .build_async()
            .await;

        eprintln!("Install the test dapp ...");
        for dapp_canister_id in dapp_canister_ids.clone() {
            install_canister(
                &pocket_ic,
                "My Test Dapp",
                dapp_canister_id,
                vec![],
                Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
                None,
            )
            .await;
        }

        eprintln!("Install the (mainnet) NNS canisters ...");
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_mainnet_nns_canister_versions();
        nns_installer.install(&pocket_ic).await;

        eprintln!(" Publish (mainnet) SNS Wasms to SNS-W ...");
        let with_mainnet_sns_wasms = true;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_wasms)
            .await
            .unwrap();

        pocket_ic
    };

    // We don't publish or upgrade any release candidate canisters yet. We want to deploy a mainnet
    // version of the SNS first, then upgrade and validate.

    eprintln!("Deploy an SNS instance via proposal ...");
    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    eprintln!("Await the swap lifecycle ...");
    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();

    eprintln!("smoke_test_participate_and_finalize ...");
    sns::swap::smoke_test_participate_and_finalize(
        &pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    eprintln!(
        "Disabling automatic upgrades to have full control over when an upgrade is triggered ..."
    );
    let automatically_advance_target_version = false;
    set_automatically_advance_target_version_flag(
        &pocket_ic,
        sns.governance.canister_id,
        automatically_advance_target_version,
    )
    .await
    .unwrap();

    eprintln!("Testing the Archive canister requires that it can be spawned ...");
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns.governance.canister_id,
        sns.ledger.canister_id,
    )
    .await;

    eprintln!("Step 3. Upgrade NNS Governance and SNS-W to the latest version ...");
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID).await;
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, SNS_WASM_CANISTER_ID).await;

    eprintln!("Test upgrading SNS Ledger via proposals. First, add all the WASMs to SNS-W ...");
    {
        let wasm = build_index_ng_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_ledger_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_archive_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // ---------------------------
    // --- Run code under test ---
    // ---------------------------

    eprintln!("Upgrade Index-Ng ...");
    {
        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            &sns,
            SnsCanisterType::Index,
        )
        .await;

        eprintln!("Index-Ng check 1: The Index canister still recognized our Ledger canister ...");
        assert_eq!(
            sns::index_ng::ledger_id(&pocket_ic, sns.index.canister_id).await,
            sns.ledger.canister_id
        );

        eprintln!("Index-Ng check 2: Index and Ledger sync ...");
        sns::wait_until_ledger_and_index_sync_is_completed(
            &pocket_ic,
            sns.ledger.canister_id,
            sns.index.canister_id,
        )
        .await;

        eprintln!("Index-Ng check 3: The same blocks can be observed via Index and Ledger ...");
        sns::assert_ledger_index_parity(&pocket_ic, sns.ledger.canister_id, sns.index.canister_id)
            .await;
    }

    eprintln!("Upgrade SNS Ledger ...");
    {
        let original_total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns.ledger.canister_id)
                .await
                .0
                .to_u64()
                .unwrap();

        let pre_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns.ledger.canister_id, 0_u64, 1_u64)
                .await
                .chain_length;

        sns::ledger::check_blocks_or_panic(&pocket_ic, sns.ledger.canister_id).await;

        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            &sns,
            SnsCanisterType::Ledger,
        )
        .await;

        eprintln!("Ledger check 1: We get the expected state in the archive(s) ...");
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns.ledger.canister_id).await;

        eprintln!(
            "Ledger check 2: We get the same number of blocks that we had before the upgrade (because no transactions have happened after the upgrade) ..."
        );
        let post_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns.ledger.canister_id, 0_u64, 1_u64)
                .await
                .chain_length;
        assert_eq!(post_upgrade_chain_length, pre_upgrade_chain_length);

        eprintln!("Ledger check 3: Total supply remains unchanged ...");
        let total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns.ledger.canister_id)
                .await
                .0
                .to_u64()
                .unwrap();
        assert_eq!(total_supply_sns_e8s, original_total_supply_sns_e8s);

        eprintln!("Ledger check 4: ICRC-2 endpoints ...");
        // First we "create" a wealthy user by minting tokens into their account.
        // Second, we use the wealthy user's credentials to test a pre-approved (ICRC-2) transaction.
        let (wealthy_user_principal_id, wealthy_user_account) = {
            let wealthy_user_principal_id = PrincipalId::new_user_test_id(1_000_001);
            let wealthy_user_account = Account {
                owner: wealthy_user_principal_id.0,
                subaccount: None,
            };

            eprintln!("Mint some tokens for the wealthy user ...");
            let _block_height = sns::ledger::icrc1_transfer(
                &pocket_ic,
                sns.ledger.canister_id,
                sns.governance.canister_id,
                TransferArg {
                    from_subaccount: None,
                    to: wealthy_user_account,
                    fee: None,
                    created_at_time: None,
                    memo: None,
                    amount: Nat::from(200_000_u64),
                },
            )
            .await
            .unwrap();
            (wealthy_user_principal_id, wealthy_user_account)
        };
        let current_ic_unix_time_nanos = pocket_ic.get_time().await.as_nanos_since_unix_epoch();
        let spender_principal_id = PrincipalId::new_user_test_id(1_000_002);
        let spender = Account {
            owner: spender_principal_id.0,
            subaccount: None,
        };
        sns::ledger::icrc2_approve(
            &pocket_ic,
            sns.ledger.canister_id,
            wealthy_user_principal_id,
            ApproveArgs {
                from_subaccount: wealthy_user_account.subaccount,
                amount: Nat::from(100_000_u64),
                expected_allowance: Some(Nat::from(0u8)),
                expires_at: Some(current_ic_unix_time_nanos + 100_000_000_000),
                fee: Some(Nat::from(transaction_fee_sns_e8s)),
                memo: None,
                created_at_time: None,
                spender,
            },
        )
        .await
        .unwrap();
        let allowance = sns::ledger::icrc2_allowance(
            &pocket_ic,
            sns.ledger.canister_id,
            PrincipalId::new_anonymous(),
            AllowanceArgs {
                account: wealthy_user_account,
                spender,
            },
        )
        .await;
        assert_eq!(allowance.allowance, Nat::from(100_000_u64));
        sns::ledger::icrc2_transfer_from(
            &pocket_ic,
            sns.ledger.canister_id,
            spender_principal_id,
            TransferFromArgs {
                spender_subaccount: None,
                from: wealthy_user_account,
                to: spender,
                amount: Nat::from(100_000_u64 - transaction_fee_sns_e8s),
                fee: Some(Nat::from(transaction_fee_sns_e8s)),
                memo: None,
                created_at_time: Some(current_ic_unix_time_nanos + 50_000_000_000),
            },
        )
        .await
        .unwrap();
    }

    eprintln!("Upgrade SNS Archive ...");
    {
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns.ledger.canister_id).await;

        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            &sns,
            SnsCanisterType::Archive,
        )
        .await;

        eprintln!("Archive check 1: We get the expected state in the archive(s) ...");
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns.ledger.canister_id).await;
    }

    eprintln!(
        "Publish modified versions of all the wasms and ensure we can upgrade a second time (pre-upgrade smoke test) ..."
    );
    {
        let wasm = create_modified_sns_wasm(&build_index_ng_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = create_modified_sns_wasm(&build_ledger_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = create_modified_sns_wasm(&build_archive_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).await.unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    for sns_canister_type in [
        SnsCanisterType::Index,
        SnsCanisterType::Ledger,
        SnsCanisterType::Archive,
    ] {
        eprintln!("upgrade_sns_to_next_version_and_assert_change {sns_canister_type:?} ...");
        sns::upgrade_sns_to_next_version_and_assert_change(&pocket_ic, &sns, sns_canister_type)
            .await;
    }
}
