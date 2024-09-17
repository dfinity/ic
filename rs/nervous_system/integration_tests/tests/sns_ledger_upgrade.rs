use candid::Nat;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, add_wasms_to_sns_wasm, install_canister, install_nns_canisters,
        nns, sns, upgrade_nns_canister_to_tip_of_master_or_panic,
    },
};
use ic_nns_constants::{self, GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm, build_swap_sns_wasm,
    create_modified_sns_wasm,
};
use ic_sns_wasm::pb::v1::{DeployedSns, SnsCanisterType};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::{allowance::AllowanceArgs, approve::ApproveArgs, transfer_from::TransferFromArgs},
};
use pocket_ic::PocketIcBuilder;
use rust_decimal::prelude::ToPrimitive;
use std::time::SystemTime;

#[test]
fn test_deploy_fresh_sns() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();

    let dapp_canister_ids: Vec<_> = create_service_nervous_system
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();

    // 1. Prepare the world (use mainnet WASMs for all NNS and SNS canisters).
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    // Install the test dapp.
    for dapp_canister_id in dapp_canister_ids.clone() {
        install_canister(
            &pocket_ic,
            "My Test Dapp",
            dapp_canister_id,
            vec![],
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM),
            None,
        );
    }

    // Step 1. Upgrade NNS Governance and SNS-W to the latest version.

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID);

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, SNS_WASM_CANISTER_ID);

    // Publish the newest Swap. This needs to happen here due to a recent breaking change in sns_init
    {
        let wasm = build_swap_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    // Test upgrading SNS Ledger via proposals. First, add all the WASMs to SNS-W.
    {
        let wasm = build_index_ng_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_ledger_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_archive_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // ---------------------------
    // --- Run code under test ---
    // ---------------------------

    // Deploy an SNS instance via proposal.
    let sns_instance_label = "1";
    let (deployed_sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    );
    let DeployedSns {
        governance_canister_id: Some(sns_governance_canister_id),
        ledger_canister_id: Some(sns_ledger_canister_id),
        ..
    } = deployed_sns
    else {
        panic!("Cannot find some SNS caniser IDs in {:#?}", deployed_sns);
    };

    // Testing the Archive canister requires that it can be spawned.
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns_governance_canister_id,
        sns_ledger_canister_id,
    );
    // TODO eventually we need to test a swap
}

#[test]
fn test_upgrade_existing_sns() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();

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

    // 1. Prepare the world (use mainnet WASMs for all NNS and SNS canisters)
    let pocket_ic = {
        let pocket_ic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_sns_subnet()
            .build();

        // Install the test dapp.
        for dapp_canister_id in dapp_canister_ids.clone() {
            install_canister(
                &pocket_ic,
                "My Test Dapp",
                dapp_canister_id,
                vec![],
                Wasm::from_bytes(UNIVERSAL_CANISTER_WASM),
                None,
            );
        }

        // Install the (mainnet) NNS canisters.
        let with_mainnet_nns_canisters = true;
        install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, None, vec![]);

        // Publish (mainnet) SNS Wasms to SNS-W.
        let with_mainnet_sns_wasms = true;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_wasms).unwrap();

        pocket_ic
    };

    // We don't publish or upgrade any release candidate canisters yet. We want to deploy a mainnet
    // version of the SNS first, then upgrade and validate.

    // Deploy an SNS instance via proposal.
    let sns_instance_label = "1";
    let (deployed_sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    );
    let DeployedSns {
        governance_canister_id: Some(sns_governance_canister_id),
        root_canister_id: Some(sns_root_canister_id),
        index_canister_id: Some(index_canister_id),
        ledger_canister_id: Some(sns_ledger_canister_id),
        ..
    } = deployed_sns
    else {
        panic!("Cannot find some SNS caniser IDs in {:#?}", deployed_sns);
    };

    // Testing the Archive canister requires that it can be spawned.
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns_governance_canister_id,
        sns_ledger_canister_id,
    );

    // Step 3. Upgrade SNS to the tip of master

    // Step 4. Upgrade NNS Governance and SNS-W to the latest version.
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID);
    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, SNS_WASM_CANISTER_ID);

    // Publish the newest Swap.
    {
        let wasm = build_swap_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // Test upgrading SNS Ledger via proposals. First, add all the WASMs to SNS-W.
    {
        let wasm = build_index_ng_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_ledger_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = build_archive_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    // ---------------------------
    // --- Run code under test ---
    // ---------------------------

    // Upgrade Swap - should be non-event
    sns::upgrade_sns_to_next_version_and_assert_change(
        &pocket_ic,
        sns_root_canister_id,
        SnsCanisterType::Swap,
    );

    // Upgrade Index-Ng
    {
        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            sns_root_canister_id,
            SnsCanisterType::Index,
        );

        // Index-Ng check 1: The Index canister still recognised our Ledger canitser.
        assert_eq!(
            sns::index_ng::ledger_id(&pocket_ic, index_canister_id),
            sns_ledger_canister_id
        );

        // Index-Ng check 2: Index and Ledger sync.
        sns::wait_until_ledger_and_index_sync_is_completed(
            &pocket_ic,
            sns_ledger_canister_id,
            index_canister_id,
        );

        // Index-Ng check 3: The same blocks can be observed via Index and Ledger.
        sns::assert_ledger_index_parity(&pocket_ic, sns_ledger_canister_id, index_canister_id);
    }

    // Upgrade SNS Ledger
    {
        let original_total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
                .0
                .to_u64()
                .unwrap();

        let pre_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns_ledger_canister_id, 0_u64, 1_u64).chain_length;

        sns::ledger::check_blocks_or_panic(&pocket_ic, sns_ledger_canister_id);

        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            sns_root_canister_id,
            SnsCanisterType::Ledger,
        );

        // Ledger check 1: We get the expected state in the archive(s).
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns_ledger_canister_id);

        // Ledger check 2: We get the same number of blocks that we had before the upgrade (because
        // no transactions have happened after the upgrade).
        let post_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns_ledger_canister_id, 0_u64, 1_u64).chain_length;
        assert_eq!(post_upgrade_chain_length, pre_upgrade_chain_length);

        // Ledger check 3: Total supply remains unchanged.
        let total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
                .0
                .to_u64()
                .unwrap();
        assert_eq!(total_supply_sns_e8s, original_total_supply_sns_e8s);

        // Ledger check 4: ICRC-2 endpoints. First we "create" a wealthy user by minting tokens into
        // their account. Second, we use the wealthy user's credentials to test a pre-approved
        // (ICRC-2) transaction.
        let (wealthy_user_principal_id, wealthy_user_account) = {
            let wealthy_user_principal_id = PrincipalId::new_user_test_id(1_000_001);
            let wealthy_user_account = Account {
                owner: wealthy_user_principal_id.0,
                subaccount: None,
            };
            // Mint some tokens for the wealthy user.
            let _block_height = sns::ledger::icrc1_transfer(
                &pocket_ic,
                sns_ledger_canister_id,
                sns_governance_canister_id,
                TransferArg {
                    from_subaccount: None,
                    to: wealthy_user_account,
                    fee: None,
                    created_at_time: None,
                    memo: None,
                    amount: Nat::from(200_000_u64),
                },
            )
            .unwrap();
            (wealthy_user_principal_id, wealthy_user_account)
        };
        let current_ic_unix_time_nanos = pocket_ic
            .get_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let spender_principal_id = PrincipalId::new_user_test_id(1_000_002);
        let spender = Account {
            owner: spender_principal_id.0,
            subaccount: None,
        };
        sns::ledger::icrc2_approve(
            &pocket_ic,
            sns_ledger_canister_id,
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
        .unwrap();
        let allowance = sns::ledger::icrc2_allowance(
            &pocket_ic,
            sns_ledger_canister_id,
            PrincipalId::new_anonymous(),
            AllowanceArgs {
                account: wealthy_user_account,
                spender,
            },
        );
        assert_eq!(allowance.allowance, Nat::from(100_000_u64));
        sns::ledger::icrc2_transfer_from(
            &pocket_ic,
            sns_ledger_canister_id,
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
        .unwrap();
    }

    // Upgrade SNS Archive
    {
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns_ledger_canister_id);

        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            sns_root_canister_id,
            SnsCanisterType::Archive,
        );

        // Archive check 1: We get the expected state in the archive(s).
        sns::ledger::check_blocks_or_panic(&pocket_ic, sns_ledger_canister_id);
    }

    // Publish modified versions of all the wasms and ensure we can upgrade a second time (pre-upgrade smoke test)
    {
        let wasm = create_modified_sns_wasm(&build_swap_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = create_modified_sns_wasm(&build_index_ng_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = create_modified_sns_wasm(&build_ledger_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }
    {
        let wasm = create_modified_sns_wasm(&build_archive_sns_wasm(), Some(42));
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
    }

    for sns_canister_type in [
        SnsCanisterType::Swap,
        SnsCanisterType::Index,
        SnsCanisterType::Ledger,
        SnsCanisterType::Archive,
    ] {
        sns::upgrade_sns_to_next_version_and_assert_change(
            &pocket_ic,
            sns_root_canister_id,
            sns_canister_type,
        );
    }
}
