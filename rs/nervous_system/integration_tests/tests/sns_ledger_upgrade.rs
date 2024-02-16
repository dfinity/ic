use candid::{Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{add_wasm_via_nns_proposal, install_canister, install_nns_canisters, nns},
};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{self, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::{
    governance::ONE_MONTH_SECONDS,
    pb::v1::{
        proposal, CreateServiceNervousSystem, ExecuteNnsFunction, Neuron, NnsFunction, Proposal,
    },
};
use ic_nns_test_utils::{
    common::build_sns_wasms_wasm,
    sns_wasm::{build_archive_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm},
};
use ic_sns_governance::pb::v1::{self as sns_pb, UpgradeSnsToNextVersion};
use ic_sns_swap::swap::principal_to_subaccount;
use ic_sns_wasm::pb::v1::get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::{allowance::AllowanceArgs, approve::ApproveArgs, transfer_from::TransferFromArgs},
};
use maplit::btreemap;
use pocket_ic::PocketIcBuilder;
use rust_decimal::prelude::ToPrimitive;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

use ic_nervous_system_integration_tests::pocket_ic_helpers::sns;

#[derive(Clone, Copy, Debug)]
pub struct DirectParticipantConfig {
    pub use_ticketing_system: bool,
}

fn test_sns_ledger_upgrade_with_params(
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
    direct_participant_principal_ids: BTreeMap<PrincipalId, DirectParticipantConfig>,
    expect_sns_ledger_to_spawn_archives: bool,
    upgrade_sns_wasm: bool,
) {
    let swap_parameters = create_service_nervous_system_proposal
        .swap_parameters
        .clone()
        .unwrap();
    let min_participant_icp_e8s = swap_parameters
        .minimum_participant_icp
        .unwrap()
        .e8s
        .unwrap();
    let max_direct_participation_icp_e8s = swap_parameters
        .maximum_direct_participation_icp
        .unwrap()
        .e8s
        .unwrap();
    let dapp_canister_ids: Vec<_> = create_service_nervous_system_proposal
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();
    let transaction_fee_sns_e8s = create_service_nervous_system_proposal
        .ledger_parameters
        .as_ref()
        .unwrap()
        .transaction_fee
        .unwrap()
        .e8s
        .unwrap();

    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let direct_participants: BTreeMap<PrincipalId, _> = if direct_participant_principal_ids
        .is_empty()
    {
        btreemap! {}
    } else {
        let participation_amount_per_direct_participant_icp = Tokens::from_e8s(
            (max_direct_participation_icp_e8s / (direct_participant_principal_ids.len() as u64))
                + DEFAULT_TRANSFER_FEE.get_e8s(),
        );
        // Sanity check
        assert!(
            participation_amount_per_direct_participant_icp.get_e8s() >= min_participant_icp_e8s
        );
        direct_participant_principal_ids
            .iter()
            .map(|(direct_participant, direct_participant_config)| {
                (
                    *direct_participant,
                    (
                        AccountIdentifier::new(*direct_participant, None),
                        participation_amount_per_direct_participant_icp,
                        direct_participant_config,
                    ),
                )
            })
            .collect()
    };

    // Install the pre-configured NNS canisters, obtaining information about the original neuron(s).
    let (_original_nns_controller_to_neurons, _sns_wasms) = {
        let direct_participant_initial_icp_balances = direct_participants
            .values()
            .map(|(account_identifier, balance_icp, _)| (*account_identifier, *balance_icp))
            .collect();

        // Start with the mainnet SNS-W wasm if and only if `upgrade_sns_wasm`.
        let with_mainnet_sns_wasm_wasm = upgrade_sns_wasm;
        let with_mainnet_ledger_wasms = true;
        let (nns_neuron_controller_principal_ids, sns_wasms) = install_nns_canisters(
            &pocket_ic,
            direct_participant_initial_icp_balances,
            with_mainnet_sns_wasm_wasm,
            with_mainnet_ledger_wasms,
        );

        let nns_neurons = nns_neuron_controller_principal_ids
            .into_iter()
            .map(|controller_principal_id| {
                let response = nns::governance::list_neurons(&pocket_ic, controller_principal_id);
                (controller_principal_id, response.full_neurons)
            })
            .collect::<BTreeMap<PrincipalId, Vec<Neuron>>>();
        (nns_neurons, sns_wasms)
    };

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

    // TODO[NNS1-2856]: Move the SNS-W upgrade to the end of the runbook.
    //
    // We currently need the order to be (SNS-W, Index, Ledger, Archive) due to a breaking change
    // in `SnsInitPayload` validation.
    //
    // Normally, the order should be (Index, Ledger, Archive, SNS-W) to avoid breaking changes in
    // one th einit args of one of the (Index, Ledger, Archive) canisters to prevent SNS deployment.
    //
    // The special order (SNS-W, Index, Ledger, Archive) works so long as we have the
    // 234f489698681ec6b6f4b996c19d693d9cbb418fd52294348c1e704d0d8f98c6 version of Index, for which
    // there is a special code path in `SnsInitPayload.build_canister_payloads`.
    if upgrade_sns_wasm {
        let pre_upgrade_module_hash = pocket_ic
            .canister_status(SNS_WASM_CANISTER_ID.into(), Some(ROOT_CANISTER_ID.get().0))
            .unwrap()
            .module_hash;

        let new_sns_wasm_wasm = build_sns_wasms_wasm();
        let change_canister_request =
            ChangeCanisterRequest::new(true, CanisterInstallMode::Upgrade, SNS_WASM_CANISTER_ID)
                .with_memory_allocation(ic_nns_constants::memory_allocation_of(
                    SNS_WASM_CANISTER_ID,
                ))
                .with_wasm(new_sns_wasm_wasm.bytes());
        let proposal_info = nns::governance::propose_and_wait(
            &pocket_ic,
            Proposal {
                title: Some("Upgrade SNS-WASM to the latest version.".to_string()),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::NnsCanisterUpgrade as i32,
                    payload: Encode!(&change_canister_request).unwrap(),
                })),
            },
        )
        .unwrap();

        // Check W1: The upgrade proposal did not fail.
        assert_eq!(proposal_info.failure_reason, None);

        // Check W2: The upgrade proposal succeeded.
        assert!(proposal_info.executed_timestamp_seconds > 0);

        pocket_ic.advance_time(Duration::from_millis(1000));
        for _ in 0..10 {
            pocket_ic.tick();
        }

        // Check W3: WASM module hash must change.
        let post_upgrade_module_hash = pocket_ic
            .canister_status(SNS_WASM_CANISTER_ID.into(), Some(ROOT_CANISTER_ID.get().0))
            .unwrap()
            .module_hash;
        assert!(
            post_upgrade_module_hash != pre_upgrade_module_hash,
            "post_upgrade_module_hash == pre_upgrade_module_hash == {:#?}",
            pre_upgrade_module_hash
        );
    }

    // 2. Create an SNS instance
    let proposal_info = nns::governance::propose_and_wait(
        &pocket_ic,
        Proposal {
            title: Some(format!("Create SNS #{}", 1)),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::CreateServiceNervousSystem(
                create_service_nervous_system_proposal,
            )),
        },
    )
    .unwrap();
    let proposal_id = proposal_info.id.unwrap();

    let Some(GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns)) =
        nns::sns_wasm::get_deployed_sns_by_proposal_id(&pocket_ic, proposal_id)
            .get_deployed_sns_by_proposal_id_result
    else {
        panic!(
            "Proposal {:?} did not result in a successfully deployed SNS",
            proposal_id
        );
    };

    // The proposal created a Swap and SNS Governance canisters that we can now start
    // interacting with.
    let sns_root_canister_id = deployed_sns.root_canister_id.unwrap();
    let sns_governance_canister_id = deployed_sns.governance_canister_id.unwrap();
    let swap_canister_id = deployed_sns.swap_canister_id.unwrap();
    let sns_ledger_canister_id = deployed_sns.ledger_canister_id.unwrap();
    let index_canister_id = deployed_sns.index_canister_id.unwrap();

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this neuron
    // either holds the majority of the voting power or the follow graph is set up s.t. when this
    // neuron submits a proposal, that proposal gets through without the need for any voting.
    let (sns_neuron_id, sns_neuron_principal_id) =
        sns::governance::find_neuron_with_majority_voting_power(
            &pocket_ic,
            sns_governance_canister_id,
        )
        .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    // Try to spawn an Archive canister. We assume that this number of transactions are needed,
    // which currently cannot be configured via proposals and is thus hard coded.
    let num_transactions_needed_to_spawn_first_archive = 2000_u64;

    // Testing the Archive canister requires that it can be spawned quickly enough.
    let archive_canister_id = if expect_sns_ledger_to_spawn_archives {
        (0..num_transactions_needed_to_spawn_first_archive).find_map(|i| {
            let mut archives = sns::ledger::archives(&pocket_ic, sns_ledger_canister_id);
            if let Some(archive) = archives.pop() {
                return Some(PrincipalId::from(archive.canister_id));
            }

            let user_principal_id = PrincipalId::new_user_test_id(i);
            let direct_participant_swap_subaccount =
                Some(principal_to_subaccount(&user_principal_id));
            let direct_participant_swap_account = Account {
                owner: swap_canister_id.0,
                subaccount: direct_participant_swap_subaccount,
            };
            let _block_height = sns::ledger::icrc1_transfer(
                &pocket_ic,
                sns_ledger_canister_id,
                sns_governance_canister_id,
                TransferArg {
                    from_subaccount: None,
                    to: direct_participant_swap_account,
                    fee: None,
                    created_at_time: None,
                    memo: None,
                    amount: Nat::from(100_000_u64), // mint an arbitrary amount of SNS tokens
                },
            )
            .unwrap();
            None
        })
    } else {
        None
    };

    // A local helper function that checks whether archived and non-archived blocks add up.
    let check_blocks = |label: &str| {
        let all_blocks: BTreeSet<_> =
            sns::ledger::get_all_blocks(&pocket_ic, sns_ledger_canister_id, 0, u64::MAX)
                .blocks
                .into_iter()
                .collect();
        let non_archived_blocks: BTreeSet<_> = {
            let response = sns::ledger::get_blocks(&pocket_ic, sns_ledger_canister_id, 0, u64::MAX);
            println!("response = {:#?}", response);
            response.blocks.into_iter().collect()
        };
        assert!(non_archived_blocks.is_subset(&all_blocks));
        assert!(
            !all_blocks.is_empty(),
            "There should be some blocks.\nall_blocks = {:?}\nnon_archived_blocks = {:?}",
            all_blocks,
            non_archived_blocks
        );
        assert!(
            !non_archived_blocks.is_empty(),
            "Some blocks should not be archived.\nall_blocks = {:?}\nnon_archived_blocks = {:?}",
            all_blocks,
            non_archived_blocks
        );
        if expect_sns_ledger_to_spawn_archives {
            assert!(
                non_archived_blocks.len() < all_blocks.len(),
                "Some blocks should be archived.\nall_blocks = {:?}\nnon_archived_blocks = {:?}",
                all_blocks,
                non_archived_blocks
            );
        }
        println!("{} check passed!", label);
    };

    // Test upgrading SNS Ledger via proposal
    // Add all the WASMs to SNS-W.
    {
        let wasm = build_index_ng_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
        println!("Add Index WASM proposal info: {:?}", proposal_info);
    }
    {
        let wasm = build_ledger_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
        println!("Add Ledger WASM proposal info: {:?}", proposal_info);
    }
    {
        let wasm = build_archive_sns_wasm();
        let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
        assert_eq!(proposal_info.failure_reason, None);
        println!("Add Archive WASM proposal info: {:?}", proposal_info);
    }

    // Upgrade; one canister at a time.
    let trigger_actual_upgrade = || {
        let proposal_result = sns::governance::propose_and_wait(
            &pocket_ic,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_pb::Proposal {
                title: "Upgrade to the next SNS version.".to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(sns_pb::proposal::Action::UpgradeSnsToNextVersion(
                    UpgradeSnsToNextVersion {},
                )),
            },
        )
        .unwrap();
        assert_eq!(proposal_result.failure_reason, None);

        pocket_ic.advance_time(Duration::from_millis(1000));
        pocket_ic.tick();
    };

    // Upgrade Index-Ng
    {
        let pre_upgrade_module_hash = pocket_ic
            .canister_status(
                index_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;

        trigger_actual_upgrade();

        // Check I1: WASM module hash must change.
        let post_upgrade_module_hash = pocket_ic
            .canister_status(
                index_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;
        assert!(
            post_upgrade_module_hash != pre_upgrade_module_hash,
            "post_upgrade_module_hash == pre_upgrade_module_hash == {:#?}",
            pre_upgrade_module_hash
        );

        // Check I2: The Index canister still recognised our Ledger canitser.
        assert_eq!(
            sns::index_ng::ledger_id(&pocket_ic, index_canister_id),
            sns_ledger_canister_id
        );

        // Check I3: Index and Ledger sync.
        sns::wait_until_ledger_and_index_sync_is_completed(
            &pocket_ic,
            sns_ledger_canister_id,
            index_canister_id,
        );

        // Check I4: The same blocks can be observed via Index and Ledger.
        sns::assert_ledger_index_parity(&pocket_ic, sns_ledger_canister_id, index_canister_id);
    }

    // Upgrade SNS Ledger
    {
        let pre_upgrade_module_hash = pocket_ic
            .canister_status(
                sns_ledger_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;

        let original_total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
                .0
                .to_u64()
                .unwrap();

        let pre_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns_ledger_canister_id, 0_u64, 1_u64).chain_length;

        check_blocks("SNS Ledger pre_upgrade");

        trigger_actual_upgrade();

        // Check L1: WASM module hash must change.
        let post_upgrade_module_hash = pocket_ic
            .canister_status(
                sns_ledger_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;
        assert!(
            post_upgrade_module_hash != pre_upgrade_module_hash,
            "post_upgrade_module_hash == pre_upgrade_module_hash == {:#?}",
            pre_upgrade_module_hash
        );

        // Check L2: We get the expected state in the archive(s).
        check_blocks("SNS Ledger post_upgrade");

        // Check L3: We get the expected number of blocks.
        let post_upgrade_chain_length =
            sns::ledger::get_blocks(&pocket_ic, sns_ledger_canister_id, 0_u64, 1_u64).chain_length;
        assert_eq!(post_upgrade_chain_length, pre_upgrade_chain_length);

        // Check L4: Total supply remains unchanged.
        let total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns_ledger_canister_id)
                .0
                .to_u64()
                .unwrap();
        assert_eq!(total_supply_sns_e8s, original_total_supply_sns_e8s);

        // Check L5: ICRC-2 endpoints
        let (wealthy_user_principal_id, wealthy_user) = {
            let wealthy_user_principal_id = PrincipalId::new_user_test_id(1_000_001);
            let wealthy_user = Account {
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
                    to: wealthy_user,
                    fee: None,
                    created_at_time: None,
                    memo: None,
                    amount: Nat::from(200_000_u64),
                },
            )
            .unwrap();
            (wealthy_user_principal_id, wealthy_user)
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
                from_subaccount: wealthy_user.subaccount,
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
                account: wealthy_user,
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
                from: wealthy_user,
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
    if expect_sns_ledger_to_spawn_archives {
        let archive_canister_id = archive_canister_id.unwrap();

        let pre_upgrade_module_hash = pocket_ic
            .canister_status(
                archive_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;

        check_blocks("SNS Archive pre_upgrade");

        trigger_actual_upgrade();

        // Check L1: WASM module hash must change.
        let post_upgrade_module_hash = pocket_ic
            .canister_status(
                archive_canister_id.into(),
                Some(Principal::from(sns_root_canister_id)),
            )
            .unwrap()
            .module_hash;
        assert!(
            post_upgrade_module_hash != pre_upgrade_module_hash,
            "post_upgrade_module_hash == pre_upgrade_module_hash == {:#?}",
            pre_upgrade_module_hash
        );

        // Check L2: We get the expected state in the archive(s).
        check_blocks("SNS Archive post_upgrade");
    }
}

#[test]
fn test_sns_ledger_upgrade_wo_archives_followed_by_sns_w_upgrade() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();
    test_sns_ledger_upgrade_with_params(create_service_nervous_system, btreemap! {}, false, true)
}

#[test]
fn test_sns_ledger_upgrade_with_archive() {
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .build();
    test_sns_ledger_upgrade_with_params(create_service_nervous_system, btreemap! {}, true, false)
}
