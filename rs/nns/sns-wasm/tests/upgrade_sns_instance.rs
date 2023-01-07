use candid::{Decode, Encode, Nat};
use canister_test::Wasm;
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::state_test_helpers::{
    query, set_controllers, setup_nns_canisters, update, update_with_sender,
};
use ic_nns_test_utils::{sns_wasm, state_test_helpers};
use maplit::hashmap;
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Duration;

pub mod common;
use crate::common::EXPECTED_SNS_CREATION_FEE;
use ic_ic00_types::CanisterInstallMode;
use ic_icrc1::endpoints::{NumTokens, TransferArg, TransferError};
use ic_icrc1::Account;
use ic_nns_test_utils::sns_wasm::{
    build_archive_sns_wasm, build_governance_sns_wasm, build_index_sns_wasm, build_ledger_sns_wasm,
    build_root_sns_wasm, build_swap_sns_wasm,
};
use ic_sns_governance::pb::v1::governance::{Mode, Version};
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::ProposalDecisionStatus;
use ic_sns_governance::pb::v1::{
    GetRunningSnsVersionRequest, GetRunningSnsVersionResponse, Proposal, UpgradeSnsToNextVersion,
};
use ic_sns_governance::types::{DEFAULT_TRANSFER_FEE, E8S_PER_TOKEN};
use ic_sns_init::pb::v1::sns_init_payload::InitialTokenDistribution;
use ic_sns_init::pb::v1::{
    AirdropDistribution, DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution,
    SnsInitPayload, SwapDistribution, TreasuryDistribution,
};
use ic_sns_root::{
    CanisterStatusResultV2, CanisterStatusType, GetSnsCanistersSummaryRequest,
    GetSnsCanistersSummaryResponse,
};
use ic_sns_wasm::pb::v1::{SnsCanisterIds, SnsCanisterType, SnsWasm};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;
use walrus::{Module, RawCustomSection};

#[test]
fn upgrade_root_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Root);
}

#[test]
fn upgrade_ledger_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Ledger);
}

#[test]
fn upgrade_governance_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Governance);
}

fn run_upgrade_test(canister_type: SnsCanisterType) {
    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);

    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_allowed_principals(vec![wallet_canister_id.into()])
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    // Enough cycles for one SNS deploy.
    let wallet_canister = state_test_helpers::set_up_universal_canister(
        &machine,
        Some(Cycles::new(EXPECTED_SNS_CREATION_FEE)),
    );

    let wasm_map = sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // To get an SNS neuron, we airdrop our new tokens to this user.
    let user = PrincipalId::new_user_test_id(0);

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: Default::default(),
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 10_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
                airdrop_distribution: Some(AirdropDistribution {
                    airdrop_neurons: vec![NeuronDistribution {
                        controller: Some(user),
                        stake_e8s: 2_000_000_000_000,
                        memo: 0,
                        dissolve_delay_seconds: 15780000, // 6 months
                        vesting_period_seconds: None,
                    }],
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing()
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        payload,
        EXPECTED_SNS_CREATION_FEE,
    );

    let SnsCanisterIds {
        root,
        ledger: _,
        governance,
        swap: _,
        index: _,
    } = response.canisters.unwrap();

    let root = CanisterId::new(root.unwrap()).unwrap();
    let governance = CanisterId::new(governance.unwrap()).unwrap();

    let original_hash = wasm_map.get(&canister_type).unwrap().sha256_hash();

    let sns_wasm_to_add = create_modified_wasm(wasm_map.get(&canister_type).unwrap());
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm_to_add);

    // Make a proposal to upgrade (that is auto-executed) with the neuron for our user.
    let neuron_id =
        state_test_helpers::sns_claim_staked_neuron(&machine, governance, user, 0, Some(1_000_000));
    let proposal_id = state_test_helpers::sns_make_proposal(
        &machine,
        governance,
        user,
        neuron_id,
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    let old_version = wasm_map_to_version(&wasm_map);
    sns_wait_for_pending_upgrade(&machine, governance);

    // After the pending upgrade is set, but before upgrade has completed, we expect the old
    // version to be reported as running. The proposal should still be in the "adopted" state.
    let version_response = Decode!(
        &query(
            &machine,
            governance,
            "get_running_sns_version",
            Encode!(&GetRunningSnsVersionRequest {}).unwrap(),
        )
        .unwrap(),
        GetRunningSnsVersionResponse
    )
    .unwrap();
    assert_eq!(version_response.deployed_version, Some(old_version.clone()));
    assert!(version_response.pending_version.is_some());

    let proposal = state_test_helpers::sns_get_proposal(&machine, governance, proposal_id)
        .expect("Unable to get proposal");

    assert_eq!(proposal.status(), ProposalDecisionStatus::Adopted);

    // Wait for proposal execution
    state_test_helpers::sns_wait_for_proposal_execution(&machine, governance, proposal_id);

    // The pending upgrade should be cleared after proposal execution
    let version_response = Decode!(
        &query(
            &machine,
            governance,
            "get_running_sns_version",
            Encode!(&GetRunningSnsVersionRequest {}).unwrap(),
        )
        .unwrap(),
        GetRunningSnsVersionResponse
    )
    .unwrap();

    assert!(version_response.pending_version.is_none());

    // Get the WASM hash of the canister given by `canister_type`. This should be the upgraded hash.
    let statuses = get_canister_statuses(canister_type, &machine, root);
    assert!(!statuses.is_empty());

    let new_hash_vec = new_wasm_hash.to_vec();
    assert!(statuses
        .iter()
        .all(|s| s.module_hash().unwrap() == new_hash_vec));

    // Now we test the upgrade success logic whereby governance confirms that the upgrade was
    // successful by checking if running system matches what was proposed.

    let mut next_version = old_version.clone();
    match canister_type {
        SnsCanisterType::Unspecified => panic!(),
        SnsCanisterType::Root => next_version.root_wasm_hash = new_hash_vec,
        SnsCanisterType::Governance => next_version.governance_wasm_hash = new_hash_vec,
        SnsCanisterType::Ledger => next_version.ledger_wasm_hash = new_hash_vec,
        SnsCanisterType::Swap => panic!("Not supported"),
        SnsCanisterType::Archive => panic!("Not supported (tested in different test)"),
        SnsCanisterType::Index => panic!("Not supported"),
    }

    assert_ne!(old_version, next_version);

    // Now we should expect that the new version is marked as deployed.
    let version_response = Decode!(
        &query(
            &machine,
            governance,
            "get_running_sns_version",
            Encode!(&GetRunningSnsVersionRequest {}).unwrap(),
        )
        .unwrap(),
        GetRunningSnsVersionResponse
    )
    .unwrap();

    assert!(version_response.pending_version.is_none());
    assert_eq!(version_response.deployed_version, Some(next_version));
}

/// This test uses a different setup than the other 3 because it is difficult to get ledgers to spawn
/// archives after SNS-WASM deploy in a test environment, as it requires finalizing the swap so that
/// there are ledger accounts that have funds to be transacted.
///
/// Using this setup allows us to skip that process and have an SNS with archive canisters more easily.
#[test]
fn upgrade_archive_sns_canister_via_sns_wasms() {
    let canister_type = SnsCanisterType::Archive;
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    let wasm_map = sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // To get an SNS neuron, we airdrop our new tokens to this user.
    let user = PrincipalId::new_user_test_id(0);

    let airdrop_neuron = |number| NeuronDistribution {
        controller: Some(PrincipalId::new_user_test_id(number)),
        stake_e8s: 100_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    };
    // We make these to create some extra transactions so an archive will spawn.
    let airdrop_neurons: Vec<NeuronDistribution> =
        (1..20_u64).map(|id| airdrop_neuron(id)).collect();

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: Default::default(),
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 10_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
                airdrop_distribution: Some(AirdropDistribution {
                    airdrop_neurons: vec![NeuronDistribution {
                        controller: Some(user),
                        stake_e8s: 2_000_000_000_000,
                        memo: 0,
                        dissolve_delay_seconds: 15780000, // 6 months
                        vesting_period_seconds: None,
                    }]
                    .into_iter()
                    .chain(airdrop_neurons)
                    .collect(),
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing()
    };

    // Create some canisterIDs
    let root = machine.create_canister(None);
    // Ledger needs cycles to spawn the archives
    let ledger = machine.create_canister_with_cycles(Cycles::new(10 * 1000000000000), None);
    let governance = machine.create_canister(None);
    let swap = machine.create_canister(None);
    let index = machine.create_canister(None);

    let old_version = wasm_map_to_version(&wasm_map);
    let mut init_payloads = payload
        .build_canister_payloads(
            &SnsCanisterIds {
                root: Some(root.get()),
                ledger: Some(ledger.get()),
                governance: Some(governance.get()),
                swap: Some(swap.get()),
                index: Some(index.get()),
            }
            .try_into()
            .unwrap(),
            Some(old_version),
        )
        .unwrap();

    // Update some init payload parameters so that our archive can spawn (i.e. can make a transaction
    // because we have a normal non-neuron ledger account, and no restrictions.
    init_payloads.governance.mode = Mode::Normal.into();
    init_payloads.ledger.archive_options.trigger_threshold = 10;
    init_payloads.ledger.archive_options.num_blocks_to_archive = 5;
    init_payloads.ledger.initial_balances.push((
        Account {
            owner: user,
            subaccount: None,
        },
        100000000,
    ));

    let wasm_for_type = |canister_type| wasm_map.get(canister_type).unwrap().wasm.clone();
    let install_code = |canister: CanisterId, wasm: Vec<u8>, payload| {
        machine
            .install_wasm_in_mode(canister, CanisterInstallMode::Install, wasm, payload)
            .unwrap()
    };
    install_code(
        root,
        wasm_for_type(&SnsCanisterType::Root),
        Encode!(&init_payloads.root).unwrap(),
    );
    install_code(
        governance,
        wasm_for_type(&SnsCanisterType::Governance),
        Encode!(&init_payloads.governance).unwrap(),
    );
    install_code(
        ledger,
        wasm_for_type(&SnsCanisterType::Ledger),
        Encode!(&init_payloads.ledger).unwrap(),
    );
    install_code(
        swap,
        wasm_for_type(&SnsCanisterType::Swap),
        Encode!(&init_payloads.swap).unwrap(),
    );
    install_code(
        index,
        wasm_for_type(&SnsCanisterType::Index),
        Encode!(&init_payloads.index).unwrap(),
    );

    machine.tick();

    // Set controllers!
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        root,
        vec![governance.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        governance,
        vec![root.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        ledger,
        vec![root.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        swap,
        vec![swap.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        index,
        vec![root.get()],
    );

    // We need a ledger archive, so we need to do a transaction to trigger that.
    // The transaction doesn't need to make any sense.
    let _: Result<Nat, TransferError> = update_with_sender(
        &machine,
        ledger,
        "icrc1_transfer",
        candid_one,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: user,
                subaccount: Some([1; 32]),
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: NumTokens::from(10_u8),
        },
        user,
    )
    .unwrap();

    // Ensure that our governance canister does not know about our archives yet. It should discover it
    // during the upgrade process.
    let status_summary = update(
        &machine,
        root,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: None
        })
        .unwrap(),
    )
    .unwrap();
    let status_summary = Decode!(&status_summary, GetSnsCanistersSummaryResponse).unwrap();

    assert!(status_summary.archives.is_empty());

    let current_wasm = wasm_map.get(&SnsCanisterType::Archive).unwrap();
    let original_hash = current_wasm.sha256_hash();

    // We add a new WASM to the SNS-WASMs (for whatever canister we want to test)
    let sns_wasm_to_add = create_modified_wasm(current_wasm);
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm_to_add);

    // Make a proposal to upgrade (that is auto-executed) with the neuron for our user.
    let neuron_id =
        state_test_helpers::sns_claim_staked_neuron(&machine, governance, user, 0, Some(1_000_000));

    let proposal_id = state_test_helpers::sns_make_proposal(
        &machine,
        governance,
        user,
        neuron_id,
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    state_test_helpers::sns_wait_for_proposal_execution(&machine, governance, proposal_id);

    // advance by more than a day so we will get the archive list
    machine.advance_time(Duration::from_secs(25 * 60 * 60));

    let statuses = sns_wait_for_upgrade_finished(canister_type, &machine, root);
    assert!(!statuses.is_empty());

    // Our selected module has the new hash.
    let new_hash_vec = new_wasm_hash.to_vec();
    assert!(statuses
        .iter()
        .all(|s| s.module_hash().unwrap() == new_hash_vec));
}

#[test]
fn test_out_of_sync_version_still_allows_upgrade_to_succeed() {
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    let root_wasm = build_root_sns_wasm();
    sns_wasm::add_wasm_via_proposal(&machine, root_wasm.clone());

    let gov_wasm = build_governance_sns_wasm();
    sns_wasm::add_wasm_via_proposal(&machine, gov_wasm.clone());

    let ledger_wasm = build_ledger_sns_wasm();
    sns_wasm::add_wasm_via_proposal(&machine, ledger_wasm.clone());

    let swap_wasm = build_swap_sns_wasm();
    sns_wasm::add_wasm_via_proposal(&machine, swap_wasm.clone());

    // we are intentionally creating the archive to have a different hash than the one deployed by ledger
    let archive_wasm = create_modified_wasm(&build_archive_sns_wasm());
    sns_wasm::add_wasm_via_proposal(&machine, archive_wasm.clone());

    let index_wasm = build_index_sns_wasm();
    sns_wasm::add_wasm_via_proposal(&machine, index_wasm.clone());

    let wasm_map = hashmap! {
        SnsCanisterType::Root => root_wasm,
        SnsCanisterType::Governance =>gov_wasm,
        SnsCanisterType::Ledger =>  ledger_wasm,
        SnsCanisterType::Swap =>  swap_wasm,
        SnsCanisterType::Archive =>  archive_wasm,
        SnsCanisterType::Index =>  index_wasm,
    };

    // To get an SNS neuron, we airdrop our new tokens to this user.
    let user = PrincipalId::new_user_test_id(0);

    let airdrop_neuron = |number| NeuronDistribution {
        controller: Some(PrincipalId::new_user_test_id(number)),
        stake_e8s: 100_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    };
    // We make these to create some extra transactions so an archive will spawn.
    let airdrop_neurons: Vec<NeuronDistribution> =
        (1..20_u64).map(|id| airdrop_neuron(id)).collect();

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: Default::default(),
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 10_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
                airdrop_distribution: Some(AirdropDistribution {
                    airdrop_neurons: vec![NeuronDistribution {
                        controller: Some(user),
                        stake_e8s: 2_000_000_000_000,
                        memo: 0,
                        dissolve_delay_seconds: 15780000, // 6 months
                        vesting_period_seconds: None,
                    }]
                    .into_iter()
                    .chain(airdrop_neurons)
                    .collect(),
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing()
    };

    // Create some canisterIDs
    let root = machine.create_canister(None);
    // Ledger needs cycles to spawn the archives
    let ledger = machine.create_canister_with_cycles(Cycles::new(10 * 1000000000000), None);
    let governance = machine.create_canister(None);
    let swap = machine.create_canister(None);
    let index = machine.create_canister(None);

    // Ensure the recorded archive version is mismatched with what ledger deploys.
    let old_version = wasm_map_to_version(&wasm_map);

    let mut init_payloads = payload
        .build_canister_payloads(
            &SnsCanisterIds {
                root: Some(root.get()),
                ledger: Some(ledger.get()),
                governance: Some(governance.get()),
                swap: Some(swap.get()),
                index: Some(index.get()),
            }
            .try_into()
            .unwrap(),
            Some(old_version.clone()),
        )
        .unwrap();

    // Update some init payload parameters so that our archive can spawn (i.e. can make a transaction
    // because we have a normal non-neuron ledger account, and no restrictions.
    init_payloads.governance.mode = Mode::Normal.into();
    init_payloads.ledger.archive_options.trigger_threshold = 10;
    init_payloads.ledger.archive_options.num_blocks_to_archive = 5;
    init_payloads.ledger.initial_balances.push((
        Account {
            owner: user,
            subaccount: None,
        },
        100000000,
    ));

    let wasm_for_type = |canister_type| wasm_map.get(canister_type).unwrap().wasm.clone();
    let install_code = |canister: CanisterId, wasm: Vec<u8>, payload| {
        machine
            .install_wasm_in_mode(canister, CanisterInstallMode::Install, wasm, payload)
            .unwrap()
    };
    install_code(
        root,
        wasm_for_type(&SnsCanisterType::Root),
        Encode!(&init_payloads.root).unwrap(),
    );
    install_code(
        governance,
        wasm_for_type(&SnsCanisterType::Governance),
        Encode!(&init_payloads.governance).unwrap(),
    );
    install_code(
        ledger,
        wasm_for_type(&SnsCanisterType::Ledger),
        Encode!(&init_payloads.ledger).unwrap(),
    );
    install_code(
        swap,
        wasm_for_type(&SnsCanisterType::Swap),
        Encode!(&init_payloads.swap).unwrap(),
    );
    install_code(
        index,
        wasm_for_type(&SnsCanisterType::Index),
        Encode!(&init_payloads.index).unwrap(),
    );

    machine.tick();

    // Set controllers!
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        root,
        vec![governance.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        governance,
        vec![root.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        ledger,
        vec![root.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        swap,
        vec![swap.get()],
    );
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        index,
        vec![root.get()],
    );

    // We need a ledger archive, so we need to do a transaction to trigger that.
    // The transaction doesn't need to make any sense.
    let _: Result<Nat, TransferError> = update_with_sender(
        &machine,
        ledger,
        "icrc1_transfer",
        candid_one,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: user,
                subaccount: Some([1; 32]),
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: NumTokens::from(10_u8),
        },
        user,
    )
    .unwrap();

    // Ensure that our governance canister does not know about our archives yet. It should discover it
    // during the upgrade process.
    let status_summary = update(
        &machine,
        root,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: None
        })
        .unwrap(),
    )
    .unwrap();
    let status_summary = Decode!(&status_summary, GetSnsCanistersSummaryResponse).unwrap();

    assert!(status_summary.archives.is_empty());

    // We add a new WASM to the SNS-WASMs (for governance)
    let modified_governance =
        create_modified_wasm(wasm_map.get(&SnsCanisterType::Governance).unwrap());

    sns_wasm::add_wasm_via_proposal(&machine, modified_governance.clone());

    // Make a proposal to upgrade (that is auto-executed) with the neuron for our user.
    let neuron_id =
        state_test_helpers::sns_claim_staked_neuron(&machine, governance, user, 0, Some(1_000_000));

    let proposal_id = state_test_helpers::sns_make_proposal(
        &machine,
        governance,
        user,
        neuron_id,
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    println!("Submitted proposal");

    sns_wait_for_pending_upgrade(&machine, governance);

    // advance time so proposal can possibly fail
    machine.advance_time(Duration::from_secs(60 * 60));

    state_test_helpers::sns_wait_for_proposal_executed_or_failed(&machine, governance, proposal_id);

    // Get governance canister hash and ensure it works.
    let statuses = sns_wait_for_upgrade_finished(SnsCanisterType::Governance, &machine, root);
    assert!(!statuses.is_empty());

    // Our selected module has the new hash.
    let upgraded_gov_hash = modified_governance.sha256_hash().to_vec();
    assert!(statuses
        .iter()
        .all(|s| s.module_hash().unwrap() == upgraded_gov_hash));

    // Assert that our recorded version has advanced
    let version_response = Decode!(
        &query(
            &machine,
            governance,
            "get_running_sns_version",
            Encode!(&GetRunningSnsVersionRequest {}).unwrap(),
        )
        .unwrap(),
        GetRunningSnsVersionResponse
    )
    .unwrap();

    // our old_version has wrong archive
    let mut old_version_plus_governance = old_version;
    old_version_plus_governance.governance_wasm_hash = modified_governance.sha256_hash().to_vec();

    let deployed_version = version_response.deployed_version.unwrap();
    assert_eq!(deployed_version, old_version_plus_governance);
    // Ensure the recorded archive_wasm_hash is not the same as the one contained in ledger
    let ledgers_archive_wasm_hash = build_archive_sns_wasm().sha256_hash().to_vec();
    assert_ne!(
        deployed_version.archive_wasm_hash,
        ledgers_archive_wasm_hash
    );

    let running_archive_statuses = get_canister_statuses(SnsCanisterType::Archive, &machine, root);
    assert!(running_archive_statuses
        .iter()
        .all(|s| { s.module_hash().unwrap() == ledgers_archive_wasm_hash }));

    // After checking version stuff, ensure proposal executed (not failed)
    state_test_helpers::sns_wait_for_proposal_execution(&machine, governance, proposal_id);
}

fn create_modified_wasm(original_wasm: &SnsWasm) -> SnsWasm {
    let original_hash = original_wasm.sha256_hash();
    let wasm_to_add = &original_wasm.wasm;
    let mut wasm_to_add = Module::from_buffer(wasm_to_add).unwrap();
    let custom_section = RawCustomSection {
        name: "no op".into(),
        data: vec![1u8, 2u8, 3u8],
    };
    wasm_to_add.customs.add(custom_section);

    // We get our new WASM, which is functionally the same.
    let wasm_to_add = Wasm::from_bytes(wasm_to_add.emit_wasm());
    let sns_wasm_to_add = SnsWasm {
        wasm: wasm_to_add.bytes(),
        canister_type: original_wasm.canister_type,
    };
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);
    sns_wasm_to_add
}

/// Wait for an upgrade caused by the UpgradeSnsToNextVersion proposal (core SNS canister)
fn sns_wait_for_upgrade_finished(
    canister_type: SnsCanisterType,
    machine: &StateMachine,
    root: CanisterId,
) -> Vec<CanisterStatusResultV2> {
    // Now we attempt to get the status for the canister (but the canister may be updating or stopped)
    // which will cause the GetSnsCanistersSummaryRequest to fail.
    let mut attempt_count = 0;

    loop {
        attempt_count += 1;
        machine.tick();
        let statuses = get_canister_statuses(canister_type, machine, root);

        // Stop waiting once it dapp has reached the Running state.
        if statuses
            .iter()
            .all(|s| s.status() == CanisterStatusType::Running)
        {
            break statuses;
        }

        assert!(attempt_count < 250, "status: {:?}", statuses);
    }
}

/// Get the canister status(es) for the given `canister_type`
fn get_canister_statuses(
    canister_type: SnsCanisterType,
    machine: &StateMachine,
    root: CanisterId,
) -> Vec<CanisterStatusResultV2> {
    let status_summary = update(
        machine,
        root,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: None
        })
        .unwrap(),
    )
    .expect("get_sns_canisters_summary failed");

    let status_summary = Decode!(&status_summary, GetSnsCanistersSummaryResponse).unwrap();

    match canister_type {
        SnsCanisterType::Unspecified => panic!("Cannot be unspecified"),
        SnsCanisterType::Root => vec![status_summary.root.unwrap().status.unwrap()],
        SnsCanisterType::Governance => vec![status_summary.governance.unwrap().status.unwrap()],
        SnsCanisterType::Ledger => vec![status_summary.ledger.unwrap().status.unwrap()],
        SnsCanisterType::Archive => status_summary
            .archives
            .into_iter()
            .map(|summary| summary.status.unwrap())
            .collect(),
        SnsCanisterType::Swap => panic!("Swap can't be upgraded by SNS"),
        SnsCanisterType::Index => vec![status_summary.index.unwrap().status.unwrap()],
    }
}

/// Return once Governance has a set pending upgrade
fn sns_wait_for_pending_upgrade(machine: &StateMachine, governance: CanisterId) {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut pending_upgrade_exists = false;
    while !pending_upgrade_exists {
        attempt_count += 1;
        machine.tick();

        let version_response = Decode!(
            &query(
                machine,
                governance,
                "get_running_sns_version",
                Encode!(&GetRunningSnsVersionRequest {}).unwrap(),
            )
            .unwrap(),
            GetRunningSnsVersionResponse
        )
        .unwrap();

        pending_upgrade_exists = version_response.pending_version.is_some();

        assert!(
            attempt_count < 50,
            "Never found pending upgrade after {} attempts",
            attempt_count
        );

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Translates a WasmMap to a Version
fn wasm_map_to_version(wasm_map: &HashMap<SnsCanisterType, SnsWasm>) -> Version {
    let version_hash_from_map = |canister_type: SnsCanisterType| {
        wasm_map.get(&canister_type).unwrap().sha256_hash().to_vec()
    };
    Version {
        root_wasm_hash: version_hash_from_map(SnsCanisterType::Root),
        governance_wasm_hash: version_hash_from_map(SnsCanisterType::Governance),
        ledger_wasm_hash: version_hash_from_map(SnsCanisterType::Ledger),
        swap_wasm_hash: version_hash_from_map(SnsCanisterType::Swap),
        archive_wasm_hash: version_hash_from_map(SnsCanisterType::Archive),
        index_wasm_hash: version_hash_from_map(SnsCanisterType::Index),
    }
}
