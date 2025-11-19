use crate::common::EXPECTED_SNS_CREATION_FEE;
use candid::{Decode, Encode, Nat};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::LedgerArgument;
use ic_management_canister_types_private::{CanisterIdRecord, CanisterInstallMode};
use ic_nervous_system_clients::canister_status::{CanisterStatusResultV2, CanisterStatusType};
use ic_nervous_system_common::{DEFAULT_TRANSFER_FEE, ledger::compute_neuron_staking_subaccount};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    sns_wasm::{self, create_modified_sns_wasm, ensure_sns_wasm_gzipped},
    state_test_helpers,
    state_test_helpers::{query, set_controllers, setup_nns_canisters, update, update_with_sender},
};
use ic_sns_governance::{
    pb::v1::{
        self as sns_governance_pb, GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
        Proposal, ProposalDecisionStatus, UpgradeSnsToNextVersion,
        governance::{Mode, Version},
        proposal::Action,
    },
    types::E8S_PER_TOKEN,
};
use ic_sns_init::pb::v1::{
    DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload,
    SwapDistribution, TreasuryDistribution, sns_init_payload::InitialTokenDistribution,
};
use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_sns_wasm::pb::v1::{
    InsertUpgradePathEntriesRequest, InsertUpgradePathEntriesResponse, SnsCanisterIds,
    SnsCanisterType, SnsWasm,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::Cycles;
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{NumTokens, TransferArg, TransferError},
};
use std::{collections::BTreeMap, convert::TryInto, time::Duration};

pub mod common;

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

#[test]
fn test_governance_restarts_root_if_root_cannot_stop_during_upgrade() {
    let canister_type = SnsCanisterType::Root;

    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    // Add cycles to the SNS-W canister to deploy an SNS.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);

    let wasm_map = sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // Replace root with unstoppable sns-root
    let unstoppable_canister_wasm =
        Project::cargo_bin_maybe_from_env("unstoppable-sns-root-canister", &[]).bytes();
    let unstoppable_sns_wasm = SnsWasm {
        wasm: unstoppable_canister_wasm,
        canister_type: canister_type.into(),
        ..SnsWasm::default()
    };
    let unstoppable_sns_wasm = sns_wasm::add_wasm_via_proposal(&machine, unstoppable_sns_wasm);

    let developer_neuron_controller = PrincipalId::new_user_test_id(0);

    let payload = SnsInitPayload {
        dapp_canisters: None,
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![developer_neuron_controller.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: vec![NeuronDistribution {
                        controller: Some(developer_neuron_controller),
                        stake_e8s: 10_000_000_000,
                        memo: 0,
                        dissolve_delay_seconds: 15780000, // 6 months
                        vesting_period_seconds: None,
                    }],
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 10_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    // Will be used to make proposals and such. Fortunately, this guy has lots
    // of money -> he'll be able to push proposals though.
    let developer_sns_neuron_id = sns_governance_pb::NeuronId {
        id: compute_neuron_staking_subaccount(developer_neuron_controller, /* memo */ 0)
            .0
            .to_vec(),
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        payload,
    );

    assert_eq!(response.error, None);

    let SnsCanisterIds {
        root,
        ledger: _,
        governance,
        swap: _,
        index: _,
    } = response.canisters.unwrap();

    let root = CanisterId::unchecked_from_principal(root.unwrap());
    let governance = CanisterId::unchecked_from_principal(governance.unwrap());

    let original_hash = wasm_map.get(&canister_type).unwrap().sha256_hash();

    let sns_wasm_to_add = create_modified_sns_wasm(wasm_map.get(&canister_type).unwrap(), None);
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm_to_add);

    // Make a proposal to upgrade (that is auto-executed) from the developer_neuron_controller.
    state_test_helpers::sns_make_proposal(
        &machine,
        governance,
        developer_neuron_controller,
        developer_sns_neuron_id,
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    machine.advance_time(Duration::from_secs(1));
    machine.tick();
    machine.tick();
    machine.tick();

    let get_root_status = || -> CanisterStatusResultV2 {
        update_with_sender(
            &machine,
            CanisterId::ic_00(),
            "canister_status",
            CanisterIdRecord::from(root),
            governance.get(),
        )
        .unwrap()
    };

    assert_eq!(get_root_status().status, CanisterStatusType::Stopping);

    machine.advance_time(Duration::from_secs(60));
    machine.tick();

    assert_eq!(get_root_status().status, CanisterStatusType::Stopping);

    machine.advance_time(Duration::from_secs(241));
    machine.tick();
    machine.tick();
    machine.tick();

    assert_eq!(get_root_status().status, CanisterStatusType::Running);
    assert_eq!(
        get_root_status().module_hash.unwrap(),
        unstoppable_sns_wasm.sha256_hash()
    );
}

fn run_upgrade_test(canister_type: SnsCanisterType) {
    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    // Add cycles to the SNS-W canister to deploy an SNS.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);

    let wasm_map = sns_wasm::add_freshly_built_sns_wasms(&machine, ensure_sns_wasm_gzipped);

    let developer_neuron_controller = PrincipalId::new_user_test_id(0);

    let payload = SnsInitPayload {
        dapp_canisters: None,
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![developer_neuron_controller.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: vec![NeuronDistribution {
                        controller: Some(developer_neuron_controller),
                        stake_e8s: 100_000_000_000,
                        memo: 0,
                        dissolve_delay_seconds: 15780000, // 6 months
                        vesting_period_seconds: None,
                    }],
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 100_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    // Will be used to make proposals and such. Fortunately, this guy has lots
    // of money -> he'll be able to push proposals though.
    let sns_neuron_id = sns_governance_pb::NeuronId {
        id: compute_neuron_staking_subaccount(developer_neuron_controller, /* memo */ 0)
            .0
            .to_vec(),
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        payload,
    );

    assert_eq!(response.error, None);

    let SnsCanisterIds {
        root,
        ledger: _,
        governance,
        swap: _,
        index: _,
    } = response.canisters.unwrap();

    let root = CanisterId::unchecked_from_principal(root.unwrap());
    let governance = CanisterId::unchecked_from_principal(governance.unwrap());

    // Validate that upgrading Swap doesn't prevent upgrading other SNS canisters
    let old_version = upgrade_swap(&machine, &wasm_map, governance, &sns_neuron_id);

    let original_hash = wasm_map.get(&canister_type).unwrap().sha256_hash();

    let sns_wasm_to_add = ensure_sns_wasm_gzipped(create_modified_sns_wasm(
        wasm_map.get(&canister_type).unwrap(),
        Some(42),
    ));
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm_to_add);

    // Instantly pass an SNS upgrade proposal.
    let proposal_id = state_test_helpers::sns_make_proposal(
        &machine,
        governance,
        developer_neuron_controller,
        sns_neuron_id,
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

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
    assert!(
        statuses
            .iter()
            .all(|s| s.module_hash().unwrap() == new_hash_vec)
    );

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

/// Publishes a new Swap WASM to SNS-WASM and then submits and executes an SNS upgrade proposal
fn upgrade_swap(
    machine: &StateMachine,
    wasm_map: &BTreeMap<SnsCanisterType, SnsWasm>,
    governance: CanisterId,
    neuron_id: &sns_governance_pb::NeuronId,
) -> Version {
    let user = PrincipalId::new_user_test_id(0);
    let original_swap_hash = wasm_map.get(&SnsCanisterType::Swap).unwrap().sha256_hash();

    let swap_wasm_to_add =
        create_modified_sns_wasm(wasm_map.get(&SnsCanisterType::Swap).unwrap(), None);
    let new_swap_hash = swap_wasm_to_add.sha256_hash();

    assert_ne!(new_swap_hash, original_swap_hash);

    sns_wasm::add_wasm_via_proposal(machine, swap_wasm_to_add);

    let proposal_id = state_test_helpers::sns_make_proposal(
        machine,
        governance,
        user,
        neuron_id.clone(),
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    state_test_helpers::sns_wait_for_proposal_execution(machine, governance, proposal_id);

    let old_version = wasm_map_to_version(wasm_map);
    let version_with_new_swap = Version {
        swap_wasm_hash: new_swap_hash.to_vec(),
        ..old_version
    };

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

    assert_eq!(
        version_response.deployed_version,
        Some(version_with_new_swap.clone())
    );
    assert!(version_response.pending_version.is_none());

    version_with_new_swap
}

/// This test uses a different setup than the other 3 because it is difficult to get ledgers to spawn
/// archives after SNS-WASM deploy in a test environment, as it requires finalizing the swap so that
/// there are ledger accounts that have funds to be transacted.
///
/// Using this setup allows us to skip that process and have an SNS with archive canisters more easily.
#[test]
fn upgrade_archive_sns_canister_via_sns_wasms() {
    let canister_type = SnsCanisterType::Archive;
    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    let wasm_map = sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // This user will act as the fallback controller and the big developer neuron controller.
    let user = PrincipalId::new_user_test_id(0);

    let mut developer_neurons = vec![NeuronDistribution {
        controller: Some(user),
        stake_e8s: 80_000_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    }];

    // We make these to create some extra transactions so an archive will spawn.
    let make_neuron_distribution = |number| NeuronDistribution {
        controller: Some(PrincipalId::new_user_test_id(number)),
        stake_e8s: 100_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    };
    developer_neurons.extend((1..20_u64).map(make_neuron_distribution));

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution { developer_neurons }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 100_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    // Create some canisterIDs
    let root = machine.create_canister(None);
    // Ledger needs cycles to spawn the archives
    let ledger = machine.create_canister_with_cycles(None, Cycles::new(10 * 1000000000000), None);
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
            false,
        )
        .unwrap();

    // Update some init payload parameters so that our archive can spawn (i.e. can make a transaction
    // because we have a normal non-neuron ledger account, and no restrictions.
    init_payloads.governance.mode = Mode::Normal.into();
    if let LedgerArgument::Init(ref mut ledger) = init_payloads.ledger {
        ledger.archive_options.trigger_threshold = 10;
        ledger.archive_options.num_blocks_to_archive = 5;
        ledger.initial_balances.push((
            Account {
                owner: user.into(),
                subaccount: None,
            },
            Nat::from(100_000_000_u32),
        ));
    } else {
        panic!("bug: expected Init got Upgrade");
    }

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
        Encode!(&init_payloads.index_ng.unwrap()).unwrap(),
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
    set_controllers(&machine, PrincipalId::new_anonymous(), swap, vec![]);
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
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: user.into(),
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
    let sns_wasm_to_add = create_modified_sns_wasm(current_wasm, None);
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
    assert!(
        statuses
            .iter()
            .all(|s| s.module_hash().unwrap() == new_hash_vec)
    );
}

#[test]
fn test_out_of_sync_version_still_allows_upgrade_to_succeed() {
    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    fn filter_wasm(mut sns_wasm: SnsWasm) -> SnsWasm {
        if sns_wasm.canister_type == SnsCanisterType::Archive as i32 {
            sns_wasm = create_modified_sns_wasm(&sns_wasm, Some(64))
        }

        ensure_sns_wasm_gzipped(sns_wasm)
    }
    let wasm_map = sns_wasm::add_freshly_built_sns_wasms(&machine, filter_wasm);

    // This user will act as the fallback controller and the big developer neuron controller.
    let user = PrincipalId::new_user_test_id(0);

    let mut developer_neurons = vec![NeuronDistribution {
        controller: Some(user),
        stake_e8s: 80_000_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    }];

    // We make these to create some extra transactions so an archive will spawn.
    let make_neuron_distribution = |number| NeuronDistribution {
        controller: Some(PrincipalId::new_user_test_id(number)),
        stake_e8s: 100_000_000,
        memo: 0,
        dissolve_delay_seconds: 15780000, // 6 months
        vesting_period_seconds: None,
    };
    developer_neurons.extend((1..20_u64).map(make_neuron_distribution));

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution { developer_neurons }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 100_000_000_000,
                    initial_swap_amount_e8s: 100_000_000_000,
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    // Create some canisterIDs
    let root = machine.create_canister(None);
    // Ledger needs cycles to spawn the archives
    let ledger = machine.create_canister_with_cycles(None, Cycles::new(10 * 1000000000000), None);
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
            false,
        )
        .unwrap();

    // Update some init payload parameters so that our archive can spawn (i.e. can make a transaction
    // because we have a normal non-neuron ledger account, and no restrictions.
    init_payloads.governance.mode = Mode::Normal.into();
    if let LedgerArgument::Init(ref mut ledger) = init_payloads.ledger {
        ledger.archive_options.trigger_threshold = 10;
        ledger.archive_options.num_blocks_to_archive = 5;
        ledger.initial_balances.push((
            Account {
                owner: user.into(),
                subaccount: None,
            },
            Nat::from(100_000_000_u32),
        ));
    } else {
        panic!("bug: expected Init got Upgrade");
    }

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
        Encode!(&init_payloads.index_ng.unwrap()).unwrap(),
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
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: user.into(),
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
    let modified_governance = create_modified_sns_wasm(
        wasm_map.get(&SnsCanisterType::Governance).unwrap(),
        Some(42),
    );
    let modified_governance = sns_wasm::add_wasm_via_proposal(&machine, modified_governance);

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
    sns_wait_for_pending_upgrade(&machine, governance);

    // advance time so proposal can possibly fail
    machine.advance_time(Duration::from_secs(60 * 60));

    state_test_helpers::sns_wait_for_proposal_executed_or_failed(&machine, governance, proposal_id);

    // Assert that the governance canister is running the new code.
    let statuses = sns_wait_for_upgrade_finished(SnsCanisterType::Governance, &machine, root);
    let expected_governance_hash = modified_governance.sha256_hash().to_vec();
    assert_eq!(
        statuses
            .iter()
            .map(|s| s.module_hash().unwrap())
            .collect::<Vec<_>>(),
        vec![expected_governance_hash],
    );

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

    // Ensure we are still mismatched between running archive version and deployed_version.archive_wasm_hash
    let running_archive_statuses = get_canister_statuses(SnsCanisterType::Archive, &machine, root);
    assert!(
        running_archive_statuses
            .iter()
            .all(|s| { s.module_hash().unwrap() != deployed_version.archive_wasm_hash })
    );

    // After checking version stuff, ensure proposal executed (not failed)
    state_test_helpers::sns_wait_for_proposal_execution(&machine, governance, proposal_id);
}

#[test]
fn insert_upgrade_path_entries_only_callable_by_governance_when_access_controls_enabled() {
    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_sns_wasm_access_controls(true)
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    let response: InsertUpgradePathEntriesResponse = update_with_sender(
        &machine,
        SNS_WASM_CANISTER_ID,
        "insert_upgrade_path_entries",
        InsertUpgradePathEntriesRequest {
            upgrade_path: vec![],
            sns_governance_canister_id: None,
        },
        PrincipalId::new_user_test_id(1),
    )
    .unwrap();

    assert_eq!(
        response,
        InsertUpgradePathEntriesResponse::error(
            "insert_upgrade_path_entries can only be called by NNS Governance".to_string()
        )
    );
}

#[test]
fn insert_upgrade_path_entries_callable_by_anyone_when_access_controls_disabled() {
    let machine = StateMachineBuilder::new().with_current_time().build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_sns_wasm_access_controls(false)
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    let response: InsertUpgradePathEntriesResponse = update_with_sender(
        &machine,
        SNS_WASM_CANISTER_ID,
        "insert_upgrade_path_entries",
        InsertUpgradePathEntriesRequest {
            upgrade_path: vec![],
            sns_governance_canister_id: None,
        },
        PrincipalId::new_user_test_id(1),
    )
    .unwrap();

    // We get an error past the access controls (request was actually processed)
    assert_eq!(
        response,
        InsertUpgradePathEntriesResponse::error(
            "No Upgrade Paths in request. No action taken.".to_string()
        )
    );
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

        assert!(attempt_count < 250, "status: {statuses:?}");
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
            "Never found pending upgrade after {attempt_count} attempts"
        );

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Translates a WasmMap to a Version
fn wasm_map_to_version(wasm_map: &BTreeMap<SnsCanisterType, SnsWasm>) -> Version {
    sns_wasm::wasm_map_to_sns_version(wasm_map).into()
}
