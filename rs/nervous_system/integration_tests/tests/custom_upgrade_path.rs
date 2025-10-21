use candid::Principal;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::{
    helpers::await_with_timeout,
    nns::{
        governance::{add_sns_wasm, insert_sns_wasm_upgrade_path_entries},
        sns_wasm::get_next_sns_version,
    },
    pocketic_impl::PocketIcAgent,
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns::{
    self,
    governance::{
        EXPECTED_UPGRADE_DURATION_MAX_SECONDS, EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        redact_human_readable, set_automatically_advance_target_version_flag,
    },
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{add_wasms_to_sns_wasm, nns},
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_test_utils::sns_wasm::{
    build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm, create_modified_sns_wasm,
};
use ic_sns_governance::governance::{
    UPGRADE_PERIODIC_TASK_LOCK_TIMEOUT_SECONDS, UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS,
};
use ic_sns_governance_api::pb::v1::upgrade_journal_entry::Event;
use ic_sns_governance_api::{
    pb::v1::{governance::Version, upgrade_journal_entry::TargetVersionReset},
    serialize_journal_entries,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::{SnsCanisterType, SnsUpgrade, SnsVersion, SnsWasm};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};

/// Wraps `pocket_ic` into an agent to use when more authority is required (e.g., making proposals).
///
/// Returns the agent and ID of a neuron controlled by this agent.
fn nns_agent(pocket_ic: &PocketIc) -> (PocketIcAgent<'_>, NeuronId) {
    let nns_neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };

    let sender = Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL);
    (PocketIcAgent { pocket_ic, sender }, nns_neuron_id)
}

const DUMMY_URL_FOR_PROPOSALS: &str = "https://forum.dfinity.org";

#[tokio::test]
async fn test_custom_upgrade_path_for_sns_auto() {
    let automatically_advance_target_version = true;
    test_custom_upgrade_path_for_sns(automatically_advance_target_version).await
}

#[tokio::test]
async fn test_custom_upgrade_path_for_sns_no_auto() {
    let automatically_advance_target_version = false;
    test_custom_upgrade_path_for_sns(automatically_advance_target_version).await
}

/// This test demonstrates how an SNS can be recovered if, for some reason, an upgrade along
/// the path of blessed SNS framework canister versions is failing. In that case, it should be
/// possible to create a *custom path* that is applicable only to that SNS to recover it.
///
/// Example:
///
/// Normal path: (Deployed) ---> +root (broken) ---> +root (fixed)  ---> +ledger ---> +swap (Last)
///                        \                                                   /
/// Custom path:             ------> +ledger ------> +root (fixed) -----------
///
/// Note that only Wasms published via `NnsFunction::AddSnsWasm` can be referred to from the custom
/// upgrade path, which leaves us with only two possible customizations:
/// 1. Hop over some upgrade.
/// 2. Switch the order of upgrades.
///
/// We use this fairly complex custom upgrade path in this test to illustrate both of these cases.
async fn test_custom_upgrade_path_for_sns(automatically_advance_target_version: bool) {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    let (pocket_ic_agent, nns_neuron_id) = nns_agent(&pocket_ic);

    // Step 0.1: Publish (master) SNS Wasms to SNS-W.
    let with_mainnet_sns_canisters = false;
    add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();
    let initial_sns_version = nns::sns_wasm::get_latest_sns_version(&pocket_ic).await;

    // Step 0.2: Deploy an SNS instance via proposal.
    let sns = {
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .clone()
            .unwrap();

        let sns_instance_label = "1";
        let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
            &pocket_ic,
            create_service_nervous_system,
            sns_instance_label,
        )
        .await;

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
            .await
            .unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        )
        .await;

        sns
    };

    // Step 0.3
    set_automatically_advance_target_version_flag(
        &pocket_ic,
        sns.governance.canister_id,
        automatically_advance_target_version,
    )
    .await
    .unwrap();

    // Step 0.4. Bless a sequence of upgrades, the first one is deemed to fail for this SNS.
    let (normal_versions, expected_custom_versions, custom_path, expected_ultimate_version) = {
        // The broken Root Wasm (used only for the normal upgrade path).
        let broken_root_wasm = SnsWasm {
            // Clearly, this isn't a Wasm that can be installed in the place of Root.
            wasm: UNIVERSAL_CANISTER_WASM.clone(),
            canister_type: SnsCanisterType::Root as i32,
            proposal_id: None,
        };

        // The remaining Wasms are good, but we still need to modify them to make sure their hash
        // differs from the one used at the time of SNS deployment.

        // The fixed Root Wasm.
        let fixed_root_wasm = create_modified_sns_wasm(&build_root_sns_wasm(), Some(42));

        let ledger_wasm = create_modified_sns_wasm(&build_ledger_sns_wasm(), Some(42));

        // The point of this last upgrade is to check that after following a custom path, the SNS
        // will continue along the normal upgrade path when the paths merge again. See the diagram
        // in the doc string of this function.
        let swap_wasm = create_modified_sns_wasm(&build_swap_sns_wasm(), Some(42));

        let normal_one = Version {
            root_wasm_hash: broken_root_wasm.sha256_hash().to_vec(),
            ..initial_sns_version.clone()
        };
        let normal_two = Version {
            root_wasm_hash: fixed_root_wasm.sha256_hash().to_vec(),
            ..normal_one.clone()
        };
        let normal_three = Version {
            ledger_wasm_hash: ledger_wasm.sha256_hash().to_vec(),
            ..normal_two.clone()
        };
        let normal_four = Version {
            swap_wasm_hash: swap_wasm.sha256_hash().to_vec(),
            ..normal_three.clone()
        };

        // We form the custom versions here to make it clear how they relate to the normal ones.
        // But they will be published to SNS-W only *after* the normal path is followed.
        let custom_one = Version {
            ledger_wasm_hash: ledger_wasm.sha256_hash().to_vec(),
            ..initial_sns_version.clone()
        };
        let custom_two = Version {
            root_wasm_hash: fixed_root_wasm.sha256_hash().to_vec(),
            ..custom_one.clone()
        };

        let custom_edge_a = SnsUpgrade {
            current_version: Some(adapt_version(&initial_sns_version.clone())),
            next_version: Some(adapt_version(&custom_one.clone())),
        };
        let custom_edge_b = SnsUpgrade {
            current_version: Some(adapt_version(&custom_one.clone())),
            next_version: Some(adapt_version(&custom_two.clone())),
        };
        let custom_edge_c = SnsUpgrade {
            current_version: Some(adapt_version(&custom_two.clone())),
            next_version: Some(adapt_version(&normal_four.clone())),
        };

        let proposal_ids = vec![
            add_sns_wasm(
                &pocket_ic_agent,
                nns_neuron_id,
                broken_root_wasm,
                DUMMY_URL_FOR_PROPOSALS,
            )
            .await
            .unwrap()
            .id,
            add_sns_wasm(
                &pocket_ic_agent,
                nns_neuron_id,
                fixed_root_wasm,
                DUMMY_URL_FOR_PROPOSALS,
            )
            .await
            .unwrap()
            .id,
            add_sns_wasm(
                &pocket_ic_agent,
                nns_neuron_id,
                ledger_wasm,
                DUMMY_URL_FOR_PROPOSALS,
            )
            .await
            .unwrap()
            .id,
            add_sns_wasm(
                &pocket_ic_agent,
                nns_neuron_id,
                swap_wasm,
                DUMMY_URL_FOR_PROPOSALS,
            )
            .await
            .unwrap()
            .id,
        ];

        for proposal_id in proposal_ids {
            nns::governance::wait_for_proposal_execution(&pocket_ic, proposal_id)
                .await
                .unwrap();
        }

        (
            vec![
                initial_sns_version.clone(),
                normal_one,
                normal_two,
                normal_three.clone(),
                normal_four.clone(),
            ],
            vec![
                initial_sns_version.clone(),
                custom_one,
                custom_two,
                normal_four.clone(),
            ],
            vec![custom_edge_a, custom_edge_b, custom_edge_c],
            normal_four,
        )
    };

    // Step 0.5: Await the normal upgrade steps to be refreshed.
    await_with_timeout(
        &pocket_ic,
        UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS..EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .upgrade_steps
                .unwrap()
                .versions
        },
        &normal_versions,
    )
    .await
    .unwrap();

    // Step 0.6. Await SNS to fail upgrading to latest, which is characterized with
    // a `TargetVersionReset` event.
    if automatically_advance_target_version {
        await_with_timeout(
            &pocket_ic,
            0..UPGRADE_PERIODIC_TASK_LOCK_TIMEOUT_SECONDS,
            |pocket_ic| async {
                sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                    .await
                    .upgrade_journal
                    .unwrap()
                    .entries
                    .into_iter()
                    .find_map(|entry| {
                        let event = redact_human_readable(entry.event.unwrap());
                        match event {
                            Event::TargetVersionReset(event) => Some(event),
                            _ => None,
                        }
                    })
            },
            &Some(TargetVersionReset {
                old_target_version: Some(normal_versions.iter().last().unwrap().clone()),
                new_target_version: None,
                human_readable: None,
            }),
        )
        .await
        .unwrap();
    }

    // Step 1.0 Propose the custom upgrade path and await the proposal being executed.
    let proposal_id = insert_sns_wasm_upgrade_path_entries(
        &pocket_ic_agent,
        nns_neuron_id,
        custom_path,
        Some(CanisterId::unchecked_from_principal(
            sns.governance.canister_id,
        )),
        DUMMY_URL_FOR_PROPOSALS,
    )
    .await
    .unwrap()
    .id;
    nns::governance::wait_for_proposal_execution(&pocket_ic, proposal_id)
        .await
        .unwrap();

    let next_normal_version =
        get_next_sns_version(&pocket_ic, adapt_version(&initial_sns_version), None)
            .await
            .unwrap();

    let next_custom_version = get_next_sns_version(
        &pocket_ic,
        adapt_version(&initial_sns_version),
        Some(sns.governance.canister_id),
    )
    .await
    .unwrap();

    // Smoke test.
    assert_ne!(next_normal_version, next_custom_version);

    // Step 1.1. Await the custom upgrade steps to be refreshed.
    let outcome = await_with_timeout(
        &pocket_ic,
        UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS..EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .upgrade_steps
                .unwrap()
                .versions
        },
        &expected_custom_versions,
    )
    .await;

    if let Err(err) = outcome {
        let journal = sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id)
            .await
            .upgrade_journal
            .unwrap();
        println!("journal = {}", serialize_journal_entries(&journal).unwrap());
        panic!("{}", err);
    }

    // Step 1.2. Advance the target version via proposal, if needed.
    if !automatically_advance_target_version {
        sns::governance::propose_to_advance_sns_target_version(
            &pocket_ic,
            sns.governance.canister_id,
        )
        .await
        .unwrap();
    }

    // Step 2. Assert that eventually the SNS returns to the normal path.
    let outcome = await_with_timeout(
        &pocket_ic,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |pocket_ic| async {
            sns::governance::try_get_upgrade_journal(pocket_ic, sns.governance.canister_id)
                .await
                .map(|upgrade_journal| upgrade_journal.deployed_version)
                .map_err(|err| format!("{err:?}"))
        },
        &Ok(Some(expected_ultimate_version)),
    )
    .await;

    if let Err(err) = outcome {
        let journal = sns::governance::get_upgrade_journal(&pocket_ic, sns.governance.canister_id)
            .await
            .upgrade_journal
            .unwrap();
        println!("journal = {}", serialize_journal_entries(&journal).unwrap());
        panic!("{}", err);
    }
}

fn adapt_version(version: &Version) -> SnsVersion {
    let Version {
        root_wasm_hash,
        governance_wasm_hash,
        ledger_wasm_hash,
        swap_wasm_hash,
        archive_wasm_hash,
        index_wasm_hash,
    } = version.clone();

    SnsVersion {
        governance_wasm_hash,
        swap_wasm_hash,
        root_wasm_hash,
        index_wasm_hash,
        ledger_wasm_hash,
        archive_wasm_hash,
    }
}
