use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_common_test_utils::get_gauge;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::governance::migration::MigrationStatus;
use ic_nns_test_utils::state_test_helpers::{
    get_canister_status, nns_create_super_powerful_neuron, nns_get_migrations,
    nns_propose_upgrade_nns_canister, scrape_metrics,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use std::{env, fs};

#[test]
fn test_copy_inactive_neurons_to_stable_memory() {
    // Step 1: Prepare the world

    // Step 1.1: Populate StateMachine from a state_dir.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Step 1.2: Create a super powerful Neuron.
    println!("Creating super powerful Neuron.");
    let controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(&state_machine, controller);
    println!("Done creating super powerful Neuron.");

    // Step 1.3: Install NNS governance WASM built with `feature = "test"`. In the future, `feature
    // = "test"` will not be needed, because the feature will be generally available, i.e. no longer
    // be guarded by `feature = "test"`. At that point, the non-"_TEST" path can be used.
    let new_wasm_path = env::var("GOVERNANCE_CANISTER_TEST_WASM_PATH").unwrap();
    let new_wasm_content: Vec<u8> = fs::read(new_wasm_path).unwrap();
    let new_wasm_hash = Sha256::hash(&new_wasm_content);
    let module_arg = Encode!(&()).unwrap();
    println!("Proposing governance upgrade... ");
    let proposal_id = nns_propose_upgrade_nns_canister(
        &state_machine,
        controller,
        neuron_id,
        GOVERNANCE_CANISTER_ID, // Target, i.e. the canister that we want to upgrade.
        new_wasm_content,       // The new code that we want the canister to start running.
        module_arg,
        true,
    );
    println!("Done proposing governance upgrade: {:?}", proposal_id);

    // Step 1.3.1: Wait for upgrade to complete.
    let mut is_upgrade_ok = false;
    let mut last_status = None;
    for i in 0..25 {
        state_machine.tick();

        // Fetch status of governance.
        let status_result = get_canister_status(
            &state_machine,
            // Request sender. Root is used because it is a controller of the subject of the
            // query, namely governance.
            PrincipalId::from(ROOT_CANISTER_ID),
            GOVERNANCE_CANISTER_ID, // Subject of the query
            CanisterId::ic_00(),    // Who the request is being sent to: the management canister.
        );

        // Continue if call was an err. This isn't necessarily a problem, because there is a brief
        // period when the canister is being upgraded during which, it is temporarily unavailable.
        let status = match status_result {
            Ok(ok) => ok,
            Err(err) => {
                println!(
                    "Unable to read the status of governance on iteration {}. \
                     This may be transient. err:\n{:?}",
                    i, err,
                );
                continue;
            }
        };

        last_status = Some(status.clone());

        // Break if we have reached the goal state.
        let done = status.status == CanisterStatusType::Running
            // Hash matches.
            && status.module_hash.as_ref().unwrap() == &new_wasm_hash.to_vec();
        if !done {
            println!(
                "Upgrade is not done yet (as of iteration {}): {}",
                i, status.status
            );
            continue;
        }

        let new_wasm_hash = new_wasm_hash
            .into_iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join("");
        println!(
            "Yay! We were able to upgrade NNS governance to {} on iteration {}.",
            new_wasm_hash, i,
        );
        is_upgrade_ok = true;
        break;
    }
    assert!(is_upgrade_ok, "{:#?}", last_status);

    // Step 2: Run code under test: Let heartbeat do its thing, until copying inactive neurons to
    // stable memory is done.
    let mut last_migration = Default::default();
    // This is used to make sure that copying begins in a "reasonably timely manner".
    let mut unspecified_count = 0;
    let mut too_long = true;
    for i in 0..600 {
        state_machine.tick();

        last_migration = nns_get_migrations(&state_machine)
            .copy_inactive_neurons_to_stable_memory_migration
            .unwrap_or_default();

        let status = MigrationStatus::try_from(last_migration.status.unwrap_or_default())
            .unwrap_or_default();

        if status == MigrationStatus::Unspecified {
            unspecified_count += 1;
            assert!(unspecified_count < 25, "{:#?}", last_migration);
        }

        if status.is_terminal() {
            println!(
                "Yay! Copying inactive neurons is Done as of iteration {}. Onto verification!",
                i,
            );
            too_long = false;
            break;
        }

        println!(
            "As of iteration {}, still waiting for copying inactive neurons...",
            i
        );
    }
    assert!(!too_long);

    // Step 3: Verify results.

    // Step 3.1: Assert that the copying was eventually successful.
    let status = MigrationStatus::try_from(*last_migration.status.as_ref().unwrap()).unwrap();
    assert_eq!(status, MigrationStatus::Succeeded);

    // Step 3.2: Assert that there is now a large number of neurons in stable memory.
    let scrape = scrape_metrics(&state_machine, GOVERNANCE_CANISTER_ID);
    let len = get_gauge(&scrape, "governance_stable_memory_neuron_count") as u64;
    assert!(len > 100_000, "{}", len);

    // TODO(NNS1-2682): Validate copy.
}
