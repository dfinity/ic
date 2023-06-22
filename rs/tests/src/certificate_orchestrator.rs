/* tag::catalog[]
Title:: Certificate orchestrator test

Goal:: Verify that the certificate orchestrator interface works.

Runbook:
. Set up an certificate orchestrator canister.
. Test that the certificate orchestrator API works.

Success:: The certificate orchestrator canister is installed and the API works.

Coverage:: The certificate orchestrator interface works as expected.

end::catalog[] */

use crate::{
    driver::{
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            retry_async, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
            IcNodeContainer, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::agent_observes_canister_module,
};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use candid::{Decode, Encode, Principal};
use certificate_orchestrator_interface::{
    BoundedString, CreateRegistrationError, CreateRegistrationResponse, DispenseTaskError,
    DispenseTaskResponse, EncryptedPair, ExportCertificatesError, ExportCertificatesResponse,
    GetRegistrationResponse, Id, InitArg, ListAllowedPrincipalsError,
    ListAllowedPrincipalsResponse, ModifyAllowedPrincipalError, ModifyAllowedPrincipalResponse,
    PeekTaskError, PeekTaskResponse, QueueTaskError, QueueTaskResponse, RemoveRegistrationError,
    RemoveRegistrationResponse, State, UpdateRegistrationError, UpdateRegistrationResponse,
    UpdateType, UploadCertificateError, UploadCertificateResponse,
};
use ic_agent::{identity::Secp256k1Identity, Agent, Identity};
use ic_registry_subnet_type::SubnetType;
use k256::elliptic_curve::SecretKey;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use slog::info;
use tokio::runtime::Runtime;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

const CERTIFICATE_ORCHESTRATOR_WASM: &str =
    "rs/boundary_node/certificate_issuance/certificate_orchestrator/certificate_orchestrator.wasm";

// Goal: Verify that the access controls of the certificate orchestrator work
//
// Runbook:
// * install the canister with two root identities
// * check that the list of allowed principals is empty
// * add allowed principals and remove them
// * check that non-roots cannot allow/remove principals
pub fn access_control_test(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let root_ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let root_ident_b = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_b = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));

    let principal_a = ident_a.sender().unwrap();
    let principal_b = ident_b.sender().unwrap();

    info!(&logger, "installing canister");

    let args = Encode!(&InitArg {
        root_principals: vec![
            root_ident_a.sender().unwrap(),
            root_ident_b.sender().unwrap()
        ],
        id_seed: 1,
    })
    .unwrap();

    let app_node = env.get_first_healthy_application_node_snapshot();
    let cid =
        app_node.create_and_install_canister_with_arg(CERTIFICATE_ORCHESTRATOR_WASM, Some(args));

    info!(&logger, "creating agent");
    let agent = app_node.build_default_agent();
    let rt = Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        // wait for canister to finish installing
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            match agent_observes_canister_module(&agent, &cid).await {
                true => Ok(()),
                false => panic!("Canister module not available yet"),
            }
        })
        .await
        .unwrap();

        info!(&logger, "created canister={cid}");

        // Check that both roots can list
        for ident in [&root_ident_a, &root_ident_b] {
            match list_allowed_principals(agent.clone(), ident.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected ok empty"),
            }
        }
        // Check that non-roots cannot list
        for ident in [&ident_a, &ident_b] {
            match list_allowed_principals(agent.clone(), ident.clone(), cid).await {
                ListAllowedPrincipalsResponse::Err(ListAllowedPrincipalsError::Unauthorized) => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected unauthorized"),
            }
        }

        // Check that both roots can add and remove
        for ident in [&root_ident_a, &root_ident_b] {
            info!(&logger, "Adding principals as {}", ident.sender().unwrap());
            // Add principal_a
            match add_allowed_principal(agent.clone(), ident.clone(), cid, principal_a).await {
                ModifyAllowedPrincipalResponse::Ok(()) => {}
                v => panic!("addAllowedPrincipal failed: {v:?}, expected ok"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v == [principal_a] => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected principal_a"),
            }

            // Remove principal_b
            match rm_allowed_principal(agent.clone(), ident.clone(), cid, principal_b).await {
                ModifyAllowedPrincipalResponse::Err(
                    ModifyAllowedPrincipalError::UnexpectedError(e),
                ) if e == "principal not found" => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected err"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v == [principal_a] => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected principal_a"),
            }

            // Remove principal_a
            match rm_allowed_principal(agent.clone(), ident.clone(), cid, principal_a).await {
                ModifyAllowedPrincipalResponse::Ok(()) => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected ok"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }
        }

        // Check that non-roots cannot add or remove
        for ident in [&ident_a, &ident_b] {
            // Try to add principal_a
            match add_allowed_principal(agent.clone(), ident.clone(), cid, principal_a).await {
                ModifyAllowedPrincipalResponse::Err(ModifyAllowedPrincipalError::Unauthorized) => {}
                v => panic!("addAllowedPrincipal failed: {v:?}, expected unauthorized"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), root_ident_a.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }

            // Try to remove principal_a
            match rm_allowed_principal(agent.clone(), ident.clone(), cid, principal_a).await {
                ModifyAllowedPrincipalResponse::Err(ModifyAllowedPrincipalError::Unauthorized) => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected unauthorized"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), root_ident_a.clone(), cid).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }
        }
    });
}

// Goal: Verify that one can create, update, and remove registrations
//
// Runbook:
// * install the canister with two root and add an allowed principal
// * create a registrations and verify it
// * submit a duplicate registration
// * create another registration
// * update the registrations (cycle through all states and update the canister id)
// * remove a registration
// * try it with an authorized and an unauthorized principal
pub fn registration_test(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let root_ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_b = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));

    let principal_a = ident_a.sender().unwrap();

    let canister_a = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    let canister_b = Principal::from_text("oa7fk-maaaa-aaaam-abgka-cai").unwrap();

    let domain_a = String::from("example.com");
    let domain_b = String::from("www.test.org");

    let inexistent_registration_id = String::from("inexistent");

    info!(&logger, "installing canister");

    let args = Encode!(&InitArg {
        root_principals: vec![root_ident_a.sender().unwrap()],
        id_seed: 1,
    })
    .unwrap();

    let app_node = env.get_first_healthy_application_node_snapshot();
    let cid =
        app_node.create_and_install_canister_with_arg(CERTIFICATE_ORCHESTRATOR_WASM, Some(args));

    info!(&logger, "creating agent");
    let agent = app_node.build_default_agent();
    let rt = Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        // wait for canister to finish installing
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            match agent_observes_canister_module(&agent, &cid).await {
                true => Ok(()),
                false => panic!("Canister module not available yet"),
            }
        })
        .await
        .unwrap();

        info!(&logger, "created canister={cid}");

        // Add identity A to the allowed principals in order to create registrations
        match add_allowed_principal(agent.clone(), root_ident_a.clone(), cid, principal_a).await {
            ModifyAllowedPrincipalResponse::Ok(()) => {}
            v => panic!("addAllowedPrincipal failed: {v:?}, expected ok"),
        }

        // Create a registration
        let registration_a_id = match create_registration(agent.clone(), ident_a.clone(), cid, domain_a.clone(), canister_a).await {
            CreateRegistrationResponse::Ok(id) => id,
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // Check the state of the registration
        check_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), domain_a.clone(), canister_a, State::PendingOrder).await;

        // Submit a duplicate registration
        match create_registration(agent.clone(), ident_a.clone(), cid, domain_a.clone(), canister_a).await {
            CreateRegistrationResponse::Err(CreateRegistrationError::Duplicate(id)) => if registration_a_id != id {
                panic!("createRegistration failed: expected {registration_a_id:?}, but got {id:?}")
            },
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // Create a registration for another domain
        let registration_b_id = match create_registration(agent.clone(), ident_a.clone(), cid, domain_b.clone(), canister_b).await {
            CreateRegistrationResponse::Ok(id) => id,
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // Check the state of the registration
        check_registration(agent.clone(), ident_a.clone(), cid, registration_b_id.clone(), domain_b.clone(), canister_b, State::PendingOrder).await;

        // Update registrations by going through all registration states
        match update_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), UpdateType::State(State::PendingChallengeResponse)).await
        {
            UpdateRegistrationResponse::Ok(()) => {},
            v => panic!("updateRegistration failed: {v:?}, expected ok"),
        };
        check_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), domain_a.clone(), canister_a, State::PendingChallengeResponse).await;

        match update_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), UpdateType::State(State::PendingAcmeApproval)).await
        {
            UpdateRegistrationResponse::Ok(()) => {},
            v => panic!("updateRegistration failed: {v:?}, expected ok"),
        };
        check_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), domain_a.clone(), canister_a, State::PendingAcmeApproval).await;

        match update_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), UpdateType::State(State::Available)).await
        {
            UpdateRegistrationResponse::Ok(()) => {},
            v => panic!("updateRegistration failed: {v:?}, expected ok"),
        };
        check_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), domain_a.clone(), canister_a, State::Available).await;

        match update_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), UpdateType::Canister(canister_b)).await
        {
            UpdateRegistrationResponse::Ok(()) => {},
            v => panic!("updateRegistration failed: {v:?}, expected ok"),
        };
        check_registration(agent.clone(), ident_a.clone(), cid, registration_a_id.clone(), domain_a.clone(), canister_b, State::Available).await;

        // Update inexistent registration
        match update_registration(agent.clone(), ident_a.clone(), cid, inexistent_registration_id.clone(), UpdateType::State(State::Available)).await
        {
            UpdateRegistrationResponse::Err(UpdateRegistrationError::NotFound) => {},
            v => panic!("updateRegistration failed: {v:?}, expected UpdateRegistrationError::NotFound"),
        };

        // Try to update registration without permissions
        match update_registration(agent.clone(), ident_b.clone(), cid, registration_b_id.clone(), UpdateType::Canister(canister_a)).await
        {
            UpdateRegistrationResponse::Err(UpdateRegistrationError::Unauthorized) => {},
            v => panic!("updateRegistration failed: {v:?}, expected UpdateRegistrationError::Unauthorized"),
        };

        // Set registration to failed state
        match update_registration(agent.clone(), ident_a.clone(), cid, registration_b_id.clone(), UpdateType::State(State::Failed(BoundedString::<127>::from("Test")))).await
        {
            UpdateRegistrationResponse::Ok(()) => {},
            v => panic!("updateRegistration failed: {v:?}, expected ok"),
        };
        check_registration(agent.clone(), ident_a.clone(), cid, registration_b_id.clone(), domain_b.clone(), canister_b, State::Failed(BoundedString::<127>::from("Test"))).await;

        // Remove failed registration
        if let RemoveRegistrationResponse::Err(err) = remove_registration(agent.clone(), ident_a.clone(), cid, registration_b_id.clone()).await {
            panic!("removeRegistration failed: {err:?} expected Ok()");
        }

        // Try to remove inexistent registration
        match remove_registration(agent.clone(), ident_a.clone(), cid, registration_b_id.clone()).await {
            RemoveRegistrationResponse::Err(RemoveRegistrationError::NotFound) => {},
            RemoveRegistrationResponse::Err(err) => panic!("removeRegistration failed: {err:?} expected RemoveRegistrationError::NotFound"),
            RemoveRegistrationResponse::Ok(()) => panic!("removeRegistration failed: got Ok(), expected RemoveRegistrationError::NotFound"),
        };

        // Try to remove a registration without permissions
        match remove_registration(agent.clone(), ident_b.clone(), cid, registration_a_id.clone()).await {
            RemoveRegistrationResponse::Err(RemoveRegistrationError::Unauthorized) => {},
            RemoveRegistrationResponse::Err(err) => panic!("removeRegistration failed: {err:?} expected RemoveRegistrationError::Unauthorized"),
            RemoveRegistrationResponse::Ok(()) => panic!("removeRegistration failed: got Ok(), expected RemoveRegistrationError::Unauthorized"),
        };
    });
}

// Goal: Verify that the task queue works
//
// Runbook:
// * install the canister with two root and add an allowed principal
// * try to look at the next available tasks (with and without tasks)
// * queue tasks for existing and inexistent registrations
// * queue tasks with deadlines now and in the future
// * dispense tasks
// * try it with and without authorization
pub fn task_queue_test(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let root_ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_b = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));

    let principal_a = ident_a.sender().unwrap();

    let canister_a = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();

    let domain_a = String::from("example.com");
    let domain_c = String::from("foo.test.org");

    let inexistent_registration_id = String::from("inexistent");

    info!(&logger, "installing canister");

    let args = Encode!(&InitArg {
        root_principals: vec![root_ident_a.sender().unwrap()],
        id_seed: 1,
    })
    .unwrap();

    let app_node = env.get_first_healthy_application_node_snapshot();
    let cid =
        app_node.create_and_install_canister_with_arg(CERTIFICATE_ORCHESTRATOR_WASM, Some(args));

    info!(&logger, "creating agent");
    let agent = app_node.build_default_agent();
    let rt = Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        // wait for canister to finish installing
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            match agent_observes_canister_module(&agent, &cid).await {
                true => Ok(()),
                false => panic!("Canister module not available yet"),
            }
        })
        .await
        .unwrap();

        info!(&logger, "created canister={cid}");

        // Preparations for the test
        // Add identity A to the allowed principals in order to create registrations
        match add_allowed_principal(agent.clone(), root_ident_a.clone(), cid, principal_a).await {
            ModifyAllowedPrincipalResponse::Ok(()) => {}
            v => panic!("addAllowedPrincipal failed: {v:?}, expected ok"),
        }

        // Create a registration
        let registration_a_id = match create_registration(
            agent.clone(),
            ident_a.clone(),
            cid,
            domain_a.clone(),
            canister_a,
        )
        .await
        {
            CreateRegistrationResponse::Ok(id) => id,
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // Create a registration for another domain
        let registration_b_id = match create_registration(
            agent.clone(),
            ident_a.clone(),
            cid,
            domain_c.clone(),
            canister_a,
        )
        .await
        {
            CreateRegistrationResponse::Ok(id) => id,
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // Test the task queue
        // peek empty task queue
        match peek_task(agent.clone(), ident_a.clone(), cid).await {
            PeekTaskResponse::Err(PeekTaskError::NoTasksAvailable) => {}
            PeekTaskResponse::Err(err) => {
                panic!("peekTask failed: {err:?} expected PeekTaskError::NoTasksAvailable")
            }
            PeekTaskResponse::Ok(_) => {
                panic!("peekTask failed: got Ok(), expected PeekTaskError::NoTasksAvailable")
            }
        };

        // peek without authorisation
        match peek_task(agent.clone(), ident_b.clone(), cid).await {
            PeekTaskResponse::Err(PeekTaskError::Unauthorized) => {}
            PeekTaskResponse::Err(err) => {
                panic!("peekTask failed: {err:?} expected PeekTaskError::Unauthorized")
            }
            PeekTaskResponse::Ok(_) => {
                panic!("peekTask failed: got Ok(), expected PeekTaskError::Unauthorized")
            }
        };

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let timestamp_now = current_time.as_nanos() as u64;
        let timestamp_future = (current_time + Duration::from_secs(2 * 60)).as_nanos() as u64;

        // queue task with inexistent Id and current timestamp
        match queue_task(
            agent.clone(),
            ident_a.clone(),
            cid,
            inexistent_registration_id.clone(),
            timestamp_now,
        )
        .await
        {
            QueueTaskResponse::Err(QueueTaskError::NotFound) => {}
            v => panic!("queueTask failed: {v:?} expected QueueTaskError::NotFound"),
        };

        // queue task without authorization
        match queue_task(
            agent.clone(),
            ident_b.clone(),
            cid,
            registration_a_id.clone(),
            timestamp_now,
        )
        .await
        {
            QueueTaskResponse::Err(QueueTaskError::Unauthorized) => {}
            v => panic!("queueTask failed: {v:?} expected QueueTaskError::Unauthorized"),
        };

        // queue task with immediate deadline
        match queue_task(
            agent.clone(),
            ident_a.clone(),
            cid,
            registration_a_id.clone(),
            timestamp_now,
        )
        .await
        {
            QueueTaskResponse::Ok(_) => {}
            v => panic!("queueTask failed: {v:?}, expected ok with a registration id"),
        };

        // check if new task appears
        match peek_task(agent.clone(), ident_a.clone(), cid).await {
            PeekTaskResponse::Ok(id) => {
                if id != registration_a_id {
                    panic!("peekTask failed: expected {registration_a_id:?}, but got {id:?}")
                }
            }
            v => panic!("peekTask failed: {v:?}, expected ok with a registration id"),
        };

        // dispense task
        match dispense_task(agent.clone(), ident_a.clone(), cid).await {
            DispenseTaskResponse::Ok(id) => {
                if id != registration_a_id {
                    panic!("dispenseTask failed: expected {registration_a_id:?}, but got {id:?}")
                }
            }
            v => panic!("dispenseTask failed: {v:?}, expected ok with a registration id"),
        };

        // try to dispense a task from empty queue
        match dispense_task(agent.clone(), ident_a.clone(), cid).await {
            DispenseTaskResponse::Err(DispenseTaskError::NoTasksAvailable) => {}
            v => panic!("dispenseTask failed: {v:?}, expected DispenseTaskError::NoTasksAvailable"),
        };

        // try to dispense a task without authorization
        match dispense_task(agent.clone(), ident_b.clone(), cid).await {
            DispenseTaskResponse::Err(DispenseTaskError::Unauthorized) => {}
            v => panic!("dispenseTask failed: {v:?}, expected DispenseTaskError::Unauthorized"),
        };

        // queue task with future deadline
        match queue_task(
            agent.clone(),
            ident_a.clone(),
            cid,
            registration_a_id.clone(),
            timestamp_future,
        )
        .await
        {
            QueueTaskResponse::Ok(_) => {}
            v => panic!("queueTask failed: {v:?}, expected ok with a registration id"),
        };

        // peek task queue with only future tasks
        match peek_task(agent.clone(), ident_a.clone(), cid).await {
            PeekTaskResponse::Err(PeekTaskError::NoTasksAvailable) => {}
            v => panic!("peekTask failed: {v:?} expected PeekTaskError::NoTasksAvailable"),
        };

        // try to dispense a task from a queue with only future tasks
        match dispense_task(agent.clone(), ident_a.clone(), cid).await {
            DispenseTaskResponse::Err(DispenseTaskError::NoTasksAvailable) => {}
            v => panic!("dispenseTask failed: {v:?}, expected DispenseTaskError::NoTasksAvailable"),
        };

        // queue task with immediate deadline
        match queue_task(
            agent.clone(),
            ident_a.clone(),
            cid,
            registration_b_id.clone(),
            timestamp_now,
        )
        .await
        {
            QueueTaskResponse::Ok(_) => {}
            v => panic!("queueTask failed: {v:?}, expected ok with a registration id"),
        };

        // check if the task appears
        match peek_task(agent.clone(), ident_a.clone(), cid).await {
            PeekTaskResponse::Ok(id) => {
                if id != registration_b_id {
                    panic!("peekTask failed: expected {registration_b_id:?}, but got {id:?}")
                }
            }
            v => panic!("peekTask failed: {v:?}, expected ok with a registration id"),
        };

        // queue another task for the same registration with a future deadline - should overwrite the existing deadline
        match queue_task(
            agent.clone(),
            ident_a.clone(),
            cid,
            registration_b_id.clone(),
            timestamp_future,
        )
        .await
        {
            QueueTaskResponse::Ok(_) => {}
            v => panic!("queueTask failed: {v:?}, expected ok with a registration id"),
        };

        // peek task queue with only future tasks - should be empty
        match peek_task(agent.clone(), ident_a.clone(), cid).await {
            PeekTaskResponse::Err(PeekTaskError::NoTasksAvailable) => {}
            v => panic!("peekTask failed: {v:?} expected PeekTaskError::NoTasksAvailable"),
        };
    });
}

// Goal: Verify that the certificate export and upload works
//
// Runbook:
// * install the canister and add an allowed principal
// * try to export certificates for inexistent registrations
// * upload certificates for existing and inexistent registration
// * try it with and without authorization
pub fn certificate_export_test(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let root_ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_a = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let ident_b = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));

    let principal_a = ident_a.sender().unwrap();

    let canister_a = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();

    let domain_a = String::from("example.com");

    let inexistent_registration_id = String::from("inexistent");

    let certificate = EncryptedPair(vec![], vec![]);

    info!(&logger, "installing canister");

    let args = Encode!(&InitArg {
        root_principals: vec![root_ident_a.sender().unwrap()],
        id_seed: 1,
    })
    .unwrap();

    let app_node = env.get_first_healthy_application_node_snapshot();
    let cid =
        app_node.create_and_install_canister_with_arg(CERTIFICATE_ORCHESTRATOR_WASM, Some(args));

    info!(&logger, "creating agent");
    let agent = app_node.build_default_agent();
    let rt = Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        // wait for canister to finish installing
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            match agent_observes_canister_module(&agent, &cid).await {
                true => Ok(()),
                false => panic!("Canister module not available yet"),
            }
        })
        .await
        .unwrap();

        info!(&logger, "created canister={cid}");

        // Preparations for the test
        // Add identity A to the allowed principals in order to create registrations
        match add_allowed_principal(agent.clone(), root_ident_a.clone(), cid, principal_a).await {
            ModifyAllowedPrincipalResponse::Ok(()) => {}
            v => panic!("addAllowedPrincipal failed: {v:?}, expected ok"),
        }

        // Create a registration
        let registration_a_id = match create_registration(
            agent.clone(),
            ident_a.clone(),
            cid,
            domain_a.clone(),
            canister_a,
        )
        .await
        {
            CreateRegistrationResponse::Ok(id) => id,
            v => panic!("createRegistration failed: {v:?}, expected ok with a registration id"),
        };

        // export certificates
        match export_certificates(agent.clone(), ident_a.clone(), cid).await {
            ExportCertificatesResponse::Ok(v) if v.is_empty() => {}
            v => panic!("exportCertificates failed: {v:?}, expected Ok with an empty vector"),
        };

        // try to export certificates without authorization
        match export_certificates(agent.clone(), ident_b.clone(), cid).await {
            ExportCertificatesResponse::Err(ExportCertificatesError::Unauthorized) => {}
            v => panic!(
                "exportCertificates failed: {v:?}, expected ExportCertificatesError::Unauthorized"
            ),
        };

        // uploadCertificate for an existing registration ID
        match upload_certificate(
            agent.clone(),
            ident_a.clone(),
            cid,
            registration_a_id.clone(),
            certificate.clone(),
        )
        .await
        {
            UploadCertificateResponse::Ok(()) => {}
            v => panic!("uploadCertificate failed: {v:?}, expected Ok()"),
        };

        // uploadCertificate for an inexistent registration ID
        match upload_certificate(
            agent.clone(),
            ident_a.clone(),
            cid,
            inexistent_registration_id.clone(),
            certificate.clone(),
        )
        .await
        {
            UploadCertificateResponse::Err(UploadCertificateError::NotFound) => {}
            v => {
                panic!("uploadCertificate failed: {v:?}, expected UploadCertificateError::NotFound")
            }
        };

        // uploadCertificate without authorization
        match upload_certificate(
            agent.clone(),
            ident_b.clone(),
            cid,
            registration_a_id.clone(),
            certificate.clone(),
        )
        .await
        {
            UploadCertificateResponse::Err(UploadCertificateError::Unauthorized) => {}
            v => panic!(
                "uploadCertificate failed: {v:?}, expected UploadCertificateError::Unauthorized"
            ),
        };

        // export certificates
        match export_certificates(agent.clone(), ident_a.clone(), cid).await {
            ExportCertificatesResponse::Ok(v) if v.len() == 1 => {
                if v[0].id != registration_a_id {
                    panic!(
                        "exportCertificates failed: expected {:?}, got {:?}",
                        registration_a_id, v[0].id
                    )
                }
                if String::from(v[0].name.clone()) != domain_a {
                    panic!(
                        "exportCertificates failed: expected {:?}, got {:?}",
                        domain_a, v[0].name
                    )
                }
                if v[0].canister != canister_a {
                    panic!(
                        "exportCertificates failed: expected {:?}, got {:?}",
                        canister_a, v[0].canister
                    )
                }
            }
            v => panic!("exportCertificates failed: {v:?}, expected Ok with one registration"),
        };
    });
}

async fn list_allowed_principals(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
) -> ListAllowedPrincipalsResponse {
    agent.set_identity(ident);
    let out = agent
        .query(&orchestrator_id, "listAllowedPrincipals")
        .with_arg(Encode!().unwrap())
        .call()
        .await
        .expect("Could not listAllowedPrincipals");
    Decode!(&out, ListAllowedPrincipalsResponse).unwrap()
}

async fn add_allowed_principal(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    principal: Principal,
) -> ModifyAllowedPrincipalResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "addAllowedPrincipal")
        .with_arg(Encode!(&principal).unwrap())
        .call_and_wait()
        .await
        .expect("Could not addAllowedPrincipal");
    Decode!(&out, ModifyAllowedPrincipalResponse).unwrap()
}

async fn rm_allowed_principal(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    principal: Principal,
) -> ModifyAllowedPrincipalResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "rmAllowedPrincipal")
        .with_arg(Encode!(&principal).unwrap())
        .call_and_wait()
        .await
        .expect("Could not rmAllowedPrincipal");
    Decode!(&out, ModifyAllowedPrincipalResponse).unwrap()
}

async fn create_registration(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    name: String,
    principal: Principal,
) -> CreateRegistrationResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "createRegistration")
        .with_arg(Encode!(&name.to_string(), &principal).unwrap())
        .call_and_wait()
        .await
        .expect("Could not createRegistration");
    Decode!(&out, CreateRegistrationResponse).unwrap()
}

async fn get_registration(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    registration_id: Id,
) -> GetRegistrationResponse {
    agent.set_identity(ident);
    let out = agent
        .query(&orchestrator_id, "getRegistration")
        .with_arg(Encode!(&registration_id.to_string()).unwrap())
        .call()
        .await
        .expect("Could not getRegistration");
    Decode!(&out, GetRegistrationResponse).unwrap()
}

async fn update_registration(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    registration_id: Id,
    update: UpdateType,
) -> UpdateRegistrationResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "updateRegistration")
        .with_arg(Encode!(&registration_id.to_string(), &update).unwrap())
        .call_and_wait()
        .await
        .expect("Could not updateRegistration");
    Decode!(&out, UpdateRegistrationResponse).unwrap()
}

async fn remove_registration(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    registration_id: Id,
) -> RemoveRegistrationResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "removeRegistration")
        .with_arg(Encode!(&registration_id.to_string()).unwrap())
        .call_and_wait()
        .await
        .expect("Could not removeRegistration");
    Decode!(&out, RemoveRegistrationResponse).unwrap()
}

async fn check_registration(
    agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    registration_id: Id,
    name: String,
    principal: Principal,
    state: State,
) {
    match get_registration(
        agent.clone(),
        ident,
        orchestrator_id,
        registration_id.clone(),
    )
    .await
    {
        GetRegistrationResponse::Ok(v) => {
            if String::from(v.name.clone()) != name {
                panic!(
                    "getRegistration failed: registration has name {:?}, expected {:?}",
                    v.name, name
                )
            }
            if v.canister != principal {
                panic!(
                    "getRegistration failed: registration has canister {:?}, expected {:?}",
                    v.canister, principal
                )
            }
            if v.state != state {
                panic!(
                    "getRegistration failed: registration has state {:?}, expected {:?}",
                    v.state, state
                )
            }
        }
        v => panic!("getRegistration failed: {v:?}"),
    }
}

async fn queue_task(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    id: Id,
    timestamp: u64,
) -> QueueTaskResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "queueTask")
        .with_arg(Encode!(&id, &timestamp).unwrap())
        .call_and_wait()
        .await
        .expect("Could not queueTask");
    Decode!(&out, QueueTaskResponse).unwrap()
}

async fn dispense_task(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
) -> DispenseTaskResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "dispenseTask")
        .with_arg(Encode!().unwrap())
        .call_and_wait()
        .await
        .expect("Could not dispenseTask");
    Decode!(&out, DispenseTaskResponse).unwrap()
}

async fn peek_task(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
) -> PeekTaskResponse {
    agent.set_identity(ident);
    let out = agent
        .query(&orchestrator_id, "peekTask")
        .with_arg(Encode!().unwrap())
        .call()
        .await
        .expect("Could not peekTask");
    Decode!(&out, PeekTaskResponse).unwrap()
}

async fn upload_certificate(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
    registration_id: Id,
    pair: EncryptedPair,
) -> UploadCertificateResponse {
    agent.set_identity(ident);
    let out = agent
        .update(&orchestrator_id, "uploadCertificate")
        .with_arg(Encode!(&registration_id, &pair).unwrap())
        .call_and_wait()
        .await
        .expect("Could not uploadCertificate");
    Decode!(&out, UploadCertificateResponse).unwrap()
}

async fn export_certificates(
    mut agent: Agent,
    ident: Secp256k1Identity,
    orchestrator_id: Principal,
) -> ExportCertificatesResponse {
    agent.set_identity(ident);
    let out = agent
        .query(&orchestrator_id, "exportCertificates")
        .with_arg(Encode!().unwrap())
        .call()
        .await
        .expect("Could not exportCertificates");
    Decode!(&out, ExportCertificatesResponse).unwrap()
}
