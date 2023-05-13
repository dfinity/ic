/* tag::catalog[]
Title:: Certificate orchestrator test

Goal:: Verify that the certificate orchestrator interface works.

Runbook:
. Set up an certificate orchestrator canister.
. Test that the certificate orchestrator API works.

Success:: The certificate orchestrator canister is installed and the API works.

Coverage:: The certificate orchestrator interface works as expected.

end::catalog[] */

use crate::driver::{
    ic::InternetComputer,
    test_env::TestEnv,
    test_env_api::{
        GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    },
};

use std::time::Duration;

use candid::{Decode, Encode};
use certificate_orchestrator_interface::{
    InitArg, ListAllowedPrincipalsError, ListAllowedPrincipalsResponse,
    ModifyAllowedPrincipalError, ModifyAllowedPrincipalResponse,
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

pub fn certificate_orchestrator_test(env: TestEnv) {
    let logger = env.logger();

    // TODO: install an orchestrator canister into one of the subnets
    // TODO: create an agent to access the canister
    // TODO: Get the canister from bazel?

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
        info!(&logger, "creating replica agent");

        // wait for canister to finish installing
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!(&logger, "created canister={cid}");

        // ACL tests
        let list_allowed_principals = |mut agent: Agent, ident| async move {
            agent.set_identity(ident);
            let out = agent
                .query(&cid, "listAllowedPrincipals")
                .with_arg(Encode!().unwrap())
                .call()
                .await
                .expect("Could not listAllowedPrincipals");
            Decode!(&out, ListAllowedPrincipalsResponse).unwrap()
        };

        // Check that both roots can list
        for ident in [&root_ident_a, &root_ident_b] {
            match list_allowed_principals(agent.clone(), ident.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected ok empty"),
            }
        }
        // Check that non-roots cannot list
        for ident in [&ident_a, &ident_b] {
            match list_allowed_principals(agent.clone(), ident.clone()).await {
                ListAllowedPrincipalsResponse::Err(ListAllowedPrincipalsError::Unauthorized) => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected unauthorized"),
            }
        }

        let add_allowed_principal = |mut agent: Agent, ident, principal| async move {
            agent.set_identity(ident);
            let out = agent
                .update(&cid, "addAllowedPrincipal")
                .with_arg(Encode!(&principal).unwrap())
                .call_and_wait()
                .await
                .expect("Could not addAllowedPrincipal");
            Decode!(&out, ModifyAllowedPrincipalResponse).unwrap()
        };

        let rm_allowed_principal = |mut agent: Agent, ident, principal| async move {
            agent.set_identity(ident);
            let out = agent
                .update(&cid, "rmAllowedPrincipal")
                .with_arg(Encode!(&principal).unwrap())
                .call_and_wait()
                .await
                .expect("Could not rmAllowedPrincipal");
            Decode!(&out, ModifyAllowedPrincipalResponse).unwrap()
        };

        // Check that both roots can add and remove
        for ident in [&root_ident_a, &root_ident_b] {
            info!(&logger, "Adding principals as {}", ident.sender().unwrap());
            // Add principal_a
            match add_allowed_principal(agent.clone(), ident.clone(), principal_a).await {
                ModifyAllowedPrincipalResponse::Ok(()) => {}
                v => panic!("addAllowedPrincipal failed: {v:?}, expected ok"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v == [principal_a] => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected principal_a"),
            }

            // Remove principal_b
            match rm_allowed_principal(agent.clone(), ident.clone(), principal_b).await {
                ModifyAllowedPrincipalResponse::Err(
                    ModifyAllowedPrincipalError::UnexpectedError(e),
                ) if e == "principal not found" => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected err"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v == [principal_a] => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected principal_a"),
            }

            // Remove principal_a
            match rm_allowed_principal(agent.clone(), ident.clone(), principal_a).await {
                ModifyAllowedPrincipalResponse::Ok(()) => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected ok"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), ident.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }
        }

        // Check that non-roots cannot add or remove
        for ident in [&ident_a, &ident_b] {
            // Try to add principal_a
            match add_allowed_principal(agent.clone(), ident.clone(), principal_a).await {
                ModifyAllowedPrincipalResponse::Err(ModifyAllowedPrincipalError::Unauthorized) => {}
                v => panic!("addAllowedPrincipal failed: {v:?}, expected unauthorized"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), root_ident_a.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }

            // Try to remove principal_a
            match rm_allowed_principal(agent.clone(), ident.clone(), principal_a).await {
                ModifyAllowedPrincipalResponse::Err(ModifyAllowedPrincipalError::Unauthorized) => {}
                v => panic!("rmAllowedPrincipal failed: {v:?}, expected unauthorized"),
            }

            // Check the list
            match list_allowed_principals(agent.clone(), root_ident_a.clone()).await {
                ListAllowedPrincipalsResponse::Ok(v) if v.is_empty() => {}
                v => panic!("listAllowedPrincipals failed: {v:?}, expected empty"),
            }
        }
    });

    // 2. get access to the orchestrator api
    // 4. test the following:
    // // Registrations
    // createRegistration: (Name, Canister) -> (CreateRegistrationResponse);
    // getRegistration: (Id) -> (GetRegistrationResponse) query;
    // updateRegistration: (Id, State) -> (UpdateRegistrationResponse);
    //
    // // Certificates
    // uploadCertificate: (Id, EncryptedPair) -> (UploadCertificateResponse);
    // exportCertificates: () -> (ExportCertificatesResponse);
    //
    // // Tasks
    // queueTask: (Id, Timestamp) -> (QueueTaskResponse);
    // dispenseTask: () -> (DispenseTaskResponse);
    // peekTask: () -> (DispenseTaskResponse) query;
}
