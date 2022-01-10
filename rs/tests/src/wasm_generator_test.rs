use crate::util;
use candid::Encode;
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_fondue::{self};
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use std::env;
use std::fs;
use std::path::Path;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let mut rng = ctx.rng.clone();
        let node = util::get_random_application_node_endpoint(&handle, &mut rng);
        node.assert_ready(ctx).await;
        let agent = util::assert_create_agent(node.url.as_str()).await;

        // A path of a directory containing canisters has to be passed in to the test
        // through an env variable named `RANDOM_CANISTERS_BASE_DIR`.
        let canisters_base_dir = env::var("RANDOM_CANISTERS_BASE_DIR")
            .expect("RANDOM_CANISTERS_BASE_DIR env variable not set");
        let can_paths =
            fs::read_dir(canisters_base_dir).expect("directory with random canisters is incorrect");

        for p in can_paths {
            let cid =
                install_random_canister(&agent, &p.expect("canister path incorrect").path()).await;
            // Verify that the compute function exported by the installed canister can be
            // called.
            agent
                .query(&cid, "compute")
                .with_arg(&Encode!().unwrap())
                .call()
                .await
                .expect("compute returned error");
        }
    });
}

async fn install_random_canister(agent: &Agent, canister_path: &Path) -> Principal {
    let random_canister: Vec<u8> =
        fs::read(&canister_path).expect("could not load random canister");

    let mgr = ManagementCanister::create(agent);
    let cid = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .call_and_wait(util::delay())
        .await
        .expect("failed to create a canister")
        .0;
    mgr.install_code(&cid, random_canister.as_slice())
        .call_and_wait(util::delay())
        .await
        .expect("failed to install canister");
    cid
}
