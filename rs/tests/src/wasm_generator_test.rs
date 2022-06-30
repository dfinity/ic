use crate::driver::ic::{InternetComputer, Subnet};
use crate::util;
use candid::Encode;
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_fondue::ic_manager::IcHandle;
use ic_fondue::{self};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use slog::info;
use std::env;
use std::fs;
use std::path::Path;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    let node = util::get_random_application_node_endpoint(&handle, &mut rng);
    util::block_on(async move {
        info!(ctx.logger, "Asserting reachability of all nodes..");
        // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
        util::assert_endpoints_reachability(
            endpoints.as_slice(),
            util::EndpointsStatus::AllReachable,
        )
        .await;

        info!(ctx.logger, "All nodes are reachable, creating agent..");
        let agent = util::assert_create_agent(node.url.as_str()).await;

        info!(ctx.logger, "Reading canister paths..");
        // A path of a directory containing canisters has to be passed in to the test
        // through an env variable named `RANDOM_CANISTERS_BASE_DIR`.
        let canisters_base_dir = env::var("RANDOM_CANISTERS_BASE_DIR")
            .expect("RANDOM_CANISTERS_BASE_DIR env variable not set");
        let can_paths =
            fs::read_dir(canisters_base_dir).expect("directory with random canisters is incorrect");

        for p in can_paths {
            info!(ctx.logger, "Installing canister {:?}..", p);
            let cid =
                install_random_canister(&agent, &p.expect("canister path incorrect").path()).await;
            info!(ctx.logger, "Send query to canister");
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
