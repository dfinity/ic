use anyhow::Result;
use candid::{Decode, Encode};
use ic_canister_client::{Agent as CanisterClient, Sender};
use ic_consensus_system_test_utils::rw_message::{
    cert_state_makes_progress_with_retries, install_nns_and_check_progress,
};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, IC_00, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    systest,
    util::{block_on, MESSAGE_CANISTER_WASM},
};
use ic_types::CanisterId;
use slog::info;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn nonce() -> Vec<u8> {
    use rand::Rng;
    let mut nonce = vec![0u8; 8];
    rand::thread_rng().fill(&mut nonce[..]);
    nonce
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    let app_node = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("No application subnet found")
        .nodes()
        .next()
        .expect("No nodes in application subnet");

    info!(logger, "Waiting for the application subnet to make progress");
    cert_state_makes_progress_with_retries(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(2),
    );

    let agent = CanisterClient::new(
        app_node.get_public_url(),
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
    );

    let effective_canister_id =
        CanisterId::unchecked_from_principal(app_node.effective_canister_id());

    block_on(async {
        info!(logger, "Creating canister");
        let create_args = ProvisionalCreateCanisterWithCyclesArgs::new(None, None);
        let result = agent
            .execute_update(
                &effective_canister_id,
                &IC_00,
                Method::ProvisionalCreateCanisterWithCycles,
                create_args.encode(),
                nonce(),
            )
            .await
            .expect("Failed to create canister")
            .expect("Empty reply from create canister");

        let canister_id = Decode!(&result, CanisterIdRecord)
            .expect("Failed to decode canister id")
            .get_canister_id();
        info!(logger, "Created canister: {}", canister_id);

        info!(logger, "Installing message canister");
        let install_args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            MESSAGE_CANISTER_WASM.to_vec(),
            vec![],
        );
        agent
            .install_canister(install_args)
            .await
            .expect("Failed to install message canister");
        info!(logger, "Message canister installed");

        let msg = "Hello from canister_client!";
        info!(logger, "Storing message: {}", msg);
        agent
            .execute_update(
                &canister_id,
                &canister_id,
                "store",
                Encode!(&msg.to_string()).unwrap(),
                nonce(),
            )
            .await
            .expect("Failed to store message");

        info!(logger, "Reading message back");
        let result = agent
            .execute_query(
                &canister_id,
                "read",
                Encode!(&()).unwrap(),
            )
            .await
            .expect("Failed to read message")
            .expect("Empty reply from read");

        let read_msg =
            Decode!(&result, Option<String>).expect("Failed to decode read result");

        info!(logger, "Read message: {:?}", read_msg);
        assert_eq!(read_msg, Some(msg.to_string()));
    });

    info!(logger, "Test passed!");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
