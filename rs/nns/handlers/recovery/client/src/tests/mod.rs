use std::path::PathBuf;

use candid::Principal;
use ic_agent::agent::AgentBuilder;
use ic_agent::{Agent, Identity};
use ic_nns_handler_recovery_interface::{
    recovery_init::RecoveryInitArgs, simple_node_operator_record::SimpleNodeOperatorRecord,
};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};

mod general;

fn fetch_canister_wasm(env: &str) -> Vec<u8> {
    let path: PathBuf = std::env::var(env)
        .expect(&format!("Path should be set in environment variable {env}"))
        .try_into()
        .unwrap();
    std::fs::read(&path).expect(&format!("Failed to read path {}", path.display()))
}

async fn init_pocket_ic(recovery_init_args: RecoveryInitArgs) -> (PocketIc, Principal) {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let subnets = pic.topology().await.get_app_subnets();
    let subnet = subnets.first().unwrap();
    let canister = pic.create_canister_on_subnet(None, None, *subnet).await;
    pic.add_cycles(canister, 100_000_000_000_000).await;
    pic.install_canister(
        canister,
        fetch_canister_wasm("RECOVERY_WASM_PATH"),
        candid::encode_one(recovery_init_args).unwrap(),
        None,
    )
    .await;

    pic.make_live(None).await;
    (pic, canister)
}

fn preconfigured_recovery_init_args(
    operators_with_keys: &Vec<NodeOperatorWithKey>,
) -> RecoveryInitArgs {
    RecoveryInitArgs {
        initial_node_operator_records: operators_with_keys
            .iter()
            .map(|o| o.record.clone())
            .collect(),
    }
}

async fn get_ic_agent(identity: Box<dyn Identity>, endpoint: &str) -> Agent {
    let agent = AgentBuilder::default()
        .with_identity(identity)
        .with_url(endpoint)
        .build()
        .unwrap();
    agent.fetch_root_key().await.unwrap();
    agent
}

struct NodeOperatorWithKey {
    record: SimpleNodeOperatorRecord,
}

fn generate_node_operators(signers: Vec<Vec<u8>>) -> Vec<NodeOperatorWithKey> {
    signers
        .iter()
        .map(|der_encoded_pub_key| NodeOperatorWithKey {
            record: SimpleNodeOperatorRecord {
                operator_id: Principal::self_authenticating(der_encoded_pub_key),
                nodes: (0..4).map(|_| Principal::anonymous()).collect(),
            },
        })
        .collect()
}
