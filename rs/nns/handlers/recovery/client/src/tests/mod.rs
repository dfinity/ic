use std::path::PathBuf;

use candid::Principal;
use ed25519_dalek::{ed25519::signature::rand_core::OsRng, SigningKey};
use ic_agent::{agent::AgentBuilder, identity::BasicIdentity, Agent};
use ic_nns_handler_recovery_interface::{
    recovery_init::RecoveryInitArgs, security_metadata::der_encode_public_key,
    simple_node_operator_record::SimpleNodeOperatorRecord,
};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};

use crate::{implementation::RecoveryCanisterImpl, RecoveryCanister};
mod general;

fn fetch_canister_wasm(env: &str) -> Vec<u8> {
    let path: PathBuf = std::env::var(env)
        .expect(&format!("Path should be set in environment variable {env}"))
        .try_into()
        .unwrap();
    std::fs::read(&path).expect(&format!("Failed to read path {}", path.display()))
}

async fn init_pocket_ic(recovery_init_args: RecoveryInitArgs) -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
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

    (pic, canister)
}

fn get_agent(signing_key: SigningKey, url: &str) -> Agent {
    let identity = BasicIdentity::from_signing_key((*signing_key.as_bytes()).into());

    AgentBuilder::default()
        .with_url(url)
        .with_boxed_identity(Box::new(identity))
        .build()
        .unwrap()
}

async fn get_client(pic: &mut PocketIc, canister: Principal) -> impl RecoveryCanister {
    let signing_key = SigningKey::generate(&mut OsRng);
    get_client_with_key(pic, canister, signing_key).await
}

async fn get_client_with_key(
    pic: &mut PocketIc,
    canister: Principal,
    signing_key: SigningKey,
) -> impl RecoveryCanister {
    let url = pic.make_live(None).await;
    let agent = get_agent(signing_key.clone(), url.as_str());
    agent.fetch_root_key().await.unwrap();

    RecoveryCanisterImpl::new(agent, canister, signing_key)
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

struct NodeOperatorWithKey {
    record: SimpleNodeOperatorRecord,
    key: SigningKey,
}

impl NodeOperatorWithKey {
    async fn into_recovery_canister_client(
        &self,
        pic: &mut PocketIc,
        canister: Principal,
    ) -> impl RecoveryCanister {
        get_client_with_key(pic, canister, self.key.clone()).await
    }
}

fn generate_node_operators() -> Vec<NodeOperatorWithKey> {
    (0..10)
        .map(|_| {
            let key = SigningKey::generate(&mut OsRng);
            NodeOperatorWithKey {
                record: SimpleNodeOperatorRecord {
                    operator_id: Principal::self_authenticating(der_encode_public_key(
                        key.verifying_key().to_bytes().to_vec(),
                    )),
                    nodes: (0..4).map(|_| Principal::anonymous()).collect(),
                },
                key,
            }
        })
        .collect()
}
