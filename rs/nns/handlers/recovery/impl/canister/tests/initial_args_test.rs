use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nns_handler_recovery_interface::{
    recovery_init::RecoveryInitArgs, simple_node_operator_record::SimpleNodeOperatorRecord,
};
use pocket_ic::{PocketIc, PocketIcBuilder};

use super::{fetch_canister_wasm, get_current_node_operators};

fn setup_and_install_canister(initial_arg: RecoveryInitArgs) -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let app_subnets = pic.topology().get_app_subnets();

    let subnet_id = app_subnets.first().expect("Should contain one app subnet");
    let canister = pic.create_canister_on_subnet(None, None, *subnet_id);
    pic.add_cycles(canister, 100_000_000_000_000);
    let encoded = candid::encode_one(initial_arg).unwrap();
    println!("Sending: {:?}", encoded);
    pic.install_canister(
        canister,
        fetch_canister_wasm("BACKUP_ROOT_WASM_PATH"),
        encoded,
        None,
    );

    (pic, canister)
}

#[test]
fn set_initial_args() {
    let initial_arg = RecoveryInitArgs {
        initial_node_operator_records: vec![SimpleNodeOperatorRecord {
            operator_id: PrincipalId::new_user_test_id(1).0,
            nodes: vec![],
        }],
    };
    let (pic, canister) = setup_and_install_canister(initial_arg);

    let node_operators = get_current_node_operators(&pic, canister);

    assert!(node_operators.len().eq(&1))
}
