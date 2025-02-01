use std::path::PathBuf;

use candid::Principal;
use ic_nns_handler_root::backup_root_proposals::ChangeSubnetHaltStatus;
use pocket_ic::{PocketIc, PocketIcBuilder};

fn fetch_backup_canister_wasm() -> Vec<u8> {
    let path: PathBuf = std::env::var("BACKUP_ROOT_WASM_PATH")
        .expect("Path should be set in environment variable BACKUP_ROOT_WASM_PATH")
        .try_into()
        .unwrap();
    std::fs::read(&path).expect(&format!("Failed to read path {}", path.display()))
}

fn init_pocket_ic() -> (PocketIc, Principal) {
    let wasm = fetch_backup_canister_wasm();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_nns_subnet()
        .build();
    let app_subnets = pic.topology().get_app_subnets();

    let subnet_id = app_subnets.first().expect("Should contain one app subnet");

    let canister = pic.create_canister_on_subnet(None, None, *subnet_id);
    pic.add_cycles(canister, 100_000_000_000_000);
    pic.install_canister(canister, wasm, candid::encode_one(()).unwrap(), None);
    (pic, canister)
}

#[test]
fn fetch_pending_proposals_empty() {
    let (pic, canister) = init_pocket_ic();
    let response = pic
        .update_call(
            canister,
            Principal::anonymous(),
            "get_pending_root_proposals_to_change_subnet_halt_status",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch pending root proposals to upgrade governance canister");

    let response: Vec<ChangeSubnetHaltStatus> =
        candid::decode_one(&response).expect("Should be able to decode response");

    assert!(response.is_empty())
}

#[test]
fn fetch_pending_proposals_submited_one() {
    let (pic, canister) = init_pocket_ic();

    let subnet_id = pic.get_subnet(canister).unwrap();

    let response = pic.update_call(
        canister,
        Principal::anonymous(),
        "submit_root_proposal_to_change_subnet_halt_status",
        candid::encode_args((subnet_id, true)).unwrap(),
    );

    assert!(response.is_ok())
}
