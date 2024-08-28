use bitcoin::{Address, Network};
use ic_btc_kyt::{blocklist_contains, get_inputs_internal, CheckAddressArgs, CheckAddressResponse};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use std::str::FromStr;

#[ic_cdk::update]
/// The function returns the Bitcoin addresses of the inputs in the
/// transaction with the given transaction ID.
async fn get_inputs(tx_id: String) -> Vec<String> {
    // TODO(XC-157): Charge cycles and also add guards.
    match get_inputs_internal(tx_id).await {
        Ok(inputs) => inputs,
        Err(err) => panic!("Error in getting transaction inputs: {:?}", err),
    }
}

#[ic_cdk::query]
/// Return `Passed` if the given bitcion address passed the KYT check, or
/// `Failed` otherwise.
/// May throw error (trap) if the given address is malformed or not a mainnet address.
async fn check_address(args: CheckAddressArgs) -> CheckAddressResponse {
    let address = Address::from_str(args.address.trim())
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Invalid bitcoin address: {}", err)))
        .require_network(Network::Bitcoin)
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Not a bitcoin mainnet address: {}", err)));

    if blocklist_contains(&address) {
        CheckAddressResponse::Failed
    } else {
        CheckAddressResponse::Passed
    }
}

#[ic_cdk::query(hidden = true)]
fn transform(raw: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers: vec![],
    }
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("btc_kyt_canister.did");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
