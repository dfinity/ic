use blob_store_lib::api::{RecordError, RecordRequest};

#[ic_cdk::init]
fn init() {}

#[ic_cdk::post_upgrade]
fn post_upgrade() {}

#[ic_cdk::update]
fn record(request: RecordRequest) -> Result<String, RecordError> {
    blob_store_lib::record(ic_cdk::api::msg_caller(), &request.hash, request.data)
        .map(|hash| hash.to_string())
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("blob_store.did");

    service_equal(
        CandidSource::Text(dbg!(&new_interface)),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
