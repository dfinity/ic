use blob_store_lib::api::{BlobMetadata, GetError, InsertError, InsertRequest};
use ic_http_types as http;

#[ic_cdk::init]
fn init() {}

#[ic_cdk::post_upgrade]
fn post_upgrade() {}

#[ic_cdk::query]
fn get(hash: String) -> Result<Vec<u8>, GetError> {
    blob_store_lib::query::get(&hash)
}

#[ic_cdk::query]
fn get_metadata(hash: String) -> Result<BlobMetadata, GetError> {
    blob_store_lib::query::get_metadata(&hash)
}

#[ic_cdk::update]
fn insert(request: InsertRequest) -> Result<String, InsertError> {
    blob_store_lib::update::insert(
        ic_cdk::api::msg_caller(),
        &request.hash,
        request.data,
        request.tags.unwrap_or_default(),
    )
    .map(|hash| hash.to_string())
}

#[ic_cdk::query(hidden = true)]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::trap("update call rejected");
    }

    match req.path() {
        "/dashboard" => {
            use askama::Template;
            let dashboard = blob_store_lib::dashboard::dashboard().render().unwrap();
            http::HttpResponseBuilder::ok()
                .header("Content-Type", "text/html; charset=utf-8")
                .with_body_and_content_length(dashboard)
                .build()
        }
        _ => http::HttpResponseBuilder::not_found()
            .with_body_and_content_length("not found")
            .build(),
    }
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
