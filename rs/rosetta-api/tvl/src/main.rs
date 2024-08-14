use candid::candid_method;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, query};
use ic_tvl_canister::dashboard::build_dashboard;
use ic_tvl_canister::metrics::encode_metrics;
use ic_tvl_canister::types::{TvlArgs, TvlResult, TvlResultError};
use ic_tvl_canister::TvlRequest;

fn main() {}

// NB: init is only called at first installation, not while upgrading canister.
#[init]
#[candid_method(init)]
fn init(args: TvlArgs) {
    ic_tvl_canister::init(args);
}

#[post_upgrade]
async fn post_upgrade(args: TvlArgs) {
    ic_tvl_canister::post_upgrade(args).await
}

#[query]
#[candid_method(query)]
async fn get_tvl(req: Option<TvlRequest>) -> Result<TvlResult, TvlResultError> {
    ic_tvl_canister::get_tvl(req).await
}

#[query]
#[candid_method(query)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);
        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        let dashboard: Vec<u8> = build_dashboard();
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid_parser::utils::CandidSource) -> String {
        match source {
            candid_parser::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid_parser::utils::CandidSource::Text(t) => t.to_string(),
        }
    }
    fn check_service_equal(
        new_name: &str,
        new: candid_parser::utils::CandidSource,
        old_name: &str,
        old: candid_parser::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid_parser::utils::service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }
    candid::export_service!();
    let new_interface = __export_service();
    // check the public interface against the actual one
    let old_interface =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("tvl.did");
    check_service_equal(
        "actual ledger candid interface",
        candid_parser::utils::CandidSource::Text(&new_interface),
        "declared candid interface in tvl.did file",
        candid_parser::utils::CandidSource::File(old_interface.as_path()),
    );
}
