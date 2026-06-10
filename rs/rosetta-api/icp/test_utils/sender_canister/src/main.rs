use ic_cdk::call::{Call, CallFailed};
use ic_cdk::update;
use ic_sender_canister_lib::{RejectionCode, SendArg, SendResult};

#[update]
async fn send(calls: Vec<SendArg>) -> Vec<SendResult> {
    let mut futures = vec![];
    for SendArg {
        to,
        method,
        arg,
        payment,
    } in calls
    {
        futures.push(async move {
            Call::unbounded_wait(to, &method)
                .take_raw_args(arg)
                .with_cycles(payment)
                .await
                .map(|response| response.into_bytes())
                .map_err(map_call_error)
        });
    }

    futures::future::join_all(futures).await
}

fn map_call_error(err: CallFailed) -> (RejectionCode, String) {
    match err {
        CallFailed::CallRejected(rejected) => (
            RejectionCode::from_raw(rejected.raw_reject_code()),
            rejected.reject_message().to_string(),
        ),
        CallFailed::InsufficientLiquidCycleBalance(e) => (RejectionCode::Unknown, e.to_string()),
        CallFailed::CallPerformFailed(e) => (RejectionCode::Unknown, e.to_string()),
    }
}

fn main() {}

candid::export_service!();

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};

    let new_interface = __export_service();
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let old_interface = manifest_dir.join("sender.did");
    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "the service interface is not compatible with {}: {:?}",
            old_interface.display(),
            e
        )
    });
}
