use ic_btc_kyt::get_inputs_internal;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};

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
fn transform(raw: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers: vec![],
    }
}

fn main() {}
