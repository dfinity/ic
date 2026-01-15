use crate::{errors::ApiError, ledger_client::OperationOutput};
use ic_nns_governance_api::ListNeuronsResponse;

pub fn handle_list_neurons(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    // Check the response from governance call.
    let response: ListNeuronsResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode LIST_NEURONS response: {err}"))?;
    Ok(Ok(Some(OperationOutput::ListNeuronsResponse(
        response.into(),
    ))))
}
