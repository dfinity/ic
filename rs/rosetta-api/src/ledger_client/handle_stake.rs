use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult;
use ic_nns_governance::pb::v1::ClaimOrRefreshNeuronFromAccountResponse;

pub fn handle_stake(bytes: Vec<u8>) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let res: ClaimOrRefreshNeuronFromAccountResponse =
        candid::decode_one(&bytes).map_err(|err| {
            format!(
                "While parsing the reply of the stake creation call: {:?}",
                err
            )
        })?;
    match res.result.unwrap() {
        ClaimOrRefreshResult::Error(err) => {
            return Ok(Err(ApiError::TransactionRejected(
                false,
                format!("Could not claim neuron: {}", err).into(),
            )));
        }
        ClaimOrRefreshResult::NeuronId(nid) => Ok(Ok(Some(OperationOutput::NeuronId(nid.id)))),
    }
}
