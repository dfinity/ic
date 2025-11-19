use crate::{
    errors::ApiError,
    ledger_client::{OperationOutput, disburse_maturity_response::DisburseMaturityResponse},
};
use ic_nns_governance_api::{
    ManageNeuronResponse,
    manage_neuron_response::{Command, DisburseMaturityResponse as NnsDisburseMaturityResponse},
};

pub fn handle_disburse_maturity(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode ManageNeuronResponse : {err}"))?;
    match &response.command {
        Some(Command::DisburseMaturity(NnsDisburseMaturityResponse {
            amount_disbursed_e8s,
        })) => Ok(Ok(Some(OperationOutput::DisburseMaturityResponse(
            DisburseMaturityResponse {
                amount_disbursed_e8s: *amount_disbursed_e8s,
            },
        )))),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not disburse maturity: {err}").into(),
        ))),
        _ => panic!(
            "Unexpected disburse maturity result: {:?}",
            response.command
        ),
    }
}
