use crate::{errors::ApiError, ledger_client::OperationOutput};
use ic_nns_governance_api::{
    ManageNeuronResponse,
    manage_neuron_response::{Command, SpawnResponse},
};

pub fn handle_spawn(bytes: Vec<u8>) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode SPAWN response: {err}"))?;
    match &response.command {
        Some(Command::Spawn(SpawnResponse { .. })) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not spawn neuron: {err}").into(),
        ))),
        _ => panic!("Unexpected spawn result: {:?}", response.command),
    }
}
