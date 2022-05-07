use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use dfn_protobuf::ProtoBuf;
use ledger_canister::BlockHeight;
use on_wire::FromWire;

pub fn handle_send(bytes: Vec<u8>) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let block_index: BlockHeight = ProtoBuf::from_bytes(bytes)
        .map(|c| c.0)
        .map_err(|err| format!("While parsing the reply of the send call: {}", err))?;
    Ok(Ok(Some(OperationOutput::BlockIndex(block_index))))
}
