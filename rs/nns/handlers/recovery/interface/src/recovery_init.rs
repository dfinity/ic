use candid::{CandidType, Deserialize};
use serde::Serialize;

use crate::simple_node_operator_record::SimpleNodeOperatorRecord;

#[derive(CandidType, Debug, Deserialize, Serialize, Default)]
pub struct RecoveryInitArgs {
    pub initial_node_operator_records: Vec<SimpleNodeOperatorRecord>,
}
