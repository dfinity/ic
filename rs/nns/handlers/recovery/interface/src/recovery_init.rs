use candid::CandidType;
use serde::Deserialize;

use crate::simple_node_operator_record::SimpleNodeOperatorRecord;

#[derive(CandidType, Clone, Deserialize)]
pub struct RecoveryInitArgs {
    pub initial_node_operator_records: Vec<SimpleNodeOperatorRecord>,
}
