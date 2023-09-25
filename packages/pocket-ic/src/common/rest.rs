//! Rust structs that reflect the structure of JSON-objects used in the v2-REST-API.

use serde::{Deserialize, Serialize};

pub type InstanceId = usize;

// ================================================================================================================= //
// HTTP JSON Request types

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Checkpoint {
    pub checkpoint_name: String,
}

// ================================================================================================================= //
// HTTP JSON Response types

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateInstanceResponse {
    Created { instance_id: InstanceId },
    Error { message: String },
}
