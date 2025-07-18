use crate::Request;
use candid::{CandidType, Principal};
use serde::Deserialize;

// ```candid
// type upload_chunk_args = record {
//     canister_id : principal;
//     chunk : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct UploadChunkArgs {
    pub canister_id: Principal,
    pub chunk: Vec<u8>,
}

// ```candid
// type chunk_hash = record {
//   hash : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ChunkHash {
    pub hash: Vec<u8>,
}

// ```candid
// type upload_chunk_result = chunk_hash;
// ```
pub type UploadChunksResult = ChunkHash;

impl Request for UploadChunkArgs {
    fn method(&self) -> &'static str {
        "upload_chunk"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    fn effective_canister_id(&self) -> Option<Principal> {
        Some(self.canister_id)
    }

    type Response = UploadChunksResult;
}

// ```candid
// type stored_chunks_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct StoredChunksArgs {
    pub canister_id: Principal,
}

// ```
// type chunk_hash = record {
//   hash : blob;
// };
// type stored_chunks_result = vec chunk_hash;
// ```
pub type StoredChunksResult = Vec<ChunkHash>;

impl Request for StoredChunksArgs {
    fn method(&self) -> &'static str {
        "stored_chunks"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    fn effective_canister_id(&self) -> Option<Principal> {
        Some(self.canister_id)
    }

    type Response = StoredChunksResult;
}

// ```
// type canister_status_args = record {
//     canister_id : canister_id;
// };
// ```

// ```
// type canister_status_result = record {
//     status : variant { running; stopping; stopped };
//     settings : definite_canister_settings;
//     module_hash : opt blob;
//     memory_size : nat;
//     cycles : nat;
//     reserved_cycles : nat;
//     idle_cycles_burned_per_day : nat;
//     query_stats: record {
//         num_calls_total: nat;
//         num_instructions_total: nat;
//         request_payload_bytes_total: nat;
//         response_payload_bytes_total: nat;
//     };
// };
// ```

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum LogVisibility {
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(Vec<Principal>),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CanisterStatusResultStatus {
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "running")]
    Running,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct DefiniteCanisterSettings {
    pub freezing_threshold: candid::Nat,
    pub controllers: Vec<Principal>,
    pub reserved_cycles_limit: candid::Nat,
    pub log_visibility: LogVisibility,
    pub wasm_memory_limit: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub compute_allocation: candid::Nat,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterStatusResultQueryStats {
    pub response_payload_bytes_total: candid::Nat,
    pub num_instructions_total: candid::Nat,
    pub num_calls_total: candid::Nat,
    pub request_payload_bytes_total: candid::Nat,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusResultStatus,
    pub settings: DefiniteCanisterSettings,
    pub module_hash: Option<Vec<u8>>,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
    pub reserved_cycles: candid::Nat,
    pub idle_cycles_burned_per_day: candid::Nat,
    pub query_stats: CanisterStatusResultQueryStats,
}

// ```
// type canister_status_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterStatusArgs {
    pub canister_id: Principal,
}

impl Request for CanisterStatusArgs {
    fn method(&self) -> &'static str {
        "canister_status"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    fn effective_canister_id(&self) -> Option<Principal> {
        Some(self.canister_id)
    }

    type Response = CanisterStatusResult;
}

// ```
// type stop_canister_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct StopCanisterArgs {
    pub canister_id: Principal,
}

impl Request for StopCanisterArgs {
    fn method(&self) -> &'static str {
        "stop_canister"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    fn effective_canister_id(&self) -> Option<Principal> {
        Some(self.canister_id)
    }

    type Response = ();
}

// ```
// type delete_canister_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct DeleteCanisterArgs {
    pub canister_id: Principal,
}

impl Request for DeleteCanisterArgs {
    fn method(&self) -> &'static str {
        "delete_canister"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    fn effective_canister_id(&self) -> Option<Principal> {
        Some(self.canister_id)
    }

    type Response = ();
}
