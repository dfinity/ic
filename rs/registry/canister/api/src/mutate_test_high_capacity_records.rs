//! See comments for `fn mutate_test_high_capacity_records` in
//! `rs/registry/canister/canister/canister.rs` (yes, there are three
//! occurrences of "canister" in that path!).

use candid::{CandidType, Deserialize};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_registry_transport::{delete, pb::v1::RegistryMutation, upsert};

#[derive(CandidType, Deserialize)]
pub struct Request {
    pub id: u64,
    pub operation: Operation,
}

#[derive(CandidType, Deserialize)]
pub enum Operation {
    UpsertSmall,
    UpsertLarge,
    Delete,
}

impl Request {
    pub fn into_mutation(self) -> RegistryMutation {
        use Operation::*;

        let Self { id, operation } = self;

        let key = format!("daniel_wong_{id}").bytes().collect::<Vec<u8>>();

        match operation {
            UpsertSmall => upsert(key, b"small value"),
            UpsertLarge => upsert(key, MEGA_BLOB.clone()),
            Delete => delete(key),
        }
    }
}
