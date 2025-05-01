use crate::registry::Registry;
use candid::{CandidType, Deserialize};
use ic_base_types::PrincipalId;
use prost::Message;
use serde::Serialize;

impl Registry {
    pub fn do_migrate_canisters(
        &mut self,
        _payload: MigrateCanistersPayload,
    ) -> MigrateCanistersResponse {
        MigrateCanistersResponse {}
    }
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct MigrateCanistersPayload {
    canister_ids: Vec<PrincipalId>,
    target_subnet_id: PrincipalId,
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct MigrateCanistersResponse {}
