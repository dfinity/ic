use std::sync::Arc;
use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;

pub struct DogecoinCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}
