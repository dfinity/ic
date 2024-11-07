use candid::Principal;
use mockall::automock;

use crate::{
    state::CanisterApi,
    storage::API_BOUNDARY_NODE_PRINCIPALS,
};

#[automock]
pub trait ResolveAccessLevel {
    fn get_access_level(&self) -> AccessLevel;
}

#[derive(PartialEq, Eq)]
pub enum AccessLevel {
    FullAccess,
    FullRead,
    RestrictedRead,
}

#[derive(Clone)]
pub struct AccessLevelResolver<R: CanisterApi> {
    pub caller_id: Principal,
    pub canister_api: R,
}

impl<R: CanisterApi> AccessLevelResolver<R> {
    pub fn new(caller_id: Principal, canister_api: R) -> Self {
        Self {
            caller_id,
            canister_api,
        }
    }
}

impl<R: CanisterApi> ResolveAccessLevel for AccessLevelResolver<R> {
    fn get_access_level(&self) -> AccessLevel {
        if let Some(authorized_principal) = self.canister_api.get_authorized_principal() {
            if self.caller_id == authorized_principal.0 {
                return AccessLevel::FullAccess;
            }
        }

        let has_full_read_access = API_BOUNDARY_NODE_PRINCIPALS.with(|cell| {
            let full_read_principals = cell.borrow();
            full_read_principals.contains(&self.caller_id)
        });

        if has_full_read_access {
            return AccessLevel::FullRead;
        }

        AccessLevel::RestrictedRead
    }
}
