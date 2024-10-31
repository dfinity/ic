use candid::Principal;
use mockall::automock;

use crate::{state::CanisterStateApi, storage::API_BOUNDARY_NODE_PRINCIPALS};

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
pub struct AccessLevelResolver<R: CanisterStateApi> {
    pub caller_id: Principal,
    pub canister_state_api: R,
}

impl<R: CanisterStateApi> AccessLevelResolver<R> {
    pub fn new(caller_id: Principal, canister_state_api: R) -> Self {
        Self {
            caller_id,
            canister_state_api,
        }
    }
}

impl<R: CanisterStateApi> ResolveAccessLevel for AccessLevelResolver<R> {
    fn get_access_level(&self) -> AccessLevel {
        if let Some(authorized_principal) = self.canister_state_api.get_authorized_principal() {
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
