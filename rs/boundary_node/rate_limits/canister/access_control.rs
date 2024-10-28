use candid::Principal;
use mockall::automock;

use crate::{state::Repository, storage::API_BOUNDARY_NODE_PRINCIPALS};

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
pub struct AccessLevelResolver<R: Repository> {
    pub caller_id: Principal,
    pub repository: R,
}

impl<R: Repository> AccessLevelResolver<R> {
    pub fn new(caller_id: Principal, repository: R) -> Self {
        Self {
            caller_id,
            repository,
        }
    }
}

impl<R: Repository> ResolveAccessLevel for AccessLevelResolver<R> {
    fn get_access_level(&self) -> AccessLevel {
        if let Some(authorized_principal) = self.repository.get_authorized_principal() {
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
