use candid::Principal;
use mockall::automock;

use crate::storage::API_BOUNDARY_NODE_PRINCIPALS;

const FULL_ACCESS_ID: &str = "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";

#[automock]
pub trait ResolveAccessLevel {
    fn get_access_level(&self) -> AccessLevel;
}

#[derive(Debug, thiserror::Error)]
pub enum AccessLevelError {}

#[derive(PartialEq, Eq)]
pub enum AccessLevel {
    FullAccess,
    FullRead,
    RestrictedRead,
}

#[derive(Clone)]
pub struct AccessLevelResolver {
    pub caller_id: Principal,
}

impl AccessLevelResolver {
    pub fn new(caller_id: Principal) -> Self {
        Self { caller_id }
    }
}

impl ResolveAccessLevel for AccessLevelResolver {
    fn get_access_level(&self) -> AccessLevel {
        let full_access_principal = Principal::from_text(FULL_ACCESS_ID).unwrap();

        if self.caller_id == full_access_principal {
            return AccessLevel::FullAccess;
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
