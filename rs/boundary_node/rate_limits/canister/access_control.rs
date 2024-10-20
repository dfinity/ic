use candid::Principal;

use crate::storage::API_BOUNDARY_NODE_PRINCIPALS;

const FULL_ACCESS_ID: &str = "2vxsx-fae";
const FULL_READ_ID: &str = "2vxsx-fae";

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

        API_BOUNDARY_NODE_PRINCIPALS.with(|cell| {
            let mut full_read_principals = cell.borrow_mut();
            // TODO: this is just for testing, remove later
            let full_read_id = Principal::from_text(FULL_READ_ID).unwrap();
            let _ = full_read_principals.insert(full_read_id);

            if self.caller_id == full_access_principal {
                return AccessLevel::FullAccess;
            } else if full_read_principals.contains(&self.caller_id) {
                return AccessLevel::FullRead;
            }

            AccessLevel::RestrictedRead
        })
    }
}
