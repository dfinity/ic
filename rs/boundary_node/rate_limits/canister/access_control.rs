use candid::Principal;

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
        let full_read_principal = Principal::from_text(FULL_READ_ID).unwrap();

        if self.caller_id == full_access_principal {
            return AccessLevel::FullAccess;
        } else if self.caller_id == full_read_principal {
            return AccessLevel::FullRead;
        }

        AccessLevel::RestrictedRead
    }
}
