use std::fmt;

use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

// Account representation of ledgers supporting the ICRC1 standard
#[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

impl Account {
    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(DEFAULT_SUBACCOUNT)
    }
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for Account {}

impl std::cmp::PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Account {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.owner.cmp(&other.owner).then_with(|| {
            self.effective_subaccount()
                .cmp(other.effective_subaccount())
        })
    }
}

impl std::hash::Hash for Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.effective_subaccount().hash(state);
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subaccount {
            None => write!(f, "{}", self.owner),
            Some(subaccount) => write!(f, "0x{}.{}", hex::encode(&subaccount[..]), self.owner),
        }
    }
}

impl From<Principal> for Account {
    fn from(owner: Principal) -> Self {
        Self {
            owner,
            subaccount: None,
        }
    }
}
