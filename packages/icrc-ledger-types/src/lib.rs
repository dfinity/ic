pub mod block;
pub mod transaction;
pub mod value;

use candid::types::number::Nat;
use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;
use std::fmt;
use std::marker::PhantomData;

pub type BlockIndex = Nat;

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchivedRange<Callback> {
    pub start: Nat,
    pub length: Nat,
    pub callback: Callback,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "candid::types::reference::Func")]
pub struct QueryArchiveFn<Input: CandidType, Output: CandidType> {
    pub canister_id: Principal,
    pub method: String,
    pub _marker: PhantomData<(Input, Output)>,
}

impl<Input: CandidType, Output: CandidType> QueryArchiveFn<Input, Output> {
    pub fn new(canister_id: Principal, method: impl Into<String>) -> Self {
        Self {
            canister_id,
            method: method.into(),
            _marker: PhantomData,
        }
    }
}

impl<Input: CandidType, Output: CandidType> Clone for QueryArchiveFn<Input, Output> {
    fn clone(&self) -> Self {
        Self {
            canister_id: self.canister_id,
            method: self.method.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Input: CandidType, Output: CandidType> From<QueryArchiveFn<Input, Output>>
    for candid::types::reference::Func
{
    fn from(archive_fn: QueryArchiveFn<Input, Output>) -> Self {
        let p: &Principal = &Principal::try_from(archive_fn.canister_id.as_ref())
            .expect("could not deserialize principal");
        Self {
            principal: *p,
            method: archive_fn.method,
        }
    }
}

impl<Input: CandidType, Output: CandidType> TryFrom<candid::types::reference::Func>
    for QueryArchiveFn<Input, Output>
{
    type Error = String;
    fn try_from(func: candid::types::reference::Func) -> Result<Self, Self::Error> {
        let canister_id = Principal::try_from(func.principal.as_slice())
            .map_err(|e| format!("principal is not a canister id: {}", e))?;
        Ok(QueryArchiveFn {
            canister_id,
            method: func.method,
            _marker: PhantomData,
        })
    }
}

impl<Input: CandidType, Output: CandidType> CandidType for QueryArchiveFn<Input, Output> {
    fn _ty() -> candid::types::Type {
        candid::types::Type::Func(candid::types::Function {
            modes: vec![candid::parser::types::FuncMode::Query],
            args: vec![Input::_ty()],
            rets: vec![Output::_ty()],
        })
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub canister_id: Principal,
    pub block_range_start: BlockIndex,
    pub block_range_end: BlockIndex,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsRequest {
    pub start: BlockIndex,
    pub length: Nat,
}

impl GetTransactionsRequest {
    pub fn as_start_and_length(&self) -> Result<(u64, u64), String> {
        use num_traits::cast::ToPrimitive;

        let start = self.start.0.to_u64().ok_or_else(|| {
            format!(
                "transaction index {} is too large, max allowed: {}",
                self.start,
                u64::MAX
            )
        })?;
        let length = self.length.0.to_u64().ok_or_else(|| {
            format!(
                "requested length {} is too large, max allowed: {}",
                self.length,
                u64::MAX
            )
        })?;
        Ok((start, length))
    }
}
