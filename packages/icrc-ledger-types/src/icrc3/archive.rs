use crate::icrc1::transfer::BlockIndex;

use super::{
    blocks::{BlockRange, GetBlocksRequest},
    transactions::{GetTransactionsRequest, TransactionRange},
};
use candid::{CandidType, Deserialize, Nat, Principal};
use serde::Serialize;
use std::marker::PhantomData;

/// Deprecated. The information in the `ArchivedRange` struct is returned as part of the return value
/// of [`crate::icrc3::blocks::GetBlocksResult`] from the
/// [`icrc3_get_blocks`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchivedRange<Callback> {
    pub start: Nat,
    pub length: Nat,
    pub callback: Callback,
}

/// Details on the callback function using which archived blocks can be retrieved. Returned as part
/// of [`crate::icrc3::blocks::GetBlocksResult`] from the
/// [`icrc3_get_blocks`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "candid::types::reference::Func")]
pub struct QueryArchiveFn<Input: CandidType, Output: CandidType> {
    pub canister_id: Principal,
    pub method: String,
    pub _marker: PhantomData<(Input, Output)>,
}

impl<Input, Output> PartialOrd for QueryArchiveFn<Input, Output>
where
    Input: CandidType + Eq,
    Output: CandidType + Eq,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Input, Output> Ord for QueryArchiveFn<Input, Output>
where
    Input: CandidType + Eq,
    Output: CandidType + Eq,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.canister_id.cmp(&other.canister_id) {
            std::cmp::Ordering::Equal => self.method.cmp(&other.method),
            c => c,
        }
        // the _marker doesn't matter
    }
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
            .map_err(|e| format!("principal is not a canister id: {e}"))?;
        Ok(QueryArchiveFn {
            canister_id,
            method: func.method,
            _marker: PhantomData,
        })
    }
}

impl<Input: CandidType, Output: CandidType> CandidType for QueryArchiveFn<Input, Output> {
    fn _ty() -> candid::types::Type {
        candid::func!((Input) -> (Output) query)
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

/// Deprecated: Use `ICRC3ArchiveInfo`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub canister_id: Principal,
    pub block_range_start: BlockIndex,
    pub block_range_end: BlockIndex,
}
pub type QueryBlockArchiveFn = QueryArchiveFn<GetBlocksRequest, BlockRange>;
pub type QueryTxArchiveFn = QueryArchiveFn<GetTransactionsRequest, TransactionRange>;

/// The argument for the
/// [`icrc3_get_archives`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetArchivesArgs {
    // The last archive seen by the client.
    // The Ledger will return archives coming
    // after this one if set, otherwise it
    // will return the first archives.
    pub from: Option<Principal>,
}

/// The information returned as part of the return value for the
/// [`icrc3_get_archives`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ICRC3ArchiveInfo {
    // The id of the archive
    pub canister_id: Principal,

    // The first block in the archive
    pub start: Nat,

    // The last block in the archive
    pub end: Nat,
}

/// The return value for the
/// [`icrc3_get_archives`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint.
pub type GetArchivesResult = Vec<ICRC3ArchiveInfo>;
