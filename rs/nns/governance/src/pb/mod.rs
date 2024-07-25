use crate::pb::storage::VersionedMonthlyNodeProviderRewards;
use ic_stable_structures::{storable::Bound, Storable};
use std::borrow::Cow;

#[allow(clippy::all)]
#[path = "../gen/ic_nns_governance.pb.v1.rs"]
pub mod v1;

#[allow(clippy::all)]
#[path = "../gen/ic_nns_governance.pb.storage.rs"]
pub mod storage;

mod conversions;
mod convert_struct_to_enum;

impl Storable for VersionedMonthlyNodeProviderRewards {
    fn to_bytes(&self) -> Cow<[u8]> {
        todo!()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        todo!()
    }

    const BOUND: Bound = Bound::Unbounded;
}
