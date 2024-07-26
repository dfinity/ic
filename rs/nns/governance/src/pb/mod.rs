use crate::pb::storage::ArchivedMonthlyNodeProviderRewards;
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

use prost::Message;

impl Storable for ArchivedMonthlyNodeProviderRewards {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoid able in the case of Err.)
            .expect("Unable to deserialize ArchivedMonthlyNodeProviderRewards.")
    }

    const BOUND: Bound = Bound::Unbounded;
}
