use crate::pb::v1::ArchivedMonthlyNodeProviderRewards;
use ic_stable_structures::{storable::Bound, Storable};
use prost::Message;
use std::borrow::Cow;

#[allow(clippy::all)]
#[path = "../gen/ic_nns_governance.pb.v1.rs"]
pub mod v1;

mod conversions;
mod convert_struct_to_enum;
pub mod proposal_conversions;

use v1::manage_neuron::{set_following::FolloweesForTopic, Follow, SetFollowing};

impl Storable for ArchivedMonthlyNodeProviderRewards {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoidable in the case of Err.)
            .expect("Unable to deserialize ArchivedMonthlyNodeProviderRewards.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl SetFollowing {
    pub fn into_vec_of_follow(self) -> Vec<Follow> {
        let SetFollowing { topic_following } = self;

        topic_following.into_iter().map(Follow::from).collect()
    }
}

impl From<FolloweesForTopic> for Follow {
    fn from(original: FolloweesForTopic) -> Self {
        let FolloweesForTopic { followees, topic } = original;

        let topic = topic.unwrap_or_default();

        Self { topic, followees }
    }
}
