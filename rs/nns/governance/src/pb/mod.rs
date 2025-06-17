use crate::{
    governance::MAX_FOLLOWEES_PER_TOPIC,
    pb::v1::{
        manage_neuron::{set_following::FolloweesForTopic, Follow, SetFollowing},
        ArchivedMonthlyNodeProviderRewards, Topic,
    },
};
use ic_nns_governance_api::{governance_error::ErrorType, GovernanceError};
use ic_stable_structures::{storable::Bound, Storable};
use prost::Message;
use std::{borrow::Cow, collections::HashSet};

#[allow(clippy::all)]
#[path = "../gen/ic_nns_governance.pb.v1.rs"]
pub mod v1;

mod conversions;
mod convert_struct_to_enum;
pub mod proposal_conversions;

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
    /// Returns Err if one or more requirement(s) are not met.
    ///
    /// Enforced properties:
    ///
    ///     1. Topics are unique. If we allowed duplicates, that would give
    ///        people an easy way to construct requests that take up lots of
    ///        time and space. But other than that, we could deal with
    ///        duplicates by having a "last one wins" rule (like in Protocol
    ///        Buffers encoding).
    ///
    ///     2. Topic codes are defined. This is not so important, since follow
    ///        also checks this. However, in order for the uniqueness check to
    ///        be effective at limiting requests, we cannot allow arbitrary
    ///        integer values to be used as topic codes.
    ///
    ///     3. The number of followees on each topic is at most
    ///        MAX_FOLLOWEES_PER_TOPIC.
    ///
    /// NOT enforced here:
    ///
    ///     1. Followees actually exist. This requires "outside" information (to
    ///        wit, the set of existing neurons, or at least, their IDs).
    pub fn validate(&self) -> Result<(), GovernanceError> {
        self.validate_topics_are_unique()?;
        self.validate_not_too_many_followees()?;

        Ok(())
    }

    fn validate_topics_are_unique(&self) -> Result<(), GovernanceError> {
        let mut topics = HashSet::<Option<Topic>>::new();
        for followees_for_topic in &self.topic_following {
            let topic = followees_for_topic.topic.map(Topic::try_from);

            let topic = match topic {
                Some(Err(err)) => {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        format!(
                            "The operation specified an invalid topic code ({:?}): {}",
                            topic, err,
                        ),
                    ));
                }

                None => None,
                Some(Ok(topic)) => Some(topic),
            };

            let is_new = topics.insert(topic);

            if !is_new {
                // Violation detected.
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!(
                        "The operation specified the same topic ({:?}) more than once.",
                        topic,
                    ),
                ));
            }
        }

        Ok(())
    }

    fn validate_not_too_many_followees(&self) -> Result<(), GovernanceError> {
        for followees_for_topic in &self.topic_following {
            let FolloweesForTopic { followees, topic } = followees_for_topic;

            if followees.len() > MAX_FOLLOWEES_PER_TOPIC {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!(
                        "Too many followees (on topic {:?}): {} followees vs. at most {} is allowed.",
                        topic.map(Topic::try_from), followees.len(), MAX_FOLLOWEES_PER_TOPIC,
                    ),
                ));
            }
        }

        Ok(())
    }
}

impl From<SetFollowing> for Vec<Follow> {
    fn from(original: SetFollowing) -> Vec<Follow> {
        let SetFollowing { topic_following } = original;

        topic_following.into_iter().map(Follow::from).collect()
    }
}

impl From<FolloweesForTopic> for Follow {
    fn from(original: FolloweesForTopic) -> Follow {
        let FolloweesForTopic { followees, topic } = original;

        let topic = topic.unwrap_or_default();

        Follow { topic, followees }
    }
}
