use crate::pb::v1::{
    manage_neuron::SetFollowing,
    neuron::{FolloweesForTopic, TopicFollowees},
    Followee, NeuronId, Topic,
};
use ic_nervous_system_governance_set_following::{
    get_inconsistent_aliases, FolloweeValidationError,
};
use itertools::{Either, Itertools};
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use strum::IntoEnumIterator;

mod downgrade_impls;
mod upgrade_impls;

lazy_static! {
    /// All topics that are available for following.
    // One enum value is reserved for the unspecified topic.
    pub(crate) static ref TOPICS: BTreeSet<Topic> = Topic::iter().skip(1).collect();

    /// All non-critical topics.
    pub(crate) static ref NON_CRITICAL_TOPICS: BTreeSet<Topic> = TOPICS.iter().copied().filter(Topic::is_non_critical).collect();

    /// Number of topics that are available for following.
    static ref NUM_TOPICS: usize = TOPICS.len();
}

impl ic_nervous_system_governance_set_following::NeuronIdLike for NeuronId {}
impl ic_nervous_system_governance_set_following::TopicLike for Topic {
    fn into_i32(self) -> i32 {
        self as i32
    }
}

pub(crate) type ValidatedSetFollowing = ic_nervous_system_governance_set_following::ValidatedSetFollowing<NeuronId, Topic>;
pub(crate) type ValidatedFolloweesForTopic = ic_nervous_system_governance_set_following::ValidatedFolloweesForTopic<NeuronId, Topic>;
pub(crate) type ValidatedFollowee = ic_nervous_system_governance_set_following::ValidatedFollowee<NeuronId, Topic>;

pub(crate) type SetFollowingError = ic_nervous_system_governance_set_following::SetFollowingError<NeuronId, Topic>;
pub(crate) type SetFollowingValidationError = ic_nervous_system_governance_set_following::SetFollowingValidationError<NeuronId, Topic>;
pub(crate) type FolloweesForTopicValidationError = ic_nervous_system_governance_set_following::FolloweesForTopicValidationError<NeuronId, Topic>;

impl TopicFollowees {
    pub fn with_default_values() -> Self {
        Self {
            topic_id_to_followees: Default::default(),
        }
    }

    pub(crate) fn new(
        topic_followees: Option<Self>,
        set_following: ValidatedSetFollowing,
    ) -> Result<Self, SetFollowingError> {
        let topic_followees = if let Some(topic_followees) = topic_followees {
            topic_followees
        } else {
            TopicFollowees::with_default_values()
        };

        topic_followees.set_following(set_following)
    }

    fn set_following(
        mut self,
        set_following: ValidatedSetFollowing,
    ) -> Result<Self, SetFollowingError> {
        let ValidatedSetFollowing {
            topic_following: mut new_topic_following,
        } = set_following;

        let mut all_followees = vec![];

        for topic in TOPICS.iter().copied() {
            let Some(ValidatedFolloweesForTopic { followees, .. }) =
                new_topic_following.remove(&topic)
            else {
                // Nothing to update for this topic, just keep track of what we had before for
                // analyzing the aliases later on.
                let followees_for_topic = self.topic_id_to_followees.get(&i32::from(topic));

                if let Some(followees_for_topic) = followees_for_topic {
                    let followees_for_topic =
                        ValidatedFolloweesForTopic::try_from(followees_for_topic.clone())
                            .map_err(SetFollowingError::InvalidExistingFollowing)?;

                    all_followees.extend(followees_for_topic.followees.into_iter());
                }

                continue;
            };

            let topic = i32::from(topic);

            all_followees.extend(followees.iter().cloned());

            if followees.is_empty() {
                // Special case: Remove following for this topic.
                self.topic_id_to_followees.remove(&topic);
                continue;
            }

            let followees_per_topic =
                self.topic_id_to_followees
                    .entry(topic)
                    .or_insert_with(|| FolloweesForTopic {
                        topic: Some(topic),
                        followees: vec![],
                    });

            followees_per_topic.followees = followees.iter().cloned().map(Followee::from).collect();
        }

        // Check that after updating `topic_followees` aliases are still unique for each neuron ID.
        let inconsistent_aliases = get_inconsistent_aliases(&all_followees.into_iter().collect());

        if !inconsistent_aliases.is_empty() {
            return Err(SetFollowingError::InconsistentFolloweeAliases(
                inconsistent_aliases,
            ));
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests;
