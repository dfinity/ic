use crate::pb::v1::{
    Followee, NeuronId, Topic,
    manage_neuron::SetFollowing,
    neuron::{FolloweesForTopic, TopicFollowees},
};
use itertools::{Either, Itertools};
use lazy_static::lazy_static;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};
use strum::IntoEnumIterator;
use thiserror::Error;

/// Maximum number of bytes that a neuron alias can have.
pub const MAX_NEURON_ALIAS_BYTES: usize = 128;

/// Maximum number of followees that a neuron can have for a given topic.
pub const MAX_FOLLOWEES_PER_TOPIC: usize = 15;

lazy_static! {
    /// All topics that are available for following.
    // One enum value is reserved for the unspecified topic.
    pub(crate) static ref TOPICS: BTreeSet<Topic> = Topic::iter().skip(1).collect();

    /// All non-critical topics.
    pub(crate) static ref NON_CRITICAL_TOPICS: BTreeSet<Topic> = TOPICS.iter().copied().filter(Topic::is_non_critical).collect();

    /// Number of topics that are available for following.
    static ref NUM_TOPICS: usize = TOPICS.len();
}

#[derive(Debug, PartialEq)]
pub(crate) struct ValidatedSetFollowing {
    /// Keys cannot contain `Topic::Unspecified`. Values cannot be empty.
    pub topic_following: BTreeMap<Topic, ValidatedFolloweesForTopic>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct ValidatedFolloweesForTopic {
    /// If this is empty, it means that the neuron is not following any other neurons on this topic.
    /// An empty set is used also to unset the followees for a given topic.
    pub followees: BTreeSet<ValidatedFollowee>,

    pub topic: Topic,
}

impl From<ValidatedFollowee> for Followee {
    fn from(value: ValidatedFollowee) -> Self {
        let ValidatedFollowee {
            neuron_id, alias, ..
        } = value;

        Self {
            neuron_id: Some(neuron_id),
            alias,
        }
    }
}

impl From<ValidatedFolloweesForTopic> for FolloweesForTopic {
    fn from(value: ValidatedFolloweesForTopic) -> Self {
        let ValidatedFolloweesForTopic { followees, topic } = value;

        let followees = followees.into_iter().map(Followee::from).collect();

        let topic = Some(i32::from(topic));

        Self { followees, topic }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ValidatedFollowee {
    topic: Topic,

    neuron_id: NeuronId,

    /// Alias is optional. If it is set, it must be unique for the same neuron ID.
    ///
    /// For example, the following is a valid topic-based following configuration:
    /// ```
    /// [
    ///     Followee(topic: T1, neuron_id: 41, alias: "Alice"),
    ///     Followee(topic: T2, neuron_id: 42, alias: "Alice"),
    /// ]
    /// ```
    /// because the alias "Alice" is unique for each neuron ID (e.g., the user Alice may control
    /// both neurons 41 and 42).
    ///
    /// And the following is not valid:
    /// ```
    /// [
    ///     Followee(topic: T1, neuron_id: 42, alias: "Alice"),
    ///     Followee(topic: T2, neuron_id: 42, alias: "Bob"),
    /// ]
    /// ```
    /// because the neuron ID 42 cannot be associated with two different aliases.
    alias: Option<String>,
}

impl fmt::Display for ValidatedFollowee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(alias) = &self.alias {
            write!(
                f,
                "Followee(topic: {}, neuron_id: {}, alias: {})",
                self.topic, self.neuron_id, alias
            )
        } else {
            write!(
                f,
                "Followee(topic: {}, neuron_id: {})",
                self.topic, self.neuron_id
            )
        }
    }
}

impl fmt::Debug for ValidatedFollowee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format_args!("{}", self))
    }
}

/// Represents followees grouped by neuron ID.
type FolloweeGroups = BTreeMap<NeuronId, Vec<ValidatedFollowee>>;

/// Helper function to aid checking the invariant: **Followees on a given topic must have
/// unique neuron IDs.**
///
/// Example pattern:
///
/// ```
/// let duplicate_followee_groups = get_duplicate_followee_groups(&followees_for_this_topic);
///
/// if !duplicate_followee_groups.is_empty() {
///     return Err(Error(duplicate_followee_groups));
/// }
/// ```
///
/// Returns the map from neuron IDs (from `followees`) to the actual followee instances
/// for the corresponding neuron IDs.
///
/// Assumption: `followees` all correspond to the same topic.
///
/// The implementation of this function relies on the fact that `ValidatedFollowee` instances are
/// ordered by topic and *then* neuron ID, which is enforced by the `PartialOrd` implementation.
///
/// This function assumes that all followees correspond to the same topic.
fn get_duplicate_followee_groups(followees: &BTreeSet<ValidatedFollowee>) -> FolloweeGroups {
    followees
        .iter()
        .sorted_by_key(|followee| followee.neuron_id.clone())
        .group_by(|followee| followee.neuron_id.clone())
        .into_iter()
        .filter_map(|(neuron_id, group)| {
            let followees_with_this_neuron_id = group.into_iter().cloned().collect::<Vec<_>>();

            if followees_with_this_neuron_id.len() > 1 {
                Some((neuron_id, followees_with_this_neuron_id))
            } else {
                None
            }
        })
        .collect()
}

/// Formats an instance of `FolloweeGroups` into a string.
///
/// Need this since `Display for Vec<ValidatedFollowee>` cannot be implemented in this crate.
fn fmt_followee_groups(followee_groups: &FolloweeGroups) -> String {
    followee_groups
        .iter()
        .map(|(neuron_id, followees)| {
            let followees = followees
                .iter()
                .map(|followee| format!("{followee}"))
                .collect::<Vec<_>>()
                .join(", ");

            format!("{neuron_id}: {followees}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Represents followee-related data grouped by neuron ID.
type FolloweeAliasGroups = BTreeMap<NeuronId, BTreeSet<ValidatedFollowee>>;

/// Helper function to aid checking the invariant: **followees with the same alias must have
/// the same neuron ID.**
///
/// Example pattern:
///
/// ```
/// let inconsistent_aliases = get_inconsistent_aliases(&followees_for_this_topic);
///
/// if !inconsistent_aliases.is_empty() {
///     return Err(Error(inconsistent_aliases));
/// }
/// ```
///
/// Returns the map of followee neuron IDs (from `followees`) that have multiple aliases. The map
/// values represent the corresponding sets followees.
///
/// The implementation of this function relies on the fact that `ValidatedFollowee` instances are
/// ordered by neuron ID and *then* alias, which is enforced by the `PartialOrd` implementation.
fn get_inconsistent_aliases(followees: &BTreeSet<ValidatedFollowee>) -> FolloweeAliasGroups {
    followees
        .iter()
        .sorted_by_key(|followee| followee.neuron_id.clone())
        .group_by(|followee| followee.neuron_id.clone())
        .into_iter()
        .filter_map(|(neuron_id, group)| {
            // Since aliases are optional, filter out the ones that are not set (since they cannot
            // cause inconsistencies).
            let followees_with_aliases = group
                .into_iter()
                .filter(|followee| followee.alias.is_some())
                .cloned()
                .collect::<BTreeSet<_>>();

            let unique_aliases = followees_with_aliases
                .iter()
                .filter_map(|followee| followee.alias.clone())
                .collect::<HashSet<_>>();

            // If there's more than one unique alias, report inconsistency.
            if unique_aliases.len() > 1 {
                Some((neuron_id.clone(), followees_with_aliases))
            } else {
                None
            }
        })
        .collect()
}

fn fmt_alias_groups(followees: &FolloweeAliasGroups) -> String {
    followees
        .iter()
        .map(|(neuron_id, followees_for_this_neuron_id)| {
            let followees_for_this_neuron_id = followees_for_this_neuron_id
                .iter()
                .map(|followee| format!("{followee}"))
                .collect::<Vec<_>>()
                .join(", ");

            format!("{neuron_id}: [{followees_for_this_neuron_id}]")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FolloweeValidationError {
    #[error("field neuron_id must be specified")]
    NeuronIdNotSpecified,

    #[error("alias cannot be the empty string")]
    AliasCannotBeEmptyString,

    #[error("alias cannot exceed {} bytes, got {} bytes", MAX_NEURON_ALIAS_BYTES, .0)]
    AliasTooLong(usize),
}

impl TryFrom<(Followee, Topic)> for ValidatedFollowee {
    type Error = FolloweeValidationError;

    fn try_from(value: (Followee, Topic)) -> Result<Self, Self::Error> {
        let (Followee { neuron_id, alias }, topic) = value;

        let Some(neuron_id) = neuron_id else {
            return Err(Self::Error::NeuronIdNotSpecified);
        };

        if let Some(alias) = &alias {
            if alias.is_empty() {
                return Err(Self::Error::AliasCannotBeEmptyString);
            }

            if alias.len() > MAX_NEURON_ALIAS_BYTES {
                return Err(Self::Error::AliasTooLong(alias.len()));
            }
        }

        Ok(Self {
            topic,
            neuron_id,
            alias,
        })
    }
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FolloweesForTopicValidationError {
    #[error("topic must be set to one from SnsGov.list_topics()")]
    UnspecifiedTopic,

    #[error("a neuron can only follow up to {} other neurons on a given topic (requested {})", MAX_FOLLOWEES_PER_TOPIC, .0)]
    TooManyFollowees(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweeValidationError(Vec<FolloweeValidationError>),

    #[error("followees on a given topic must have unique neuron IDs, got: {}", fmt_followee_groups(.0))]
    DuplicateFolloweeNeuronId(FolloweeGroups),
}

impl TryFrom<FolloweesForTopic> for ValidatedFolloweesForTopic {
    type Error = FolloweesForTopicValidationError;

    fn try_from(value: FolloweesForTopic) -> Result<Self, Self::Error> {
        let FolloweesForTopic { followees, topic } = value;

        let topic = match topic.map(Topic::try_from) {
            Some(Ok(topic)) if topic != Topic::Unspecified => topic,
            _ => {
                return Err(Self::Error::UnspecifiedTopic);
            }
        };

        if followees.len() > MAX_FOLLOWEES_PER_TOPIC {
            return Err(Self::Error::TooManyFollowees(followees.len()));
        }

        let (followees, errors): (Vec<_>, Vec<_>) =
            followees.into_iter().partition_map(|followee| {
                match ValidatedFollowee::try_from((followee, topic)) {
                    Ok(followee) => Either::Left(followee),
                    Err(err) => Either::Right(err),
                }
            });

        if !errors.is_empty() {
            return Err(Self::Error::FolloweeValidationError(errors));
        }

        let followees = followees.into_iter().collect();

        let duplicate_neuron_ids = get_duplicate_followee_groups(&followees);

        if !duplicate_neuron_ids.is_empty() {
            return Err(Self::Error::DuplicateFolloweeNeuronId(duplicate_neuron_ids));
        }

        Ok(Self { followees, topic })
    }
}

fn fmt_topics(topics: &[Topic]) -> String {
    topics
        .iter()
        .map(|topic| format!("{} ({})", topic, *topic as i32))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SetFollowingValidationError {
    #[error("topic_following must contain at least one element")]
    NoTopicFollowingSpecified,

    #[error("topic_followees cannot contain more than {} elements (got {})", *NUM_TOPICS, .0)]
    TooManyTopicFollowees(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweesForTopicValidationError(BTreeSet<FolloweesForTopicValidationError>),

    #[error("topics must be unique, but the following topics had duplicates: {}", fmt_topics(.0))]
    DuplicateTopics(Vec<Topic>),

    #[error("followees are identified by ID and cannot have more than one alias, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups),
}

impl TryFrom<SetFollowing> for ValidatedSetFollowing {
    type Error = SetFollowingValidationError;

    fn try_from(value: SetFollowing) -> Result<Self, Self::Error> {
        let SetFollowing { topic_following } = value;

        if topic_following.is_empty() {
            return Err(Self::Error::NoTopicFollowingSpecified);
        }

        if topic_following.len() > *NUM_TOPICS {
            return Err(Self::Error::TooManyTopicFollowees(topic_following.len()));
        }

        let (topic_following, errors): (Vec<_>, BTreeSet<_>) =
            topic_following.into_iter().partition_map(|topic_follow| {
                match ValidatedFolloweesForTopic::try_from(topic_follow) {
                    Ok(topic_follow) => Either::Left(topic_follow),
                    Err(err) => Either::Right(err),
                }
            });

        if !errors.is_empty() {
            return Err(Self::Error::FolloweesForTopicValidationError(errors));
        }

        let duplicate_topics = topic_following
            .iter()
            .sorted_by_key(|followee| followee.topic)
            .group_by(|topic_following| topic_following.topic)
            .into_iter()
            .filter_map(
                |(topic, group)| {
                    if group.count() > 1 { Some(topic) } else { None }
                },
            )
            .collect::<Vec<_>>();

        if !duplicate_topics.is_empty() {
            return Err(Self::Error::DuplicateTopics(duplicate_topics));
        }

        let all_followees = topic_following
            .iter()
            .flat_map(|followees_for_topic| followees_for_topic.followees.iter().cloned())
            .collect();

        let inconsistent_aliases = get_inconsistent_aliases(&all_followees);

        if !inconsistent_aliases.is_empty() {
            return Err(Self::Error::InconsistentFolloweeAliases(
                inconsistent_aliases,
            ));
        }

        let topic_following = topic_following
            .into_iter()
            .map(|followees_for_topic| (followees_for_topic.topic, followees_for_topic))
            .collect();

        Ok(Self { topic_following })
    }
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SetFollowingError {
    #[error("existing following is not valid: {:?}", .0)]
    InvalidExistingFollowing(FolloweesForTopicValidationError),

    #[error("followees are identified by ID and cannot have more than one alias, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups),
}

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
