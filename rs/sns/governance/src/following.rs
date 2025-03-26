use crate::pb::v1::{
    manage_neuron::SetFollowing, neuron::FolloweesForTopic, Followee, NeuronId, Topic,
};
use itertools::{Either, Itertools};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use strum::IntoEnumIterator;
use thiserror::Error;

/// Maximum number of bytes that a neuron alias can have.
pub const MAX_NEURON_ALIAS_BYTES: usize = 128;

/// Maximum number of followees that a neuron can have for a given topic.
pub const MAX_FOLLOWEES_PER_TOPIC: usize = 15;

#[derive(Clone, Eq, PartialEq, Ord)]
pub(crate) struct ValidatedFollowee {
    topic: Topic,
    alias: Option<String>,
    neuron_id: NeuronId,
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

/// Defines lexicographic ordering for `ValidatedFollowee` instances. This ordering is helpful for
/// grouping followees by topic or alias first, and then by neuron ID, which is helpful
/// for detecting inconsistencies across multiple followees.
impl PartialOrd for ValidatedFollowee {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.topic.partial_cmp(&other.topic) {
            Some(Ordering::Equal) => {}
            ord => return ord,
        }
        match self.alias.partial_cmp(&other.alias) {
            Some(Ordering::Equal) => {}
            ord => return ord,
        }
        self.neuron_id.partial_cmp(&other.neuron_id)
    }
}

impl fmt::Debug for ValidatedFollowee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{}", self))
    }
}

/// Represents followees grouped by neuron ID.
pub(crate) type FolloweeGroups = BTreeMap<Topic, BTreeMap<NeuronId, Vec<ValidatedFollowee>>>;

/// Helper function to aid checking the invariant: Followees on a given topic must have
/// unique neuron IDs. Example pattern:
///
/// ```
/// let duplicate_followee_groups = get_duplicate_followee_groups(&followees_for_this_topic);
///
/// if !duplicate_followee_groups.is_empty() {
///     return Err(Error(duplicate_followee_groups));
/// }
/// ```
///
/// To that end, this function returns the map of neuron IDs (from `followees`) that have duplicate
/// neuron IDs. The map values are the actual followee instances for the corresponding neuron IDs.
///
/// Assumption: `followees` all correspond to the same topic.
pub(crate) fn get_duplicate_followee_groups(
    followees: &BTreeSet<ValidatedFollowee>,
) -> FolloweeGroups {
    followees
        .iter()
        .group_by(|followee| followee.topic)
        .into_iter()
        .filter_map(|(topic, group_for_this_topic)| {
            let duplicates_for_this_topic = group_for_this_topic
                .into_iter()
                .group_by(|followee| followee.neuron_id.clone())
                .into_iter()
                .filter_map(|(neuron_id, group)| {
                    let followees_with_this_neuron_id = group.cloned().collect::<Vec<_>>();

                    if followees_with_this_neuron_id.len() > 1 {
                        Some((neuron_id, followees_with_this_neuron_id))
                    } else {
                        None
                    }
                })
                .collect::<BTreeMap<NeuronId, _>>();

            if !duplicates_for_this_topic.is_empty() {
                Some((topic, duplicates_for_this_topic))
            } else {
                None
            }
        })
        .collect()
}

/// Formats an instance of `FolloweeGroups` into a string.
///
/// Need this since `Display for Vec<ValidatedFollowee>` cannot be implemented in this crate.
fn fmt_neuron_groups(followee_groups: &FolloweeGroups) -> String {
    followee_groups
        .iter()
        .map(|(topic, neuron_ids_to_followees)| {
            let neuron_ids_to_followees = neuron_ids_to_followees
                .iter()
                .map(|(neuron_id, followees)| {
                    let followees = followees
                        .iter()
                        .map(|followee| format!("{}", followee))
                        .collect::<Vec<_>>()
                        .join(", ");

                    format!("{}: {}", neuron_id, followees)
                })
                .collect::<Vec<_>>()
                .join(", ");

            format!("{}: [{}]", topic, neuron_ids_to_followees)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Represents followee-related data grouped by alias.
///
/// Normally, followees are represented by `ValidatedFollowee` instances, but in this case, we need
/// to group them by alias to check for inconsistencies (as defined in `get_inconsistent_aliases`),
/// and the topics are associated with each neuron ID for auditability, i.e., if followee aliases
/// are inconsistent, it should be possible to report which exact topics are misconfigured (since
/// the same followee can appear under multiple topics).
pub(crate) type FolloweeAliasGroups = BTreeMap<String, BTreeMap<NeuronId, Vec<ValidatedFollowee>>>;

/// Helper function to aid checking the invariant: followees with the same alias must have
/// the same neuron ID.
///
/// To that end, this function returns the map of followee aliases (from `followees`) that have
/// multiple neuron IDs. The map values represent the corresponding sets of `(neuron_id, topic)`
/// pairs.
pub(crate) fn get_inconsistent_aliases(
    followees: &BTreeSet<ValidatedFollowee>,
) -> FolloweeAliasGroups {
    followees
        .into_iter()
        // Aliases are optional, and only the ones that are *present* may cause inconsistencies.
        // Thus, we filter out the followees that do not have an alias.
        .filter_map(|followee| followee.clone().alias.map(|alias| (alias, followee)))
        .group_by(|(alias, _)| alias.clone())
        .into_iter()
        .filter_map(|(alias, group_for_this_alias)| {
            let followees_for_this_alias = group_for_this_alias
                .into_iter()
                .map(|(_, followees)| followees);

            let duplicate_followees_for_this_alias = followees_for_this_alias
                .group_by(|followee| followee.neuron_id.clone())
                .into_iter()
                .filter_map(|(neuron_id, group_for_this_neuron_id)| {
                    let followees_with_this_neuron_id = group_for_this_neuron_id
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>();

                    if followees_with_this_neuron_id.len() > 1 {
                        Some((neuron_id, followees_with_this_neuron_id))
                    } else {
                        None
                    }
                })
                .collect::<BTreeMap<NeuronId, Vec<ValidatedFollowee>>>();

            if duplicate_followees_for_this_alias.len() > 1 {
                Some((alias.clone(), duplicate_followees_for_this_alias))
            } else {
                None
            }
        })
        .collect()
}

fn fmt_alias_groups(followees: &FolloweeAliasGroups) -> String {
    followees
        .iter()
        .map(|(alias, neuron_ids_to_followees)| {
            let neuron_ids_to_followees = neuron_ids_to_followees
                .iter()
                .map(|(neuron_id, followees_for_this_neuron_id)| {
                    let followees_for_this_neuron_id = followees_for_this_neuron_id
                        .iter()
                        .map(|followee| format!("{}", followee))
                        .collect::<Vec<_>>()
                        .join(", ");

                    format!("{}: [{}]", neuron_id, followees_for_this_neuron_id)
                })
                .collect::<Vec<_>>()
                .join(", ");

            format!("{}: [{}]", alias, neuron_ids_to_followees)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Error, Debug)]
pub(crate) enum FolloweeValidationError {
    #[error("field neuron_id must be specified")]
    NeuronIdNotSpecified,

    #[error("alias cannot be the empty string")]
    AliasCannotBeEmptyString,

    #[error("alias cannot exceed {} bytes", MAX_NEURON_ALIAS_BYTES)]
    AliasTooLong,
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
                return Err(Self::Error::AliasTooLong);
            }
        }

        Ok(Self {
            topic,
            neuron_id,
            alias,
        })
    }
}

pub(crate) struct ValidatedFolloweesForTopic {
    pub followees: BTreeSet<ValidatedFollowee>,
    pub topic: Topic,
}

#[derive(Error, Debug)]
pub(crate) enum FolloweesForTopicValidationError {
    #[error("topic must be set to one from SnsGov.list_topics()")]
    UnspecifiedTopic,

    #[error("a neuron can only follow up to {} other neurons on a given topic (requested {})", MAX_FOLLOWEES_PER_TOPIC, .0)]
    TooManyFollowees(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweeValidationError(Vec<FolloweeValidationError>),

    #[error("followees on a given topic must have unique neuron IDs, got: {}", fmt_neuron_groups(.0))]
    DuplicateFolloweeNeuronId(FolloweeGroups),

    #[error("followees with the same alias must have the same neuron ID, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups),
}

impl TryFrom<FolloweesForTopic> for ValidatedFolloweesForTopic {
    type Error = FolloweesForTopicValidationError;

    fn try_from(value: FolloweesForTopic) -> Result<Self, Self::Error> {
        let FolloweesForTopic { followees, topic } = value;

        let Some(Ok(topic)) = topic.map(Topic::try_from) else {
            return Err(Self::Error::UnspecifiedTopic);
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

        let inconsistent_aliases = get_inconsistent_aliases(&followees);

        if !inconsistent_aliases.is_empty() {
            return Err(Self::Error::InconsistentFolloweeAliases(
                inconsistent_aliases,
            ));
        }

        Ok(Self { followees, topic })
    }
}

// #[error("topics must be unique, but found a duplicate: {:?}", .0)]
//     DuplicateTopics(Topic),

pub(crate) struct ValidatedSetFollowing {
    pub topic_following: BTreeMap<Topic, BTreeSet<ValidatedFollowee>>,
}

fn fmt_topics(topics: &Vec<Topic>) -> String {
    topics
        .iter()
        .map(|topic| format!("{} ({})", topic, *topic as i32))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Error, Debug)]
pub(crate) enum SetFollowingValidationError {
    #[error("topic_following must contain at least one element")]
    NoTopicFollowsSpecified,

    #[error("topic_followees cannot contain more than {} elements (got {})", Topic::iter().count(), .0)]
    TooManyTopicFollows(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweesForTopicValidationError(Vec<FolloweesForTopicValidationError>),

    #[error("topics must be unique, but the following topics had duplicates: {}", fmt_topics(.0))]
    DuplicateTopics(Vec<Topic>),

    #[error("followees with the same alias must have the same neuron ID, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups),
}

impl TryFrom<SetFollowing> for ValidatedSetFollowing {
    type Error = SetFollowingValidationError;

    fn try_from(value: SetFollowing) -> Result<Self, Self::Error> {
        let SetFollowing { topic_following } = value;

        if topic_following.is_empty() {
            return Err(Self::Error::NoTopicFollowsSpecified);
        }

        if topic_following.len() > Topic::iter().count() {
            return Err(Self::Error::TooManyTopicFollows(topic_following.len()));
        }

        let (topic_following, errors): (Vec<_>, Vec<_>) =
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
            .group_by(|topic_following| topic_following.topic.clone())
            .into_iter()
            .filter_map(
                |(topic, group)| {
                    if group.count() > 1 {
                        Some(topic)
                    } else {
                        None
                    }
                },
            )
            .collect::<Vec<_>>();

        if !duplicate_topics.is_empty() {
            return Err(Self::Error::DuplicateTopics(duplicate_topics));
        }

        let inconsistent_aliases = get_inconsistent_aliases(
            &topic_following
                .iter()
                .flat_map(|followees_for_topic| followees_for_topic.followees.iter().cloned())
                .collect(),
        );

        if !inconsistent_aliases.is_empty() {
            return Err(Self::Error::InconsistentFolloweeAliases(
                inconsistent_aliases,
            ));
        }

        let topic_following = topic_following
            .into_iter()
            .map(|ValidatedFolloweesForTopic { followees, topic }| (topic, followees))
            .collect();

        Ok(Self { topic_following })
    }
}

#[cfg(test)]
mod tests;
