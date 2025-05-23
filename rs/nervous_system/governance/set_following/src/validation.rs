use super::*;
use itertools::{Either, Itertools};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SetFollowingError<NeuronId: NeuronIdLike, Topic: TopicLike> {
    #[error("existing following is not valid: {:?}", .0)]
    InvalidExistingFollowing(FolloweesForTopicValidationError<NeuronId, Topic>),

    #[error("followees are identified by ID and cannot have more than one alias, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups<NeuronId, Topic>),
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SetFollowingValidationError<NeuronId: NeuronIdLike, Topic: TopicLike> {
    #[error("topic_following must contain at least one element")]
    NoTopicFollowingSpecified,

    #[error("topic_followees cannot contain more than {} elements (got {})", MAX_FOLLOWEES_PER_TOPIC, .0)]
    TooManyTopicFollowees(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweesForTopicValidationError(BTreeSet<FolloweesForTopicValidationError<NeuronId, Topic>>),

    #[error("topics must be unique, but the following topics had duplicates: {}", fmt_topics(.0))]
    DuplicateTopics(Vec<Topic>),

    #[error("followees are identified by ID and cannot have more than one alias, got: {}", fmt_alias_groups(.0))]
    InconsistentFolloweeAliases(FolloweeAliasGroups<NeuronId, Topic>),
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FolloweeValidationError {
    #[error("field neuron_id must be specified")]
    NeuronIdNotSpecified,

    #[error("alias cannot be the empty string")]
    AliasCannotBeEmptyString,

    #[error("alias cannot exceed {} bytes, got {} bytes", MAX_NEURON_ALIAS_BYTES, .0)]
    AliasTooLong(usize),
}

#[derive(Error, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FolloweesForTopicValidationError<NeuronId: NeuronIdLike, Topic: TopicLike> {
    #[error("topic must be set to one from SnsGov.list_topics()")]
    UnspecifiedTopic,

    #[error("a neuron can only follow up to {} other neurons on a given topic (requested {})", MAX_FOLLOWEES_PER_TOPIC, .0)]
    TooManyFollowees(usize),

    #[error("some followees were not specified correctly: {:?}", .0)]
    FolloweeValidationError(Vec<FolloweeValidationError>),

    #[error("followees on a given topic must have unique neuron IDs, got: {}", fmt_followee_groups(.0))]
    DuplicateFolloweeNeuronId(FolloweeGroups<NeuronId, Topic>),
}

/// Represents followees grouped by neuron ID.
pub type FolloweeGroups<NeuronId: NeuronIdLike, Topic: TopicLike> =
    BTreeMap<NeuronId, Vec<ValidatedFollowee<NeuronId, Topic>>>;

/// Represents followee-related data grouped by neuron ID.
type FolloweeAliasGroups<NeuronId: NeuronIdLike, Topic: TopicLike> =
    BTreeMap<NeuronId, BTreeSet<ValidatedFollowee<NeuronId, Topic>>>;

/// Groups followees grouped by NeuronId, with singleton/unique groups excluded.
///
/// This helps enforce that a neuron cannot be multiply followed (by the same
/// follower neuron on the same topic). In NNS, multiply following (the same
/// neuron on the same topic) is ACTUALLY allowed, but NOT in SNS.
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
fn get_duplicate_followee_groups<NeuronId: NeuronIdLike, Topic: TopicLike>(
    followees: &BTreeSet<ValidatedFollowee<NeuronId, Topic>>,
) -> FolloweeGroups<NeuronId, Topic> {
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
fn get_inconsistent_aliases<NeuronId: NeuronIdLike, Topic: TopicLike>(
    followees: &BTreeSet<ValidatedFollowee<NeuronId, Topic>>,
) -> FolloweeAliasGroups<NeuronId, Topic> {
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

/// Formats an instance of `FolloweeGroups` into a string.
///
/// Need this since `Display for Vec<ValidatedFollowee>` cannot be implemented in this crate.
fn fmt_followee_groups<NeuronId: NeuronIdLike, Topic: TopicLike>(
    followee_groups: &FolloweeGroups<NeuronId, Topic>,
) -> String {
    followee_groups
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
        .join(", ")
}

fn fmt_alias_groups<NeuronId: NeuronIdLike, Topic: TopicLike>(
    followees: &FolloweeAliasGroups<NeuronId, Topic>,
) -> String {
    followees
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
        .join(", ")
}

fn fmt_topics<Topic: TopicLike>(topics: &[Topic]) -> String {
    topics
        .iter()
        .map(|topic| format!("{} ({})", topic, topic.into_i32()))
        .collect::<Vec<_>>()
        .join(", ")
}
