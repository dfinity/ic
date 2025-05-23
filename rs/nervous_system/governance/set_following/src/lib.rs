use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display},
};

mod fmt_impls;
mod validation;

pub use validation::*;

/// Maximum number of bytes that a neuron alias can have.
pub const MAX_NEURON_ALIAS_BYTES: usize = 128;

/// Maximum number of followees that a neuron can have for a given topic.
pub const MAX_FOLLOWEES_PER_TOPIC: usize = 15;

pub trait NeuronIdLike: Debug + Display + Clone + Eq + Ord {}

pub trait TopicLike: Debug + Display + Copy + Eq + Ord {
    fn into_i32(self) -> i32;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedSetFollowing<NeuronId: NeuronIdLike, Topic: TopicLike> {
    /// Keys cannot contain `Topic::Unspecified`. Values cannot be empty.
    pub topic_following: BTreeMap<Topic, ValidatedFolloweesForTopic<NeuronId, Topic>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedFolloweesForTopic<NeuronId: NeuronIdLike, Topic: TopicLike> {
    /// If this is empty, it means that the neuron is not following any other neurons on this topic.
    /// An empty set is used also to unset the followees for a given topic.
    pub followees: BTreeSet<ValidatedFollowee<NeuronId, Topic>>,

    pub topic: Topic,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ValidatedFollowee<NeuronId: NeuronIdLike, Topic: TopicLike> {
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
