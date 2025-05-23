use super::*;
use ic_nervous_system_governance_set_following::{
    get_duplicate_followee_groups, get_inconsistent_aliases, MAX_FOLLOWEES_PER_TOPIC, MAX_NEURON_ALIAS_BYTES,
};

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
                match ValidatedFollowee::try_from_followee_and_topic(followee, topic) {
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

pub(crate) trait TryFromFolloweeAndTopic: Sized {
    fn try_from_followee_and_topic(followee: Followee, topic: Topic) -> Result<Self, FolloweeValidationError>;
}

impl TryFromFolloweeAndTopic for ValidatedFollowee {
    fn try_from_followee_and_topic(followee: Followee, topic: Topic) -> Result<Self, FolloweeValidationError> {
        let Followee { neuron_id, alias } = followee;

        let Some(neuron_id) = neuron_id else {
            return Err(FolloweeValidationError::NeuronIdNotSpecified);
        };

        if let Some(alias) = &alias {
            if alias.is_empty() {
                return Err(FolloweeValidationError::AliasCannotBeEmptyString);
            }

            if alias.len() > MAX_NEURON_ALIAS_BYTES {
                return Err(FolloweeValidationError::AliasTooLong(alias.len()));
            }
        }

        Ok(Self {
            topic,
            neuron_id,
            alias,
        })
    }
}
