use super::*;

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
