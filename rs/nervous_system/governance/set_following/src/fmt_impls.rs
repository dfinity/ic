use super::*;
use std::fmt::{self, Display, Formatter};

impl<NeuronId: NeuronIdLike, Topic: TopicLike> Display for ValidatedFollowee<NeuronId, Topic> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
