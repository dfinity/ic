use crate::{
    governance::MAX_FOLLOWEES_PER_TOPIC,
    neuron::Neuron,
    pb::v1::{
        ArchivedMonthlyNodeProviderRewards, Topic,
        manage_neuron::{SetFollowing, set_following::FolloweesForTopic},
    },
};
use ic_base_types::PrincipalId;
use ic_nns_governance_api::{GovernanceError, governance_error::ErrorType};
use ic_stable_structures::{Storable, storable::Bound};
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
    /// Returns Err if some of the following requirements are not met:
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
    ///     4. caller is authorized to make (all) the changes. In general, this
    ///        requires being a controller or hot key. However, in the special
    ///        case of the NeuronManagement topic, only the controller is
    ///        allowed.
    pub fn validate(&self, caller: &PrincipalId, neuron: &Neuron) -> Result<(), GovernanceError> {
        self.validate_intrinsically()?;
        self.validate_authorized(caller, neuron)?;

        Ok(())
    }

    /// Does the same thing as validate, except no authorization check.
    pub fn validate_intrinsically(&self) -> Result<(), GovernanceError> {
        self.validate_topics_are_unique()?;
        self.validate_not_too_many_followees()?;

        Ok(())
    }

    fn validate_topics_are_unique(&self) -> Result<(), GovernanceError> {
        let mut topics = HashSet::<Topic>::new();
        for followees_for_topic in &self.topic_following {
            // Treat None the same as Some(0). This also occurs during execution.
            let topic = followees_for_topic.topic.unwrap_or_default();

            // Validate topic.
            let topic = Topic::try_from(topic).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("The operation specified an invalid topic code ({topic:?}): {err}",),
                )
            })?;

            let is_new = topics.insert(topic);

            if !is_new {
                // Violation of uniqueness.
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("The operation specified the same topic ({topic:?}) more than once.",),
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
                        topic.map(Topic::try_from),
                        followees.len(),
                        MAX_FOLLOWEES_PER_TOPIC,
                    ),
                ));
            }
        }

        Ok(())
    }

    /// neuron is the one that is going to be operated on by self.
    fn validate_authorized(
        &self,
        caller: &PrincipalId,
        neuron: &Neuron,
    ) -> Result<(), GovernanceError> {
        let ok = {
            let any_manage_neuron = self.topic_following.iter().any(|followees_for_topic| {
                followees_for_topic.topic == Some(Topic::NeuronManagement as i32)
            });

            if any_manage_neuron {
                neuron.is_controlled_by(caller)
            } else {
                neuron.is_authorized_to_vote(caller)
            }
        };

        if !ok {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller ({}) is not authorized to make such changes to the following of neuron {}.",
                    caller,
                    neuron.id().id,
                ),
            ));
        }

        Ok(())
    }
}
