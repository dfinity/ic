use ic_canister_log::log;

use crate::{
    logs::ERROR,
    pb::v1::{Followee, Neuron, NeuronId, Topic, neuron::FolloweesForTopic},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type FollowerIndex = BTreeMap<Topic, BTreeMap<String, BTreeSet<NeuronId>>>;

/// This is analogous to the legacy `remove_neuron_from_function_followee_index` function, but for
/// topic following.
pub fn remove_neuron_from_follower_index(index: &mut FollowerIndex, neuron: &Neuron) {
    let Some(follower_id) = &neuron.id else {
        log!(ERROR, "Neuron {:?} does not have an ID!", neuron);
        return;
    };

    let Some(topic_followees) = &neuron.topic_followees else {
        return;
    };

    for (topic, FolloweesForTopic { followees, .. }) in &topic_followees.topic_id_to_followees {
        let Ok(topic) = Topic::try_from(*topic) else {
            log!(
                ERROR,
                "Neuron {} has followees for an invalid topic ID: {}",
                follower_id,
                topic
            );
            continue;
        };

        if let Some(topic_index) = index.get_mut(&topic) {
            for Followee {
                neuron_id: followee_id,
                alias,
            } in followees
            {
                let Some(followee_id) = followee_id else {
                    let alias = alias
                        .as_ref()
                        .map(|alias| format!(" ({alias})"))
                        .unwrap_or_default();
                    log!(
                        ERROR,
                        "Neuron with ID {:?} has a followee{} with no ID!",
                        follower_id,
                        alias
                    );
                    continue;
                };

                let key = followee_id.to_string();
                if let Some(followers) = topic_index.get_mut(&key) {
                    if !followers.remove(follower_id) {
                        log!(
                            ERROR,
                            "Following index was missing an edge from followee with ID {:?} \
                                to follower with ID {:?} in topic {:?}.",
                            followee_id,
                            follower_id,
                            topic,
                        );
                    };
                    if followers.is_empty() {
                        topic_index.remove(&key);
                    }
                }
            }
        }
    }
}

/// This is analogous to the legacy `add_neuron_to_function_followee_index` function, but for
/// topic following.
pub fn add_neuron_to_follower_index(
    index: &mut BTreeMap<Topic, BTreeMap<String, BTreeSet<NeuronId>>>,
    follower: &Neuron,
) {
    let Some(follower_id) = &follower.id else {
        log!(ERROR, "Neuron {:?} does not have an ID!", follower);
        return;
    };

    let Some(topic_followees) = &follower.topic_followees else {
        return;
    };

    for (topic, FolloweesForTopic { followees, .. }) in &topic_followees.topic_id_to_followees {
        let Ok(topic) = Topic::try_from(*topic) else {
            log!(
                ERROR,
                "Neuron {} has followees for an invalid topic ID: {}",
                follower_id,
                topic
            );
            continue;
        };
        let topic_index = index.entry(topic).or_default();

        for Followee {
            neuron_id: followee_id,
            alias,
        } in followees
        {
            let Some(followee_id) = followee_id else {
                let alias = alias
                    .as_ref()
                    .map(|alias| format!(" ({alias})"))
                    .unwrap_or_default();
                log!(
                    ERROR,
                    "Neuron with ID {:?} has a followee{} with no ID!",
                    follower_id,
                    alias
                );
                continue;
            };

            let key = followee_id.to_string();
            topic_index
                .entry(key)
                .or_default()
                .insert(follower_id.clone());
        }
    }
}

/// This is analogous to the legacy `build_function_followee_index` function, but for topic
/// following.
pub(crate) fn build_follower_index(
    neurons: &BTreeMap<String, Neuron>,
) -> BTreeMap<Topic, BTreeMap<String, BTreeSet<NeuronId>>> {
    let mut function_followee_index = BTreeMap::new();
    for neuron in neurons.values() {
        add_neuron_to_follower_index(&mut function_followee_index, neuron);
    }
    function_followee_index
}

pub(crate) mod legacy {
    use crate::{pb::v1::NervousSystemFunction, types::is_registered_function_id};

    use super::*;

    pub(crate) type FollowerIndex = BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>>;

    /// Builds an index that maps proposal sns functions to (followee) neuron IDs to these neuron's
    /// followers. The resulting index is a map
    /// Function Id -> (followee's neuron ID) -> set of followers' neuron IDs.
    ///
    /// The index is built from the `neurons` in the `Governance` struct, which map followers
    /// (the neuron ID) to a set of followees per function.
    pub(crate) fn build_function_followee_index(
        id_to_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
        neurons: &BTreeMap<String, Neuron>,
    ) -> BTreeMap<u64, BTreeMap<String, BTreeSet<NeuronId>>> {
        let mut function_followee_index = BTreeMap::new();
        for neuron in neurons.values() {
            add_neuron_to_function_followee_index(
                &mut function_followee_index,
                id_to_nervous_system_functions,
                neuron,
            );
        }
        function_followee_index
    }

    /// Adds a neuron to the function_followee_index.
    pub(crate) fn add_neuron_to_function_followee_index(
        index: &mut FollowerIndex,
        id_to_nervous_system_functions: &BTreeMap<u64, NervousSystemFunction>,
        neuron: &Neuron,
    ) {
        for (function_id, followees) in neuron.followees.iter() {
            if !is_registered_function_id(*function_id, id_to_nervous_system_functions) {
                continue;
            }

            let followee_index = index.entry(*function_id).or_default();
            for followee in followees.followees.iter() {
                followee_index
                    .entry(followee.to_string())
                    .or_default()
                    .insert(
                        neuron
                            .id
                            .as_ref()
                            .expect("Neuron must have a NeuronId")
                            .clone(),
                    );
            }
        }
    }

    pub fn remove_neuron_from_function_followee_index_for_function(
        index: &mut FollowerIndex,
        neuron: &Neuron,
        function: u64,
    ) {
        let Some(neuron_id) = neuron.id.as_ref() else {
            log!(ERROR, "Neuron {:?} does not have an ID!", neuron);
            return;
        };

        let Some(followees) = neuron.followees.get(&function) else {
            return;
        };

        let Some(followee_index) = index.get_mut(&function) else {
            return;
        };

        for followee in followees.followees.iter() {
            let nid = followee.to_string();

            if let Some(followee_set) = followee_index.get_mut(&nid) {
                followee_set.remove(neuron_id);

                if followee_set.is_empty() {
                    followee_index.remove(&nid);
                }
            }
        }
    }

    /// Removes a neuron from the function_followee_index.
    pub fn remove_neuron_from_function_followee_index(index: &mut FollowerIndex, neuron: &Neuron) {
        for function in neuron.followees.keys() {
            remove_neuron_from_function_followee_index_for_function(index, neuron, *function);
        }
    }
}
