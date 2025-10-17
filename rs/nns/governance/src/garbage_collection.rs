use crate::{
    governance::{Governance, LOG_PREFIX},
    pb::v1::{ProposalData, Topic},
};
use ic_cdk::println;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use lazy_static::lazy_static;
use maplit::hashset;
use std::collections::{HashMap, HashSet};

lazy_static! {
    static ref TOPICS_EXEMPT_FROM_GARBAGE_COLLECTION: HashSet<Topic> =
        hashset![Topic::SnsAndCommunityFund];
}

impl Governance {
    /// Garbage collect obsolete data from the governance canister.
    ///
    /// Current implementation only garbage collects proposals - not neurons.
    ///
    /// Returns true if GC was run and false otherwise.
    pub fn maybe_gc(&mut self) -> bool {
        let now_seconds = self.env.now();
        // Run GC if either (a) more than 24 hours has passed since it
        // was run last, or (b) more than 100 proposals have been
        // added since it was run last.
        if !(now_seconds
            > self
                .latest_gc_timestamp_seconds
                .saturating_add(ONE_DAY_SECONDS)
            || self.heap_data.proposals.len() > self.latest_gc_num_proposals.saturating_add(100))
        {
            // Condition to run was not met. Return false.
            return false;
        }
        self.latest_gc_timestamp_seconds = self.env.now();
        println!(
            "{}Running GC now at timestamp {} seconds",
            LOG_PREFIX, self.latest_gc_timestamp_seconds
        );
        let max_proposals = self.economics().max_proposals_to_keep_per_topic as usize;
        // If `max_proposals_to_keep_per_topic` is unspecified, or
        // specified as zero, don't garbage collect any proposals.
        if max_proposals == 0 {
            return true;
        }
        // This data structure contains proposals grouped by topic. Do not include topics
        // that are exempt from garbage collection.
        let proposals_by_topic = {
            let mut tmp: HashMap<Topic, Vec<u64>> = HashMap::new();
            for (id, prop) in self.heap_data.proposals.iter() {
                let topic = prop.topic();
                if !TOPICS_EXEMPT_FROM_GARBAGE_COLLECTION.contains(&topic) {
                    tmp.entry(topic).or_default().push(*id);
                }
            }
            tmp
        };
        // Only keep the latest 'max_proposals' per topic.
        for (topic, props) in proposals_by_topic {
            let voting_period_seconds = self.voting_period_seconds()(topic);
            println!(
                "{}GC - topic {:#?} max {} current {}",
                LOG_PREFIX,
                topic,
                max_proposals,
                props.len()
            );
            if props.len() > max_proposals {
                // As the above condition holds, we are guaranteed that
                // `props.len() - max_proposals` does not underflow.
                for prop_id in props.iter().take(props.len().saturating_sub(max_proposals)) {
                    // Check that this proposal can be purged.
                    if let Some(prop) = self.heap_data.proposals.get(prop_id)
                        && prop.can_be_purged(now_seconds, voting_period_seconds)
                    {
                        self.heap_data.proposals.remove(prop_id);
                        self.heap_data
                            .topic_of_garbage_collected_proposals
                            .insert(*prop_id, topic);
                    }
                }
            }
        }
        self.latest_gc_num_proposals = self.heap_data.proposals.len();
        true
    }
}

impl ProposalData {
    /// Return true if this proposal can be purged from storage, e.g.,
    /// if it is allowed to be garbage collected.
    pub fn can_be_purged(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        if !self.status().is_final() {
            return false;
        }

        if !self
            .reward_status(now_seconds, voting_period_seconds)
            .is_final()
        {
            return false;
        }

        true
    }
}
