use crate::governance::{Governance, LOG_PREFIX};
use crate::pb::v1::proposal::Action;
use crate::pb::v1::{ProposalData, ProposalStatus, Topic};
use ic_sns_swap::pb::v1::Lifecycle;
use lazy_static::lazy_static;
use maplit::hashset;
use std::collections::{HashMap, HashSet};

lazy_static! {
    static ref TOPICS_EXEMPT_FROM_GARBAGE_COLLECTION: HashSet<Topic> =
        hashset![Topic::SnsAndCommunityFund, Topic::SnsDecentralizationSale];
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
        if !(now_seconds > self.latest_gc_timestamp_seconds + 60 * 60 * 24
            || self.heap_data.proposals.len() > self.latest_gc_num_proposals + 100)
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
                    tmp.entry(topic).or_insert_with(Vec::new).push(*id);
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
                for prop_id in props.iter().take(props.len() - max_proposals) {
                    // Check that this proposal can be purged.
                    if let Some(prop) = self.heap_data.proposals.get(prop_id) {
                        if prop.can_be_purged(now_seconds, voting_period_seconds) {
                            self.heap_data.proposals.remove(prop_id);
                        }
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

        if let Some(Action::OpenSnsTokenSwap(_)) =
            self.proposal.as_ref().and_then(|p| p.action.as_ref())
        {
            return self.open_sns_token_swap_can_be_purged();
        }

        if let Some(Action::CreateServiceNervousSystem(_)) =
            self.proposal.as_ref().and_then(|p| p.action.as_ref())
        {
            return self.create_service_nervous_system_can_be_purged();
        }

        true
    }

    // Precondition: action must be OpenSnsTokenSwap (behavior is undefined otherwise).
    //
    // The idea here is that we must wait until Neurons' Fund participation has
    // been settled (part of swap finalization), because in that case, we are
    // holding NF participation in escrow.
    //
    // We can tell whether NF participation settlement has been taken care of by
    // looking at the sns_token_swap_lifecycle field.
    fn open_sns_token_swap_can_be_purged(&self) -> bool {
        match self.status() {
            ProposalStatus::Rejected => {
                // Because nothing has been taken from the neurons' fund yet (and never
                // will). We handle this specially, because in this case,
                // sns_token_swap_lifecycle will be None, which is later treated as not
                // terminal.
                true
            }

            ProposalStatus::Failed => {
                // Because because maturity is refunded to the Neurons' Fund before setting
                // execution status to failed.
                true
            }

            ProposalStatus::Executed => {
                // Need to wait for settle_community_fund_participation.
                self.sns_token_swap_lifecycle
                    .and_then(Lifecycle::from_i32)
                    .unwrap_or(Lifecycle::Unspecified)
                    .is_terminal()
            }

            status => {
                println!(
                    "{}WARNING: Proposal status unexpectedly {:?}. self={:#?}",
                    LOG_PREFIX, status, self,
                );
                false
            }
        }
    }

    // Precondition: action must be CreateServiceNervousSystem (behavior is undefined otherwise).
    //
    // The idea here is that we must wait until Neurons' Fund participation has
    // been settled (part of swap finalization), because in that case, we are
    // holding NF participation in escrow.
    //
    // We can tell whether NF participation settlement has been taken care of by
    // looking at the sns_token_swap_lifecycle field.
    fn create_service_nervous_system_can_be_purged(&self) -> bool {
        match self.status() {
            ProposalStatus::Rejected => {
                // Because nothing has been taken from the community fund yet (and never
                // will). We handle this specially, because in this case,
                // sns_token_swap_lifecycle will be None, which is later treated as not
                // terminal.
                true
            }

            ProposalStatus::Failed => {
                // Because because maturity is refunded to the Community Fund before setting
                // execution status to failed.
                true
            }

            ProposalStatus::Executed => {
                // Need to wait for settle_community_fund_participation.
                self.sns_token_swap_lifecycle
                    .and_then(Lifecycle::from_i32)
                    .unwrap_or(Lifecycle::Unspecified)
                    .is_terminal()
            }

            status => {
                println!(
                    "{}WARNING: Proposal status unexpectedly {:?}. self={:#?}",
                    LOG_PREFIX, status, self,
                );
                false
            }
        }
    }
}
