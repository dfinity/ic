use crate::pb::v1::{
    Governance as GovernancePb, NetworkEconomics as NetworkEconomicsPb, Neuron as NeuronPb,
    ProposalData as ProposalPb, RewardEvent as RewardEventPb,
};

pub struct GovernanceProtoBuilder {
    governance_proto: GovernancePb,
}

impl Default for GovernanceProtoBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceProtoBuilder {
    /// Minimaly valid Governance proto.
    pub fn new() -> Self {
        let governance_proto = GovernancePb {
            wait_for_quiet_threshold_seconds: 1,
            short_voting_period_seconds: 30,
            neuron_management_voting_period_seconds: Some(30),
            economics: Some(NetworkEconomicsPb::default()),
            ..Default::default()
        };
        Self { governance_proto }
    }

    /// Ensures that proposals can be decided and neurons can be managed instantly.
    pub fn with_instant_neuron_operations(mut self) -> Self {
        self.governance_proto.wait_for_quiet_threshold_seconds = 0;
        self.governance_proto.short_voting_period_seconds = 0;
        self.governance_proto
            .neuron_management_voting_period_seconds = None;
        self
    }

    pub fn with_latest_reward_event(mut self, reward_event: RewardEventPb) -> Self {
        self.governance_proto.latest_reward_event = Some(reward_event);
        self
    }

    pub fn with_neurons(mut self, neurons: Vec<NeuronPb>) -> Self {
        let neurons = neurons
            .into_iter()
            .map(|neuron| (neuron.id.unwrap().id, neuron))
            .collect();
        self.governance_proto.neurons = neurons;
        self
    }

    pub fn with_genesis_timestamp(mut self, genesis_timestamp_seconds: u64) -> Self {
        self.governance_proto.genesis_timestamp_seconds = genesis_timestamp_seconds;
        self
    }

    pub fn with_proposals(mut self, proposals: Vec<ProposalPb>) -> Self {
        let proposals = proposals
            .into_iter()
            .map(|proposal| (proposal.id.unwrap().id, proposal))
            .collect();
        self.governance_proto.proposals = proposals;
        self
    }

    pub fn with_economics(mut self, network_economics: NetworkEconomicsPb) -> Self {
        self.governance_proto.economics = Some(network_economics);
        self
    }

    pub fn with_short_voting_period(mut self, short_voting_period_seconds: u64) -> Self {
        self.governance_proto.short_voting_period_seconds = short_voting_period_seconds;
        self
    }

    pub fn with_neuron_management_voting_period(
        mut self,
        neuron_management_voting_period_seconds: u64,
    ) -> Self {
        self.governance_proto
            .neuron_management_voting_period_seconds =
            Some(neuron_management_voting_period_seconds);
        self
    }

    pub fn with_wait_for_quiet_threshold(mut self, wait_for_quiet_threshold_seconds: u64) -> Self {
        self.governance_proto.wait_for_quiet_threshold_seconds = wait_for_quiet_threshold_seconds;
        self
    }

    pub fn build(self) -> GovernancePb {
        self.governance_proto
    }
}
