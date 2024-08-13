use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::E8;
use ic_nervous_system_proto::pb::v1::{Canister, Duration as DurationPb, Tokens as TokensPb};
use ic_nns_governance::governance::test_data::CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING;
use ic_nns_governance_api::pb::v1::{
    create_service_nervous_system::{
        initial_token_distribution::developer_distribution::NeuronDistribution, SwapParameters,
    },
    CreateServiceNervousSystem,
};

#[derive(Clone, Debug)]
pub struct CreateServiceNervousSystemBuilder(CreateServiceNervousSystem);

#[cfg(not(target_arch = "wasm32"))]
impl Default for CreateServiceNervousSystemBuilder {
    fn default() -> Self {
        let swap_parameters = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .swap_parameters
            .clone()
            .map(|x| x.into())
            .unwrap();
        let swap_parameters = SwapParameters {
            // Ensure just one huge direct participant can finalize the swap.
            minimum_participants: Some(1),
            minimum_participant_icp: Some(TokensPb::from_e8s(150_000 * E8)),
            maximum_participant_icp: Some(TokensPb::from_e8s(650_000 * E8)),
            minimum_direct_participation_icp: Some(TokensPb::from_e8s(150_000 * E8)),
            maximum_direct_participation_icp: Some(TokensPb::from_e8s(650_000 * E8)),
            // Instantly transit from Lifecycle::Committed to Lifecycle::Open.
            start_time: None,
            // Avoid the need to say that we're human.
            confirmation_text: None,
            ..swap_parameters
        };
        CreateServiceNervousSystemBuilder(CreateServiceNervousSystem {
            dapp_canisters: vec![],
            swap_parameters: Some(swap_parameters),
            ..CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                .clone()
                .into()
        })
    }
}

impl CreateServiceNervousSystemBuilder {
    pub fn neurons_fund_participation(mut self, neurons_fund_participation: bool) -> Self {
        *self
            .0
            .swap_parameters
            .as_mut()
            .unwrap()
            .neurons_fund_participation
            .as_mut()
            .unwrap() = neurons_fund_participation;
        self
    }

    /// Sets the developer's distribution (which is within the initial token distribution)
    pub fn initial_token_distribution_developer_neurons(
        mut self,
        developer_neurons: Vec<NeuronDistribution>,
    ) -> Self {
        let developer_distribution = self
            .0
            .initial_token_distribution
            .as_mut()
            .unwrap()
            .developer_distribution
            .as_mut()
            .unwrap();
        developer_distribution.developer_neurons = developer_neurons;
        self
    }

    pub fn with_one_developer_neuron(
        self,
        controller: PrincipalId,
        dissolve_delay_seconds: u64,
        stake_sns_e8s: u64,
        vesting_period_seconds: u64,
    ) -> Self {
        let developer_neurons = vec![NeuronDistribution {
            controller: Some(controller),
            memo: Some(763535),
            dissolve_delay: Some(DurationPb::from_secs(dissolve_delay_seconds)),
            stake: Some(TokensPb::from_e8s(stake_sns_e8s)),
            vesting_period: Some(DurationPb::from_secs(vesting_period_seconds)),
        }];
        self.initial_token_distribution_developer_neurons(developer_neurons)
    }

    pub fn with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(
        mut self,
        neuron_minimum_dissolve_delay_to_vote_seconds: u64,
    ) -> Self {
        let governance_parameters = self.0.governance_parameters.as_mut().unwrap();
        governance_parameters.neuron_minimum_dissolve_delay_to_vote = Some(DurationPb {
            seconds: Some(neuron_minimum_dissolve_delay_to_vote_seconds),
        });
        self
    }

    /// Sets the total distribution (which is the sum of all the initial distributions)
    pub fn initial_token_distribution_total(mut self, total: TokensPb) -> Self {
        let swap_distribution = self
            .0
            .initial_token_distribution
            .as_mut()
            .unwrap()
            .swap_distribution
            .as_mut()
            .unwrap();
        swap_distribution.total = Some(total);
        self
    }

    pub fn with_dapp_canisters(mut self, dapp_canisters: Vec<CanisterId>) -> Self {
        self.0.dapp_canisters = dapp_canisters
            .into_iter()
            .map(|id| Canister { id: Some(id.get()) })
            .collect();
        self
    }

    pub fn with_minimum_participants(mut self, minimum_participants: u64) -> Self {
        let swap_parameters = self.0.swap_parameters.as_mut().unwrap();
        swap_parameters.minimum_participants = Some(minimum_participants);
        self
    }

    pub fn build(self) -> CreateServiceNervousSystem {
        self.0
    }
}
