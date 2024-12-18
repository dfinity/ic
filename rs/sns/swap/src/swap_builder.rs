use self::pb::v1::{Init, Lifecycle, Swap};
use super::*;
use crate::pb::v1::{
    BuyerState, NeuronBasketConstructionParameters, NeuronsFundParticipationConstraints,
    SnsNeuronRecipe,
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_proto::pb::v1::Countries;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct SwapBuilder {
    lifecycle: Lifecycle,
    buyers: BTreeMap<String, BuyerState>,

    nns_governance_canister_id: CanisterId,
    sns_governance_canister_id: CanisterId,
    sns_ledger_canister_id: CanisterId,
    icp_ledger_canister_id: CanisterId,
    sns_root_canister_id: CanisterId,

    fallback_controller_principal_ids: Vec<PrincipalId>,
    transaction_fee_e8s: Option<u64>,
    neuron_minimum_stake_e8s: Option<u64>,
    confirmation_text: Option<String>,
    restricted_countries: Option<Countries>,
    min_participants: Option<u32>,
    min_direct_participation_icp_e8s: Option<u64>,
    max_direct_participation_icp_e8s: Option<u64>,
    min_participant_icp_e8s: Option<u64>,
    max_participant_icp_e8s: Option<u64>,
    swap_start_timestamp_seconds: Option<u64>,
    swap_due_timestamp_seconds: Option<u64>,
    sns_token_e8s: Option<u64>,
    neuron_basket_construction_parameters: Option<NeuronBasketConstructionParameters>,
    nns_proposal_id: Option<u64>,
    should_auto_finalize: Option<bool>,
    neurons_fund_participation_constraints: Option<NeuronsFundParticipationConstraints>,
    neurons_fund_participation: Option<bool>,
    neuron_recipes: Vec<SnsNeuronRecipe>,
    // The following fields are deprecated and thus don't need to be represented here.
    // min_icp_e8s,
    // max_icp_e8s,
}

fn i2canister_id(i: u64) -> CanisterId {
    CanisterId::try_from(PrincipalId::new_user_test_id(i)).unwrap()
}

impl Default for SwapBuilder {
    fn default() -> Self {
        Self {
            lifecycle: Default::default(),
            buyers: Default::default(),
            nns_governance_canister_id: i2canister_id(0),
            sns_governance_canister_id: i2canister_id(1),
            sns_ledger_canister_id: i2canister_id(2),
            icp_ledger_canister_id: i2canister_id(3),
            sns_root_canister_id: i2canister_id(4),
            fallback_controller_principal_ids: vec![PrincipalId::new_user_test_id(5)],
            transaction_fee_e8s: Some(0),
            neuron_minimum_stake_e8s: Some(0),
            confirmation_text: None,
            restricted_countries: None,
            min_participants: Some(1),
            min_direct_participation_icp_e8s: Some(10),
            max_direct_participation_icp_e8s: Some(100),
            min_participant_icp_e8s: Some(10),
            max_participant_icp_e8s: Some(20),
            swap_start_timestamp_seconds: None,
            swap_due_timestamp_seconds: Some(1234567),
            sns_token_e8s: Some(1000),
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 2,
                dissolve_delay_interval_seconds: 700,
            }),
            nns_proposal_id: Some(101),
            should_auto_finalize: Some(true),
            neurons_fund_participation_constraints: None,
            neurons_fund_participation: None,
            neuron_recipes: vec![],
        }
    }
}

impl SwapBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_nns_governance_canister_id(
        mut self,
        nns_governance_canister_id: CanisterId,
    ) -> Self {
        self.nns_governance_canister_id = nns_governance_canister_id;
        self
    }

    pub fn with_sns_governance_canister_id(
        mut self,
        sns_governance_canister_id: CanisterId,
    ) -> Self {
        self.sns_governance_canister_id = sns_governance_canister_id;
        self
    }

    pub fn with_sns_root_canister_id(mut self, sns_root_canister_id: CanisterId) -> Self {
        self.sns_root_canister_id = sns_root_canister_id;
        self
    }

    pub fn with_lifecycle(mut self, lifecycle: Lifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub fn with_buyers(mut self, buyers: BTreeMap<String, BuyerState>) -> Self {
        self.buyers = buyers;
        self
    }

    pub fn with_swap_start_due(
        mut self,
        swap_start_timestamp_seconds: Option<u64>,
        swap_due_timestamp_seconds: Option<u64>,
    ) -> Self {
        self.swap_start_timestamp_seconds = swap_start_timestamp_seconds;
        self.swap_due_timestamp_seconds = swap_due_timestamp_seconds;
        self
    }

    pub fn with_min_participants(mut self, min_participants: u32) -> Self {
        self.min_participants = Some(min_participants);
        self
    }

    pub fn with_min_max_participant_icp(
        mut self,
        min_participant_icp_e8s: u64,
        max_participant_icp_e8s: u64,
    ) -> Self {
        self.min_participant_icp_e8s = Some(min_participant_icp_e8s);
        self.max_participant_icp_e8s = Some(max_participant_icp_e8s);
        self
    }

    pub fn with_min_max_direct_participation(
        mut self,
        min_direct_participation_icp_e8s: u64,
        max_direct_participation_icp_e8s: u64,
    ) -> Self {
        self.min_direct_participation_icp_e8s = Some(min_direct_participation_icp_e8s);
        self.max_direct_participation_icp_e8s = Some(max_direct_participation_icp_e8s);
        self
    }

    pub fn with_sns_tokens(mut self, sns_token_e8s: u64) -> Self {
        self.sns_token_e8s = Some(sns_token_e8s);
        self
    }

    pub fn with_neuron_basket_dissolve_delay_interval(
        mut self,
        dissolve_delay_interval_seconds: u64,
    ) -> Self {
        self.neuron_basket_construction_parameters = Some(NeuronBasketConstructionParameters {
            dissolve_delay_interval_seconds,
            ..self.neuron_basket_construction_parameters.unwrap()
        });
        self
    }

    pub fn with_neuron_basket_count(mut self, count: u64) -> Self {
        self.neuron_basket_construction_parameters = Some(NeuronBasketConstructionParameters {
            count,
            ..self.neuron_basket_construction_parameters.unwrap()
        });
        self
    }

    pub fn with_nns_proposal_id(mut self, nns_proposal_id: u64) -> Self {
        self.nns_proposal_id = Some(nns_proposal_id);
        self
    }

    pub fn with_neurons_fund_participation(mut self) -> Self {
        self.neurons_fund_participation = Some(true);
        self
    }

    pub fn with_neurons_fund_participation_constraints(
        mut self,
        neurons_fund_participation_constraints: NeuronsFundParticipationConstraints,
    ) -> Self {
        self.neurons_fund_participation_constraints = Some(neurons_fund_participation_constraints);
        self
    }

    pub fn with_confirmation_text(mut self, confirmation_text: String) -> Self {
        self.confirmation_text = Some(confirmation_text);
        self
    }

    pub fn without_confirmation_text(mut self) -> Self {
        self.confirmation_text = None;
        self
    }

    pub fn with_neuron_recipes(mut self, neuron_recipes: Vec<SnsNeuronRecipe>) -> Self {
        self.neuron_recipes = neuron_recipes;
        self
    }

    pub fn build(self) -> Swap {
        let init = Init {
            nns_governance_canister_id: self.nns_governance_canister_id.to_string(),
            sns_governance_canister_id: self.sns_governance_canister_id.to_string(),
            sns_ledger_canister_id: self.sns_ledger_canister_id.to_string(),
            icp_ledger_canister_id: self.icp_ledger_canister_id.to_string(),
            sns_root_canister_id: self.sns_root_canister_id.to_string(),
            fallback_controller_principal_ids: self
                .fallback_controller_principal_ids
                .into_iter()
                .map(|fallback_controller_principal_id| {
                    fallback_controller_principal_id.to_string()
                })
                .collect(),
            transaction_fee_e8s: self.transaction_fee_e8s,
            neuron_minimum_stake_e8s: self.neuron_minimum_stake_e8s,
            confirmation_text: self.confirmation_text,
            restricted_countries: self.restricted_countries,
            min_participants: self.min_participants,
            min_direct_participation_icp_e8s: self.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: self.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: self.min_participant_icp_e8s,
            max_participant_icp_e8s: self.max_participant_icp_e8s,
            swap_start_timestamp_seconds: self.swap_start_timestamp_seconds,
            swap_due_timestamp_seconds: self.swap_due_timestamp_seconds,
            sns_token_e8s: self.sns_token_e8s,
            neuron_basket_construction_parameters: self.neuron_basket_construction_parameters,
            nns_proposal_id: self.nns_proposal_id,
            should_auto_finalize: self.should_auto_finalize,
            neurons_fund_participation_constraints: self.neurons_fund_participation_constraints,
            neurons_fund_participation: self.neurons_fund_participation,

            // The following fields are deprecated.
            min_icp_e8s: None,
            max_icp_e8s: None,
        };
        let swap = Swap::new(init);
        Swap {
            lifecycle: self.lifecycle as i32,
            buyers: self.buyers,
            neuron_recipes: self.neuron_recipes,
            ..swap
        }
    }
}
