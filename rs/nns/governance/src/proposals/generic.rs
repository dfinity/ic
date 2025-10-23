use crate::{
    pb::v1::{
        ApproveGenesisKyc, CreateServiceNervousSystem, FulfillSubnetRentalRequest,
        GenericProposalRepresentation, ManageNeuron, Motion, NetworkEconomics, RewardNodeProvider,
        RewardNodeProviders,
    },
    proposals::{
        install_code::ValidInstallCode, stop_or_start_canister::ValidStopOrStartCanister,
        update_canister_settings::ValidUpdateCanisterSettings,
    },
};

use ic_base_types::PrincipalId;
use ic_nns_governance_api::GenericValue;
use maplit::hashmap;

pub trait LocalProposalType {
    const TYPE_NAME: &'static str;
    const TYPE_DESCRIPTION: &'static str;

    fn to_generic_value(&self) -> GenericValue;

    fn to_generic_representation(&self) -> GenericProposalRepresentation {
        GenericProposalRepresentation {
            type_name: Self::TYPE_NAME.to_string(),
            type_description: Self::TYPE_DESCRIPTION.to_string(),
            value: Some(self.to_generic_value().into()),
        }
    }
}

impl LocalProposalType for Motion {
    const TYPE_NAME: &'static str = "Motion";
    const TYPE_DESCRIPTION: &'static str = "A motion is a text that can be adopted or rejected. No code is executed when a motion is adopted. An adopted motion should guide the future strategy of the Internet Computer ecosystem.";

    fn to_generic_value(&self) -> GenericValue {
        GenericValue::Text(self.motion_text.clone())
    }
}

impl LocalProposalType for ManageNeuron {
    const TYPE_NAME: &'static str = "Manage Neuron";
    const TYPE_DESCRIPTION: &'static str = "This type of proposal calls a major function on a specified target neuron. Only the followees of the target neuron may vote on these proposals, which effectively provides the followees with control over the target neuron. This can provide a convenient and \nhighly secure means for a team of individuals to manage an important neuron. For example, a neuron might hold a large balance, or belong to an organization of high repute, and be publicized so that many other neurons can follow its vote. In both cases, managing the private key of the principal securely could be problematic. (Either a single copy is held, which is very insecure and provides for a single party to take control, or a group of individuals must divide responsibility — for example, using threshold cryptography, which is complex and time consuming). To address this using this proposal type, the important neuron can be configured to follow the neurons controlled by individual members of a team. Now they can submit proposals to make the important neuron perform actions, which are adopted if and only if a majority of them vote to adopt. (Submitting such a proposal costs a small fee, to prevent denial-of-service attacks.) Nearly any command on the target neuron can be executed, including commands that change the follow rules, allowing the set of team members to be dynamic. Only the final step of dissolving the neuron once its dissolve delay reaches zero cannot be performed using this type of proposal, since this would allow control/\"ownership\" over the locked balances to be transferred. (The only exception to this rule applies to not-for-profit organizations, which may be allowed to dissolve their neurons without using the initial private key.) To prevent a neuron falling under the malign control of the principal's private key by accident, the private key can be destroyed so that the neuron can only be controlled by its followees, although this makes it impossible to subsequently unlock the balance.";

    fn to_generic_value(&self) -> GenericValue {
        // ManageNeuron is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

impl LocalProposalType for NetworkEconomics {
    const TYPE_NAME: &'static str = "Manage Network Economics";
    const TYPE_DESCRIPTION: &'static str = "This is a single proposal type which can update one or several economic parameters:<br/>• <b>Reject cost: </b>The amount of ICP the proposer of a rejected proposal will be charged — to prevent the spamming of frivolous proposals.<br/><b>Minimum Neuron Stake: </b>Set the minimum number of ICP required for creation of a neuron. The same limit must also be respected when increasing dissolve delay or changing the neuron state from dissolving to aging.<br/>• <b>Neuron Management fee: </b>The cost in ICP per neuron management proposal. Here the NNS is doing work on behalf of a specific neuron, and a small fee will be applied to prevent overuse of this feature (i.e., spam).<br/>• <b>Minimum ICP/SDR rate: </b>To prevent mistakes, there is a lower bound for the ICP/SDR rate, managed by network economic proposals.<br/>• <b>Dissolve delay of spawned neurons: </b>The dissolve delay of a neuron spawned from the maturity of an existing neuron.<br/>• <b>Maximum node provider rewards: </b>The maximum rewards to be distributed to node providers in a single distribution event (proposal).<br/>• <b>Transaction fee: </b>The transaction fee that must be paid for each ledger transaction.<br/>• <b>Maximum number of proposals to keep per topic: </b>The maximum number of proposals to keep, per topic. When the total number of proposals for a given topic is greater than this number, the oldest proposals that have reached a \"final\" state may be deleted to save space.";

    fn to_generic_value(&self) -> GenericValue {
        // NetworkEconomics is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

impl LocalProposalType for ApproveGenesisKyc {
    const TYPE_NAME: &'static str = "Approve Genesis KYC";
    const TYPE_DESCRIPTION: &'static str = "When new neurons are created at Genesis, they have GenesisKYC=false. This restricts what actions they can perform. Specifically, they cannot spawn new neurons, and once their dissolve delays are zero, they cannot be disbursed and their balances unlocked to new accounts. This proposal sets GenesisKYC=true for batches of principals.<br/>(<i>Special note:</i> The Genesis event disburses all ICP in the form of neurons, whose principals must be KYCed. Consequently, all neurons created after Genesis have GenesisKYC=true set automatically since they must have been derived from balances that have already been KYCed.)";

    fn to_generic_value(&self) -> GenericValue {
        let ApproveGenesisKyc { principals } = self;

        GenericValue::Map(hashmap! {
            "principals".to_string() => GenericValue::Array(principals.iter().map(|p| generic_principal(*p)).collect()),
        })
    }
}

impl LocalProposalType for CreateServiceNervousSystem {
    const TYPE_NAME: &'static str = "Create Service Nervous System (SNS)";
    const TYPE_DESCRIPTION: &'static str = "Create a new Service Nervous System (SNS).";

    fn to_generic_value(&self) -> GenericValue {
        // CreateServiceNervousSystem is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

impl LocalProposalType for ValidInstallCode {
    const TYPE_NAME: &'static str = "Install Code";
    const TYPE_DESCRIPTION: &'static str =
        "Install, reinstall or upgrade the code of a canister that is controlled by the NNS.";

    fn to_generic_value(&self) -> GenericValue {
        GenericValue::from(self)
    }
}

impl LocalProposalType for ValidStopOrStartCanister {
    const TYPE_NAME: &'static str = "Stop or Start Canister";
    const TYPE_DESCRIPTION: &'static str =
        "Stop or start a canister that is controlled by the NNS.";

    fn to_generic_value(&self) -> GenericValue {
        GenericValue::from(self)
    }
}

impl LocalProposalType for ValidUpdateCanisterSettings {
    const TYPE_NAME: &'static str = "Update Canister Settings";
    const TYPE_DESCRIPTION: &'static str =
        "Update the settings of a canister that is controlled by the NNS.";

    fn to_generic_value(&self) -> GenericValue {
        GenericValue::from(self)
    }
}

impl LocalProposalType for FulfillSubnetRentalRequest {
    const TYPE_NAME: &'static str = "Subnet Rental Agreement";
    const TYPE_DESCRIPTION: &'static str = "A proposal to create a rented subnet with a subnet rental agreement, based on a previously executed Subnet Rental Request proposal. The resulting subnet allows only the user of the rental agreement to create canisters, and canisters are not charged cycles for computation and storage.";

    fn to_generic_value(&self) -> GenericValue {
        // FulfillSubnetRentalRequest is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

impl LocalProposalType for RewardNodeProvider {
    const TYPE_NAME: &'static str = "Reward Node Provider";
    const TYPE_DESCRIPTION: &'static str = "A proposal to reward a node provider an amount of ICP as compensation for providing nodes to the IC.";

    fn to_generic_value(&self) -> GenericValue {
        // RewardNodeProvider is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

impl LocalProposalType for RewardNodeProviders {
    const TYPE_NAME: &'static str = "Reward Node Providers";
    const TYPE_DESCRIPTION: &'static str = "A proposal to reward multiple node providers an amount of ICP as compensation for providing nodes to the IC.";

    fn to_generic_value(&self) -> GenericValue {
        // RewardNodeProviders is not supported - return an empty map
        GenericValue::Map(hashmap! {})
    }
}

// fn generic_nat<T: Into<Nat>>(value: T) -> GenericValue {
//     GenericValue::Nat(value.into())
// }

fn generic_principal(principal_id: PrincipalId) -> GenericValue {
    GenericValue::Text(principal_id.to_string())
}
