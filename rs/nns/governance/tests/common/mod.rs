use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::governance::Governance;
use ic_nns_governance::pb::v1::{
    manage_neuron, manage_neuron::NeuronIdOrSubaccount, ManageNeuron, ManageNeuronResponse,
};

pub async fn increase_dissolve_delay_raw(
    gov: &mut Governance,
    principal_id: &PrincipalId,
    neuron_id: NeuronId,
    delay_increase: u32,
) -> ManageNeuronResponse {
    gov.manage_neuron(
        principal_id,
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::IncreaseDissolveDelay(
                        manage_neuron::IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: delay_increase,
                        },
                    )),
                },
            )),
        },
    )
    .await
}

pub async fn set_dissolve_delay_raw(
    gov: &mut Governance,
    principal_id: &PrincipalId,
    neuron_id: NeuronId,
    timestamp_seconds: u64,
) -> ManageNeuronResponse {
    gov.manage_neuron(
        principal_id,
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(
                        manage_neuron::SetDissolveTimestamp {
                            dissolve_timestamp_seconds: timestamp_seconds,
                        },
                    )),
                },
            )),
        },
    )
    .await
}
