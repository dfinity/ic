//! Test neuron operations using the governance and other NNS canisters.

use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance::governance::TimeWarp;
use ic_nns_governance::pb::v1::governance_error::ErrorType;
use ic_nns_governance::pb::v1::manage_neuron::Command;
use ic_nns_governance::pb::v1::manage_neuron::Disburse;
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_nns_governance::pb::v1::manage_neuron_response;
use ic_nns_governance::pb::v1::{
    neuron::DissolveState, ManageNeuron, ManageNeuronResponse, Neuron,
};
use ic_nns_test_keys::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ledger_canister::AccountIdentifier;

fn get_timestamp_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn test_time_warp() {
    local_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        // Boot up a mini NNS.
        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.with_test_neurons();
        let neuron_id_4 = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_4_subaccount = nns_builder.governance.make_subaccount().into();
        let start_timestamp_s = get_timestamp_s();
        let pre_existing_neuron = nns_builder.governance.proto.neurons.insert(
            neuron_id_4.id,
            Neuron {
                id: Some(neuron_id_4.clone()),
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                    TWELVE_MONTHS_SECONDS + start_timestamp_s,
                )),
                cached_neuron_stake_e8s: 123_000_000_000,
                account: neuron_4_subaccount,
                not_for_profit: true,
                kyc_verified: true,
                ..Default::default()
            },
        );
        assert_eq!(
            pre_existing_neuron, None,
            "There is more than one neuron with the same id."
        );
        let nns_init_payload = nns_builder.build();
        // Very slow...
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Make sure that neuron cannot be disbursed yet.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        neuron_id_4.clone(),
                    )),
                    command: Some(Command::Disburse(Disburse {
                        amount: None,
                        to_account: Some(
                            AccountIdentifier::new(*TEST_NEURON_1_OWNER_PRINCIPAL, None).into(),
                        ),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await?;
        let command = disburse_result.command.unwrap();
        let governance_error = match command {
            manage_neuron_response::Command::Error(error) => error,
            _ => panic!("\n\n{:?}\n\n", command),
        };
        assert_eq!(
            governance_error.error_type(),
            ErrorType::PreconditionFailed,
            "{:?}",
            governance_error
        );

        // Fast forward in time to right before the neuron-held funds becomes eligible for
        // disbursal.
        let duration_since_start_s = get_timestamp_s() - start_timestamp_s;
        let mut delta_s = (TWELVE_MONTHS_SECONDS - duration_since_start_s - 100) as i64;
        nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await?;
        // Make sure that the funds cannot be disbursed yet.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        neuron_id_4.clone(),
                    )),
                    command: Some(Command::Disburse(Disburse {
                        amount: None,
                        to_account: Some(
                            AccountIdentifier::new(*TEST_NEURON_1_OWNER_PRINCIPAL, None).into(),
                        ),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await?;
        let command = disburse_result.command.unwrap();
        let governance_error = match command {
            manage_neuron_response::Command::Error(error) => error,
            _ => panic!("\n\n{:?}\n\n", command),
        };
        assert_eq!(
            governance_error.error_type(),
            ErrorType::PreconditionFailed,
            "{:?}",
            governance_error
        );

        // Advance time slightly (200 s) such that that the neuron should be fully
        // disolved.
        delta_s += 200;
        nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await?;
        // This time, disburse should succeed.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        neuron_id_4.clone(),
                    )),
                    command: Some(Command::Disburse(Disburse {
                        amount: None,
                        to_account: Some(
                            AccountIdentifier::new(*TEST_NEURON_1_OWNER_PRINCIPAL, None).into(),
                        ),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await?;
        let command = disburse_result.command.unwrap();
        match command {
            manage_neuron_response::Command::Disburse(disburse) => disburse,
            _ => panic!("\n\n{:?}\n\n", command),
        };

        Ok(())
    });
}
