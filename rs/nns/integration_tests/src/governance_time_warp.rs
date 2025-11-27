//! Test neuron operations using the governance and other NNS canisters.

use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance_api::{
    GovernanceError, ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, Neuron,
    NeuronInfo,
    governance_error::ErrorType,
    manage_neuron::{Disburse, NeuronIdOrSubaccount},
    manage_neuron_response,
    neuron::DissolveState,
    test_api::TimeWarp,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
};
use icp_ledger::AccountIdentifier;

fn get_timestamp_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn test_time_warp() {
    state_machine_test_on_nns_subnet(|runtime| async move {
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
                id: Some(neuron_id_4),
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                    TWELVE_MONTHS_SECONDS + start_timestamp_s,
                )),
                aging_since_timestamp_seconds: u64::MAX,
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
        let nns_up_timestamp_s = get_timestamp_s();
        println!("setup time (s): {}", nns_up_timestamp_s - start_timestamp_s);

        // Make sure that neuron cannot be disbursed yet.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id_4)),
                    command: Some(ManageNeuronCommandRequest::Disburse(Disburse {
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
            _ => panic!("\n\n{command:?}\n\n"),
        };
        assert_eq!(
            governance_error.error_type,
            ErrorType::PreconditionFailed as i32,
            "{governance_error:?}"
        );

        // Fast forward in time to right before the neuron-held funds becomes eligible for
        // disbursal.
        let duration_since_start_s = get_timestamp_s() - start_timestamp_s;
        println!("duration_since_start_s = {duration_since_start_s}");
        let delta_s = (TWELVE_MONTHS_SECONDS - duration_since_start_s - 100) as i64;
        () = nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await?;
        // Make sure that the funds cannot be disbursed yet.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id_4)),
                    command: Some(ManageNeuronCommandRequest::Disburse(Disburse {
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
            _ => panic!("\n\n{command:?}\n\n"),
        };
        assert_eq!(
            governance_error.error_type,
            ErrorType::PreconditionFailed as i32,
            "{governance_error:?}"
        );
        let error_message = governance_error.error_message.to_lowercase();
        {
            let key_word = "dissolve";
            assert!(
                error_message.contains(key_word),
                "{key_word:?} not in {error_message:?}"
            );
        }

        // Advance time slightly such that the neuron would be considered dissolved.
        let delta_s = (TWELVE_MONTHS_SECONDS + 1000) as i64;
        () = nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await?;
        // This time, disburse should succeed.
        let disburse_result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id_4)),
                    command: Some(ManageNeuronCommandRequest::Disburse(Disburse {
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
            manage_neuron_response::Command::Disburse(_) => (),

            _ => {
                let neuron_info: Result<NeuronInfo, GovernanceError> = nns_canisters
                    .governance
                    .update_from_sender(
                        "get_neuron_info",
                        candid_one,
                        neuron_id_4.id,
                        &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
                    )
                    .await
                    .unwrap();
                let neuron_info = neuron_info.unwrap();

                panic!("\n\n{command:?}\n\n{neuron_info:#?}");
            }
        }

        Ok(())
    });
}
