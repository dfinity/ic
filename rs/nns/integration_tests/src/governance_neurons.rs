//! Test neuron operations using the governance and other NNS canisters.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance::pb::v1::manage_neuron::Command;
use ic_nns_governance::pb::v1::manage_neuron::Merge;
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_nns_governance::pb::v1::manage_neuron::Spawn;
use ic_nns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_nns_governance::pb::v1::manage_neuron_response::{self, MergeResponse};
use ic_nns_governance::pb::v1::GovernanceError;
use ic_nns_governance::pb::v1::NeuronState;
use ic_nns_governance::pb::v1::{
    neuron::DissolveState, ManageNeuron, ManageNeuronResponse, Neuron,
};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ledger_canister::{tokens_from_proto, AccountBalanceArgs, AccountIdentifier, Tokens};

#[test]
fn test_merge_neurons() {
    local_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        //
        // Build the testing environment
        //

        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.with_test_neurons();

        // Add another neuron owned by the same owner as the first test
        // neuron.
        let neuron_id_4 = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_4_subaccount = nns_builder.governance.make_subaccount().into();
        assert_eq!(
            nns_builder.governance.proto.neurons.insert(
                neuron_id_4.id,
                Neuron {
                    id: Some(neuron_id_4.clone()),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 123_000_000_000,
                    account: neuron_4_subaccount,
                    not_for_profit: true,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );

        //
        // Bootstrap the environment from the details above
        //

        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        //
        // Execute operations to be tested
        //

        // The balance of the main account should be 0.
        let user_balance: Tokens = nns_canisters
            .ledger
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::from(*TEST_NEURON_1_OWNER_PRINCIPAL),
                },
            )
            .await
            .map(tokens_from_proto)?;
        assert_eq!(Tokens::from_e8s(0), user_balance);

        // Let us transfer ICP into the main account, and stake two neurons
        // owned by TEST_NEURON_1_OWNER_PRINCIPAL.

        let merge1_res: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronIdProto {
                        id: TEST_NEURON_1_ID,
                    })),
                    id: None,
                    command: Some(Command::Merge(Merge {
                        source_neuron_id: Some(neuron_id_4),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();
        assert_eq!(
            merge1_res,
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Merge(MergeResponse {}),),
            }
        );

        Ok(())
    });
}

#[test]
fn test_spawn_neuron() {
    local_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        let mut nns_builder = NnsInitPayloadsBuilder::new();

        // Add another neuron owned by the same owner as the first test
        // neuron.
        let neuron_id = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_subaccount = nns_builder.governance.make_subaccount().into();
        assert_eq!(
            nns_builder.governance.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id.clone()),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 123_000_000_000,
                    account: neuron_subaccount,
                    not_for_profit: true,
                    maturity_e8s_equivalent: 1_000_000_000, // Equivalent to 10 ICP
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );

        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let spawn_res: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        neuron_id.clone(),
                    )),
                    id: None,
                    command: Some(Command::Spawn(Spawn {
                        new_controller: None,
                        nonce: None,
                        percentage_to_spawn: None,
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let spawned_neuron_id = match spawn_res.clone().command.unwrap() {
            CommandResponse::Spawn(res) => res.created_neuron_id.unwrap(),
            _ => panic!("Unexpected response: {:?}", spawn_res),
        };

        // Neuron should now exist and be in "spawning" state.
        let response: Result<Neuron, GovernanceError> = nns_canisters
            .governance
            .query_from_sender(
                "get_full_neuron",
                candid_one,
                spawned_neuron_id.id,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let spawned_neuron = response.unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(spawned_neuron.state(now), NeuronState::Spawning);
        assert_eq!(spawned_neuron.cached_neuron_stake_e8s, 0);
        assert_eq!(spawned_neuron.maturity_e8s_equivalent, 1_000_000_000);

        // Advance the time in the governance canister.
        nns_canisters
            .set_time_warp((86400 * 7 + 1) as i64)
            .await
            .expect(r#"Expected set_time_warp to succeed"#);

        // Now loop a few times and expect the neuron's stake to be minted and for the
        // neuron to be dissolved.
        for _i in 0..10 {
            let response: Result<Neuron, GovernanceError> = nns_canisters
                .governance
                .update_from_sender(
                    "get_full_neuron",
                    candid_one,
                    spawned_neuron_id.id,
                    &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
                )
                .await
                .unwrap();

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 86400 * 7
                + 1;
            println!("Found neuron [now: {:?}]: {:?}", now, spawned_neuron);

            let spawned_neuron = response.unwrap();

            if spawned_neuron.state(now) == NeuronState::Dissolved {
                assert!(
                    spawned_neuron.cached_neuron_stake_e8s > 950_000_000
                        && spawned_neuron.cached_neuron_stake_e8s < 1_050_000_000
                );
                assert_eq!(spawned_neuron.maturity_e8s_equivalent, 0);
                return Ok(());
            } else {
                println!("Neuron not spawned yet: {:?}", spawned_neuron);
            }
        }

        Err("Spawned neuron's stake did not show up.".to_string())
    });
}
