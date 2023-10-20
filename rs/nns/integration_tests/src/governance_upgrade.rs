//! Test where the governance canister goes through several self-upgrades in a
//! row.
//!
//! This is to make sure that the previous stable memory content does not have
//! a detrimental impact on future upgrades.

use canister_test::local_test_e;
use dfn_candid::candid_one;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::{
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        manage_neuron::{configure, Command, Configure, NeuronIdOrSubaccount, RemoveHotKey},
        ManageNeuron, ManageNeuronResponse,
    },
};
use ic_nns_test_utils::{ids::TEST_NEURON_1_ID, itest_helpers::install_governance_canister};

/// This is a regression test: it used to be that, if two upgrades happened in a
/// row, with the stable memory of the second being smaller than for the first,
/// the second upgrade would read too many bytes from stable memory, resulting
/// in a trap in post_upgrade.
#[test]
fn test_upgrade_after_state_shrink() {
    local_test_e(|runtime| async move {
        let mut governance_proto = GovernanceCanisterInitPayloadBuilder::new()
            .with_test_neurons()
            .build();
        let hot_key = PrincipalId::new_self_authenticating(b"this is the pub key of the hot key");
        governance_proto
            .neurons
            .get_mut(&TEST_NEURON_1_ID)
            .unwrap()
            .hot_keys
            .push(hot_key);

        let mut canister = runtime
            .create_canister_at_id_max_cycles_with_retries(GOVERNANCE_CANISTER_ID.get())
            .await
            .unwrap();
        install_governance_canister(&mut canister, governance_proto).await;

        // First let's do a self-upgrade
        canister.stop().await.unwrap();
        canister.upgrade_to_self_binary(Vec::new()).await.unwrap();
        canister.start().await.unwrap();

        // Now make the state smaller
        let _remove_hot_res: ManageNeuronResponse = canister
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronIdProto {
                        id: TEST_NEURON_1_ID,
                    })),
                    id: None,
                    command: Some(Command::Configure(Configure {
                        operation: Some(configure::Operation::RemoveHotKey(RemoveHotKey {
                            hot_key_to_remove: Some(hot_key),
                        })),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        // Now, one more self-upgrade
        canister.stop().await.unwrap();
        canister.upgrade_to_self_binary(Vec::new()).await.unwrap();
        canister.start().await.unwrap();

        Ok(())
    });
}
