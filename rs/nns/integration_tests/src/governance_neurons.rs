//! Test neuron operations using the governance and other NNS canisters.

use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance::pb::v1::manage_neuron::Command;
use ic_nns_governance::pb::v1::manage_neuron::Merge;
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_nns_governance::pb::v1::manage_neuron_response::{self, MergeResponse};
use ic_nns_governance::pb::v1::{
    neuron::DissolveState, ManageNeuron, ManageNeuronResponse, Neuron,
};
use ic_nns_test_keys::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ledger_canister::{AccountBalanceArgs, AccountIdentifier, Tokens};

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
            .await?;
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
