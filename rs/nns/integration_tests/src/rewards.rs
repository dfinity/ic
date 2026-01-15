use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client_sender::Sender;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, NodeProvider, ProposalActionRequest, ProposalStatus, RewardNodeProvider,
    add_or_remove_node_provider::Change,
    manage_neuron::NeuronIdOrSubaccount,
    manage_neuron_response::Command as CommandResponse,
    reward_node_provider::{RewardMode, RewardToAccount},
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::wait_for_final_state,
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
};
use icp_ledger::{AccountBalanceArgs, AccountIdentifier, Subaccount, Tokens, tokens_from_proto};

/// Tests that we can add and reward a node provider.
#[test]
fn test_node_provider_rewards() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new().with_test_neurons().build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let user = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
        let np_pid = *TEST_NEURON_1_OWNER_PRINCIPAL;

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

        // Add a node provider
        //
        // No need to vote since the neuron votes automatically and this neuron
        // has enough votes for a majority.
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: TEST_NEURON_1_ID,
                    })),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Just want to add this NP.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(
                                AddOrRemoveNodeProvider {
                                    change: Some(Change::ToAdd(NodeProvider {
                                        id: Some(np_pid),
                                        reward_account: None,
                                    })),
                                },
                            )),
                        },
                    ))),
                },
                &user,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            _ => panic!("Invalid response"),
        };

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                .await
                .status,
            ProposalStatus::Executed as i32
        );

        let to_subaccount = Subaccount({
            let mut sha = Sha256::new();
            sha.write(b"my_account");
            sha.finish()
        });

        let to_account =
            AccountIdentifier::new(*TEST_NEURON_1_OWNER_PRINCIPAL, Some(to_subaccount));

        // Reward the node provider.
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: TEST_NEURON_1_ID,
                    })),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Just want to add this NP.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::RewardNodeProvider(
                                RewardNodeProvider {
                                    node_provider: Some(NodeProvider {
                                        id: Some(np_pid),
                                        reward_account: None,
                                    }),
                                    amount_e8s: 234 * 100_000_000,
                                    reward_mode: Some(RewardMode::RewardToAccount(
                                        RewardToAccount {
                                            to_account: Some(to_account.into()),
                                        },
                                    )),
                                },
                            )),
                        },
                    ))),
                },
                &user,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            _ => panic!("Invalid response"),
        };

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid))
                .await
                .status,
            ProposalStatus::Executed as i32
        );

        // The balance of the main account should now include the rewards.
        let user_balance: Tokens = nns_canisters
            .ledger
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: to_account,
                },
            )
            .await
            .map(tokens_from_proto)?;
        assert_eq!(Tokens::from_e8s(23_400_000_000), user_balance);

        Ok(())
    });
}
