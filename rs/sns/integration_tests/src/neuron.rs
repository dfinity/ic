use canister_test::Canister;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nns_constants::ids::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::pb::v1::manage_neuron::claim_or_refresh::{By, MemoAndController};
use ic_sns_governance::pb::v1::manage_neuron::{ClaimOrRefresh, Command};
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::{
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Neuron, NeuronId,
};
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ic_sns_test_utils::TEST_GOVERNANCE_CANISTER_ID;
use ledger_canister::{
    AccountIdentifier, Memo, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};

// This tests the determinism of list_neurons, now that the subaccount is used for
// the unique identifier of the Neuron.
#[test]
fn test_list_neurons_determinism() {
    local_test_on_sns_subnet(|runtime| async move {
        let users = vec![
            Sender::from_keypair(&TEST_USER1_KEYPAIR),
            Sender::from_keypair(&TEST_USER2_KEYPAIR),
            Sender::from_keypair(&TEST_USER3_KEYPAIR),
            Sender::from_keypair(&TEST_USER4_KEYPAIR),
        ];

        let account_identifiers = users
            .iter()
            .map(|user| AccountIdentifier::from(user.get_principal_id()))
            .collect();

        let alloc = Tokens::from_tokens(1000).unwrap();
        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_accounts(account_identifiers, alloc)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        for user in &users {
            stake_and_claim_neuron(&sns_canisters, user).await;
        }

        let list_neuron_response: ListNeuronsResponse = sns_canisters
            .governance
            .query_from_sender(
                "list_neurons",
                candid_one,
                ListNeurons {
                    limit: 100,
                    after_neuron: None,
                    of_principal: None,
                },
                &users[0],
            )
            .await
            .expect("Error calling the list_neurons api");

        let expected = list_neuron_response.neurons;
        let actual = paginate_neurons(&sns_canisters.governance, &users[0], 1_usize).await;

        assert_eq!(expected, actual);

        Ok(())
    });
}

async fn paginate_neurons(
    governance_canister: &Canister<'_>,
    user: &Sender,
    limit: usize,
) -> Vec<Neuron> {
    let mut all_neurons = vec![];
    let mut last_neuron_id: Option<NeuronId> = None;

    loop {
        let list_neuron_response: ListNeuronsResponse = governance_canister
            .query_from_sender(
                "list_neurons",
                candid_one,
                ListNeurons {
                    limit: limit as u32,
                    after_neuron: last_neuron_id.clone(),
                    of_principal: None,
                },
                user,
            )
            .await
            .expect("Error calling the list_neurons api");

        let len = list_neuron_response.neurons.len();
        let is_last = len < limit;
        assert!(len <= limit);

        if !list_neuron_response.neurons.is_empty() {
            last_neuron_id = Some(
                list_neuron_response.neurons[list_neuron_response.neurons.len() - 1]
                    .id
                    .as_ref()
                    .unwrap()
                    .clone(),
            );
            all_neurons.extend(list_neuron_response.neurons);
        }

        if is_last {
            return all_neurons;
        }
    }
}

async fn stake_and_claim_neuron(sns_canisters: &SnsCanisters<'_>, user: &Sender) {
    // Stake a neuron by transferring to a subaccount of the neurons
    // canister and claiming the neuron on the governance canister..
    let nonce = 12345u64;
    let to_subaccount = Subaccount({
        let mut state = Sha256::new();
        state.write(&[0x0c]);
        state.write(b"neuron-stake");
        state.write(user.get_principal_id().as_slice());
        state.write(&nonce.to_be_bytes());
        state.finish()
    });

    // Stake the neuron.
    let stake = Tokens::from_tokens(100).unwrap();
    let _block_height: u64 = sns_canisters
        .ledger
        .update_from_sender(
            "send_pb",
            protobuf,
            SendArgs {
                memo: Memo(nonce),
                amount: stake,
                fee: DEFAULT_TRANSFER_FEE,
                from_subaccount: None,
                to: AccountIdentifier::new(
                    PrincipalId::from(TEST_GOVERNANCE_CANISTER_ID),
                    Some(to_subaccount),
                ),
                created_at_time: None,
            },
            user,
        )
        .await
        .expect("Couldn't send funds.");

    // Claim the neuron on the governance canister.
    let manage_neuron_response: ManageNeuronResponse = sns_canisters
        .governance
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                subaccount: to_subaccount.to_vec(),
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo: nonce,
                        controller: None,
                    })),
                })),
            },
            user,
        )
        .await
        .expect("Error calling the manage_neuron api.");

    match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(_) => {
            println!(
                "User {} successfully claimed neuron",
                user.get_principal_id()
            )
        }
        CommandResponse::Error(error) => panic!(
            "Unexpected error for user {}: {}",
            user.get_principal_id(),
            error
        ),
        _ => panic!(
            "Unexpected command response for user {}.",
            user.get_principal_id()
        ),
    };
}
