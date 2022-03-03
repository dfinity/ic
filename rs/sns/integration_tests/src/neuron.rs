use canister_test::Canister;
use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_nns_constants::ids::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::pb::v1::governance_error::ErrorType;
use ic_sns_governance::pb::v1::manage_neuron::Command;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Motion,
    NervousSystemParameters, Neuron, NeuronId, NeuronPermission, NeuronPermissionList,
    NeuronPermissionType, Proposal,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ledger_canister::{AccountIdentifier, Tokens};

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
            sns_canisters.stake_and_claim_neuron(user, None).await;
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

#[test]
fn test_claim_neuron_with_default_permissions() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let account_identifier = AccountIdentifier::from(user.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(account_identifier, alloc)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let nid = sns_canisters.stake_and_claim_neuron(&user, None).await;
        let neuron = sns_canisters.get_neuron(nid).await;

        let expected = vec![NeuronPermission::new(
            &user.get_principal_id(),
            NervousSystemParameters::with_default_values()
                .neuron_claimer_permissions
                .unwrap()
                .permissions,
        )];

        assert_eq!(neuron.permissions, expected);
        Ok(())
    });
}

#[test]
fn test_neuron_action_is_not_authorized() {
    local_test_on_sns_subnet(|runtime| async move {
        let neuron_owner = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let unauthorized_caller = Sender::from_keypair(&TEST_USER2_KEYPAIR);

        let neuron_owner_account_identifier =
            AccountIdentifier::from(neuron_owner.get_principal_id());
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(neuron_owner_account_identifier, alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron capable of making a proposal
        let neuron_owner_nid = sns_canisters
            .stake_and_claim_neuron(&neuron_owner, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Get that neuron's subaccount
        let neuron_owner_subaccount = match neuron_owner_nid.subaccount() {
            Ok(s) => s,
            Err(e) => panic!("Error creating the subaccount, {}", e),
        };

        let proposal_payload = Proposal {
            title: "Motion to delete this SNS".into(),
            action: Some(Action::Motion(Motion {
                motion_text: "I'm a bad actor and this should not be tolerated".into(),
            })),
            ..Default::default()
        };

        let manage_neuron_response: ManageNeuronResponse = sns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: neuron_owner_subaccount.to_vec(),
                    command: Some(Command::MakeProposal(proposal_payload)),
                },
                &unauthorized_caller,
            )
            .await
            .expect("Error calling manage_neuron");

        match manage_neuron_response.command.unwrap() {
            CommandResponse::Error(e) => assert_eq!(e.error_type, ErrorType::NotAuthorized as i32),
            response => panic!("Unexpected response, {:?}", response),
        }

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
