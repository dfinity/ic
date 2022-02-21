use ic_canister_client::Sender;
use ic_nns_constants::ids::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{Motion, Proposal};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ledger_canister::Tokens;

/// Assert that Motion proposals can be submitted, voted on, and executed
#[test]
fn test_motion_proposal_execution() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;

            let subaccount = match neuron_id.subaccount() {
                Ok(s) => s,
                Err(e) => panic!("Error creating the subaccount, {}", e),
            };

            let proposal_payload = Proposal {
                title: "Test Motion proposal".into(),
                action: Some(Action::Motion(Motion {
                    motion_text: "Spoon".into(),
                })),
                ..Default::default()
            };

            // Submit a motion proposal. It should then be executed because the
            // submitter has a majority stake and submitting also votes automatically.
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal_payload)
                .await;

            let proposal = sns_canisters.get_proposal(proposal_id).await;

            assert_eq!(proposal.action, 1);
            assert_ne!(proposal.decided_timestamp_seconds, 0);
            assert_ne!(proposal.executed_timestamp_seconds, 0);

            match proposal.proposal.unwrap().action.unwrap() {
                Action::Motion(motion) => {
                    assert_eq!(motion.motion_text, "Spoon".to_string());
                }
                _ => panic!("Proposal has unexpected action"),
            }

            Ok(())
        }
    });
}
