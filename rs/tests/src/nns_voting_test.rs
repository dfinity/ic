/* tag::catalog[]
Title:: Authorized voters can vote through Neurons

Goals:: Ensure the following invariants hold
- neuron holder of neuron A cannot vote for neuron B
- neurons can't vote twice:
** it can't happen that the leader neuron (say C) votes for neuron A and A’s neuron holder votes and both votes are counted
** it can't happen that the neuron holder A votes twice (e.g., close together)
- Neuron can only be dissolved after dissolution time is over
- Dissolved neuron can't vote
- Voting on a proposal whose deadline has expired has no effect (neither on result nor on voting reward)
- Voting on a proposal before this proposal ID is created has no effect
- Voting method calls of the governance canister by an entity other than the neuron holders are rejected

Runbook::
. Setup NNS with a ledger canister tracking test neuron's account
  and with `lifeline` being the minting canister
. Do some voting via test neurons and their owning identity (vs. test identity)

Covered::
. voting attempts via a combination of invalid neuron owner, neuron, proposal
. neuron owners as external identities
. voting yes to non-existing proposal (with anticipated Id) has no effect
. neuron without funds to cover penalties cannot submit proposal

Not Covered::
. voting with dissolving neuron (when less than 6 months left) has no effect
. voting with dynamically created neurons (regular or splitting)
. voting power testing, considering changes
. upgrade preserves behaviour
. neurons cannot be created to be owned by canisters
. exercise the `manage_neuron` interface
. non-eligibility (neuron created after proposal)


end::catalog[] */

use slog::info;

use crate::util::{get_random_nns_node_endpoint, runtime_from_url};

use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};

use ic_nns_governance::pb::v1::{
    governance_error::ErrorType,
    manage_neuron::{Command, NeuronIdOrSubaccount, RegisterVote},
    GovernanceError, ManageNeuron, ManageNeuronResponse, Neuron, NeuronInfo,
    NnsFunction::NnsCanisterUpgrade,
    ProposalInfo, Vote,
};

use crate::nns::NnsExt;
use canister_test::{Canister, Runtime};
use dfn_candid::candid_one;
use ic_nns_test_utils::ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID, TEST_NEURON_3_ID};

use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR, TEST_NEURON_3_OWNER_KEYPAIR},
    GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_handler_root::common::ChangeNnsCanisterProposalPayload;
use ic_nns_test_utils::governance::submit_external_update_proposal_allowing_error;
use ic_registry_subnet_type::SubnetType;
use rand::Rng;

/// A test runs within a given IC configuration. Later on, we really want to
/// combine tests that are being run in similar environments. Please, keep this
/// in mind when writing your tests!
pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();

    // choose a random endpoint from the nns subnet
    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());

        // Voting method calls of the governance canister by an entity other than
        // the neuron holders are rejected
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        let test_neuron1 = NeuronId(TEST_NEURON_1_ID);
        let test_neuron1_identity = &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
        let test_neuron2 = NeuronId(TEST_NEURON_2_ID);
        let test_neuron2_identity = &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR);
        let test_neuron3 = NeuronId(TEST_NEURON_3_ID);
        let test_neuron3_identity = &Sender::from_keypair(&TEST_NEURON_3_OWNER_KEYPAIR);

        let n = governance
            .query_(
                "get_neuron_info",
                candid_one::<Result<NeuronInfo, GovernanceError>, NeuronId>,
                test_neuron1,
            )
            .await
            .expect("cannot obtain neuron_info?");
        info!(ctx.logger, "neuron info {:?}", n);

        // Observe a reject for "manage_neuron(MakeProposal)" when
        // called from a principal not being owner, here the test identity.
        let proposal_reject = submit_proposal_by_non_authorised_neuron1(&nns)
            .await
            .map_err(|GovernanceError { error_type, .. }| {
                error_type == ErrorType::NotAuthorized as i32
            });
        assert!(proposal_reject.err().unwrap());

        // Observe a reject for "forward_vote" when called from
        // a principal not being owner, here the test identity.
        let fake_proposal_id = ProposalId(rng.gen());
        let vote_reject = forward_vote(
            &governance,
            None,
            (test_neuron1, fake_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(
            vote_reject.err().unwrap().error_type(),
            ErrorType::NotAuthorized
        );

        // Observe a reject for "forward_vote" when called from
        // owner principal, but with invalid proposal Id.
        let fake_proposal_id = ProposalId(rng.gen());
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (test_neuron1, fake_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(vote_reject.err().unwrap().error_type(), ErrorType::NotFound);

        // Observe reject for "forward_vote" when called from
        // the test identity principal that is not authorised, via neuron2.
        let vote_reject = forward_vote(
            &governance,
            None,
            (test_neuron2, fake_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(
            vote_reject.err().unwrap().error_type(),
            ErrorType::NotAuthorized
        );

        // Observe reject for "forward_vote" for neuron1 when called from
        // a principal not being owner, here the neuron2 identity.
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron2_identity),
            (test_neuron1, fake_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(
            vote_reject.err().unwrap().error_type(),
            ErrorType::NotAuthorized
        );

        // Now try with proper authorisation and observe that we now pass authorisation
        // and the proposal Id is discovered to be non-existent.
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (test_neuron1, fake_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(vote_reject.err().unwrap().error_type(), ErrorType::NotFound);

        // Set up proposal by neuron1 and vote with neuron2, expecting success.
        let proposal_id = submit_proposal_by_neuron1(&nns).await;
        info!(ctx.logger, "proposal_id {}", proposal_id);

        let vote_result = forward_vote(
            &governance,
            Some(test_neuron2_identity),
            (test_neuron2, proposal_id, Vote::No),
        )
        .await;
        assert!(vote_result.is_ok());

        // Observe reject for "forward_vote" when called from
        // a principal not being owner, here the test identity.
        let vote_reject =
            forward_vote(&governance, None, (test_neuron1, proposal_id, Vote::Yes)).await;
        assert_eq!(
            vote_reject.err_ref().unwrap().error_type(),
            ErrorType::NotAuthorized
        );

        // Retry with proper authorisation. Since the proposal was issued by neuron1,
        // explicit voting will be rejected, as it has already implicitly voted.
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (test_neuron1, proposal_id, Vote::No),
        )
        .await;
        assert_eq!(
            vote_reject.err_ref().unwrap().error_type(),
            ErrorType::PreconditionFailed
        );
        assert!(vote_reject
            .err_ref()
            .unwrap()
            .error_message
            .contains("already voted"));

        // Similarly, since neuron2 already voted explicitly, voting again will be
        // rejected.
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron2_identity),
            (test_neuron2, proposal_id, Vote::No),
        )
        .await;
        assert_eq!(
            vote_reject.err_ref().unwrap().error_type(),
            ErrorType::PreconditionFailed
        );
        assert!(vote_reject
            .err_ref()
            .unwrap()
            .error_message
            .contains("already voted"));

        // Now vote as another (unknown) neuron by neuron1's identity
        // and expect reject because authorisation cannot be checked
        // since the neuron doesn't exist.
        // Note: the chances to hit a real one is minuscule with a random
        //       neuron Id. At least we don't use magic Ids.
        let fake_neuron_id: u64 = rng.gen_range(0..TEST_NEURON_1_ID - 1);
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (NeuronId(fake_neuron_id), proposal_id, Vote::No),
        )
        .await;
        assert_eq!(vote_reject.err().unwrap().error_type(), ErrorType::NotFound);

        // Voting on a proposal before this proposal ID is created has no effect.
        // We check this by running following steps:
        // - vote on `proposal_id + 1` with high powered neuron 1
        // - submit proposal by neuron 2, resulting in new proposal Id
        // - assert (proposal_id + 1 = new_proposal)
        // - check voting success (expecting pending)
        let guessed_proposal_id = ProposalId(proposal_id.0 + 1);
        let vote_reject = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (test_neuron1, guessed_proposal_id, Vote::Yes),
        )
        .await;
        assert_eq!(vote_reject.err().unwrap().error_type(), ErrorType::NotFound);

        // Since the rejection fee is deduced when submitting, obtain the neuron stake
        // here.
        let funds_before = governance
            .query_from_sender(
                "get_full_neuron",
                candid_one::<Result<Neuron, GovernanceError>, _>,
                test_neuron2,
                test_neuron2_identity,
            )
            .await
            .expect("cannot obtain neuron_info?")
            .expect("get_full_neuron rejected?")
            .stake_e8s();

        let proposal_id = submit_proposal_by_neuron2(&nns).await;
        assert_eq!(proposal_id, guessed_proposal_id);

        let proposals: Vec<ProposalInfo> = governance
            .query_("get_pending_proposals", candid_one, ())
            .await
            .expect("query failed?");
        info!(
            ctx.logger,
            "get_pending_proposals({:?}): {:?}", proposal_id, proposals
        );
        let proposal: &ProposalInfo = proposals
            .iter()
            .find(|p| p.id == Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id.0 }))
            .unwrap();

        // Either there is no ballot registered for neuron1 or it is unspecified.
        if proposal.ballots.contains_key(&test_neuron1.0) {
            assert_eq!(proposal.ballots[&test_neuron1.0].vote(), Vote::Unspecified);
        }

        // Proposal cannot be submitted when the initiating neuron has insufficient
        // funds. Precisely, when proposal gets rejected, it needs to cover
        // reject_cost_e8s. See also NNS1-297.
        let submit_reject = submit_proposal_by_neuron3(&nns).await.map_err(
            |GovernanceError {
                 error_type,
                 error_message,
             }| {
                error_type == ErrorType::PreconditionFailed as i32
                    && error_message.contains("'t have enough stake to submit proposal")
            },
        );
        assert_eq!(submit_reject, Result::Err(true));

        // Proposal can be voted on even when the voting neuron has insufficient
        // funds for submitting proposals.
        let vote_result = forward_vote(
            &governance,
            Some(test_neuron3_identity),
            (test_neuron3, proposal_id, Vote::Yes),
        )
        .await;
        assert!(vote_result.is_ok());

        // Verify that penalty for proposal rejection goes to submitter neuron.
        // We evaluate following steps:
        // - check funds on neuron2 (this is done above, before submission)
        // - vote by neuron1: No
        // - re-check funds on neuron2

        let vote_result = forward_vote(
            &governance,
            Some(test_neuron1_identity),
            (test_neuron1, proposal_id, Vote::No),
        )
        .await;
        assert!(vote_result.is_ok());

        // To obtain precise information, we use `.update`.
        let funds_after = governance
            .update_from_sender(
                "get_full_neuron",
                candid_one::<Result<Neuron, GovernanceError>, _>,
                test_neuron2,
                test_neuron2_identity,
            )
            .await
            .expect("cannot obtain neuron_info?")
            .expect("get_full_neuron rejected?")
            .stake_e8s();
        info!(
            ctx.logger,
            "funds_before: {:?} funds_after: {:?}", funds_before, funds_after
        );
        assert!(funds_before > funds_after);
    });
}

// Submit a proposal (with nonsensical payload -- which won't matter, since
// in this test it will be always voted `No`, thus preventing it from
// execution).
async fn submit_proposal_by_neuron(
    neuron: NeuronId,
    keypair: &ed25519_dalek::Keypair,
    runtime: &Runtime,
) -> Result<ProposalId, GovernanceError> {
    let root = Canister::new(runtime, ROOT_CANISTER_ID);
    let governance = Canister::new(runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = ChangeNnsCanisterProposalPayload::new(
        false,
        ic_base_types::CanisterInstallMode::Upgrade,
        root.canister_id(),
    );
    submit_external_update_proposal_allowing_error(
        &governance,
        Sender::from_keypair(keypair),
        neuron,
        NnsCanisterUpgrade,
        proposal_payload,
        "<proposal created by submit_proposal_by_neuron>".to_string(),
        "".to_string(),
    )
    .await
}

async fn submit_proposal_by_neuron1(runtime: &Runtime) -> ProposalId {
    submit_proposal_by_neuron(
        NeuronId(TEST_NEURON_1_ID),
        &TEST_NEURON_1_OWNER_KEYPAIR,
        runtime,
    )
    .await
    .expect("submission failed?")
}

async fn submit_proposal_by_non_authorised_neuron1(
    runtime: &Runtime,
) -> Result<ProposalId, GovernanceError> {
    submit_proposal_by_neuron(
        NeuronId(TEST_NEURON_1_ID),
        &ic_test_identity::TEST_IDENTITY_KEYPAIR,
        runtime,
    )
    .await
}

async fn submit_proposal_by_neuron2(runtime: &Runtime) -> ProposalId {
    submit_proposal_by_neuron(
        NeuronId(TEST_NEURON_2_ID),
        &TEST_NEURON_2_OWNER_KEYPAIR,
        runtime,
    )
    .await
    .expect("submission failed?")
}

async fn submit_proposal_by_neuron3(runtime: &Runtime) -> Result<ProposalId, GovernanceError> {
    submit_proposal_by_neuron(
        NeuronId(TEST_NEURON_3_ID),
        &TEST_NEURON_3_OWNER_KEYPAIR,
        runtime,
    )
    .await
}

async fn forward_vote(
    governance: &Canister<'_>,
    sender: Option<&Sender>,
    payload: (NeuronId, ProposalId, Vote),
) -> ManageNeuronResponse {
    let message = ManageNeuron {
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
            ic_nns_common::pb::v1::NeuronId { id: (payload.0).0 },
        )),
        id: None,
        command: Some(Command::RegisterVote(RegisterVote {
            vote: payload.2 as i32,
            proposal: Some(ic_nns_common::pb::v1::ProposalId { id: (payload.1).0 }),
        })),
    };
    match sender {
        Some(identity) => {
            governance
                .update_from_sender("manage_neuron", candid_one, message, identity)
                .await
        }
        None => {
            governance
                .update_("manage_neuron", candid_one, message)
                .await
        }
    }
    .expect("Forwarding failed?")
}
