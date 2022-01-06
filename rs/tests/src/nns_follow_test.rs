/* tag::catalog[]
Title:: "Following" end to end

Goal:: Add/remove followers; follow lead voter, chain of following, unhappy paths

Runbook::
. set up an NNS  subnet with test neurons (N1 .. N3)
. make N2 follow N1, this should pass
. make N2 follow itself, this should pass (cycles are allowed)
. try again with wrong { topic, authorisation } expecting corresponding errors
. try again with non-existing followee, observe success
. remove following
. try follow a mix of existing and non-existing neurons
. follow-after-proposal (doesn't propagate)
. follow-before-proposal (propagates votes)
. split N1 into a heavier and a lighter one
. establish a follow cascade and observe it working

Covered:
. simultaneous follows (e.g. mixed success, duplicate Ids)
. retrieving who follows whom
. follow chains

NotCovered:
. spawning (in addition to splitting) neurons

end::catalog[] */

use crate::util::{get_random_nns_node_endpoint, runtime_from_url};

use ic_fondue::{ic_manager::IcHandle, internet_computer::InternetComputer};

use ic_nns_governance::pb::v1::{
    governance_error::ErrorType,
    manage_neuron::{Command, Follow, NeuronIdOrSubaccount, RegisterVote, Split},
    manage_neuron_response, proposal, ExecuteNnsFunction, GovernanceError, ManageNeuron,
    ManageNeuronResponse, Neuron, NnsFunction, Proposal, ProposalInfo, Tally, Topic, Vote,
};

use crate::nns::NnsExt;
use canister_test::Canister;
use dfn_candid::{candid, candid_one};
use ic_nns_test_utils::ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID, TEST_NEURON_3_ID};

use assert_matches::assert_matches;
use ed25519_dalek::Keypair;
use ic_canister_client::Sender;
use ic_fondue::log::info;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR, TEST_NEURON_3_OWNER_KEYPAIR},
    GOVERNANCE_CANISTER_ID,
};
use ic_registry_subnet_type::SubnetType;
use rand::Rng;
use std::collections::HashSet;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();

    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());

        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        let valid_topic = Topic::ParticipantManagement as i32;

        let n1: (ic_nns_common::types::NeuronId, &Keypair) =
            (NeuronId(TEST_NEURON_1_ID), &TEST_NEURON_1_OWNER_KEYPAIR);
        let n2: (ic_nns_common::types::NeuronId, &Keypair) =
            (NeuronId(TEST_NEURON_2_ID), &TEST_NEURON_2_OWNER_KEYPAIR);
        let n3: (ic_nns_common::types::NeuronId, &Keypair) =
            (NeuronId(TEST_NEURON_3_ID), &TEST_NEURON_3_OWNER_KEYPAIR);

        // expect everything working
        let result = setup_following(&ctx.logger, &governance, n2, n1, valid_topic)
            .await
            .command
            .unwrap();
        assert_eq!(
            result,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        let followees = obtain_followees(&ctx.logger, &governance, n2, valid_topic).await;
        // At this point n2 has one followee (n1).
        assert_eq!(followees, vec![n1.0]);

        // self-follow: expect success (this is somewhat weird,
        // but nothing nefarious, as cycles in the following graph get broken)
        let result = setup_following(&ctx.logger, &governance, n2, n2, valid_topic)
            .await
            .command
            .unwrap();
        assert_eq!(
            result,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        let followees = obtain_followees(&ctx.logger, &governance, n2, valid_topic).await;
        // At this point n2 has one followee (itself).
        assert_eq!(followees, vec![n2.0]);

        // Note: the chances to hit a real topic is minuscule with a random
        //       number from the below range. At least we don't use magics.
        // expect reject
        let invalid_topic = rng.gen_range(i32::MAX - 10000..i32::MAX);
        let reject = setup_following(&ctx.logger, &governance, n2, n1, invalid_topic)
            .await
            .command
            .unwrap();
        assert_matches!(reject,
                        manage_neuron_response::Command::Error(err)
                        if err.error_type() == ErrorType::InvalidCommand
                        && err.error_message.contains("Invalid topic"));

        // expect reject
        let n2_not_authz: (ic_nns_common::types::NeuronId, &Keypair) =
            (NeuronId(TEST_NEURON_2_ID), &TEST_NEURON_3_OWNER_KEYPAIR);
        let reject = setup_following(&ctx.logger, &governance, n2_not_authz, n1, valid_topic)
            .await
            .command
            .unwrap();
        assert_matches!(reject,
                        manage_neuron_response::Command::Error(err)
                        if err.error_type() == ErrorType::NotAuthorized);

        // Note: the chances to hit a real neuron NeuronIdOrSubaccount is minuscule with
        // a random neuron NeuronIdOrSubaccount. At least we don't use magic Ids.
        // Expect reject, a non-existent neuron cannot have followees.
        let fake_neuron_id: u64 = rng.gen_range(0..u64::MAX);
        let n_fake: (ic_nns_common::types::NeuronId, &Keypair) =
            (NeuronId(fake_neuron_id), &TEST_NEURON_2_OWNER_KEYPAIR);
        let reject = setup_following(&ctx.logger, &governance, n_fake, n1, valid_topic)
            .await
            .command
            .unwrap();
        assert_matches!(reject,
                        manage_neuron_response::Command::Error(err)
                        if err.error_type() == ErrorType::NotFound);

        // The next step might be regarded controversial, as allowing to
        // follow non-existent neurons might result in surprising following
        // relationships when a future neuron is created with the exact same
        // NeuronIdOrSubaccount. We accept this here because currently there is
        // no guarding against orphaned neuron Ids in `governance` either.
        // Deleting neurons (a planned feature) may also create orphaned Ids.
        let accept = setup_following(&ctx.logger, &governance, n2, n_fake, valid_topic)
            .await
            .command
            .unwrap();
        assert_eq!(
            accept,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        let followees = obtain_followees(&ctx.logger, &governance, n2, valid_topic).await;
        // At this point n2 has one followee (the non-existing neuron).
        assert_eq!(followees, vec![n_fake.0]);

        // clearing is always expected to work
        clear_followees(&ctx.logger, &governance, n2, valid_topic).await;
        assert_no_followees(&ctx.logger, &governance, n2, valid_topic).await;

        // adding mixed (valid and invalid) followees is currently accepted
        let accept = setup_followees(
            &ctx.logger,
            &governance,
            n2,
            vec![n_fake.0, n1.0],
            valid_topic,
        )
        .await
        .command
        .unwrap();

        assert_eq!(
            accept,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        let followees = obtain_followees(&ctx.logger, &governance, n2, valid_topic).await;
        // At this point n2 has two followees (the non-existing neuron and n1).
        assert_eq!(followees, vec![n_fake.0, n1.0]);

        // adding duplicated followees is currently accepted
        let accept = setup_followees(
            &ctx.logger,
            &governance,
            n2,
            vec![n1.0, n1.0, n1.0],
            valid_topic,
        )
        .await
        .command
        .unwrap();

        assert_eq!(
            accept,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        let followees = obtain_followees(&ctx.logger, &governance, n2, valid_topic).await;
        // At this point n2 has three duplicated followees.
        assert_eq!(followees, vec![n1.0, n1.0, n1.0]);

        // clearing again
        clear_followees(&ctx.logger, &governance, n2, valid_topic).await;
        assert_no_followees(&ctx.logger, &governance, n2, valid_topic).await;

        // make a proposal via n2 before setting up followees
        let proposal =
            submit_proposal(&ctx.logger, &governance, n2, NnsFunction::NnsRootUpgrade).await;

        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 140_400_410);
        let ballot_n2 = check_ballots(&ctx.logger, &governance, proposal, &n2).await;
        assert_eq!(ballot_n2, (140_400_410, Vote::Yes));

        // now make n1 follow n2
        let result = setup_following(
            &ctx.logger,
            &governance,
            n1,
            n2,
            Topic::NetworkCanisterManagement as i32,
        )
        .await
        .command
        .unwrap();
        assert_eq!(
            result,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        // voting doesn't get propagated by mutating the following graph
        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 140_400_410);
        let ballot_n1 = check_ballots(&ctx.logger, &governance, proposal, &n1).await;
        assert_eq!(ballot_n1, (1_404_004_106, Vote::Unspecified));
        let ballot_n2 = check_ballots(&ctx.logger, &governance, proposal, &n2).await;
        assert_eq!(ballot_n2, (140_400_410, Vote::Yes));

        // re-vote explicitly, still no change
        cast_vote(&ctx.logger, &governance, n2, proposal).await;
        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 140_400_410);

        // n1 needs to vote explicitly
        cast_vote(&ctx.logger, &governance, n1, proposal).await;
        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 1_544_404_516);
        let ballot_n1 = check_ballots(&ctx.logger, &governance, proposal, &n1).await;
        assert_eq!(ballot_n1, (1_404_004_106, Vote::Yes));

        // now set up n3 follows n2 and n2 follows n1 (the latter gives circularity)
        let result1 = setup_following(
            &ctx.logger,
            &governance,
            n3,
            n2,
            Topic::NetworkCanisterManagement as i32,
        )
        .await
        .command
        .unwrap();
        assert_eq!(
            result1,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );
        let result2 = setup_following(
            &ctx.logger,
            &governance,
            n2,
            n1,
            Topic::NetworkCanisterManagement as i32,
        )
        .await
        .command
        .unwrap();
        assert_eq!(
            result2,
            manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
        );

        // make another proposal via n2 now that followees are set up
        let proposal =
            submit_proposal(&ctx.logger, &governance, n2, NnsFunction::NnsRootUpgrade).await;

        // verify that all three neurons did vote
        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 1_404_004_106 + 140_400_410 + 14_040_040);
        let ballot_n1 = check_ballots(&ctx.logger, &governance, proposal, &n1).await;
        assert_eq!(ballot_n1, (1_404_004_106, Vote::Yes));
        let ballot_n2 = check_ballots(&ctx.logger, &governance, proposal, &n2).await;
        assert_eq!(ballot_n2, (140_400_410, Vote::Yes));
        let ballot_n3 = check_ballots(&ctx.logger, &governance, proposal, &n3).await;
        assert_eq!(ballot_n3, (14_040_040, Vote::Yes));

        // Split n1 and build a follow chain like this:
        // n2 -> n1a -> n3 -> n1
        let n1a_id = split_neuron(&ctx.logger, &governance, n1, 500_000_000).await;

        let n1a: (ic_nns_common::types::NeuronId, &Keypair) =
            (n1a_id, &TEST_NEURON_1_OWNER_KEYPAIR);

        setup_following_asserting(
            &ctx.logger,
            &governance,
            n2,
            n1a,
            Topic::NetworkCanisterManagement,
        )
        .await;

        // at this point n2 is not influential
        let influential = get_neuron_ids(&governance, n1a.1).await;
        info!(&ctx.logger, "influential (before): {:?}", influential);
        assert_eq!(influential.len(), 2);
        assert!(influential.contains(&n1a_id));
        assert!(influential.contains(&n1.0));

        // same following, different topic
        setup_following_asserting(&ctx.logger, &governance, n2, n1a, Topic::NeuronManagement).await;

        // at this point n2 becomes influential (a `NeuronManagement` follower to n1a)
        let influential = get_neuron_ids(&governance, n1a.1).await;
        info!(&ctx.logger, "influential (n2 added): {:?}", influential);
        assert_eq!(influential.len(), 3);
        assert!(influential.contains(&n1a_id));
        assert!(influential.contains(&n1.0));
        assert!(influential.contains(&n2.0));

        // change following, in `NeuronManagement` topic
        setup_following_asserting(&ctx.logger, &governance, n3, n1a, Topic::NeuronManagement).await;
        // at this point n3 becomes influential (a `NeuronManagement` follower to n1a)
        let influential = get_neuron_ids(&governance, n1a.1).await;
        info!(&ctx.logger, "influential (n3 added): {:?}", influential);
        assert_eq!(influential.len(), 4);
        assert!(influential.contains(&n1a_id));
        assert!(influential.contains(&n1.0));
        assert!(influential.contains(&n2.0));
        assert!(influential.contains(&n3.0));

        // change following, in `NeuronManagement` topic
        setup_following_asserting(&ctx.logger, &governance, n2, n3, Topic::NeuronManagement).await;
        // at this point n2 ceases to be influential (as a `NeuronManagement` follower
        // to n1a)
        let influential = get_neuron_ids(&governance, n1a.1).await;
        info!(&ctx.logger, "influential (n2 removed): {:?}", influential);
        assert_eq!(influential.len(), 3);
        assert!(influential.contains(&n1a_id));
        assert!(influential.contains(&n1.0));
        assert!(influential.contains(&n3.0));

        setup_following_asserting(
            &ctx.logger,
            &governance,
            n1a,
            n3,
            Topic::NetworkCanisterManagement,
        )
        .await;

        setup_following_asserting(
            &ctx.logger,
            &governance,
            n3,
            n1,
            Topic::NetworkCanisterManagement,
        )
        .await;

        // fire off a new proposal by n1, and see all neurons voting
        // immediately along the chain
        let proposal =
            submit_proposal(&ctx.logger, &governance, n1, NnsFunction::NnsRootUpgrade).await;

        // verify that all four neurons did vote
        let votes = check_votes(&ctx.logger, &governance, proposal).await;
        assert_eq!(votes, 702_002_052 + 701_988_012 + 140_400_410 + 14_040_040);
        let ballot_n1 = check_ballots(&ctx.logger, &governance, proposal, &n1).await;
        assert_eq!(ballot_n1, (702_002_052, Vote::Yes));
        let ballot_n1a = check_ballots(&ctx.logger, &governance, proposal, &n1a).await;
        assert_eq!(ballot_n1a, (701_988_012, Vote::Yes));
        let ballot_n2 = check_ballots(&ctx.logger, &governance, proposal, &n2).await;
        assert_eq!(ballot_n2, (140_400_410, Vote::Yes));
        let ballot_n3 = check_ballots(&ctx.logger, &governance, proposal, &n3).await;
        assert_eq!(ballot_n3, (14_040_040, Vote::Yes));
    });
}

async fn setup_followees(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    follower: (NeuronId, &Keypair),
    leaders: Vec<NeuronId>,
    topic: i32,
) -> ManageNeuronResponse {
    let result: ManageNeuronResponse = gov
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId { id: (follower.0).0 },
                )),
                id: None,
                command: Some(Command::Follow(Follow {
                    topic,
                    followees: leaders
                        .iter()
                        .map(|leader| ic_nns_common::pb::v1::NeuronId { id: leader.0 })
                        .collect(),
                })),
            },
            &Sender::from_keypair(follower.1),
        )
        .await
        .unwrap();

    info!(logger, "Follow: {:?}", result);
    result
}

async fn setup_following(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    follower: (NeuronId, &Keypair),
    leader: (NeuronId, &Keypair),
    topic: i32,
) -> ManageNeuronResponse {
    setup_followees(logger, gov, follower, vec![leader.0], topic).await
}

async fn setup_following_asserting(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    follower: (NeuronId, &Keypair),
    leader: (NeuronId, &Keypair),
    topic: Topic,
) {
    let result = setup_following(logger, gov, follower, leader, topic as i32)
        .await
        .command
        .unwrap();
    assert_eq!(
        result,
        manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
    );
}

async fn clear_followees(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    follower: (NeuronId, &Keypair),
    topic: i32,
) {
    let result = setup_followees(logger, gov, follower, vec![], topic)
        .await
        .command
        .unwrap();
    assert_eq!(
        result,
        manage_neuron_response::Command::Follow(manage_neuron_response::FollowResponse {})
    );
}

async fn split_neuron(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    neuron: (NeuronId, &Keypair),
    amount: u64,
) -> NeuronId {
    let result: ManageNeuronResponse = gov
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId { id: (neuron.0).0 },
                )),
                id: None,
                command: Some(Command::Split(Split { amount_e8s: amount })),
            },
            &Sender::from_keypair(neuron.1),
        )
        .await
        .unwrap();

    info!(logger, "Split: {:?}", result);

    if let manage_neuron_response::Command::Split(resp) = result.command.unwrap() {
        NeuronId::from(resp.created_neuron_id.unwrap())
    } else {
        panic!("funny ManageNeuronResponse")
    }
}

async fn get_neuron_ids(gov: &Canister<'_>, neuron: &Keypair) -> HashSet<NeuronId> {
    gov.query_from_sender("get_neuron_ids", candid, (), &Sender::from_keypair(neuron))
        .await
        .unwrap()
}

async fn obtain_followees(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    neuron: (NeuronId, &Keypair),
    topic: i32,
) -> Vec<NeuronId> {
    let followees = gov
        .query_from_sender(
            "get_full_neuron",
            candid_one::<Result<Neuron, GovernanceError>, _>,
            neuron.0,
            &Sender::from_keypair(neuron.1),
        )
        .await
        .expect("cannot obtain neuron_info?")
        .expect("get_full_neuron rejected?")
        .followees;

    info!(logger, "Followees: {:?}", followees);

    followees[&topic]
        .followees
        .iter()
        .map(|ic_nns_common::pb::v1::NeuronId { id }| NeuronId(*id))
        .collect()
}

async fn assert_no_followees(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    neuron: (NeuronId, &Keypair),
    topic: i32,
) {
    let followees = gov
        .query_from_sender(
            "get_full_neuron",
            candid_one::<Result<Neuron, GovernanceError>, _>,
            neuron.0,
            &Sender::from_keypair(neuron.1),
        )
        .await
        .expect("cannot obtain neuron_info?")
        .expect("get_full_neuron rejected?")
        .followees;

    info!(logger, "Followees: {:?}", followees);

    match followees.get_key_value(&topic) {
        None => (),
        Some((_, fs)) => assert!(fs.followees.is_empty()),
    }
}

async fn submit_proposal(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    neuron: (NeuronId, &Keypair),
    update_type: NnsFunction,
) -> ProposalId {
    let proposal = Proposal {
        title: Some("<proposal created from initialization>".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: update_type as i32,
            payload: Vec::new(),
        })),
    };

    let result: ManageNeuronResponse = gov
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId { id: (neuron.0).0 },
                )),
                id: None,
                command: Some(Command::MakeProposal(Box::new(proposal))),
            },
            &Sender::from_keypair(neuron.1),
        )
        .await
        .unwrap();

    info!(logger, "Proposal: {:?}", result);

    if let manage_neuron_response::Command::MakeProposal(resp) = result.command.unwrap() {
        ProposalId::from(resp.proposal_id.unwrap())
    } else {
        panic!("funny ManageNeuronResponse")
    }
}

async fn cast_vote(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    neuron: (NeuronId, &Keypair),
    proposal: ProposalId,
) {
    let result: ManageNeuronResponse = gov
        .update_from_sender(
            "manage_neuron",
            candid_one,
            ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId { id: (neuron.0).0 },
                )),
                id: None,
                command: Some(Command::RegisterVote(RegisterVote {
                    vote: Vote::Yes as i32,
                    proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal.0 }),
                })),
            },
            &Sender::from_keypair(neuron.1),
        )
        .await
        .unwrap();

    info!(logger, "RegisterVote: {:?}", result);
}

async fn check_votes(logger: &slog::Logger, gov: &Canister<'_>, proposal: ProposalId) -> u64 {
    let reply = gov
        .query_(
            "get_proposal_info",
            candid_one::<Option<ProposalInfo>, _>,
            proposal.0,
        )
        .await
        .unwrap()
        .unwrap();

    info!(logger, "Info: {:?}", reply);

    match reply.latest_tally {
        Some(Tally { yes, .. }) => yes,
        _ => panic!("funny tally"),
    }
}

async fn check_ballots(
    logger: &slog::Logger,
    gov: &Canister<'_>,
    proposal: ProposalId,
    by: &(ic_nns_common::types::NeuronId, &Keypair),
) -> (u64, Vote) {
    let reply = gov
        .query_from_sender(
            "get_proposal_info",
            candid_one::<Option<ProposalInfo>, _>,
            proposal.0,
            &Sender::from_keypair(by.1),
        )
        .await
        .unwrap()
        .unwrap();

    let ballots = reply.ballots;
    info!(logger, "Ballots: {:?}", ballots);
    assert!(!ballots.is_empty());

    let ballot = &ballots[&(by.0).0];
    (ballot.voting_power, Vote::from(ballot.vote))
}
