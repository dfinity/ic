use dfn_candid::{candid, candid_one};
use ic_canister_client::Sender;
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_governance::governance::REWARD_DISTRIBUTION_PERIOD_SECONDS;
use ic_nns_governance::pb::v1::{
    Ballot, Governance as GovernanceProto, GovernanceError, NetworkEconomics, Neuron, ProposalData,
    RewardEvent, Vote,
};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use std::iter::once;
use std::time::{Duration, SystemTime};

/// This is trying to the simplest possible integration test for reward
/// distribution.
///
/// To avoid having to deal with time, in this test the initial paylod for the
/// governance canister simulates a genesis 1.5 reward period in the past, and
/// some proposal, also in the past, that is already ready to settle.
///
/// This means that immediately after initialization, a reward event should be
/// created for the first reward period after genesis, and maturity should
/// increase.
///
/// Hence we don't really need to wait for time to pass: all the interesting
/// things should happen with a few blocks of initialization. This makes a test
/// that is fast and robust, but a bit weak, because only a single reward event
/// can be tested.
#[test]
fn test_increase_maturity_just_after_init() {
    local_test_on_nns_subnet(|runtime| async move {
        // Set up the governance proto to simulate:
        // - genesis 1.5 voting reward period in the past
        // - one proposal that have been voted on by one neuron and is ready to be
        //   settled

        let now = SystemTime::now();
        let one_and_half_period = Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS) * 3 / 2;
        let genesis = now - one_and_half_period;
        let genesis_timestamp_secs = genesis
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let governance_proto = GovernanceProto {
            wait_for_quiet_threshold_seconds: 11,
            economics: Some(NetworkEconomics {
                neuron_minimum_stake_e8s: 5,
                ..Default::default()
            }),
            proposals: once((
                1,
                ProposalData {
                    proposal_timestamp_seconds: genesis_timestamp_secs,
                    ballots: once((
                        TEST_NEURON_1_ID,
                        Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 153,
                        },
                    ))
                    .collect(),
                    ..Default::default()
                },
            ))
            .collect(),
            latest_reward_event: Some(RewardEvent {
                day_after_genesis: 0, // Specified explicitly for emphasis.
                ..Default::default()
            }),
            genesis_timestamp_seconds: genesis_timestamp_secs,
            ..Default::default()
        };

        let init_payloads = NnsInitPayloadsBuilder::new()
            .with_test_neurons()
            .with_governance_proto(governance_proto)
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, init_payloads).await;

        // There should be very soon after initialization a first reward event
        let mut latest_reward_event: RewardEvent = nns_canisters
            .governance
            .query_("get_latest_reward_event", candid, ())
            .await
            .unwrap();
        eprintln!("{:?}", latest_reward_event);
        while latest_reward_event.day_after_genesis == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            latest_reward_event = dbg!(nns_canisters
                .governance
                .query_("get_latest_reward_event", candid, ())
                .await
                .unwrap());
        }
        assert_eq!(latest_reward_event.day_after_genesis, 1);
        assert!(
            latest_reward_event.distributed_e8s_equivalent > 0,
            "latest_reward_event: {:?}",
            latest_reward_event
        );

        let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
        // Check maturity increase
        let neuron_res: Result<Neuron, GovernanceError> = nns_canisters
            .governance
            .query_from_sender(
                "get_full_neuron",
                candid_one,
                NeuronId(TEST_NEURON_1_ID),
                &sender,
            )
            .await
            .unwrap();
        let neuron = neuron_res.unwrap();

        // There was a single voter, so it should get the entire amount that was
        // distributed.
        assert_eq!(
            neuron.maturity_e8s_equivalent, latest_reward_event.distributed_e8s_equivalent,
            "Neuron: {:?}",
            neuron
        );

        Ok(())
    });
}
