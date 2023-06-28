//! Tests for artifact clients

mod setup;

use assert_matches::assert_matches;
use ic_interfaces::artifact_manager::OnArtifactError;
use ic_test_utilities::{
    consensus::{fake::*, make_genesis},
    types::ids::node_test_id,
};
use ic_types::{artifact::ArtifactKind, artifact_kind::ConsensusArtifact, consensus::*};
use setup::run_test;

#[test]
fn test_artifact_advert_match() {
    run_test(|manager| {
        // Positive case: advert matches artifact
        let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
        let block = BlockProposal::fake(cup.content.block.into_inner(), node_test_id(0));
        let msg = block.into_message();
        let mut advert: ic_types::p2p::GossipAdvert =
            ConsensusArtifact::message_to_advert(&msg).into();
        let result = manager.on_artifact(msg.clone().into(), advert.clone(), &node_test_id(0));
        assert_matches!(result, Ok(()));

        // Negative case: advert does not match artifact
        advert.size = 0;
        let result = manager.on_artifact(msg.into(), advert, &node_test_id(0));
        assert_matches!(result, Err(OnArtifactError::AdvertMismatch(_)));
    });
}
