//! Tests for artifact clients

mod setup;

use actix::prelude::*;
use assert_matches::assert_matches;
use ic_artifact_manager::artifact::ConsensusArtifact;
use ic_consensus_message::{make_genesis, ConsensusMessageHashable};
use ic_interfaces::{artifact_manager::OnArtifactError, artifact_pool::ArtifactPoolError};
use ic_test_utilities::{consensus::fake::*, types::ids::node_test_id};
use ic_types::{artifact::ArtifactKind, consensus::*, ReplicaVersion};
use setup::run_test;
use std::convert::TryFrom;

#[actix_rt::test]
async fn test_artifact_version() {
    run_test(|manager| {
        // Positive case
        let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
        let block1 = BlockProposal::fake(cup.content.block.into_inner(), node_test_id(0));
        let msg1 = block1.clone().to_message();
        let result = manager.on_artifact(
            msg1.clone().into(),
            ConsensusArtifact::to_advert(&msg1).into(),
            &node_test_id(0),
        );
        assert_matches!(result, Ok(()));

        // Negative case
        let next_version = ReplicaVersion::try_from(format!("{}.1234", block1.version())).unwrap();
        let block2 = BlockProposal::fake(
            block1.content.as_ref().fake_version(next_version),
            node_test_id(1),
        );
        let msg2 = block2.to_message();
        let result = manager.on_artifact(
            msg2.clone().into(),
            ConsensusArtifact::to_advert(&msg2).into(),
            &node_test_id(0),
        );
        assert_matches!(
            result,
            Err(
                OnArtifactError::ArtifactPoolError(
                    ArtifactPoolError::ArtifactReplicaVersionError(_),
                ),
            )
        );
        System::current().stop();
    });
}

#[actix_rt::test]
async fn test_artifact_advert_match() {
    run_test(|manager| {
        // Positive case: advert matches artifact
        let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
        let block = BlockProposal::fake(cup.content.block.into_inner(), node_test_id(0));
        let msg = block.to_message();
        let mut advert: ic_types::p2p::GossipAdvert = ConsensusArtifact::to_advert(&msg).into();
        let result = manager.on_artifact(msg.clone().into(), advert.clone(), &node_test_id(0));
        assert_matches!(result, Ok(()));

        // Negative case: advert does not match artifact
        advert.size = 0;
        let result = manager.on_artifact(msg.into(), advert, &node_test_id(0));
        assert_matches!(result, Err(OnArtifactError::AdvertMismatch(_)));
        System::current().stop();
    });
}
