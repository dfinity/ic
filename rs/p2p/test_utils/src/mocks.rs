use async_trait::async_trait;
use axum::http::{Request, Response};
use bytes::Bytes;
use ic_interfaces::{
    canister_http::CanisterHttpPool,
    p2p::{
        consensus::{
            ArtifactAssembler, AssembleResult, Bouncer, BouncerFactory, Peers, ValidatedPoolReader,
        },
        state_sync::{
            AddChunkError, Chunk, ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient,
        },
    },
};
use ic_quic_transport::{ConnId, P2PError, Transport};
use ic_types::NodeId;
use ic_types::artifact::{CanisterHttpResponseId, IdentifiableArtifact};
use ic_types::canister_http::{
    CanisterHttpResponse, CanisterHttpResponseArtifact, CanisterHttpResponseShare,
};
use ic_types::crypto::CryptoHashOf;
use mockall::mock;
use std::collections::BTreeMap;

use crate::consensus::U64Artifact;

/// A canister HTTP pool that serves the response contents it was built with, and
/// nothing else.
///
/// Hand-written rather than a `mock!` because
/// [`CanisterHttpPool::get_response_content_by_hash`] returns a reference into the
/// pool, which a mock cannot hand back for data it owns itself.
pub struct FakeCanisterHttpPool {
    contents: BTreeMap<CryptoHashOf<CanisterHttpResponse>, CanisterHttpResponse>,
}

impl FakeCanisterHttpPool {
    pub fn new(responses: impl IntoIterator<Item = CanisterHttpResponse>) -> Self {
        Self {
            contents: responses
                .into_iter()
                .map(|response| (ic_types::crypto::crypto_hash(&response), response))
                .collect(),
        }
    }

    pub fn empty() -> Self {
        Self::new(std::iter::empty())
    }
}

impl CanisterHttpPool for FakeCanisterHttpPool {
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_> {
        Box::new(std::iter::empty())
    }

    fn get_unvalidated_artifacts(
        &self,
    ) -> Box<dyn Iterator<Item = &CanisterHttpResponseArtifact> + '_> {
        Box::new(std::iter::empty())
    }

    fn get_unvalidated_artifact(
        &self,
        _share: &CanisterHttpResponseShare,
    ) -> Option<&CanisterHttpResponseArtifact> {
        None
    }

    fn get_response_content_items(
        &self,
    ) -> Box<dyn Iterator<Item = (&CryptoHashOf<CanisterHttpResponse>, &CanisterHttpResponse)> + '_>
    {
        Box::new(self.contents.iter())
    }

    fn get_response_content_by_hash(
        &self,
        hash: &CryptoHashOf<CanisterHttpResponse>,
    ) -> Option<&CanisterHttpResponse> {
        self.contents.get(hash)
    }

    fn lookup_validated(
        &self,
        _msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        None
    }
}

mock! {
    pub StateSync<T: Send> {}

    impl<T: Send + Sync> StateSyncClient for StateSync<T> {
        type Message = T;

        fn available_states(&self) -> Vec<StateSyncArtifactId>;

        fn maybe_start_state_sync(
            &self,
            id: &StateSyncArtifactId,
        ) -> Option<Box<dyn Chunkable<T> + Send>>;

        fn cancel_if_running(&self, id: &StateSyncArtifactId) -> bool;

        fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk>;
    }
}

mock! {
    pub Transport {}

    #[async_trait]
    impl Transport for Transport{
        async fn rpc(
            &self,
            peer_id: &NodeId,
            request: Request<Bytes>,
        ) -> Result<Response<Bytes>, P2PError>;

        fn peers(&self) -> Vec<(NodeId, ConnId)>;
    }
}

mock! {
    pub Chunkable<T> {}

    impl<T> Chunkable<T> for Chunkable<T> {
        fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
        fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError>;
    }
}

mock! {
    pub ValidatedPoolReader<A: IdentifiableArtifact> {}

    impl<A: IdentifiableArtifact> ValidatedPoolReader<A> for ValidatedPoolReader<A> {
        fn get(&self, id: &A::Id) -> Option<A>;
        fn get_all_for_initial_broadcast(
            &self,
        ) -> Box<dyn Iterator<Item = A>>;
    }
}

mock! {
    pub BouncerFactory<A: IdentifiableArtifact> {}

    impl<A: IdentifiableArtifact + Sync> BouncerFactory<A::Id, MockValidatedPoolReader<A>> for BouncerFactory<A> {
        fn new_bouncer(&self, pool: &MockValidatedPoolReader<A>) -> Bouncer<A::Id>;
        fn refresh_period(&self) -> std::time::Duration;
    }
}

mock! {
    pub Peers {}

    impl Clone for Peers {
        fn clone(&self) -> Self;
    }

    impl Peers for Peers {
        fn peers(&self) -> Vec<NodeId>;
    }
}

mock! {
    pub ArtifactAssembler {}

    impl Clone for ArtifactAssembler {
        fn clone(&self) -> Self;
    }

    impl ArtifactAssembler<U64Artifact, U64Artifact> for ArtifactAssembler {
        fn disassemble_message(&self, msg: U64Artifact) -> U64Artifact;
        fn assemble_message<P: Peers + Send + 'static>(
            &self,
            id: u64,
            artifact: Option<(U64Artifact, NodeId)>,
            peers: P,
        ) -> impl std::future::Future<Output = AssembleResult<U64Artifact>> + Send;
    }
}
