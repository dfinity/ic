use async_trait::async_trait;
use axum::http::{Request, Response};
use bytes::Bytes;
use ic_interfaces::p2p::{
    consensus::{Aborted, ArtifactAssembler, Bouncer, BouncerFactory, Peers, ValidatedPoolReader},
    state_sync::{AddChunkError, Chunk, ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient},
};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::IdentifiableArtifact;
use ic_types::NodeId;
use mockall::mock;

use crate::consensus::U64Artifact;

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
        ) -> Result<Response<Bytes>, anyhow::Error>;

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
        fn get_all_validated(
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
        ) -> impl std::future::Future<Output = Result<(U64Artifact, NodeId), Aborted>> + Send;
    }
}
