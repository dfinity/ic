use async_trait::async_trait;
use axum::http::{Request, Response};
use bytes::Bytes;
use ic_interfaces::p2p::{
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
    state_sync::{AddChunkError, Chunk, ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient},
};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{ArtifactKind, PriorityFn};
use ic_types::NodeId;
use mockall::mock;

mock! {
    pub StateSync<T: Send> {}

    impl<T: Send + Sync> StateSyncClient for StateSync<T> {
        type Message = T;

        fn available_states(&self) -> Vec<StateSyncArtifactId>;

        fn start_state_sync(
            &self,
            id: &StateSyncArtifactId,
        ) -> Option<Box<dyn Chunkable<T> + Send>>;

        fn should_cancel(&self, id: &StateSyncArtifactId) -> bool;

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

        async fn push(
            &self,
            peer_id: &NodeId,
            request: Request<Bytes>,
        ) -> Result<(), anyhow::Error>;

        fn peers(&self) -> Vec<(NodeId, ConnId)>;
    }
}

mock! {
    pub Chunkable<T> {}

    impl<T> Chunkable<T> for Chunkable<T> {
        fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
        fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError>;
        fn completed(&self) -> bool;
    }
}

mock! {
    pub ValidatedPoolReader<A: ArtifactKind> {}

    impl<A: ArtifactKind> ValidatedPoolReader<A> for ValidatedPoolReader<A> {
        fn contains(&self, id: &A::Id) -> bool;
        fn get_validated_by_identifier(&self, id: &A::Id) -> Option<A::Message>;
        fn get_all_validated_by_filter(
            &self,
            filter: &A::Filter,
        ) -> Box<dyn Iterator<Item = A::Message>>;
    }
}

mock! {
    pub PriorityFnAndFilterProducer<A: ArtifactKind> {}

    impl<A: ArtifactKind + Sync> PriorityFnAndFilterProducer<A, MockValidatedPoolReader<A>> for PriorityFnAndFilterProducer<A> {
        fn get_priority_function(&self, pool: &MockValidatedPoolReader<A>) -> PriorityFn<A::Id, A::Attribute>;
        fn get_filter(&self) -> A::Filter {
           A::Filter::default()
        }

    }
}
