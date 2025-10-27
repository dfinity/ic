use ic_interfaces::consensus_pool::{ConsensusPoolCache, ConsensusTime};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    Height, RegistryVersion,
    consensus::{Block, CatchUpPackage},
    time::Time,
};
use mockall::mock;

mock! {
    pub ConsensusPoolCache {}

    impl ConsensusPoolCache for ConsensusPoolCache {
        fn finalized_block(&self) -> Block;

        fn catch_up_package(&self) -> CatchUpPackage;

        fn summary_block(&self) -> Block;

        fn cup_as_protobuf(&self) -> pb::CatchUpPackage;

        fn get_oldest_registry_version_in_use(&self) -> RegistryVersion;

        fn is_replica_behind(&self, certified_height: Height) -> bool;
    }
}

mock! {
    pub ConsensusTime {}

    impl ConsensusTime for ConsensusTime {
        fn consensus_time(&self) -> Option<Time>;
    }
}
