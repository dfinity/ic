use ic_config::artifact_pool::{
    ArtifactPoolConfig, ArtifactPoolTomlConfig, LMDBConfig, PersistentPoolBackend, RocksDBConfig,
};
use tempfile::Builder;

/// Creates a new ArtifactPoolConfig, based on the default, for tests.
/// It removes the persistent pool directory afterwards.
pub fn with_test_pool_config<T>(run: impl FnOnce(ArtifactPoolConfig) -> T) -> T {
    let tempdir = Builder::new().prefix("persistent-pool").tempdir().unwrap();
    run(ArtifactPoolConfig::new(tempdir.path().to_path_buf()))
}

/// Creates a new RocksDBConfig, based on the default, for tests.
/// It removes the persistent pool directory afterwards.
pub fn with_test_rocksdb_pool_config<T>(run: impl FnOnce(RocksDBConfig) -> T) -> T {
    let tempdir = Builder::new().prefix("persistent-pool").tempdir().unwrap();
    let mut toml_config = ArtifactPoolTomlConfig::new(tempdir.path().to_path_buf(), None);
    toml_config.consensus_pool_backend = Some("rocksdb".to_string());
    let config = match ArtifactPoolConfig::from(toml_config).persistent_pool_backend {
        PersistentPoolBackend::RocksDB(config) => config,
        _ => panic!("Missing rocksdb persistent pool config"),
    };
    run(config)
}

/// Creates a new LMDBConfig, based on the default, for tests.
/// It removes the persistent pool directory afterwards.
pub fn with_test_lmdb_pool_config<T>(run: impl FnOnce(LMDBConfig) -> T) -> T {
    let tempdir = Builder::new().prefix("persistent-pool").tempdir().unwrap();
    let mut toml_config = ArtifactPoolTomlConfig::new(tempdir.path().to_path_buf(), None);
    toml_config.consensus_pool_backend = Some("lmdb".to_string());
    let config = match ArtifactPoolConfig::from(toml_config).persistent_pool_backend {
        PersistentPoolBackend::Lmdb(config) => config,
        _ => panic!("Missing rocksdb persistent pool config"),
    };
    run(config)
}

/// Creates a set of ArtifactPoolConfig(s), based on the default, for tests.
/// It removes all persistent pool directories afterwards.
pub fn with_test_pool_configs<T>(num: usize, run: impl FnOnce(Vec<ArtifactPoolConfig>) -> T) -> T {
    let configs = (0..num)
        .map(|_| {
            Builder::new()
                .prefix("persistent-pool")
                .tempdir()
                .expect("unable to create tempdir")
        })
        .map(|dir| ArtifactPoolConfig::new(dir.path().to_path_buf()))
        .collect::<Vec<_>>();
    run(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ids::node_test_id;
    use crate::types::messages::SignedIngressBuilder;
    use crate::util::mock_time;
    use crate::with_test_replica_logger;
    use ic_artifact_pool::ingress_pool::IngressPoolImpl;
    use ic_interfaces::artifact_pool::UnvalidatedArtifact;
    use ic_interfaces::ingress_pool::{IngressPool, MutableIngressPool};
    use ic_metrics::MetricsRegistry;

    #[test]
    fn test_artifact_pool_config() {
        with_test_replica_logger(|log| {
            with_test_pool_config(|pool_config| {
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool = IngressPoolImpl::new(pool_config, metrics_registry, log);
                assert_eq!(ingress_pool.unvalidated().size(), 0);
                for _ in 1..1024u64 {
                    let ingress_msg = SignedIngressBuilder::new()
                        .sign_for_randomly_generated_sender()
                        .build();
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg,
                        peer_id: node_test_id(0),
                        timestamp: mock_time(),
                    })
                }
                assert_eq!(ingress_pool.unvalidated().size(), 1023);
            })
        });
    }
}
