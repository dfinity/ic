use ic_crypto_internal_csp::LocalCspVault;
use ic_crypto_internal_csp::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use ic_crypto_internal_csp::secret_key_store::memory_secret_key_store::InMemorySecretKeyStore;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use proptest::prelude::ProptestConfig;
use rand::rngs::OsRng;
use std::sync::Arc;
use tempfile::TempDir;

#[allow(unused)]
pub fn local_vault_in_temp_dir() -> (
    LocalCspVault<OsRng, ProtoSecretKeyStore, InMemorySecretKeyStore, ProtoPublicKeyStore>,
    TempDir,
) {
    use ic_config::crypto::CryptoConfig;

    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let local_vault = LocalCspVault::new_in_dir(
        &config.crypto_root,
        Arc::new(CryptoMetrics::none()),
        no_op_logger(),
    );
    (local_vault, _temp_dir)
}

#[allow(unused)]
pub fn proptest_config_for_delegation() -> ProptestConfig {
    ProptestConfig {
        //default uses FileFailurePersistence::SourceParallel which expects a main.rs or a lib.rs,
        //which does not work for a Rust integration test and results in a warning being printed.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}
