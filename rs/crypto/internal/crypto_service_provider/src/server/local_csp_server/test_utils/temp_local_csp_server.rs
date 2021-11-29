//! Utilities to test the local CSP vault.

use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use rand_core::OsRng;
use std::sync::Arc;
use tempfile::TempDir;

use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::LocalCspVault;

/// This local CSP vault has key stores in a newly created temporary directory,
/// which will exist for as long as the object stays in scope. As soon as the
/// object (or rather, the contained tempdir field) goes out of scope, the
/// created temporary directory will automatically be deleted.
pub struct TempLocalCspVault {
    pub vault: LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore>,
    #[allow(dead_code)]
    pub tempdir: TempDir,
}

impl TempLocalCspVault {
    pub fn new() -> Self {
        let sks_file = "temp_sks_data.pb";
        let canister_sks_file = "temp_canister_sks_data.pb";
        TempLocalCspVault::new_from_store_files(sks_file, canister_sks_file)
    }

    pub fn new_from_store_files(sks_file: &str, canister_sks_file: &str) -> Self {
        let temp_dir = mk_temp_dir_with_permissions(0o700);

        let sks = ProtoSecretKeyStore::open(temp_dir.path(), sks_file, None);
        let canister_sks = ProtoSecretKeyStore::open(temp_dir.path(), canister_sks_file, None);
        Self {
            vault: LocalCspVault::new(
                sks,
                canister_sks,
                Arc::new(CryptoMetrics::none()),
                no_op_logger(),
            ),
            tempdir: temp_dir,
        }
    }
}
