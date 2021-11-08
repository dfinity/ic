//! Tests for Local CSP Server

use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::LocalCspServer;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use std::sync::Arc;

// CRP-1223: extend the following test
#[test]
#[should_panic(
    expected = "The node secret-key-store and the canister secret-key-store must use different files"
)]
fn should_panic_if_sks_and_csks_coincide() {
    let temp_dir = mk_temp_dir_with_permissions(0o700);
    let temp_file = "temp_sks_data.pb";

    let sks = ProtoSecretKeyStore::open(temp_dir.path(), temp_file, None);
    let csks = ProtoSecretKeyStore::open(temp_dir.path(), temp_file, None);

    LocalCspServer::new(sks, csks, Arc::new(CryptoMetrics::none()), no_op_logger());
}
