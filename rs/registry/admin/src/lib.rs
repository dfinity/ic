use ic_base_types::{PrincipalId, SubnetId};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_protobuf::types::v1 as pb;
use ic_registry_local_store::{KeyMutation, LocalStoreImpl, LocalStoreWriter};
use ic_types::RegistryVersion;
use prost::Message;
use std::path::Path;
use std::str::FromStr;

/// Populates a directory so that `ic-admin update-registry-local-store` can
/// populate it with data from the Registry canister.
///
/// # Arguments
///
/// `path` - Should be an empty directory, or a path that doesn't exist yet.
/// (Otherwise, behavior is not defined.)
///
/// `root_public_key` - For an example of a possible value that could be used
/// here, see [this code].
///
/// [this code]: https://github.com/dfinity/ic/pull/5029/files#r2086304186
///
/// # Misc Remarks
///
/// Currently, this is only used by test(s). Regardless, calling this from
/// non-test code is also acceptable.
pub fn initialize_registry_local_store(path: &Path, root_public_key: Vec<u8>) {
    let local_store = LocalStoreImpl::new(path);

    let nns_subnet_id = PrincipalId::from_str(
        // I got this from dashboard.internetcomputer.org.
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
    )
    .unwrap();

    let root_public_key = parse_threshold_sig_key_from_der(&root_public_key)
        .expect("Failed to decode mainnet public key.");

    // Composite mutation that inserts NNS subnet ID and ICP root public key
    // (into Registry local store).
    let entry = vec![
        KeyMutation {
            key: "nns_subnet_id".to_string(),
            value: Some(
                pb::SubnetId {
                    principal_id: Some(pb::PrincipalId::from(nns_subnet_id)),
                }
                .encode_to_vec(),
            ),
        },
        KeyMutation {
            key: format!(
                "crypto_threshold_signing_public_key_{}",
                SubnetId::from(nns_subnet_id)
            ),
            value: Some(
                ic_protobuf::registry::crypto::v1::PublicKey::from(root_public_key).encode_to_vec(),
            ),
        },
    ];

    // Apply the mutation.
    local_store.store(RegistryVersion::from(1), entry).unwrap();
}
