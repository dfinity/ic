use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_protobuf::types::v1 as pb;
use ic_registry_local_store::{LocalStoreImpl, LocalStoreWriter, KeyMutation};
use ic_base_types::{PrincipalId, SubnetId};
use ic_types::RegistryVersion;
use prost::Message;
use std::str::FromStr;
use std::path::Path;

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
            key: format!("crypto_threshold_signing_public_key_{}", SubnetId::from(nns_subnet_id)),
            value: Some(
                ic_protobuf::registry::crypto::v1::PublicKey::from(root_public_key)
                .encode_to_vec(),
            ),
        },
    ];

    // Apply the mutation.
    local_store.store(RegistryVersion::from(1), entry).unwrap();
}
