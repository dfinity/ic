use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_protobuf::types::v1 as pb;
use ic_registry_local_store::{LocalStoreImpl, LocalStoreWriter, KeyMutation};
use ic_base_types::{PrincipalId, SubnetId};
use ic_types::RegistryVersion;
use prost::Message;
use std::str::FromStr;

fn main() {
    let local_store = LocalStoreImpl::new("/Users/daniel.wong/Desktop/registry-local-store");

    let nns_subnet_id = PrincipalId::from_str(
        // I got this from dashboard.internetcomputer.org.
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
    )
    .unwrap();
    let root_public_key = {
        // I ripped this off from rs/registry/admin/src/main.rs.
        const IC_ROOT_PUBLIC_KEY_BASE64: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;
        let decoded_nns_mainnet_key = base64::decode(IC_ROOT_PUBLIC_KEY_BASE64)
            .expect("Failed to decode mainnet public key from base64.");
        parse_threshold_sig_key_from_der(&decoded_nns_mainnet_key)
            .expect("Failed to decode mainnet public key.")
    };

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
    local_store.store(RegistryVersion::from(1), entry).unwrap();

    println!("STORED!");
}
