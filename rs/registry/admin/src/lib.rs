use ic_base_types::{PrincipalId, SubnetId};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_protobuf::registry::routing_table::v1::{
    RoutingTable, routing_table::Entry as RoutingTableEntry,
};
use ic_protobuf::types::v1 as pb;
use ic_registry_client::client::RegistryClient;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_keys::CANISTER_RANGES_PREFIX;
use ic_registry_local_store::{KeyMutation, LocalStoreImpl, LocalStoreWriter};
use ic_registry_nns_data_provider_wrappers::NnsDataProvider;
use ic_registry_routing_table::CanisterIdRange;
use ic_types::RegistryVersion;
use ic_types::subnet_id_try_from_protobuf;
use prost::Message;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

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

pub fn get_routing_table(
    nns_urls: Vec<Url>,
    registry_version: Option<RegistryVersion>,
) -> (Vec<(CanisterIdRange, SubnetId)>, RegistryVersion) {
    let registry_client = RegistryClientImpl::new(
        Arc::new(NnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
        )),
        None,
    );

    registry_client
        .try_polling_latest_version(usize::MAX)
        .unwrap();

    let version = registry_version.unwrap_or_else(|| registry_client.get_latest_version());

    let keys = registry_client
        .get_key_family(CANISTER_RANGES_PREFIX, version)
        .unwrap();

    let routing_table = keys
        .iter()
        .flat_map(|key| {
            let value = registry_client
                .get_versioned_value(key, version)
                .unwrap()
                .value
                .unwrap();
            let routing_table = RoutingTable::decode(&value[..]).unwrap();
            routing_table.entries
        })
        .map(|RoutingTableEntry { range, subnet_id }| {
            let subnet_id = subnet_id_try_from_protobuf(
                subnet_id.expect("subnet_id is missing from routing table entry"),
            )
            .unwrap();
            let range = CanisterIdRange::try_from(
                range.expect("range is missing from routing table entry"),
            )
            .expect("failed to parse range");
            (range, subnet_id)
        })
        .collect();
    (routing_table, version)
}
