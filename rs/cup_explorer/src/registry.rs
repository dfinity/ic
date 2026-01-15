use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_pem_file;
use ic_interfaces_registry::{
    RegistryClient, RegistryClientVersionedResult, RegistryVersionedRecord,
};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::node::NodeRecord;
use ic_registry_keys::{make_node_record_key, make_subnet_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{
    NodeId, PrincipalId, RegistryVersion, SubnetId, Time, registry::RegistryClientError,
};
use prost::Message;
use std::{io::Write, path::PathBuf, sync::Arc, thread};
use tempfile::NamedTempFile;
use tokio::{runtime::Runtime, task};
use url::Url;

/// A wrapper struct allowing us to implement the [RegistryClient] interface for [RegistryCanister].
pub(crate) struct RegistryCanisterClient(Arc<RegistryCanister>);

impl RegistryCanisterClient {
    /// Create a new [RegistryCanisterClient]
    pub fn new(nns_url: Url, nns_pem: Option<PathBuf>) -> RegistryCanisterClient {
        let mut temp = NamedTempFile::new().unwrap();
        let nns_pem_path = nns_pem.unwrap_or_else(|| {
            println!("Using mainnet NNS public key.");
            let pem_bytes: &[u8] = include_bytes!("../ic_public_key.pem");
            // Write public keys to a temp file, because `parse_threshold_sig_key` expects a file path
            temp.write_all(pem_bytes).unwrap();
            temp.path().into()
        });

        let content = std::fs::read_to_string(nns_pem_path.as_path()).unwrap();
        println!("NNS public key being used: \n{content}");

        let nns_public_key = parse_threshold_sig_key_from_pem_file(nns_pem_path.as_path()).unwrap();

        RegistryCanisterClient(Arc::new(RegistryCanister::new_with_agent_transformer(
            vec![nns_url],
            |a| a.with_nns_public_key(nns_public_key),
        )))
    }
}

impl RegistryClient for RegistryCanisterClient {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        println!("Getting registry value of key {key} at version {version}...");

        let canister = self.0.clone();
        let key_bytes = key.as_bytes().to_vec();

        let join_handle = thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(canister.get_value_with_update(key_bytes, Some(version.get())))
        });

        let result = join_handle.join().unwrap();
        result
            .map(|(val, version)| RegistryVersionedRecord {
                key: key.to_string(),
                version: version.into(),
                value: Some(val),
            })
            .map_err(|err| RegistryClientError::DecodeError {
                error: err.to_string(),
            })
    }

    fn get_key_family(
        &self,
        _key_prefix: &str,
        _version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        unimplemented!()
    }

    fn get_latest_version(&self) -> RegistryVersion {
        let canister = self.0.clone();
        let join_handle = thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(canister.get_latest_version())
        });
        let result = join_handle.join().unwrap();
        RegistryVersion::from(result.unwrap_or_default())
    }

    fn get_version_timestamp(&self, _registry_version: RegistryVersion) -> Option<Time> {
        unimplemented!()
    }
}

/// Returns the list of nodes assigned to the specified subnet_id at the latest registry version.
pub(crate) async fn get_nodes(
    registry_canister: &Arc<RegistryCanister>,
    subnet_id: SubnetId,
) -> Vec<(NodeId, NodeRecord)> {
    let (subnet_record, version) = registry_canister
        .get_value(make_subnet_record_key(subnet_id).as_bytes().to_vec(), None)
        .await
        .expect("failed to fetch the list of nodes");

    let subnet = SubnetRecord::decode(&subnet_record[..]).expect("failed to decode subnet record");

    let futures: Vec<_> = subnet
        .membership
        .into_iter()
        .map(|n| {
            let registry_canister = Arc::clone(registry_canister);
            task::spawn(async move {
                let node_id = NodeId::from(PrincipalId::try_from(&n[..]).unwrap());
                let (node_record_bytes, _) = registry_canister
                    .get_value(
                        make_node_record_key(node_id).as_bytes().to_vec(),
                        Some(version),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("failed to get node record {node_id}: {e}"));
                let record = NodeRecord::decode(&node_record_bytes[..])
                    .unwrap_or_else(|e| panic!("failed to deserialize node record {node_id}: {e}"));
                (node_id, record)
            })
        })
        .collect();

    let mut results = Vec::new();
    for f in futures {
        results.push(f.await.unwrap());
    }
    results
}
