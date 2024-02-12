use std::{
    collections::BTreeMap,
    convert::TryFrom,
    path::{Path, PathBuf},
};

use ic_management_canister_types::EcdsaKeyId;
use ic_protobuf::registry::{
    crypto::v1::{EcdsaSigningSubnetList, PublicKey},
    subnet::v1::{CatchUpPackageContents, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_ecdsa_signing_subnet_list_key, make_subnet_record_key,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::{subnet_id_into_protobuf, RegistryVersion, SubnetId};

use crate::{node::InitializedNode, util::write_registry_entry};
use crate::{
    node::NodeIndex,
    subnet_configuration::{InitializeSubnetError, SubnetConfig},
};

/// Represents a subnet for which all initial state (node crypto keys, initial
/// dkg transcript) was generated.
#[derive(Clone, Debug)]
pub struct InitializedSubnet {
    pub subnet_index: u64,

    pub subnet_id: SubnetId,

    pub initialized_nodes: BTreeMap<NodeIndex, InitializedNode>,

    pub subnet_record: SubnetRecord,

    pub subnet_dkg: CatchUpPackageContents,

    pub subnet_threshold_signing_public_key: PublicKey,

    pub subnet_path: PathBuf,

    pub subnet_config: SubnetConfig,
}

impl InitializedSubnet {
    /// Writes registry entries belonging to this subnetwork into the provided
    /// ProtoRegistryDataProvider. Further, for each registry entry, a
    /// corresponding file is generated with the same key as the registry entry
    /// and the value as its content.
    pub fn write_registry_entries(
        &self,
        data_provider: &ProtoRegistryDataProvider,
        version: RegistryVersion,
        // Since this tool heavily mixes data handling and data persistence
        // we pass this argument here to ensure no subnet record is written
        // if instructed. Thus, if this is false, the function writes only
        // the the node records.
        generate_subnet_records: bool,
    ) -> Result<(), InitializeSubnetError> {
        let subnet_id = self.subnet_id;
        let subnet_path = self.subnet_path.clone();

        if generate_subnet_records {
            // set subnet record
            write_registry_entry(
                data_provider,
                subnet_path.as_path(),
                make_subnet_record_key(subnet_id).as_ref(),
                version,
                self.subnet_record.clone(),
            );

            // set subnet dkg transcripts
            write_registry_entry(
                data_provider,
                subnet_path.as_path(),
                make_catch_up_package_contents_key(subnet_id).as_ref(),
                version,
                self.subnet_dkg.clone(),
            );

            // set subnet threshold signing public key
            write_registry_entry(
                data_provider,
                subnet_path.as_path(),
                make_crypto_threshold_signing_pubkey_key(subnet_id).as_ref(),
                version,
                self.subnet_threshold_signing_public_key.clone(),
            );

            // set subnet ecdsa signing key
            if let Some(ecdsa_config) = &self.subnet_config.ecdsa_config {
                for key_id in ecdsa_config.key_ids.iter() {
                    let key_id = EcdsaKeyId::try_from(key_id.clone())
                        .unwrap_or_else(|err| panic!("Invalid key_id {}", err));
                    write_registry_entry(
                        data_provider,
                        subnet_path.as_path(),
                        make_ecdsa_signing_subnet_list_key(&key_id).as_ref(),
                        version,
                        EcdsaSigningSubnetList {
                            subnets: vec![subnet_id_into_protobuf(subnet_id)],
                        },
                    );
                }
            }
        }

        for init_node in self.initialized_nodes.values() {
            init_node.write_registry_entries(data_provider, version)?;
        }

        Ok(())
    }

    pub fn build_node_path<P: AsRef<Path>>(base_path: P, node_index: NodeIndex) -> PathBuf {
        PathBuf::from(base_path.as_ref()).join(format!("node-{}", node_index))
    }
}
