#![allow(dead_code)]
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ic_crypto_utils_threshold_sig_der::{
    parse_threshold_sig_key_from_pem_file, threshold_sig_public_key_to_der,
};

use crate::internet_computer::{IC_REGISTRY_LOCAL_STORE_PATH, IC_ROOT_PUB_KEY_PATH};

/// Provides a strongly typed view for a state directory as prepared by ic-prep.
#[derive(Clone, Debug)]
pub struct IcPrepStateDir {
    pub prep_dir: PathBuf,
}

impl IcPrepStateDir {
    pub fn new<P: AsRef<Path>>(p: P) -> Self {
        IcPrepStateDir {
            prep_dir: PathBuf::from(p.as_ref()),
        }
    }

    pub fn registry_local_store_path(&self) -> PathBuf {
        self.join(IC_REGISTRY_LOCAL_STORE_PATH)
    }

    /// DER-encoded root public key.
    pub fn root_public_key(&self) -> Result<Vec<u8>> {
        let path = self.root_public_key_path();
        let pk = parse_threshold_sig_key_from_pem_file(&path)
            .with_context(|| format!("failed to parse threshold sig key from {:?}", path))?;
        threshold_sig_public_key_to_der(pk)
            .with_context(|| "failed to convert threshold sig public key to DER")
    }

    /// Returns the path to the PEM-encoded root public key.
    pub fn root_public_key_path(&self) -> PathBuf {
        // nns public key is a misnomer.
        self.join(IC_ROOT_PUB_KEY_PATH)
    }

    fn join(&self, part: &str) -> PathBuf {
        self.prep_dir.join(part)
    }

    pub fn path(&self) -> PathBuf {
        self.prep_dir.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internet_computer::{IcConfig, TopologyConfig};
    use crate::node::{NodeConfiguration, NodeIndex};
    use crate::subnet_configuration::{SubnetConfig, SubnetRunningState};
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    use ic_registry_subnet_type::SubnetType;
    use ic_types::ReplicaVersion;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn root_subnet_key_exists() {
        let (_tmp_dir, ic_prep_state_dir) = init_ic().unwrap();

        assert!(ic_prep_state_dir.root_public_key_path().is_file());
    }

    #[test]
    fn registry_local_store_exists() {
        let (_tmp_dir, ic_prep_state_dir) = init_ic().unwrap();

        assert!(ic_prep_state_dir.registry_local_store_path().is_dir());
    }

    #[test]
    fn root_subnet_key_parseable() {
        let (_tmp_dir, ic_prep_state_dir) = init_ic().unwrap();

        let pk = ic_prep_state_dir
            .root_public_key()
            .expect("Could not parse public key pem file.");
        assert!(parse_threshold_sig_key_from_der(&pk).is_ok());
    }

    fn init_ic() -> Result<(TempDir, IcPrepStateDir)> {
        let tmp = tempfile::Builder::new()
            .prefix("prep-test")
            .tempdir()
            .unwrap();

        let mut subnet_nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();
        subnet_nodes.insert(
            0,
            NodeConfiguration {
                xnet_api: SocketAddr::from_str("1.2.3.4:8080").unwrap(),
                public_api: SocketAddr::from_str("1.2.3.4:8081").unwrap(),
                node_operator_principal_id: None,
                secret_key_store: None,
                domain: None,
                node_reward_type: None,
            },
        );

        let mut topology_config = TopologyConfig::default();
        topology_config.insert_subnet(
            0,
            SubnetConfig::new(
                0,
                subnet_nodes,
                ReplicaVersion::default(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                SubnetType::System,
                None,
                None,
                None,
                None,
                None,
                None,
                vec![],
                vec![],
                SubnetRunningState::Active,
                None,
            ),
        );

        let ic_config = IcConfig::new(
            /* target_dir= */ tmp.path(),
            topology_config,
            ReplicaVersion::default(),
            /* generate_subnet_records= */ true, // see note above
            /* nns_subnet_index= */ Some(0),
            /* release_package_download_url= */ None,
            /* release_package_sha256_hex */ None,
            /* guest_launch_measurements */ None,
            /* provisional_whitelist */ None,
            /* initial_node_operator */ None,
            /* initial_node_provider */ None,
            /* ssh_readonly_access_to_unassigned_nodes */ vec![],
        );
        let _init_ic = ic_config.initialize()?;

        let prep_state_dir = IcPrepStateDir::new(tmp.path());
        Ok((tmp, prep_state_dir))
    }
}
