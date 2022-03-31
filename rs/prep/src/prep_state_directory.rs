#![allow(dead_code)]
use std::{
    fmt, io,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

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
        parse_threshold_sig_key(self.root_public_key_path())
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

fn parse_threshold_sig_key<P: AsRef<Path> + fmt::Debug>(pem_file: P) -> Result<Vec<u8>> {
    fn invalid_data_err(msg: impl std::string::ToString) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
    }

    let buf =
        std::fs::read(&pem_file).with_context(|| format!("failed to read from {:?}", &pem_file))?;
    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<_> = s.trim_end().lines().collect();
    let n = lines.len();

    if n < 3 {
        bail!("input file is too short: {:?}", &pem_file);
    }

    if !lines[0].starts_with("-----BEGIN PUBLIC KEY-----") {
        bail!(
            "PEM file doesn't start with BEGIN PK block: {:?}",
            &pem_file
        );
    }
    if !lines[n - 1].starts_with("-----END PUBLIC KEY-----") {
        bail!("PEM file doesn't end with END PK block: {:?}", &pem_file);
    }

    let decoded = base64::decode(&lines[1..n - 1].join(""))
        .with_context(|| format!("failed to decode base64 from: {:?}", &pem_file))?;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internet_computer::{IcConfig, TopologyConfig};
    use crate::node::{NodeConfiguration, NodeIndex};
    use crate::subnet_configuration::SubnetConfig;
    use ic_crypto::threshold_sig_public_key_from_der;
    use ic_registry_subnet_type::SubnetType;
    use std::collections::BTreeMap;
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
        assert!(threshold_sig_public_key_from_der(&pk).is_ok());
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
                xnet_api: vec!["http://1.2.3.4:1".parse()?],
                public_api: vec!["http://1.2.3.4:2".parse()?],
                private_api: vec![],
                prometheus_metrics: vec!["http://1.2.3.4:3".parse()?],
                p2p_addr: "org.internetcomputer.p2p1://1.2.3.4:4".parse()?,
                p2p_num_flows: 1,
                p2p_start_flow_tag: 0,
                node_operator_principal_id: None,
                no_idkg_key: false,
                secret_key_store: None,
            },
        );

        let mut topology_config = TopologyConfig::default();
        topology_config.insert_subnet(
            0,
            SubnetConfig::new(
                0,
                subnet_nodes,
                None,
                None,
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
                vec![],
                vec![],
            ),
        );

        let ic_config = IcConfig::new(
            /* target_dir= */ tmp.path(),
            topology_config,
            /* replica_version_id= */ None,
            /* generate_subnet_records= */ true, // see note above
            /* nns_subnet_index= */ Some(0),
            /* release_package_download_url= */ None,
            /* release_package_sha256_hex */ None,
            None,
            None,
            None,
            /* ssh_readonly_access_to_unassigned_nodes */ vec![],
        );
        let _init_ic = ic_config.initialize()?;
        let prep_state_dir = IcPrepStateDir::new(tmp.path());
        Ok((tmp, prep_state_dir))
    }
}
