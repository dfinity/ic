//! The prep allows an operator to generate a `registry.proto` based on a
//! set of ip-addresses of a subnetwork.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use reqwest::blocking::ClientBuilder;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::{Node, NodeConfiguration, NodeIndex},
    subnet_configuration::{SubnetConfig, SubnetIndex, SubnetRunningState},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, PrincipalId, ReplicaVersion};

/// the filename of the update disk image, as published on the cdn
const UPD_IMG_FILENAME: &str = "update-img.tar.zst";
/// in case the replica version id is specified on the command line, but not the
/// release package url and hash, the following url-template will be used to
/// fetch the sha256 of the corresponding image.
const UPD_IMG_DEFAULT_SHA256_URL: &str =
    "https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img-dev/SHA256SUMS";
/// in case the replica version id is specified on the command line, but not the
/// release package url and hash, the following url-template will be used to
/// specify the update image.
const UPD_IMG_DEFAULT_URL: &str =
    "https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img-dev/update-img.tar.zst";
const CDN_HTTP_ATTEMPTS: usize = 3;
const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Parser)]
#[clap(name = "ic-prep")]
/// Prepare initial files for an Internet Computer instance.
///
/// See the README.adoc file for more details.
struct CliArgs {
    /// The version of the Replica being run
    #[clap(long, parse(try_from_str = ReplicaVersion::try_from))]
    pub replica_version: Option<ReplicaVersion>,

    /// The URL against which a HTTP GET request will return a release
    /// package that corresponds to this version.
    ///
    /// If replica-version is specified and both release-package-download-url
    /// and release-package-sha256-hex are unspecified, the
    /// release-package-download-url will default to
    /// https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img/update-img.tar.zst
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub release_package_download_url: Option<Url>,

    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_url'. Must be present if release_package_url is
    /// present.
    ///
    /// If replica-version is specified and both release-package-download-url
    /// and release-package-sha256-hex are unspecified, the
    /// release-package-download-url will downloaded from
    /// https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img-dev/SHA256SUMS
    #[clap(long)]
    pub release_package_sha256_hex: Option<String>,

    /// JSON5 node definition
    #[clap(long = "node", group = "node_spec", multiple_values(true), parse(try_from_str = Node::from_json5_without_braces))]
    pub nodes: Vec<Node>,

    /// Path to working directory for node states.
    #[clap(long, parse(from_os_str))]
    pub working_dir: PathBuf,

    /// Skip generating subnet records
    #[clap(long)]
    pub no_subnet_records: bool,

    /// The index of the subnet that should act as NNS subnet, if any.
    #[clap(long)]
    pub nns_subnet_index: Option<u64>,

    /// Reads a directory containing datacenter's DER keys and a "meta.json"
    /// file containing metainformation for each datacenter.
    #[clap(long, parse(from_os_str))]
    pub dc_pk_path: Option<PathBuf>,

    /// Indicate whether each node operator entry is required to specify a file
    /// that contains the node provider public key of the corresponding node
    /// provider.
    #[clap(long)]
    pub require_node_provider_key: bool,

    /// DKG interval length
    /// Negative integer means the default should be used.
    #[clap(long, allow_hyphen_values = true)]
    pub dkg_interval_length: Option<i64>,

    /// A json-file containing a list of whitelisted principal IDs. A
    /// whitelisted principal is allowed to create canisters on any subnet on
    /// the IC.
    #[clap(long, parse(from_os_str))]
    pub provisional_whitelist: Option<PathBuf>,

    /// The Principal Id of the node operator that is used for all nodes created
    /// in the initial (!) registry. Note that this is unrelated to the node
    /// operators that are specified via the `dc-pk-path`-option. The latter are
    /// used to add new node _after_ the IC has been initialized/bootstrapped.
    #[clap(long)]
    pub initial_node_operator: Option<PrincipalId>,

    /// If an initial node operator is provided, this is the Principal Id that
    /// is set as the node provider of that node operator.
    #[clap(long)]
    pub initial_node_provider: Option<PrincipalId>,

    /// The path to the file which contains the initial set of SSH public keys
    /// to populate the registry with, to give "readonly" access to all the
    /// nodes.
    #[clap(long, parse(from_os_str))]
    pub ssh_readonly_access_file: Option<PathBuf>,

    /// The path to the file which contains the initial set of SSH public keys
    /// to populate the registry with, to give "backup" access to all the
    /// nodes.
    #[clap(long, parse(from_os_str))]
    pub ssh_backup_access_file: Option<PathBuf>,

    /// Maximum size of ingress message in bytes.
    /// Negative integer means the default should be used.
    #[clap(long, allow_hyphen_values = true)]
    pub max_ingress_bytes_per_message: Option<i64>,

    /// Maximum size of a block payload in bytes.
    #[clap(long)]
    pub max_block_payload_size: Option<u64>,

    /// if release-package-download-url is not specified and this option is
    /// specified, the corresponding update image field in the blessed replica
    /// version record is left empty.
    #[clap(long)]
    pub allow_empty_update_image: bool,

    /// Whether or not to assign canister ID allocation range for specified IDs to subnet.
    /// Used only for local and testnet replicas.
    #[clap(long)]
    use_specified_ids_allocation_range: bool,

    /// Whitelisted firewall prefixes for initial registry state, separated by
    /// commas.
    #[clap(long)]
    whitelisted_prefixes: Option<String>,

    /// Whitelisted ports for the firewall prefixes, separated by
    /// commas. Port 8080 is always included.
    #[clap(long)]
    whitelisted_ports: Option<String>,
}

fn main() -> Result<()> {
    let mut valid_args = CliArgs::parse().validate()?;

    // set replica update image if necessary
    if let Some(ref replica_version_id) = valid_args.replica_version_id {
        if !valid_args.allow_empty_update_image && valid_args.release_package_download_url.is_none()
        {
            let url = Url::parse(
                &UPD_IMG_DEFAULT_URL.replace("<REPLICA_VERSION>", replica_version_id.as_ref()),
            )?;
            valid_args.release_package_download_url = Some(url);
            valid_args.release_package_sha256_hex =
                Some(fetch_replica_version_sha256(replica_version_id.clone())?);
        }
    }

    let replica_version = valid_args.replica_version_id.unwrap_or_default();
    let root_subnet_idx = valid_args.nns_subnet_index.unwrap_or(0);
    let mut topology_config = TopologyConfig::default();
    for (i, (subnet_id, nodes)) in valid_args.subnets.iter().enumerate() {
        let subnet_type = if i as u64 == root_subnet_idx {
            SubnetType::System
        } else {
            SubnetType::Application
        };

        let subnet_configuration = SubnetConfig::new(
            *subnet_id,
            nodes.to_owned(),
            replica_version.clone(),
            valid_args.max_ingress_bytes_per_message,
            /*max_ingress_messages_per_block=*/ None,
            valid_args.max_block_payload_size,
            /*unit_delay=*/ None,
            /*initial_notary_delay=*/ None,
            valid_args.dkg_interval_length,
            /*dkg_dealings_per_block=*/ None,
            subnet_type,
            /*max_instructions_per_message=*/ None,
            /*max_instructions_per_round=*/ None,
            /*max_instructions_per_install_code=*/ None,
            /*features=*/ None,
            /*chain_key_config=*/ None,
            /*max_number_of_canisters=*/ None,
            valid_args.ssh_readonly_access.clone(),
            valid_args.ssh_backup_access.clone(),
            SubnetRunningState::Active,
            None,
        );
        topology_config.insert_subnet(*subnet_id, subnet_configuration);
    }
    for (n_idx, nc) in valid_args.unassigned_nodes.iter() {
        topology_config.insert_unassigned_node(*n_idx, nc.clone())
    }
    let mut ic_config0 = IcConfig::new(
        valid_args.working_dir.as_path(),
        topology_config,
        replica_version,
        valid_args.generate_subnet_records,
        Some(root_subnet_idx),
        valid_args.release_package_download_url,
        valid_args.release_package_sha256_hex,
        valid_args.provisional_whitelist,
        valid_args.initial_node_operator,
        valid_args.initial_node_provider,
        valid_args.ssh_readonly_access,
    );

    ic_config0
        .set_use_specified_ids_allocation_range(valid_args.use_specified_ids_allocation_range);
    ic_config0.set_whitelisted_prefixes(valid_args.whitelisted_prefixes);
    ic_config0.set_whitelisted_ports(valid_args.whitelisted_ports);

    let ic_config = match valid_args.dc_pk_dir {
        Some(dir) => ic_config0.load_registry_node_operator_records_from_dir(
            &dir,
            valid_args.require_node_provider_key,
        )?,
        None => ic_config0,
    };

    let _ = ic_config.initialize()?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedArgs {
    pub working_dir: PathBuf,
    pub replica_version_id: Option<ReplicaVersion>,
    pub release_package_download_url: Option<Url>,
    pub release_package_sha256_hex: Option<String>,
    pub subnets: BTreeMap<SubnetIndex, BTreeMap<NodeIndex, NodeConfiguration>>,
    pub unassigned_nodes: BTreeMap<NodeIndex, NodeConfiguration>,
    pub generate_subnet_records: bool,
    pub nns_subnet_index: Option<u64>,
    pub dc_pk_dir: Option<PathBuf>,
    pub require_node_provider_key: bool,
    pub dkg_interval_length: Option<Height>,
    pub provisional_whitelist: Option<ProvisionalWhitelist>,
    pub initial_node_operator: Option<PrincipalId>,
    pub initial_node_provider: Option<PrincipalId>,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,
    pub max_ingress_bytes_per_message: Option<u64>,
    pub max_block_payload_size: Option<u64>,
    pub allow_empty_update_image: bool,
    pub use_specified_ids_allocation_range: bool,
    pub whitelisted_prefixes: Option<String>,
    pub whitelisted_ports: Option<String>,
}

impl CliArgs {
    fn validate(self) -> Result<ValidatedArgs> {
        let working_dir = self.working_dir;
        if !working_dir.is_dir() {
            bail!("working directory not found at: {:?}", working_dir);
        }

        // check whether state_dir is writeable
        if working_dir.metadata()?.permissions().readonly() {
            bail!("cannot write working directory at: {:?}", working_dir);
        }

        let mut unassigned_nodes: BTreeMap<_, _> = Default::default();
        let mut node_idx_set: BTreeSet<_> = Default::default();
        let mut subnets: BTreeMap<SubnetIndex, BTreeMap<NodeIndex, NodeConfiguration>> =
            BTreeMap::new();

        for (
            i,
            Node {
                idx: node_index,
                subnet_idx: subnet_index,
                config,
            },
        ) in self.nodes.iter().enumerate()
        {
            if !node_idx_set.insert(node_index) {
                bail!("the {}'th entry repeats the node index {}", i, node_index);
            }
            let config = config.clone();

            if let Some(subnet_index) = subnet_index {
                subnets
                    .entry(*subnet_index)
                    .or_default()
                    .insert(*node_index, config);
            } else {
                unassigned_nodes.insert(*node_index, config);
            }
        }

        if self
            .nns_subnet_index
            .map(|idx| !subnets.contains_key(&idx))
            .unwrap_or(false)
        {
            bail!(
                "NNS subnet index {} does not match any of subnet indices {:?}",
                self.nns_subnet_index.unwrap(),
                subnets.keys().collect::<Vec<_>>()
            );
        }

        let dc_pk_path = match self.dc_pk_path {
            Some(dir) => {
                if !dir.is_dir() {
                    bail!(
                        "directory {} for DC configuration doesn't exist",
                        dir.display()
                    );
                }
                Some(dir)
            }
            None => None,
        };

        let provisional_whitelist = match self.provisional_whitelist {
            Some(path) => {
                let whitelist_contents: ProvisionalWhitelistFile = load_json(&path)?;

                // If the provisional whitelist is set to the wildcard "*", then all principals
                // should be whitelisted.
                if whitelist_contents.provisional_whitelist == vec!["*"] {
                    Some(ProvisionalWhitelist::All)
                } else {
                    let whitelist = whitelist_contents
                        .provisional_whitelist
                        .iter()
                        .map(|s| {
                            PrincipalId::from_str(s)
                                .with_context(|| format!("could not convert {} to principal", s))
                        })
                        .collect::<Result<BTreeSet<PrincipalId>>>()?;

                    Some(ProvisionalWhitelist::Set(whitelist))
                }
            }
            None => None,
        };

        match (
            &self.release_package_download_url,
            &self.release_package_sha256_hex,
        ) {
            (Some(_), None) => bail!(
                "Missing release package sha256 hex when release package download url is given"
            ),
            (None, Some(_)) => {
                bail!("Missing release download url when release package sha256 hex is given")
            }
            _ => (),
        }

        Ok(ValidatedArgs {
            working_dir,
            replica_version_id: self.replica_version,
            release_package_download_url: self.release_package_download_url,
            release_package_sha256_hex: self.release_package_sha256_hex,
            subnets,
            unassigned_nodes,
            generate_subnet_records: !self.no_subnet_records,
            nns_subnet_index: self.nns_subnet_index,
            dc_pk_dir: dc_pk_path,
            require_node_provider_key: self.require_node_provider_key,
            dkg_interval_length: self.dkg_interval_length.and_then(|x| {
                if x >= 0 {
                    Some(Height::from(x as u64))
                } else {
                    None
                }
            }),
            provisional_whitelist,
            initial_node_operator: self.initial_node_operator,
            initial_node_provider: self.initial_node_provider,
            ssh_readonly_access: self
                .ssh_readonly_access_file
                .map_or(vec![], read_keys_from_pub_file),
            ssh_backup_access: self
                .ssh_backup_access_file
                .map_or(vec![], read_keys_from_pub_file),
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message.and_then(|x| {
                if x >= 0 {
                    Some(x as u64)
                } else {
                    None
                }
            }),
            max_block_payload_size: self.max_block_payload_size,
            allow_empty_update_image: self.allow_empty_update_image,
            use_specified_ids_allocation_range: self.use_specified_ids_allocation_range,
            whitelisted_prefixes: self.whitelisted_prefixes,
            whitelisted_ports: self.whitelisted_ports,
        })
    }
}

fn read_keys_from_pub_file(filename: PathBuf) -> Vec<String> {
    let mut keys = Vec::<String>::new();
    if let Ok(file) = fs::File::open(filename.clone()) {
        for line in io::BufReader::new(file).lines() {
            match line {
                Ok(key) => keys.push(key),
                Err(e) => eprintln!(
                    "Error while reading a key from {}: {}",
                    filename.as_path().display(),
                    e
                ),
            }
        }
        keys
    } else {
        vec![]
    }
}

/// Loads JSON or JSON5 from `path` in to a struct of type `T`.
fn load_json<T: DeserializeOwned, P: AsRef<Path> + Copy>(path: P) -> Result<T> {
    let json = fs::read_to_string(path)?;
    let res = json5::from_str(&json)?;
    Ok(res)
}

/// List of whitelisted principal ids.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct ProvisionalWhitelistFile {
    pub provisional_whitelist: Vec<String>,
}

fn fetch_replica_version_sha256(version_id: ReplicaVersion) -> Result<String> {
    let url = UPD_IMG_DEFAULT_SHA256_URL.replace("<REPLICA_VERSION>", version_id.as_ref());
    let url = Url::parse(&url)?;
    let c = ClientBuilder::new().timeout(REQUEST_TIMEOUT).build()?;

    let send_req = || c.get(url.clone()).send();

    let mut attempts = CDN_HTTP_ATTEMPTS;
    let resp = loop {
        match send_req() {
            Ok(resp) => break resp,
            Err(e) if attempts < 1 => {
                bail!(
                    "timed out fetching SHA256 value for version id: {}. error: {:?}",
                    version_id,
                    e
                )
            }
            _ => std::thread::sleep(RETRY_BACKOFF),
        }
        attempts -= 1;
    };

    let contents = resp.text()?;
    for line in contents.lines() {
        let words: Vec<&str> = line.split(char::is_whitespace).collect();
        if words.len() == 2 && words[1].ends_with(UPD_IMG_FILENAME) {
            return Ok(words[0].to_string());
        }
    }

    bail!("SHA256 hash is not found at: {}. Make sure the file is downloadable and contains an entry for {}", url, UPD_IMG_FILENAME);
}

#[cfg(test)]
mod test_flag_node_parser {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    const GOOD_FLAG: &str = r#"idx:1,subnet_idx:2,xnet_api:"1.2.3.4:81",public_api:"3.4.5.6:82""#;

    /// Verifies that a good flag parses correctly
    #[test]
    fn valid_flag() {
        let got = Node::from_json5_without_braces(GOOD_FLAG).unwrap();
        let want = Node {
            idx: 1,
            subnet_idx: Some(2),
            config: NodeConfiguration {
                xnet_api: "1.2.3.4:81".parse().unwrap(),
                public_api: "3.4.5.6:82".parse().unwrap(),
                node_operator_principal_id: None,
                secret_key_store: None,
            },
        };

        assert_eq!(got, want);
    }

    /// Verifies that flags with missing fields return an Err
    #[test]
    fn missing_fields() {
        // Each flag variant omits a field, starting with `idx`.
        let flags = vec![
            r#"subnet_idx:2,xnet_api:"1.2.3.4:81",public_api:"3.4.5.6:82""#,
            // Omitting subnet index yields an unassigned node.
            // r#"idx:1,xnet_api:"1.2.3.4:81",public_api:"3.4.5.6:82""#,
            r#"idx:1,subnet_idx:2,public_api:"3.4.5.6:82""#,
            r#"idx:1,subnet_idx:2,xnet_api:"1.2.3.4:81""#,
        ];

        for flag in flags {
            assert_matches!(Node::from_json5_without_braces(flag), Err(_));
        }
    }

    /// Verifies that unknown fields return an Err
    #[test]
    fn unknown_fields() {
        let flag = format!("new_field:0,{}", GOOD_FLAG);
        assert_matches!(Node::from_json5_without_braces(&flag), Err(_));
    }

    /// Verifies that the flag can roundrip through parsing
    #[test]
    fn roundtrip() {
        let node = Node::from_json5_without_braces(GOOD_FLAG).unwrap();
        let node_flag = node.to_string();

        let new_node = Node::from_json5_without_braces(&node_flag).unwrap();

        assert_eq!(node, new_node);
    }

    #[test]
    #[ignore] // side-effectful unit tests are ignored
    fn can_fetch_sha256() {
        let version_id =
            ReplicaVersion::try_from("963c47c0179fb302cb02b1e4712f51b14ea738b6").unwrap();
        assert_eq!(
            fetch_replica_version_sha256(version_id).unwrap(),
            "d081ffe20488380b4cf90069f3fc23e2fa4a904e4103d6f175c85ea87b2634b5"
        );
    }
}
