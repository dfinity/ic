//! The prep allows an operator to generate a `registry.proto` based on a
//! set of ip-addresses of a subnetwork.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt::Display,
    fs,
    io::{self, BufRead},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use reqwest::blocking::ClientBuilder;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::{NodeConfiguration, NodeIndex},
    subnet_configuration::{SubnetConfig, SubnetIndex},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, PrincipalId, ReplicaVersion};

/// the filename of the update disk image, as published on the cdn
const UPD_IMG_FILENAME: &str = "update-img.tar.gz";
/// in case the replica version id is specified on the command line, but not the
/// release package url and hash, the following url-template will be used to
/// fetch the sha256 of the corresponding image.
const UPD_IMG_DEFAULT_SHA256_URL: &str =
    "https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img/SHA256SUMS";
/// in case the replica version id is specified on the command line, but not the
/// release package url and hash, the following url-template will be used to
/// specify the update image.
const UPD_IMG_DEFAULT_URL: &str =
    "https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img/update-img.tar.gz";
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

    /// URL from which to download the replica binary
    ///
    /// deprecated.
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub replica_download_url: Option<Url>,

    /// sha256-hash of the replica binary in hex.
    ///
    /// deprecated.
    #[clap(long)]
    pub replica_hash: Option<String>,

    /// URL from which to download the orchestrator binary
    ///
    /// deprecated.
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub orchestrator_download_url: Option<Url>,

    /// sha256-hash of the orchestrator binary in hex.
    ///
    /// deprecated.
    #[clap(long)]
    pub orchestrator_hash: Option<String>,

    /// The URL against which a HTTP GET request will return a release
    /// package that corresponds to this version.
    ///
    /// If replica-version is specified and both release-package-download-url
    /// and release-package-sha256-hex are unspecified, the
    /// release-package-download-url will default to
    /// https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img/update-img.tar.gz
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub release_package_download_url: Option<Url>,

    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_url'. Must be present if release_package_url is
    /// present.
    ///
    /// If replica-version is specified and both release-package-download-url
    /// and release-package-sha256-hex are unspecified, the
    /// release-package-download-url will downloaded from
    /// https://download.dfinity.systems/ic/<REPLICA_VERSION>/guest-os/update-img/SHA256SUMS
    #[clap(long)]
    pub release_package_sha256_hex: Option<String>,

    /// List of tuples describing the nodes
    #[clap(long, parse(try_from_str = parse_nodes_deprecated), group = "node_spec", multiple_values(true))]
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

    /// if release-package-download-url is not specified and this option is
    /// specified, the corresponding update image field in the blessed replica
    /// version record is left empty.
    #[clap(long)]
    pub allow_empty_update_image: bool,

    /// The hex-formatted SHA-256 hash measurement of the SEV guest launch context.
    #[clap(long)]
    pub guest_launch_measurement_sha256_hex: Option<String>,

    /// Whether or not to assign canister ID allocation range for specified IDs to subnet.
    /// Used only for local and testnet replicas.
    #[clap(long = "use-specified-ids-allocation-range")]
    use_specified_ids_allocation_range: bool,

    /// Whitelisted firewall prefixes for initial registry state, separated by
    /// commas.
    #[clap(long = "whitelisted-prefixes")]
    whitelisted_prefixes: Option<String>,
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
            valid_args.replica_version_id.clone(),
            None,
            valid_args.max_ingress_bytes_per_message,
            None,
            None,
            None,
            None,
            valid_args.dkg_interval_length,
            None,
            subnet_type,
            None,
            None,
            None,
            None,
            None,
            None,
            valid_args.ssh_readonly_access.clone(),
            valid_args.ssh_backup_access.clone(),
        );
        topology_config.insert_subnet(*subnet_id, subnet_configuration);
    }
    for (n_idx, nc) in valid_args.unassigned_nodes.iter() {
        topology_config.insert_unassigned_node(*n_idx, nc.clone())
    }
    let mut ic_config0 = IcConfig::new(
        valid_args.working_dir.as_path(),
        topology_config,
        valid_args.replica_version_id,
        valid_args.generate_subnet_records,
        Some(root_subnet_idx),
        valid_args.release_package_download_url,
        valid_args.release_package_sha256_hex,
        valid_args.provisional_whitelist,
        valid_args.initial_node_operator,
        valid_args.initial_node_provider,
        valid_args.ssh_readonly_access,
        valid_args.guest_launch_measurement_sha256_hex,
    );

    ic_config0
        .set_use_specified_ids_allocation_range(valid_args.use_specified_ids_allocation_range);

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
    pub replica_download_url: Option<Url>,
    pub replica_hash: Option<String>,
    pub orchestrator_download_url: Option<Url>,
    pub orchestrator_hash: Option<String>,
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
    pub allow_empty_update_image: bool,
    pub guest_launch_measurement_sha256_hex: Option<String>,
    pub use_specified_ids_allocation_range: bool,
    pub whitelisted_prefixes: Option<String>,
}

/// Structured definition of a node provided by the `--nodes` flag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Node {
    /// Node index
    node_index: u64,

    /// Index of the subnet to add the node to. If the index is not set, the key
    /// material and registry entries for the node will be generated, but the
    /// node will not be added to a subnet.
    subnet_index: Option<u64>,

    /// The node's configuration
    config: NodeConfiguration,
}

/// Parse a --nodes flag value in to a Node.
///
/// This approach is deprecated -- it doesn't support specifying multiple
/// values for different endpoints, the protocols, and so on. It exists
/// for backwards compatbility with deployment tooling, and will be removed
/// when that has been updated.
// TODO(O4-43) Remove --nodes flag
fn parse_nodes_deprecated(src: &str) -> Result<Node> {
    // We allow for both, the comma (',') and dash ('-'), to be used as separators
    // of tuple components. The dash ('-') conflicts with using domain names
    // containing dashes in place of ip addresses.
    // TODO(RPL-255): The goal is to switch to commas (',') entirely, but we will
    // remain backwards compatible for the moment.
    let separator = if src.contains(',') { ',' } else { '-' };
    let parts = src.splitn(6, separator).collect::<Vec<&str>>();
    let node_index = parts[0].parse::<u64>().unwrap();

    let subnet_part = parts[1];
    let subnet_index = if subnet_part.is_empty() {
        None
    } else {
        Some(subnet_part.parse::<u64>().unwrap())
    };

    // For most endpoints default to `http` as the protocol, which is consistent
    // with existing behaviour for this flag.
    let xnet_addr: SocketAddr = parts[3]
        .parse()
        .with_context(|| format!("did not parse {} as SocketAddr", parts[3]))?;

    let http_addr: SocketAddr = parts[5]
        .parse()
        .with_context(|| format!("did not parse {} as SocketAddr", parts[5]))?;

    let p2p_addr: SocketAddr = parts[2]
        .parse()
        .with_context(|| format!("did not parse {} as SocketAddr", parts[2]))?;

    // chip_id is optional
    let mut chip_id = vec![];
    if parts.len() > 6 {
        chip_id = hex::decode(parts[6])?;
    }

    Ok(Node {
        node_index,
        subnet_index,
        config: NodeConfiguration {
            xnet_api: xnet_addr,
            public_api: http_addr,
            p2p_addr,
            node_operator_principal_id: None,
            secret_key_store: None,
            chip_id,
        },
    })
}

/// Values passed to the `--node` flag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct NodeFlag {
    idx: Option<u64>,
    subnet_idx: Option<u64>,
    pub xnet_api: Option<SocketAddr>,
    pub public_api: Option<SocketAddr>,
    /// The initial endpoint that P2P uses.
    pub p2p_addr: Option<SocketAddr>,
    pub chip_id: Option<Vec<u8>>,
}

#[derive(Error, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum MissingFieldError {
    #[error("idx")]
    NodeIndex,

    #[error("subnet_idx")]
    SubnetIndex,

    #[error("xnet")]
    Xnet,

    #[error("public_api")]
    PublicApi,

    #[error("p2p_addr")]
    P2PAddr,
}

impl Display for Node {
    /// Displays the node in a format that will be accepted by the `--node`
    /// flag.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "idx:{}", self.node_index)?;
        if let Some(subnet_index) = self.subnet_index {
            write!(f, ",subnet_idx:{}", subnet_index)?;
        }
        write!(f, r#",public_api:"{}""#, self.config.public_api)?;
        write!(f, r#",p2p_addr:"{}""#, self.config.p2p_addr)?;
        write!(f, r#",xnet_api:"{}""#, self.config.xnet_api)?;

        Ok(())
    }
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
                node_index,
                subnet_index,
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
                    .or_insert_with(BTreeMap::<_, _>::new)
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

        match (&self.replica_download_url, &self.replica_hash) {
            (Some(_), None) => {
                eprintln!("WARNING: missing replica hash when replica download url is given")
            }
            (None, Some(_)) => bail!("Missing replica download url when replica hash is given"),
            _ => (),
        }

        match (&self.orchestrator_download_url, &self.orchestrator_hash) {
            (Some(_), None) => eprintln!(
                "WARNING: missing orchestrator hash when orchestrator download url is given"
            ),
            (None, Some(_)) => {
                bail!("Missing orchestrator download url when orchestrator hash is given")
            }
            _ => (),
        }

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
            replica_hash: self.replica_hash,
            replica_version_id: self.replica_version,
            replica_download_url: self.replica_download_url,
            orchestrator_download_url: self.orchestrator_download_url,
            orchestrator_hash: self.orchestrator_hash,
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
            allow_empty_update_image: self.allow_empty_update_image,
            guest_launch_measurement_sha256_hex: self.guest_launch_measurement_sha256_hex,
            use_specified_ids_allocation_range: self.use_specified_ids_allocation_range,
            whitelisted_prefixes: self.whitelisted_prefixes,
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
mod test_flag_nodes_parser_deprecated {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Components separated by hyphens should parse correctly
    #[test]
    fn valid_nodes_hyphen() {
        let got = parse_nodes_deprecated("1-2-1.2.3.4:80-2.3.4.5:81-82-3.4.5.6:82").unwrap();
        let want = Node {
            node_index: 1,
            subnet_index: Some(2),
            config: NodeConfiguration {
                xnet_api: SocketAddr::from_str("2.3.4.5:81").unwrap(),
                public_api: SocketAddr::from_str("3.4.5.6:82").unwrap(),
                p2p_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                node_operator_principal_id: None,
                secret_key_store: None,
                chip_id: vec![],
            },
        };

        assert_eq!(got, want);
    }

    /// Components separated by commas should parse correctly
    #[test]
    fn valid_nodes_comma() {
        // Identical to valid_nodes_hyphen, just using commas instead
        let got = parse_nodes_deprecated("1,2,1.2.3.4:80,2.3.4.5:81,82,3.4.5.6:82").unwrap();
        let want = Node {
            node_index: 1,
            subnet_index: Some(2),
            config: NodeConfiguration {
                xnet_api: SocketAddr::from_str("2.3.4.5:81").unwrap(),
                public_api: SocketAddr::from_str("3.4.5.6:82").unwrap(),
                p2p_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                node_operator_principal_id: None,
                secret_key_store: None,
                chip_id: vec![],
            },
        };

        assert_eq!(got, want);
    }
}
