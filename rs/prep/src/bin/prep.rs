//! The prep allows an operator to generate a `registry.proto` based on a
//! set of ip-addresses of a subnetwork.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt::Display,
    fs,
    io::{self, BufRead},
    net::{SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
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
use ic_types::{
    registry::connection_endpoint::ConnectionEndpoint, Height, PrincipalId, ReplicaVersion,
};

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
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub replica_download_url: Option<Url>,

    /// sha256-hash of the replica binary in hex.
    #[clap(long)]
    pub replica_hash: Option<String>,

    /// URL from which to download the orchestrator binary
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub orchestrator_download_url: Option<Url>,

    /// sha256-hash of the orchestrator binary in hex.
    #[clap(long)]
    pub orchestrator_hash: Option<String>,

    /// The URL against which a HTTP GET request will return a release
    /// package that corresponds to this version.
    #[clap(long, parse(try_from_str = url::Url::parse))]
    pub release_package_download_url: Option<Url>,

    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_url'. Must be present if release_package_url is
    /// present.
    #[clap(long)]
    pub release_package_sha256_hex: Option<String>,

    /// List of tuples describing the nodes
    #[clap(long, parse(try_from_str = parse_nodes_deprecated), group = "node_spec", multiple_values(true))]
    pub nodes: Vec<Node>,

    /// JSON5 node definition
    #[clap(long, group = "node_spec", multiple_values(true))]
    pub node: Vec<Node>,

    /// Path to working directory for node states.
    #[clap(long, parse(from_os_str))]
    pub working_dir: PathBuf,

    /// Flows per node.
    #[clap(long, parse(try_from_str = parse_flows))]
    pub p2p_flows: FlowConfig,

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
}

fn main() -> Result<()> {
    let valid_args = CliArgs::parse().validate()?;

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
            valid_args.ssh_readonly_access.clone(),
            valid_args.ssh_backup_access.clone(),
        );
        topology_config.insert_subnet(*subnet_id, subnet_configuration);
    }
    for (n_idx, nc) in valid_args.unassigned_nodes.iter() {
        topology_config.insert_unassigned_node(*n_idx, nc.clone())
    }
    let ic_config0 = IcConfig::new(
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
    );

    let ic_config = match valid_args.dc_pk_dir {
        Some(dir) => ic_config0.load_registry_node_operator_records_from_dir(
            &dir,
            valid_args.require_node_provider_key,
        )?,
        None => ic_config0,
    };

    ic_config.initialize()?;
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
}

/// Structured definition of a flow provided by the `--p2p-flows` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct FlowConfig {
    /// The initial flow starting tag
    start_tag: u32,

    /// The number of flows to create
    num_flows: u32,
}

/// Parse a `--p2p-flows` flag value in to a FlowConfig.
fn parse_flows(src: &str) -> Result<FlowConfig> {
    let parts = src.splitn(2, '-').collect::<Vec<&str>>();
    let start_tag = parts[0]
        .parse::<u32>()
        .with_context(|| format!("did not parse {} as u32", parts[0]))?;

    let num_flows = parts[1]
        .parse::<u32>()
        .with_context(|| format!("did not parse {} as u32", parts[0]))?;

    Ok(FlowConfig {
        start_tag,
        num_flows,
    })
}

/// Structured definition of a node provided by the `--nodes` flag.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    // Default to listening on 0.0.0.0 for metrics (consistent with past
    // behaviour)
    let metrics_port = parts[4].parse::<u16>().unwrap();
    let metrics_addr: SocketAddr =
        SocketAddrV4::new("0.0.0.0".parse().expect("can't fail"), metrics_port).into();

    let http_addr: SocketAddr = parts[5]
        .parse()
        .with_context(|| format!("did not parse {} as SocketAddr", parts[3]))?;

    // P2P is special, and needs a custom protocol
    let p2p_addr: Url = format!("org.internetcomputer.p2p1://{}", parts[2]).parse()?;

    Ok(Node {
        node_index,
        subnet_index,
        config: NodeConfiguration {
            p2p_num_flows: 0,
            p2p_start_flow_tag: 0,
            xnet_api: vec![ConnectionEndpoint::from(xnet_addr)],
            public_api: vec![ConnectionEndpoint::from(http_addr)],
            // TODO(O4-41): Empty, because the replica does not distinguish
            // between them and the --nodes flag doesn't support providing it.
            private_api: vec![],
            prometheus_metrics: vec![ConnectionEndpoint::from(metrics_addr)],
            p2p_addr: ConnectionEndpoint::try_from(p2p_addr)?,
            node_operator_principal_id: None,
            no_idkg_key: false,
            secret_key_store: None,
        },
    })
}

/// Values passed to the `--node` flag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeFlag {
    idx: Option<u64>,
    subnet_idx: Option<u64>,
    pub xnet_api: Option<Vec<ConnectionEndpoint>>,
    pub public_api: Option<Vec<ConnectionEndpoint>>,
    // TODO(O4-41): When the replica supports serving private and public APIs
    // on different endpoints this will become non-optional.
    pub private_api: Option<Vec<ConnectionEndpoint>>,
    pub prometheus_metrics: Option<Vec<ConnectionEndpoint>>,

    /// The initial endpoint that P2P uses. The complete list of endpoints
    /// is generated by creating `p2p_num_flows` endpoints, and incrementing
    /// the port number by one for each.
    pub p2p_addr: Option<ConnectionEndpoint>,
}

#[derive(Error, Clone, Debug, PartialEq)]
enum NodeFlagParseError {
    #[error("field is missing: {source}")]
    MissingField {
        #[from]
        source: MissingFieldError,
    },

    #[error("parsing flag '{flag}' failed: {source}")]
    Json5ParseFailed { source: json5::Error, flag: String },
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

    #[error("private_api")]
    PrivateApi,

    #[error("prometheus_metrics")]
    PrometheusMetrics,

    #[error("p2p_addr")]
    P2PAddr,
}

impl TryFrom<NodeFlag> for Node {
    type Error = NodeFlagParseError;

    fn try_from(value: NodeFlag) -> Result<Self, Self::Error> {
        let node_index = value.idx.ok_or(MissingFieldError::NodeIndex)?;
        let xnet_api = value.xnet_api.ok_or(MissingFieldError::Xnet)?;
        let public_api = value.public_api.ok_or(MissingFieldError::PublicApi)?;

        // TODO(O4-41): At the moment the private_api endpoint is the same as
        // the public_api endpoint. When the replica supports serving these on
        // different endpoints then this code becomes a simple assignment, and
        // the field is required.
        let private_api = match value.private_api {
            Some(value) => value,
            None => public_api.clone(),
        };
        let prometheus_metrics = value
            .prometheus_metrics
            .ok_or(MissingFieldError::PrometheusMetrics)?;
        let p2p_addr = value.p2p_addr.ok_or(MissingFieldError::P2PAddr)?;

        Ok(Self {
            node_index,
            subnet_index: value.subnet_idx,
            config: NodeConfiguration {
                xnet_api,
                public_api,
                private_api,
                prometheus_metrics,
                p2p_addr,
                p2p_num_flows: 0,
                p2p_start_flow_tag: 0,
                node_operator_principal_id: None,
                no_idkg_key: false,
                secret_key_store: None,
            },
        })
    }
}

impl FromStr for Node {
    type Err = NodeFlagParseError;

    /// Parses a node string in to a `Node`.
    ///
    /// A --node flag and node string looks like this:
    ///
    /// ```text
    /// --node field:value,field:value,array_field:[value,value],...
    /// ```
    ///
    /// The field names must match the field names in `NodeConfiguration`, with
    /// the associated types.
    ///
    /// This is because the text is actually the JSON5 representation of the
    /// value, without the opening/closing `{` and `}`. This means that the
    /// field names do not need to be quoted
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let flag: NodeFlag = json5::from_str(&format!("{{ {} }}", s)).map_err(|source| {
            Self::Err::Json5ParseFailed {
                source,
                flag: s.to_string(),
            }
        })?;

        let node = Node::try_from(flag)?;
        Ok(node)
    }
}

impl Display for Node {
    /// Displays the node in a format that will be accepted by the `--node`
    /// flag.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn joiner(endpoints: &[ConnectionEndpoint]) -> String {
            endpoints
                .iter()
                .map(|ce| format!(r#""{}""#, ce))
                .collect::<Vec<_>>()
                .join(",")
        }

        write!(f, "idx:{}", self.node_index)?;
        if let Some(subnet_index) = self.subnet_index {
            write!(f, ",subnet_idx:{}", subnet_index)?;
        }
        write!(f, ",public_api:[{}]", joiner(&self.config.public_api))?;
        write!(f, ",private_api:[{}]", joiner(&self.config.private_api))?;
        write!(
            f,
            ",prometheus_metrics:[{}]",
            joiner(&self.config.prometheus_metrics)
        )?;
        write!(f, r#",p2p_addr:"{}""#, self.config.p2p_addr)?;
        write!(f, r#",xnet_api:[{}]"#, joiner(&self.config.xnet_api))?;

        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for Node {
    type Error = <Node as FromStr>::Err;
    fn try_from(s: &'a str) -> Result<Node, Self::Error> {
        Node::from_str(s)
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

        let nodes: Vec<_> = if self.nodes.is_empty() {
            self.node
        } else {
            self.nodes
        };

        for (
            i,
            Node {
                node_index,
                subnet_index,
                config,
            },
        ) in nodes.iter().enumerate()
        {
            if !node_idx_set.insert(node_index) {
                bail!("the {}'th entry repeats the node index {}", i, node_index);
            }
            let mut config = config.clone();
            config.p2p_num_flows = self.p2p_flows.num_flows;
            config.p2p_start_flow_tag = self.p2p_flows.start_tag;

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

#[cfg(test)]
mod test_flag_p2p_flows_parser {
    use super::*;
    use anyhow::Result;
    use pretty_assertions::assert_eq;

    /// "1234-1" deconstructs in to a start_tag and num_flows
    #[test]
    fn valid_flow() -> Result<()> {
        let got = parse_flows("1234-1")?;
        let want = FlowConfig {
            start_tag: 1234,
            num_flows: 1,
        };

        assert_eq!(got, want);
        Ok(())
    }

    /// An invalid value is recognised
    #[test]
    fn invalid_flow() -> Result<()> {
        let got = parse_flows("x-x");

        assert!(got.is_err());
        Ok(())
    }
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
                xnet_api: vec!["http://2.3.4.5:81".parse().unwrap()],
                public_api: vec!["http://3.4.5.6:82".parse().unwrap()],
                private_api: vec![],
                prometheus_metrics: vec!["http://0.0.0.0:82".parse().unwrap()],
                p2p_addr: "org.internetcomputer.p2p1://1.2.3.4:80".parse().unwrap(),
                p2p_num_flows: 0,
                p2p_start_flow_tag: 0,
                node_operator_principal_id: None,
                no_idkg_key: false,
                secret_key_store: None,
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
                xnet_api: vec!["http://2.3.4.5:81".parse().unwrap()],
                public_api: vec!["http://3.4.5.6:82".parse().unwrap()],
                private_api: vec![],
                p2p_addr: "org.internetcomputer.p2p1://1.2.3.4:80".parse().unwrap(),
                prometheus_metrics: vec!["http://0.0.0.0:82".parse().unwrap()],
                p2p_num_flows: 0,
                p2p_start_flow_tag: 0,
                node_operator_principal_id: None,
                no_idkg_key: false,
                secret_key_store: None,
            },
        };

        assert_eq!(got, want);
    }
}

#[cfg(test)]
mod test_flag_node_parser {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    const GOOD_FLAG: &str = r#"idx:1,subnet_idx:2,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#;

    /// Verifies that a good flag parses correctly
    #[test]
    fn valid_flag() {
        let got: Node = GOOD_FLAG.parse().unwrap();
        let want = Node {
            node_index: 1,
            subnet_index: Some(2),
            config: NodeConfiguration {
                xnet_api: vec!["http://1.2.3.4:81".parse().unwrap()],
                public_api: vec!["http://3.4.5.6:82".parse().unwrap()],
                private_api: vec!["http://3.4.5.6:83".parse().unwrap()],
                p2p_addr: "org.internetcomputer.p2p1://1.2.3.4:80".parse().unwrap(),
                prometheus_metrics: vec!["http://5.6.7.8:9090".parse().unwrap()],
                p2p_num_flows: 0,
                p2p_start_flow_tag: 0,
                node_operator_principal_id: None,
                no_idkg_key: false,
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
            r#"subnet_idx:2,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            // Omitting subnet index yields an unassigned node.
            // r#"idx:1,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            r#"idx:1,subnet_idx:2,public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            r#"idx:1,subnet_idx:2,xnet_api:["http://1.2.3.4:81"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            // TODO(O4-41): Omitting private_api is currently OK.
            //r#"idx:1,subnet_idx:2,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],prometheus_metrics:["http://5.6.7.8:9090"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            r#"idx:1,subnet_idx:2,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],p2p_addr:"org.internetcomputer.p2p1://1.2.3.4:80""#,
            r#"idx:1,subnet_idx:2,xnet_api:["http://1.2.3.4:81"],public_api:["http://3.4.5.6:82"],private_api:["http://3.4.5.6:83"],prometheus_metrics:["http://5.6.7.8:9090"]"#,
        ];

        for flag in flags {
            assert_matches!(
                flag.parse::<Node>(),
                Err(NodeFlagParseError::MissingField { .. })
            );
        }
    }

    /// Verifies that unknown fields return an Err
    #[test]
    fn unknown_fields() {
        let flag = format!("new_field:0,{}", GOOD_FLAG);
        assert_matches!(
            flag.parse::<Node>(),
            Err(NodeFlagParseError::Json5ParseFailed { .. })
        );
    }

    /// Verifies that the flag can roundrip through parsing
    #[test]
    fn roundtrip() {
        let node: Node = GOOD_FLAG.parse().unwrap();
        let node_flag = node.to_string();

        let new_node: Node = node_flag.parse().unwrap();

        assert_eq!(node, new_node);
    }
}
