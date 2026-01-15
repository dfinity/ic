use clap::{Arg, Command, arg};
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl,
    consensus_pool::{PoolSectionOps, UncachedConsensusPoolImpl},
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::consensus_pool::*;
use ic_logger::{LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    NodeId, PrincipalId,
    consensus::{
        CatchUpPackage, ConsensusMessage, ConsensusMessageHashable,
        certification::CertificationMessage,
    },
    time::current_time,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_bytes_repr::{ByteFmtDeserializer, ByteFmtSerializer};
use serde_json::{Deserializer, Serializer};
use std::convert::TryFrom;
use std::io::BufRead;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let mut app = Command::new("ic-consensus-pool-util")
        .version("0.1")
        .about("IC Consensus Pool Utility")
        .subcommand(
            Command::new("export").about("Export data to stdout").arg(
                Arg::new("artifact")
                    .short('a')
                    .long("artifact")
                    .value_name("NAME")
                    .help("Artifact name")
                    .num_args(1..),
            ),
        )
        .subcommand(Command::new("import").about("Import data from stdin"))
        .subcommand(
            Command::new("export-cup-proto")
                .about("Export the highest CatchUpPackage protobuf (binary) data")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output filename")
                        .required(true)
                        .num_args(1),
                ),
        )
        .arg(arg!(<PATH>       "PATH to the consensus pool directory"));
    let mut help = Vec::new();
    app.write_help(&mut help)
        .expect("Unable to output help message");
    let matches = app.get_matches();
    let path = matches
        .get_one::<String>("PATH")
        .expect("Missing PATH to consensus pool directory");
    if let Some(matches) = matches.subcommand_matches("export") {
        export(path, matches)
    } else if let Some(_matches) = matches.subcommand_matches("import") {
        import(path)
    } else if let Some(matches) = matches.subcommand_matches("export-cup-proto") {
        export_cup_proto(path, matches)
    } else {
        eprintln!(
            "{}",
            String::from_utf8(help).expect("Help message is malformed")
        )
    }
}

const ALL_ARTIFACT_NAMES: [&str; 13] = [
    "RandomBeacon",
    "Finalization",
    "Notarization",
    "BlockProposal",
    "RandomBeaconShare",
    "NotarizationShare",
    "FinalizationShare",
    "RandomTape",
    "RandomTapeShare",
    "CatchUpPackage",
    "CatchUpPackageShare",
    "Certification",
    "CertificationShare",
];

fn parse_artifact_names(names: &[&str]) -> Vec<&'static str> {
    for name in names {
        if !ALL_ARTIFACT_NAMES
            .iter()
            .any(|x| x.eq_ignore_ascii_case(name))
        {
            panic!("Unknown artifact name '{name}'")
        }
    }
    ALL_ARTIFACT_NAMES
        .iter()
        .filter(|x| names.iter().any(|n| n.eq_ignore_ascii_case(x)))
        .cloned()
        .collect::<Vec<_>>()
}

fn open_consensus_pool(path: &str, read_only: bool) -> UncachedConsensusPoolImpl {
    let logger = LoggerImpl::new(&Default::default(), "dump_consensus_pool".to_string());
    let log = ReplicaLogger::new(logger.root.clone().into());

    let path = PathBuf::from(path);
    let mut config = ArtifactPoolConfig::new(path);
    config.persistent_pool_read_only = read_only;
    UncachedConsensusPoolImpl::new(config, log)
}

fn open_certification_pool(path: &str, read_only: bool) -> CertificationPoolImpl {
    let logger = LoggerImpl::new(&Default::default(), "dump_consensus_pool".to_string());
    let log = ReplicaLogger::new(logger.root.clone().into());

    let path = PathBuf::from(path);
    let mut config = ArtifactPoolConfig::new(path);
    config.persistent_pool_read_only = read_only;
    let node_id = NodeId::from(PrincipalId::new_node_test_id(0));
    CertificationPoolImpl::new(node_id, config, log, MetricsRegistry::new())
}

fn from_str<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, serde_json::Error> {
    let mut json_de = Deserializer::from_str(json);
    let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);
    T::deserialize(bytefmt_json_de)
}

fn to_string<T: Serialize>(msg: &T) -> String {
    let mut out = vec![];
    let mut ser = Serializer::new(&mut out);
    let ser = ByteFmtSerializer::hex(&mut ser);
    msg.serialize(ser).expect("Failed to serialize to JSON");
    String::from_utf8(out).expect("UTF8 conversion error")
}

fn export(path: &str, matches: &clap::ArgMatches) {
    let artifacts = match matches.get_many::<String>("artifact") {
        Some(names) => {
            parse_artifact_names(&names.map(|name| name.as_str()).collect::<Vec<&str>>())
        }
        None => ALL_ARTIFACT_NAMES.to_vec(),
    };

    let consensus_pool = open_consensus_pool(path, true);
    let certification_pool = open_certification_pool(path, true);

    for artifact in artifacts {
        match artifact {
            "RandomBeacon" => {
                for x in consensus_pool.validated().random_beacon().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "Finalization" => {
                for x in consensus_pool.validated().finalization().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "Notarization" => {
                for x in consensus_pool.validated().notarization().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "BlockProposal" => {
                for x in consensus_pool.validated().block_proposal().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "RandomBeaconShare" => {
                for x in consensus_pool.validated().random_beacon_share().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "NotarizationShare" => {
                for x in consensus_pool.validated().notarization_share().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "FinalizationShare" => {
                for x in consensus_pool.validated().finalization_share().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "RandomTape" => {
                for x in consensus_pool.validated().random_tape().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "RandomTapeShare" => {
                for x in consensus_pool.validated().random_tape_share().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "CatchUpPackage" => {
                for x in consensus_pool.validated().catch_up_package().get_all() {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "CatchUpPackageShare" => {
                for x in consensus_pool
                    .validated()
                    .catch_up_package_share()
                    .get_all()
                {
                    println!("{}", to_string(&x.into_message()));
                }
            }
            "Certification" => {
                for x in certification_pool.validated.certifications().get_all() {
                    println!("{}", to_string(&CertificationMessage::Certification(x)));
                }
            }
            "CertificationShare" => {
                for x in certification_pool
                    .validated
                    .certification_shares()
                    .get_all()
                {
                    println!(
                        "{}",
                        to_string(&CertificationMessage::CertificationShare(x))
                    );
                }
            }
            _ => unreachable!("Unsupported artifact name: {}", artifact),
        }
    }
}

fn import(path: &str) {
    let mut consensus_pool = open_consensus_pool(path, false);
    let certification_pool = open_certification_pool(path, false);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let s = line.expect("Cannot read input");
        if let Ok(msg) = from_str::<ConsensusMessage>(&s) {
            let mut ops = PoolSectionOps::new();
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: current_time(),
            });
            consensus_pool.validated.mutate(ops);
        } else if let Ok(msg) = from_str::<CertificationMessage>(&s) {
            certification_pool.validated.insert(msg)
        } else {
            panic!("Failed to parse JSON: {}", s);
        }
    }
}

fn export_cup_proto(path: &str, matches: &clap::ArgMatches) {
    let filename = matches
        .get_one::<String>("output")
        .expect("Expect an output filename");
    let mut file = std::fs::File::create(filename)
        .unwrap_or_else(|err| panic!("Cannot open file {filename} for write: {err:?}"));
    let consensus_pool = open_consensus_pool(path, true);
    let mut buf = Vec::<u8>::new();
    let cup_proto = consensus_pool.validated().highest_catch_up_package_proto();
    let cup = CatchUpPackage::try_from(&cup_proto).unwrap_or_else(|err| panic!("{}", err));
    println!("{}", to_string(&cup));
    cup_proto
        .encode(&mut buf)
        .unwrap_or_else(|err| panic!("Error encoding protobuf: {err:?}"));
    file.write_all(&buf)
        .unwrap_or_else(|err| panic!("Cannot write to file {filename}: {err:?}"));
}
