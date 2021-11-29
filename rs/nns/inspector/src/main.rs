//! An utility to help inspecting the stable memory of NNS canisters.

use ic_base_types::CanisterId;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{Governance as GovernanceProto, Neuron};
use ic_nns_gtc::pb::v1::Gtc as GtcProto;
use ledger_canister::{AccountIdentifier, Subaccount};
use prost::Message;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::string::ToString;
use structopt::StructOpt;

/// Command line argument to the utility.
#[derive(Debug, StructOpt)]
#[structopt(
    name = "nns-inspector",
    about = "Read and decode the NNS's stable memory."
)]
struct CliArgs {
    /// Path to stable the `canister_states` directory
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    #[structopt(parse(from_os_str), default_value = ".")]
    output: PathBuf,

    /// The location of the "rs" directory. Used to find .proto files.
    #[structopt(long, parse(from_os_str), default_value = ".")]
    rs: PathBuf,
}

/// Main method to run the utility.
fn main() {
    let args = CliArgs::from_iter_safe(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {}", e));

    assert!(
        args.input.is_dir(),
        "{} is not a directory",
        args.input.display()
    );
    match std::fs::create_dir(args.output.clone()) {
        Ok(()) => eprintln!("Created output dir {}", args.output.display()),
        Err(_) => eprintln!(
            "Could not create output dir {}. It may mean it already exists, so continuing. \
        This may override existing files.",
            args.output.display()
        ),
    }

    // Registry.
    // Stable memory = binary proto, type RegistryCanisterStableStorage.
    match extract_stable_memory(&args, REGISTRY_CANISTER_ID, "registry_stable_memory.pb") {
        Ok(pb) => eprintln!("Extracted registry stable memory to {}", pb.display()),
        Err(e) => eprintln!("Could not extract the registry stable memory: {}", e),
    }

    // Governance.
    // Stable memory = binary proto, type Governance.
    match extract_stable_memory(&args, GOVERNANCE_CANISTER_ID, "governance_stable_memory.pb") {
        Ok(pb) => decode_governance_stable_memory(pb, &args.output, &args.rs),
        Err(e) => eprintln!("Could not extract the governance stable memory: {}", e),
    }

    // Ledger.
    // Stable memory = binary CBOR, type Ledger (rust struct).
    match extract_stable_memory(&args, LEDGER_CANISTER_ID, "ledger_stable_memory.cbor") {
        Ok(cbor) => decode_ledger_stable_memory(cbor, &args.output),
        Err(e) => eprintln!("Could not extract the ledger stable memory: {}", e),
    }

    // Gtc.
    // Stable memory = binary proto, type Gtc.
    match extract_stable_memory(&args, GENESIS_TOKEN_CANISTER_ID, "gtc_stable_memory.pb") {
        Ok(pb) => decode_gtc_stable_memory(pb, &args.output, &args.rs),
        Err(e) => eprintln!("Could not extract the gtc stable memory: {}", e),
    }

    // Cycle minting.
    // Stable memory = binary candid, type State.
    match extract_stable_memory(
        &args,
        CYCLES_MINTING_CANISTER_ID,
        "cycles_stable_memory.didb",
    ) {
        Ok(_) => eprintln!("Wrote cycles_stable_memory.didb"),
        Err(e) => eprintln!("Could not extract the cycles stable memory: {}", e),
    }
}

/// Extract a stable_memory.bin file.
///
/// This depends only on the stable memory using the `dfn_core::stable` library,
/// not on the actual data schema inside.
///
/// Returns the PathBuf to the extracted stable memory.
fn extract_stable_memory(
    args: &CliArgs,
    id: CanisterId,
    filename: &str,
) -> std::io::Result<PathBuf> {
    let encoded = args
        .input
        .join(hex::encode(id.get_ref().as_slice()))
        .join("stable_memory.bin");
    assert!(encoded.is_file(), "{} is not a file.", encoded.display());
    let decoded = args.output.join(filename);
    stable_reader::read(&mut File::open(encoded)?, File::create(decoded.clone())?)?;
    Ok(decoded)
}

/// Extract of a neuron data suitable for csv output.
#[derive(serde::Serialize)]
struct NeuronRecord {
    id: String,
    account_hex: String,
    controller: String,
    hot_keys: String,
    cached_neuron_stake_e8s: u64,
    neuron_fees_e8s: u64,
    aging_since_timestamp_seconds: u64,
    kyc_verified: bool,
    maturity_e8s_equivalent: u64,
    not_for_profit: bool,
    account_id: String,
}

/// Decode stable memory for the governance canister.
///
/// gov_pb is expected to be a binary Governance proto. Extraction should have
/// already happened.
fn decode_governance_stable_memory(gov_pb: PathBuf, output: &Path, rs: &Path) {
    // Decode
    // It's REALLY IMPORTANT to use `protoc` here, NOT the prost library.
    // The prost generated code silently drops all unknown fields when reading
    // serialized protobuf, hence it is NOT suitable for state auditing, or in
    // general for debugging.
    let mut cmd_base = std::process::Command::new("protoc");
    let cmd = cmd_base
        // -I: where to find included protos (transitively)
        .args(&["-I", "nns/governance/proto"])
        .args(&["-I", "rosetta-api/ledger_canister/proto"])
        .args(&["-I", "types/base_types/proto"])
        .args(&["-I", "nns/common/proto"])
        // Main arg: the main proto file
        .arg("nns/governance/proto/ic_nns_governance/pb/v1/governance.proto")
        // the actual command
        .args(&["--decode", "ic_nns_governance.pb.v1.Governance"])
        .current_dir(rs)
        .stdin(File::open(gov_pb.clone()).unwrap())
        .stdout(File::create(output.join("governance_stable_memory.textproto")).unwrap());
    let status = cmd.status().unwrap();
    match status.success() {
        true => eprintln!("Wrote governance_stable_memory.textproto"),
        false => eprintln!(
            "Something went wrong with parsing the governance proto. The command was: {:?}",
            cmd
        ),
    };

    // This time we use prost. This is fine: this is for an EXTRACT of the data.
    let mut bytes = Vec::<u8>::new();
    File::open(gov_pb).unwrap().read_to_end(&mut bytes).unwrap();
    match GovernanceProto::decode(bytes.as_slice()) {
        Err(e) => eprintln!("Can't prost-deserialize the governance proto: {}", e),
        Ok(proto) => {
            let mut csv_writer =
                csv::Writer::from_path(output.join("governance_neurons_EXTRACT.csv")).unwrap();
            let mut neurons: Vec<Neuron> = proto.neurons.values().cloned().collect();
            neurons.sort_by_key(|n| n.id.as_ref().map_or(0, |nid| nid.id));
            for n in neurons {
                let record = NeuronRecord {
                    id: n
                        .id
                        .map_or_else(|| "none".to_string(), |nid| nid.id.to_string()),
                    account_hex: hex::encode(n.account.as_slice()),
                    controller: n
                        .controller
                        .map_or_else(|| "none".to_string(), |c| c.to_string()),
                    hot_keys: n
                        .hot_keys
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(";"),
                    cached_neuron_stake_e8s: n.cached_neuron_stake_e8s,
                    neuron_fees_e8s: n.neuron_fees_e8s,
                    aging_since_timestamp_seconds: n.aging_since_timestamp_seconds,
                    kyc_verified: n.kyc_verified,
                    maturity_e8s_equivalent: n.maturity_e8s_equivalent,
                    not_for_profit: n.not_for_profit,
                    account_id: AccountIdentifier::new(
                        GOVERNANCE_CANISTER_ID.get(),
                        Some(Subaccount(n.account.as_slice().try_into().unwrap())),
                    )
                    .to_string(),
                };
                csv_writer.serialize(record).unwrap();
            }
            eprintln!("Wrote governance_neurons_EXTRACT.csv");
        }
    }
}

/// The type of record expected to be found in the GTC canister's stable memory.
#[derive(serde::Serialize)]
struct GtcAccountRecord {
    account_address: String,
    neuron_ids: String,
    acount_value_icpts: u32,
    has_claimed: bool,
    has_donated: bool,
}

/// Decode stable memory for the GTC canister.
fn decode_gtc_stable_memory(gtc_pb: PathBuf, output: &Path, rs: &Path) {
    let mut cmd_base = std::process::Command::new("protoc");
    let cmd = cmd_base
        // -I: where to find included protos (transitively)
        .args(&["-I", "nns/governance/proto"])
        .args(&["-I", "rosetta-api/ledger_canister/proto"])
        .args(&["-I", "types/base_types/proto"])
        .args(&["-I", "nns/common/proto"])
        .args(&["-I", "nns/gtc/proto"])
        // Main arg: the main proto file
        .arg("nns/gtc/proto/ic_nns_gtc/pb/v1/gtc.proto")
        // the actual command
        .args(&["--decode", "ic_nns_gtc.pb.v1.Gtc"])
        .current_dir(rs)
        .stdin(File::open(gtc_pb.clone()).unwrap())
        .stdout(File::create(output.join("gtc_stable_memory.textproto")).unwrap());
    let status = cmd.status().unwrap();
    match status.success() {
        true => eprintln!("Wrote gtc_stable_memory.textproto"),
        false => eprintln!(
            "Something went wrong with parsing the gtc proto. The command was: {:?}",
            cmd
        ),
    }

    let mut bytes = Vec::<u8>::new();
    File::open(gtc_pb).unwrap().read_to_end(&mut bytes).unwrap();
    let proto = match GtcProto::decode(bytes.as_slice()) {
        Err(e) => {
            eprintln!("Can't prost-deserialize the gtc proto: {}", e);
            return;
        }
        Ok(p) => p,
    };
    let mut csv_writer = csv::Writer::from_path(output.join("gtc_accounts_EXTRACT.csv")).unwrap();
    let mut records: Vec<GtcAccountRecord> = proto
        .accounts
        .iter()
        .map(|(addr, s)| GtcAccountRecord {
            account_address: addr.to_string(),
            neuron_ids: s
                .neuron_ids
                .iter()
                .map(|id| id.id.to_string())
                .collect::<Vec<String>>()
                .join(";"),
            acount_value_icpts: s.icpts,
            has_claimed: s.has_claimed,
            has_donated: s.has_donated,
        })
        .collect();
    records.sort_by_key(|record| record.account_address.clone());
    for r in records {
        csv_writer.serialize(r).unwrap();
    }
    eprintln!("Wrote gtc_accounts_EXTRACT.csv");
}

/// The type of record expected to be found in the ledger canister's stable
/// memory.
#[derive(serde::Serialize)]
struct LedgerBalanceRecord {
    account_identitifier: String,
    balance_e8s: u64,
}

/// Decode stable memory for the ledger canister.
fn decode_ledger_stable_memory(cbor: PathBuf, output: &Path) {
    // For the same argument as above, do NOT deserialize to a specific struct.
    // This is an audit tool, we don't want any risk of dropping data.
    // So go the schema-less way.
    use serde_cbor::value::Value;
    let value_res: serde_cbor::Result<Value> =
        serde_cbor::from_reader(File::open(cbor.clone()).unwrap());
    let val = match value_res {
        Err(e) => {
            eprintln!(
                "Could not parse the cbor for the ledger stable memory: {}",
                e
            );
            return;
        }
        Ok(v) => v,
    };
    // The following is very slow and the output is very verbose. Serialization to
    // json is not a viable alternative as some keys are not strings, which is
    // allowed in cbor but not in json.
    match write!(
        File::create(output.join("ledger_stable_memory.txt")).unwrap(),
        "{:#?}",
        val
    ) {
        Ok(()) => eprintln!("Wrote ledger_stable_memory.txt"),
        Err(e) => eprintln!("Could not write ledger_stable_memory.txt: {}", e),
    };

    let ledger: ledger_canister::Ledger = match serde_cbor::from_reader(File::open(cbor).unwrap()) {
        Err(e) => {
            eprintln!(
                "Could parse the ledger stable memory as a Ledger struct: {}",
                e
            );
            return;
        }
        Ok(l) => l,
    };
    let mut records: Vec<LedgerBalanceRecord> = ledger
        .balances
        .store
        .iter()
        .map(|(key, icpts)| LedgerBalanceRecord {
            account_identitifier: key.to_string(),
            balance_e8s: icpts.get_e8s(),
        })
        .collect();
    records.sort_by_key(|record| record.account_identitifier.clone());
    let mut csv_writer =
        csv::Writer::from_path(output.join("ledger_balances_EXTRACT.csv")).unwrap();
    for r in records.into_iter() {
        csv_writer.serialize(r).unwrap();
    }
    eprintln!("Wrote ledger_balances_EXTRACT.csv");
}
