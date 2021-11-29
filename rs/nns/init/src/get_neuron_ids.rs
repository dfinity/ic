use ic_nns_governance::pb::v1::Governance as GovernanceProto;
use prost::Message;
use std::fs;

/// Given a governance proto file in binary format (typically with .pb
/// extension) and a principal (in textual representation, see
/// docs.dfinity.systems/public/#textual-ids), prints the neuron ids of all
/// neurons controlled by that principal.
fn main() {
    let mut args = std::env::args();
    let _command = args.next();
    let file_path = args.next().expect("need arg: pb file");
    let principal = args.next();

    let bytes = fs::read(file_path).expect("Couldn't read governance protobuf file.");
    let parsed = GovernanceProto::decode(&bytes[..])
        .map_err(|err| format!("Error decoding governance protobuf file: {:?}", err));

    for id in parsed
        .expect("Parsing failed")
        .neurons
        .iter()
        .filter(|i| i.1.controller.map(|controller| format!("{}", controller)) == principal)
        .map(|(key, _)| key)
    {
        println!("{}", id)
    }
}
