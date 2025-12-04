use crate::{
    SubnetDescriptor,
    types::{NodeDetails, SubnetRecord},
};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_protobuf::registry::{
    node::v1::NodeRecord as NodeRecordPb,
    subnet::v1::{SubnetListRecord as SubnetListRecordPb, SubnetRecord as SubnetRecordPb},
};
use ic_registry_keys::{make_node_record_key, make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_transport::Error;
use ic_types::{NodeId, PrincipalId, SubnetId};
use indexmap::IndexMap;
use prost::Message;
use std::{convert::TryFrom, fs::read_to_string, path::PathBuf};
use url::Url;

pub(crate) async fn get_subnet_record_pb(
    registry_canister: &RegistryCanister,
    subnet_id: SubnetId,
) -> SubnetRecordPb {
    let registry_answer = registry_canister
        .get_value_with_update(make_subnet_record_key(subnet_id).into_bytes(), None)
        .await;

    let (bytes, _) = registry_answer.unwrap();
    SubnetRecordPb::decode(&bytes[..]).expect("Error decoding value from registry.")
}

pub(crate) async fn get_subnet_record(
    registry_canister: &RegistryCanister,
    subnet_id: SubnetId,
) -> SubnetRecord {
    let value_pb = get_subnet_record_pb(registry_canister, subnet_id).await;
    SubnetRecord::from(&value_pb)
}

pub(crate) async fn get_subnet_record_with_details(
    subnet_id: SubnetId,
    registry_canister: &RegistryCanister,
    all_nodes_with_details: &IndexMap<PrincipalId, NodeDetails>,
) -> SubnetRecord {
    get_subnet_record(registry_canister, subnet_id)
        .await
        .with_node_details(all_nodes_with_details)
}

pub(crate) async fn get_node_record_pb(
    registry_canister: &RegistryCanister,
    node_id: NodeId,
) -> NodeRecordPb {
    let registry_answer = registry_canister
        .get_value_with_update(make_node_record_key(node_id).into_bytes(), None)
        .await;

    let (bytes, _) = registry_answer.unwrap();
    NodeRecordPb::decode(&bytes[..]).expect("Error decoding NodeRecord from registry.")
}

/// Extracts the summary from either a file or from a string.
pub(crate) fn summary_from_string_or_file(
    summary: &Option<String>,
    summary_file: &Option<PathBuf>,
) -> String {
    match (summary, summary_file) {
        (None, None) | (Some(_), Some(_)) => {
            panic!("Exactly one of summary or summary_file must be specified.")
        }
        (Some(s), None) => s.clone(),
        (None, Some(p)) => read_to_string(p).expect("Couldn't read summary from file."),
    }
}

/// Parses the URL of a proposal.
pub(crate) fn parse_proposal_url(url: &Option<Url>) -> String {
    match url {
        Some(url) => {
            if url.scheme() != "https" {
                panic!("proposal-url must use https");
            }
            url.to_string()
        }
        // By default point to the landing page of `nns-proposals` repository.
        None => "".to_string(),
    }
}

/// Selects a `(NeuronId, Sender)` pair to submit the proposal. If
/// `use_test_neuron` is true, it returns `TEST_NEURON_1_ID` and a `Sender`
/// based on that test neuron's private key, otherwise it validates and returns
/// the `NeuronId` and `Sender` passed as argument.
pub(crate) fn get_proposer_and_sender(
    proposer: Option<NeuronId>,
    sender: Sender,
    use_test_neuron: bool,
) -> (NeuronId, Sender) {
    if use_test_neuron {
        return (
            NeuronId(TEST_NEURON_1_ID),
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        );
    }
    let proposer = proposer.expect("A proposal must have a proposer.");
    assert!(
        sender.get_principal_id() != Sender::Anonymous.get_principal_id(),
        "Must specify a keypair to submit a proposal that corresponds to the owner of a neuron."
    );
    (proposer, sender)
}

/// Shortens the provided `PrincipalId` to make it easier to display.
pub(crate) fn shortened_pid_string(pid: &PrincipalId) -> String {
    format!("{pid}")[..5].to_string()
}

/// Shortens the id of the provided subent to make it easier to display.
pub(crate) fn shortened_subnet_string(subnet: &SubnetDescriptor) -> String {
    match *subnet {
        SubnetDescriptor::Id(pid) => shortened_pid_string(&pid),
        SubnetDescriptor::Index(i) => format!("{i}"),
    }
}

/// Returns the ids from all the subnets currently in the registry.
pub(crate) async fn get_subnet_ids(registry: &RegistryCanister) -> Vec<SubnetId> {
    let (subnet_list_record, _) = get_subnet_list_record(registry).await;
    extract_subnet_ids(&subnet_list_record)
}

/// Returns the record that lists all the subnets currently in the registry.
pub(crate) async fn get_subnet_list_record(
    registry: &RegistryCanister,
) -> (SubnetListRecordPb, bool) {
    // First we need to get the current subnet list record.

    let subnet_list_record_result = registry
        .get_value_with_update(make_subnet_list_record_key().as_bytes().to_vec(), None)
        .await;
    match subnet_list_record_result {
        Ok((bytes, _version)) => match SubnetListRecordPb::decode(&bytes[..]) {
            Ok(record) => (record, false),
            Err(error) => panic!("Error decoding subnet list record: {error:?}"),
        },
        Err(error) => match error {
            // It might be the first time we store a subnet, so we might
            // have to update the subnet list record.
            Error::KeyNotPresent(_) => (SubnetListRecordPb::default(), true),
            _ => panic!("Error while fetching current subnet list record: {error:?}"),
        },
    }
}

/// Extracts the ids from a `SubnetListRecord`.
pub(crate) fn extract_subnet_ids(subnet_list_record: &SubnetListRecordPb) -> Vec<SubnetId> {
    subnet_list_record
        .subnets
        .iter()
        .map(|x| {
            SubnetId::from(
                PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
            )
        })
        .collect()
}

/// Shortens the provided `PrincipalId`s to make them easier to display.
pub(crate) fn shortened_pids_string(pids: &[PrincipalId]) -> String {
    let mut pids_string = "[".to_string();
    pids_string.push_str(
        &pids
            .to_vec()
            .iter()
            .map(PrincipalId::to_string)
            .map(|mut s| {
                s.truncate(5);
                s
            })
            .collect::<Vec<String>>()
            .join(", "),
    );
    pids_string.push(']');
    pids_string
}
