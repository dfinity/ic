//! Contains methods and structs that support settings up the NNS.
use crate::util::{block_on, create_agent, runtime_from_url};
use candid::CandidType;
use canister_test::{Canister, RemoteTestRuntime, Runtime};
use cycles_minting_canister::SetAuthorizedSubnetworkListArgs;
use dfn_candid::candid_one;
use fondue::{
    self,
    log::{info, Logger},
};
use ic_base_types::NodeId;
use ic_canister_client::{Agent, Sender};
use ic_fondue::{
    ic_manager::{IcEndpoint, IcHandle},
    node_software_version::NodeSoftwareVersion,
};
use ic_interfaces::registry::ZERO_REGISTRY_VERSION;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::TEST_NEURON_1_OWNER_KEYPAIR, ids::TEST_USER1_PRINCIPAL, CYCLES_MINTING_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    manage_neuron::{Command, NeuronIdOrSubaccount, RegisterVote},
    ManageNeuron, ManageNeuronResponse, NnsFunction, ProposalInfo, ProposalStatus, Vote,
};
use ic_nns_test_utils::governance::submit_external_update_proposal_allowing_error;
use ic_nns_test_utils::{governance::get_proposal_info, ids::TEST_NEURON_1_ID};
use ic_nns_test_utils::{
    governance::{submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, NnsInitPayloadsBuilder},
};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_common::local_store::{
    ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreReader,
};
use ic_registry_keys::{get_node_record_node_id, make_subnet_list_record_key};
use ic_registry_transport::pb::v1::registry_mutation::Type;
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use ic_types::{CanisterId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId};
use ledger_canister::LedgerCanisterInitPayload;
use ledger_canister::Tokens;
use prost::Message;
use registry_canister::mutations::do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload;
use registry_canister::mutations::{
    do_bless_replica_version::BlessReplicaVersionPayload,
    do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

/// Reads the initial content to inject into the registry in the "local store"
/// format.
///
/// `local_store_dir` is expected to be a directory containing specially-named
/// files following the schema implemented in local_store.rs.
fn read_initial_mutations_from_local_store_dir<P: AsRef<Path>>(
    local_store_dir: P,
) -> Vec<RegistryAtomicMutateRequest> {
    let store = LocalStoreImpl::new(local_store_dir.as_ref());
    let changelog = store
        .get_changelog_since_version(ZERO_REGISTRY_VERSION)
        .unwrap_or_else(|e| {
            panic!(
                "Could not read the content of the local store at {} due to: {}",
                local_store_dir.as_ref().to_str().unwrap_or("").to_string(),
                e
            )
        });
    changelog
        .into_iter()
        .map(|cle: ChangelogEntry| RegistryAtomicMutateRequest {
            mutations: cle
                .into_iter()
                .map(|km: KeyMutation| match km.value {
                    Some(bytes) => upsert(km.key.as_bytes(), bytes),
                    None => delete(km.key),
                })
                .collect(),
            preconditions: vec![],
        })
        .collect()
}

/// Shorthand to create a RegistryMutation with type Delete.
fn delete(key: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Delete, key, b"")
}

/// Shorthand to create a RegistryMutation with type Upsert.
fn upsert(key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> RegistryMutation {
    mutation(Type::Upsert, key, value)
}

fn mutation(
    mutation_type: Type,
    key: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
) -> RegistryMutation {
    RegistryMutation {
        mutation_type: mutation_type as i32,
        key: key.as_ref().to_vec(),
        value: value.as_ref().to_vec(),
    }
}

/// Installation of NNS Canisters.

pub trait NnsExt {
    fn install_nns_canisters(&self, handle: &IcHandle, nns_test_neurons_present: bool);

    /// Convenience method to bless a software update using the binaries
    /// available on the $PATH.
    ///
    /// Generates a new `ReplicaVersionRecord` with replica version `version`.
    /// Depending on `package_content`, only `nodemanager`, only `replica`, or
    /// both, will be updated with the given version. The binaries that are
    /// referenced in the update are the same that are used as the initial
    /// replica version.
    ///
    /// This function can only succeed if the NNS with test neurons have been
    /// installed on the root subnet.
    fn bless_replica_version(
        &self,
        handle: &IcHandle,
        node_implementation_version: NodeSoftwareVersion,
        package_content: UpgradeContent,
    );

    /// Update the subnet given by the subnet index `subnet_index` (enumerated
    /// in order in which they were added) to version `version`.
    ///
    /// This function can only succeed if the NNS with test neurons have been
    /// installed on the root subnet.
    ///
    /// # Panics
    ///
    /// This function will panic if the index is out of bounds wrt. to the
    /// subnets that were _initially_ added to the IC; subnets that were added
    /// after bootstrapping the IC are not supported.
    fn update_subnet_by_idx(&self, handle: &IcHandle, subnet_index: usize, version: ReplicaVersion);

    /// Waits for a given software version `version` to become available on the
    /// subnet with subnet index `subnet_index`.
    ///
    /// This method assumes that only one application subnet is present and that
    /// that subnet is being updated.
    fn await_status_change(
        &self,
        endpoint: &IcEndpoint,
        retry_delay: Duration,
        timeout: Duration,
        acceptance_criterium: impl Fn(&ic_agent::agent::status::Status) -> bool,
    ) -> bool;

    /// A function to remove a node from a subnet.
    fn remove_node(&self, handle: &IcHandle, node_id: NodeId);

    /// A list of all nodes that were registered with the initial registry (i.e.
    /// at bootstrap).
    fn initial_node_ids(&self, handle: &IcHandle) -> Vec<NodeId> {
        let ic_prep_dir = handle
            .ic_prep_working_dir
            .as_ref()
            .expect("ic_prep_working_dir is not set.");

        LocalStoreImpl::new(ic_prep_dir.registry_local_store_path().as_path())
            .get_changelog_since_version(RegistryVersion::from(0))
            .expect("Could not fetch changelog.")
            .iter()
            .flat_map(|c| c.iter())
            .filter_map(|km| {
                km.value
                    .as_ref()
                    .map(|_| &km.key)
                    .and_then(|s| get_node_record_node_id(s))
            })
            .map(NodeId::from)
            .collect()
    }
}

impl NnsExt for fondue::pot::Context {
    fn install_nns_canisters(&self, handle: &IcHandle, nns_test_neurons_present: bool) {
        let mut is_installed = self.is_nns_installed.lock().unwrap();
        if is_installed.eq(&false) {
            install_nns_canisters(
                &self.logger,
                first_root_url(handle),
                handle.ic_prep_working_dir.as_ref().unwrap(),
                nns_test_neurons_present,
            );
            *is_installed = true;
        }
    }

    fn await_status_change(
        &self,
        endpoint: &IcEndpoint,
        retry_delay: Duration,
        timeout: Duration,
        acceptance_criterium: impl Fn(&ic_agent::agent::status::Status) -> bool,
    ) -> bool {
        block_on(async move {
            endpoint.assert_ready(self).await;
            await_replica_status_change(self, endpoint, retry_delay, timeout, acceptance_criterium)
                .await
        })
    }

    fn bless_replica_version(
        &self,
        handle: &IcHandle,
        impl_version: NodeSoftwareVersion,
        _package_content: UpgradeContent,
    ) {
        let replica_version = impl_version.replica_version;
        let root_url = first_root_url(handle);
        block_on(async move {
            let rt = runtime_from_url(root_url);
            add_replica_version(&rt, replica_version)
                .await
                .expect("adding replica version failed.");
        });
    }

    fn update_subnet_by_idx(
        &self,
        handle: &IcHandle,
        subnet_index: usize,
        version: ReplicaVersion,
    ) {
        // get the subnet id of the subnet with index subnet index
        let reg_path = handle
            .ic_prep_working_dir
            .as_ref()
            .unwrap()
            .registry_local_store_path();
        let local_store = LocalStoreImpl::new(&reg_path);
        let changelog = local_store
            .get_changelog_since_version(RegistryVersion::from(0))
            .expect("Could not read registry.");

        // The initial registry may only contain a single version.
        let bytes = changelog
            .first()
            .expect("Empty changelog")
            .iter()
            .find_map(|k| {
                if k.key == make_subnet_list_record_key() {
                    Some(k.value.clone().expect("Subnet list not set"))
                } else {
                    None
                }
            })
            .expect("Subnet list not found");
        let subnet_list_record =
            SubnetListRecord::decode(&bytes[..]).expect("Could not decode subnet list record.");
        let subnet_id = SubnetId::from(
            PrincipalId::try_from(&subnet_list_record.subnets[subnet_index][..]).unwrap(),
        );

        let url = first_root_url(handle);
        // send the update proposal
        block_on(async move {
            let rt = runtime_from_url(url);
            update_subnet_replica_version(&rt, subnet_id, version.to_string())
                .await
                .expect("updating subnet failed");
        });
    }

    fn remove_node(&self, handle: &IcHandle, node_id: NodeId) {
        let rt = tokio::runtime::Runtime::new().expect("Tokio runtime failed to create");
        rt.block_on(async move {
            remove_node(handle, node_id).await.unwrap();
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UpgradeContent {
    All,
    Nodemanager,
    Replica,
}

pub fn first_root_url(ic_handle: &IcHandle) -> Url {
    ic_handle
        .public_api_endpoints
        .iter()
        .find(|i| i.is_root_subnet)
        .expect("empty iterator")
        .url
        .clone()
}

/// Installs the NNS canisters on the node given by `nc` using the initial
/// registry created by `ic-prep`, stored under `registry_local_store`.
pub fn install_nns_canisters(
    logger: &Logger,
    url: Url,
    ic_prep_state_dir: &IcPrepStateDir,
    nns_test_neurons_present: bool,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    info!(
        logger,
        "Compiling/installing NNS canisters (might take a while). See README.md of ic-fondue."
    );
    rt.block_on(async move {
        let mut init_payloads = NnsInitPayloadsBuilder::new();
        if nns_test_neurons_present {
            let mut ledger_balances = HashMap::new();
            ledger_balances.insert(
                LIFELINE_CANISTER_ID.get().into(),
                Tokens::from_tokens(10000).unwrap(),
            );
            ledger_balances.insert(
                (*TEST_USER1_PRINCIPAL).into(),
                Tokens::from_tokens(200000).unwrap(),
            );
            info!(logger, "Initial ledger: {:?}", ledger_balances);
            let mut ledger_init_payload = LedgerCanisterInitPayload::new(
                GOVERNANCE_CANISTER_ID.get().into(),
                ledger_balances,
                None,
                None,
                None,
                HashSet::new(),
            );
            ledger_init_payload
                .send_whitelist
                .insert(CYCLES_MINTING_CANISTER_ID);
            init_payloads
                .with_test_neurons()
                .with_ledger_init_state(ledger_init_payload);
        }
        let registry_local_store = ic_prep_state_dir.registry_local_store_path();
        let initial_mutations = read_initial_mutations_from_local_store_dir(registry_local_store);
        init_payloads.with_initial_mutations(initial_mutations);

        let agent = Agent::new(
            url,
            Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
        );
        let runtime = Runtime::Remote(RemoteTestRuntime { agent });

        NnsCanisters::set_up(&runtime, init_payloads.build()).await;
    });
}

/// Send an update-call to the governance-canister on the NNS asking for Subnet
/// `subnet_id` to be updated to replica with version id `replica_version_id`.
async fn update_subnet_replica_version(
    nns_api: &'_ Runtime,
    subnet_id: SubnetId,
    replica_version_id: String,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = UpdateSubnetReplicaVersionPayload {
        subnet_id: subnet_id.get(),
        replica_version_id,
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::UpdateSubnetReplicaVersion,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

/// Detect whether a proposal is executed within `timeout`.
///
/// # Arguments
///
/// * `ctx`         - Fondue context
/// * `governance`  - Governance canister
/// * `proposal_id` - ID of a proposal to be executed
/// * `retry_delay` - Duration between polling attempts
/// * `timeout`     - Duration after which we give up (returning false)
///
/// Eventually returns whether the proposal has been executed.
pub async fn await_proposal_execution(
    ctx: &fondue::pot::Context,
    governance: &Canister<'_>,
    proposal_id: ProposalId,
    retry_delay: Duration,
    timeout: Duration,
) -> bool {
    let mut i = 0usize;
    let start_time = std::time::Instant::now();
    loop {
        i += 1;
        info!(
            ctx.logger,
            "Attempt #{} of obtaining final execution status for {:?}", i, proposal_id
        );

        let proposal_info = get_proposal_info(governance, proposal_id)
            .await
            .unwrap_or_else(|| panic!("could not obtain proposal status"));

        match ProposalStatus::from_i32(proposal_info.status).unwrap() {
            ProposalStatus::Open => {
                // This proposal is still open
                info!(ctx.logger, "{:?} is open...", proposal_id,)
            }
            ProposalStatus::Adopted => {
                // This proposal is adopted but not yet executed
                info!(ctx.logger, "{:?} is adopted...", proposal_id,)
            }
            ProposalStatus::Executed => {
                // This proposal is already executed
                info!(ctx.logger, "{:?} has been executed.", proposal_id,);
                return true;
            }
            other_status => {
                // This proposal will not be executed
                info!(
                    ctx.logger,
                    "{:?} could not be adopted: {:?}", proposal_id, other_status
                );
                return false;
            }
        }

        if std::time::Instant::now()
            .duration_since(start_time)
            .gt(&timeout)
        {
            // Give up
            return false;
        } else {
            // Continue polling with delay
            sleep(retry_delay).await;
        }
    }
}

/// Detect whether a replica's status becomes acceptable within `timeout`.
///
/// # Arguments
///
/// * `ctx`                  - Fondue context
/// * `endpoint`             - Endpoint of
/// * `retry_delay`          - Duration between polling attempts
/// * `timeout`              - Duration after which we give up (returning false)
/// * `acceptance_criterium` - Predicate determining whether the current status
///   is accepted
///
/// Eventually returns whether the replica status has changed as specified via
/// `acceptance_criterium`.
pub async fn await_replica_status_change(
    ctx: &fondue::pot::Context,
    endpoint: &IcEndpoint,
    retry_delay: Duration,
    timeout: Duration,
    acceptance_criterium: impl Fn(&ic_agent::agent::status::Status) -> bool,
) -> bool {
    let start_time = std::time::Instant::now();
    let mut i = 0usize;
    loop {
        i += 1;
        info!(
            ctx.logger,
            "Attempt #{} of detecting replica status change", i
        );

        let status = get_replica_status(endpoint)
            .await
            .expect("Could not obtain new agent status");

        if acceptance_criterium(&status) {
            info!(
                ctx.logger,
                " status change has been accepted.\nNew status:\n{:?}", status
            );
            return true;
        }

        if std::time::Instant::now()
            .duration_since(start_time)
            .gt(&timeout)
        {
            // Give up
            info!(
                ctx.logger,
                " did not detect status change within {:?}.\nStatus remains:\n{:?}",
                timeout,
                status
            );
            return false;
        } else {
            // Continue polling with delay
            sleep(retry_delay).await;
        }
    }
}

/// Obtain the status of a replica via its `endpoint`.
///
/// Eventually returns the status of the replica.
async fn get_replica_status(
    endpoint: &IcEndpoint,
) -> Result<ic_agent::agent::status::Status, ic_agent::AgentError> {
    match create_agent(&endpoint.url.to_string()).await {
        Ok(agent) => agent.status().await,
        Err(e) => Err(e),
    }
}

/// Obtain the software version of a replica via its `endpoint`.
///
/// Eventually returns the replica software version.
pub async fn get_software_version(endpoint: &IcEndpoint) -> Option<ReplicaVersion> {
    match get_replica_status(endpoint).await {
        Ok(status) => status
            .impl_version
            .map(|v| ReplicaVersion::try_from(v).unwrap()),
        Err(_) => None,
    }
}

/// Adds the given `ReplicaVersionRecord` to the registry and returns the
/// registry version after the update.
async fn add_replica_version(nns_api: &'_ Runtime, version: ReplicaVersion) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = BlessReplicaVersionPayload {
        replica_version_id: version.to_string(),
        release_package_url: "".to_string(),
        release_package_sha256_hex: "".to_string(),
    };

    let proposal_id: ProposalId = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::BlessReplicaVersion,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;

    Ok(())
}

pub async fn update_xdr_per_icp(
    nns_api: &'_ Runtime,
    timestamp_seconds: u64,
    xdr_permyriad_per_icp: u64,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = ic_nns_common::types::UpdateIcpXdrConversionRatePayload {
        data_source: "".to_string(),
        timestamp_seconds,
        xdr_permyriad_per_icp,
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::IcpXdrConversionRate,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

pub async fn set_authorized_subnetwork_list(
    nns_api: &'_ Runtime,
    who: Option<PrincipalId>,
    subnets: Vec<SubnetId>,
) -> Result<(), String> {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = SetAuthorizedSubnetworkListArgs { who, subnets };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::SetAuthorizedSubnetworks,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    Ok(())
}

async fn remove_node(handle: &IcHandle, node_id: NodeId) -> Result<(), String> {
    let root_url = first_root_url(handle);
    let nns_api = runtime_from_url(root_url);
    let governance_canister = get_canister(&nns_api, GOVERNANCE_CANISTER_ID);
    let proposal_payload = RemoveNodesFromSubnetPayload {
        node_ids: vec![node_id],
    };

    let proposal_id = submit_external_update_proposal(
        &governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::RemoveNodesFromSubnet,
        proposal_payload,
        String::from("Remove node for testing"),
        "".to_string(),
    )
    .await;

    vote_and_execute_proposal(&governance_canister, proposal_id).await;
    Ok(())
}

pub fn get_canister(nns_api: &'_ Runtime, canister_id: CanisterId) -> Canister<'_> {
    Canister::new(nns_api, canister_id)
}

/// Votes for and executes the proposal identified by `proposal_id`. Asserts
/// that the ProposalStatus is Executed.
pub async fn vote_execute_proposal_assert_executed(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
) {
    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        vote_and_execute_proposal(governance_canister, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );
}

/// Votes for and executes the proposal identified by `proposal_id`. Asserts
/// that the ProposalStatus is Failed.
///
/// It is also verified that the rejection message contains (case-insensitive)
/// expected_message_substring. This can be left empty to guarantee a match when
/// not needed.
pub async fn vote_execute_proposal_assert_failed(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
    expected_message_substring: impl ToString,
) {
    let expected_message_substring = expected_message_substring.to_string();
    // Wait for the proposal to be accepted and executed.
    let proposal_info = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(proposal_info.status(), ProposalStatus::Failed);
    let reason = proposal_info.failure_reason.unwrap_or_default();
    assert!(
       reason
            .error_message
            .to_lowercase()
            .contains(expected_message_substring.to_lowercase().as_str()),
        "Rejection error for proposal {}, which is '{}', does not contain the expected substring '{}'",
        proposal_id,
        reason,
        expected_message_substring
    );
}

pub async fn vote_and_execute_proposal(
    governance_canister: &Canister<'_>,
    proposal_id: ProposalId,
) -> ProposalInfo {
    // Cast votes.
    let input = ManageNeuron {
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
            ic_nns_common::pb::v1::NeuronId {
                id: TEST_NEURON_1_ID,
            },
        )),
        id: None,
        command: Some(Command::RegisterVote(RegisterVote {
            vote: Vote::Yes as i32,
            proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id.0 }),
        })),
    };
    let _result: ManageNeuronResponse = governance_canister
        .update_from_sender(
            "manage_neuron",
            candid_one,
            input,
            &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        )
        .await
        .expect("Vote failed");
    wait_for_final_state(governance_canister, proposal_id).await
}

pub fn get_governance_canister(nns_api: &'_ Runtime) -> Canister<'_> {
    get_canister(nns_api, GOVERNANCE_CANISTER_ID)
}

pub async fn submit_external_proposal_with_test_id<T: CandidType>(
    governance_canister: &Canister<'_>,
    nns_function: NnsFunction,
    payload: T,
) -> ProposalId {
    let sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let neuron_id = NeuronId(TEST_NEURON_1_ID);
    submit_external_update_proposal(
        governance_canister,
        sender,
        neuron_id,
        nns_function,
        payload,
        "<proposal created by submit_external_proposal_with_test_id>".to_string(),
        "".to_string(),
    )
    .await
}

/// Submits a proposal for blessing a replica software version.
///
/// # Arguments
///
/// * `governance`  - Governance canister
/// * `sender`      - Sender of the proposal
/// * `neuron_id`   - ID of the proposing neuron. This neuron will automatically
///   vote in favor of the proposal.
/// * `version`     - Replica software version
/// * `sha256`      - Claimed SHA256 of the replica image file
/// * `upgrade_url` - URL leading to the replica image file
///
/// Note: The existing replica *may or may not* check that the
/// provided `sha256` corresponds to the image checksum. In case
/// this proposal is adopted, the replica *assumes* that the file
/// under `upgrade_url` has the provided `sha256`. If there has
/// been a mismatch (or if the image has been forged after blessing),
/// the replica will reject the follow-up proposal for updating the
/// replica version.
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_bless_replica_version_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: ReplicaVersion,
    sha256: String,
    upgrade_url: String,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::BlessReplicaVersion,
        BlessReplicaVersionPayload {
            replica_version_id: String::from(version.clone()),
            release_package_url: upgrade_url,
            release_package_sha256_hex: sha256.clone(),
        },
        format!(
            "Bless replica version: {} with hash: {}",
            String::from(version),
            sha256
        ),
        "".to_string(),
    )
    .await
    .expect("submit_bless_replica_version_proposal failed")
}

/// Submits a proposal for updating a subnet replica software version.
///
/// # Arguments
///
/// * `governance`  - Governance canister
/// * `sender`      - Sender of the proposal
/// * `neuron_id`   - ID of the proposing neuron. This neuron will automatically
///   vote in favor of the proposal.
/// * `version`     - Replica software version
/// * `subnet_id`   - ID of the subnet to be updated
///
/// Note: The existing replica *must* check that the new replica image
/// has the expected SHA256. If there is a mismatch, then this proposal
/// must eventually fail.
///
/// Eventually returns the identifier of the newly submitted proposal.
pub async fn submit_update_subnet_replica_version_proposal(
    governance: &Canister<'_>,
    sender: Sender,
    neuron_id: NeuronId,
    version: ReplicaVersion,
    subnet_id: SubnetId,
) -> ProposalId {
    submit_external_update_proposal_allowing_error(
        governance,
        sender,
        neuron_id,
        NnsFunction::UpdateSubnetReplicaVersion,
        UpdateSubnetReplicaVersionPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: String::from(version.clone()),
        },
        format!(
            "Update {} subnet's replica version to: {}",
            subnet_id,
            String::from(version)
        ),
        "".to_string(),
    )
    .await
    .expect("submit_update_subnet_replica_version_proposal failed")
}
