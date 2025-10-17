#![allow(deprecated)]
use crate::{
    canister_api::CanisterApi,
    pb::v1::{
        AddWasmRequest, AddWasmResponse, DappCanistersTransferResult, DeployNewSnsRequest,
        DeployNewSnsResponse, DeployedSns, GetDeployedSnsByProposalIdRequest,
        GetDeployedSnsByProposalIdResponse, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
        GetProposalIdThatAddedWasmRequest, GetProposalIdThatAddedWasmResponse,
        GetSnsSubnetIdsResponse, GetWasmMetadataRequest as GetWasmMetadataRequestPb,
        GetWasmMetadataResponse as GetWasmMetadataResponsePb, GetWasmRequest, GetWasmResponse,
        InsertUpgradePathEntriesRequest, InsertUpgradePathEntriesResponse,
        ListDeployedSnsesRequest, ListDeployedSnsesResponse, ListUpgradeStep,
        ListUpgradeStepsRequest, ListUpgradeStepsResponse, MetadataSection as MetadataSectionPb,
        SnsCanisterIds, SnsCanisterType, SnsUpgrade, SnsVersion, SnsWasm, SnsWasmError,
        SnsWasmStableIndex, StableCanisterState, UpdateSnsSubnetListRequest,
        UpdateSnsSubnetListResponse, add_wasm_response,
    },
    stable_memory::SnsWasmStableMemory,
    wasm_metadata::MetadataSection,
};
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::stable::StableMemory;
use ic_nervous_system_clients::canister_id_record::CanisterIdRecord;
use ic_nervous_system_common::{ONE_TRILLION, SNS_CREATION_FEE, hash_to_hex_string};
use ic_nervous_system_proto::pb::v1::Canister;
use ic_nns_constants::{
    DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT,
    DEFAULT_SNS_NON_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_handler_root_interface::{
    ChangeCanisterControllersRequest, ChangeCanisterControllersResult,
    client::NnsRootCanisterClient,
};
use ic_sns_governance::pb::v1::governance::Version;
use ic_sns_init::{SnsCanisterInitPayloads, pb::v1::SnsInitPayload};
use ic_sns_root::GetSnsCanistersSummaryResponse;
use ic_types::{Cycles, SubnetId};
use ic_wasm;
use maplit::{btreemap, hashmap};
use serde_json::{Value as JsonValue, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    convert::TryInto,
    iter::zip,
    thread::LocalKey,
};

use ic_cdk::println;

const LOG_PREFIX: &str = "[SNS-WASM] ";

const INITIAL_CANISTER_CREATION_CYCLES: u64 = 3 * ONE_TRILLION;

/// The number of canisters that the SNS-WASM canister will install when deploying
/// an SNS. This constant is different than `SNS_CANISTER_COUNT` due to the Archive
/// canister being spawned by the Ledger canister, and not the directly by the
/// SNS-WASM canister. The canisters being installed are the:
///   - SNS Governance Canister
///   - SNS Root Canister
///   - SNS Swap Canister
///   - ICRC Ledger Canister
///   - ICRC Index Canister
pub const SNS_CANISTER_COUNT_AT_INSTALL: u64 = 5;

/// The total number of SNS canister types that make up an SNS. These are:
///   - SNS Governance Canister
///   - SNS Root Canister
///   - SNS Swap Canister
///   - ICRC Ledger Canister
///   - ICRC Index Canister
///   - ICRC Ledger Archive Canister
pub const SNS_CANISTER_TYPE_COUNT: u64 = 6;

impl From<SnsCanisterIds> for DeployedSns {
    fn from(src: SnsCanisterIds) -> Self {
        Self {
            root_canister_id: src.root,
            governance_canister_id: src.governance,
            ledger_canister_id: src.ledger,
            swap_canister_id: src.swap,
            index_canister_id: src.index,
        }
    }
}

/// The struct that implements the public API of the canister
#[derive(Clone, Default)]
pub struct SnsWasmCanister<M: StableMemory + Clone + Default>
where
    SnsWasmCanister<M>: From<StableCanisterState>,
{
    /// A map from WASM hash to the index of this WASM in stable memory
    pub wasm_indexes: BTreeMap<[u8; 32], SnsWasmStableIndex>,
    /// Allowed subnets for SNSes to be installed
    pub sns_subnet_ids: Vec<SubnetId>,
    /// Stored deployed_sns instances
    pub deployed_sns_list: Vec<DeployedSns>,
    /// Specifies the upgrade path for SNS instances
    pub upgrade_path: UpgradePath,
    /// Provides convenient access to stable memory
    pub stable_memory: SnsWasmStableMemory<M>,
    /// If true, updates (e.g. add_wasm) can only be made by NNS Governance
    /// (via proposal execution), otherwise updates can be made by any caller
    pub access_controls_enabled: bool,
    /// List of principals that are allowed to deploy an SNS
    pub allowed_principals: Vec<PrincipalId>,
    /// Map of nns proposal id to index in the `deployed_sns_list`.
    pub nns_proposal_to_deployed_sns: BTreeMap<u64, u64>,
}

/// Internal implementation to give the wasms we explicitly handle a name (instead of Vec<u8>) for
/// safer handling in our internal logic.  This is not intended to be persisted outside of method logic
struct SnsWasmsForDeploy {
    root: Vec<u8>,
    governance: Vec<u8>,
    ledger: Vec<u8>,
    swap: Vec<u8>,
    index: Vec<u8>,
}

/// Internal structure representing a canister that failed to have its controllers changed
/// and the reason why.
struct FailedChangeCanisterControllersRequest {
    canister: Canister,
    reason: String,
}

/// Internal structure representing the results of having the controllers changed of
/// a list of canisters. This structure captures which canisters successfully had their
/// controllers changed, and which canisters failed to have their controllers changed.
/// This is especially important when dealing with irreversible controller-ship changes
/// where NNS Root may no longer have control and be able to return the dapps to
/// their original controllers.
struct FailedChangeCanisterControllersResult {
    successful: Vec<Canister>,
    failed: Vec<FailedChangeCanisterControllersRequest>,
}

impl FailedChangeCanisterControllersResult {
    fn new() -> Self {
        Self {
            successful: vec![],
            failed: vec![],
        }
    }

    fn get_failed_canisters(&self) -> Vec<Canister> {
        self.failed.iter().map(|f| f.canister).collect()
    }

    fn get_successful_canisters(&self) -> Vec<Canister> {
        self.successful.clone()
    }

    fn join_failed_reasons(&self) -> String {
        self.failed
            .iter()
            .map(
                |FailedChangeCanisterControllersRequest { canister, reason }| {
                    format!("Canister: {canister:?}. Failure Reason: {reason:?}.")
                },
            )
            .collect::<Vec<String>>()
            .join("\n")
    }
}

/// Helper function to create a DeployError::Validation(ValidationDeployError {})
/// Directly returns the error (unlike other two helpers)
fn validation_deploy_error(message: String) -> DeployError {
    DeployError::Validation(ValidationDeployError { message })
}

/// Concatenates error messages from a vector of Result<(), String>, if one or more errors is found
fn join_errors_or_ok(results: Vec<Result<(), String>>) -> Result<(), String> {
    if results.iter().any(|r| r.is_err()) {
        Err(results
            .into_iter()
            .flat_map(|result| result.err())
            .collect::<Vec<_>>()
            .join("\n"))
    } else {
        Ok(())
    }
}

/// Extracts key value pairs from a BtreeMap based on a list of input keys.
fn extract_keys<K: Ord + Clone, V: Clone>(map: &BTreeMap<K, V>, keys: &[K]) -> BTreeMap<K, V> {
    keys.iter()
        .filter_map(|key| map.get(key).map(|value| (key.clone(), value.clone())))
        .collect()
}

enum DeployError {
    Validation(ValidationDeployError),
    Reversible(ReversibleDeployError),
    PartiallyReversible(PartiallyReversibleDeployError),
}

/// Error in preconditions
struct ValidationDeployError {
    /// The error message to be returned externally
    message: String,
}

/// Struct representing an error that can be cleaned up
#[derive(Clone)]
struct ReversibleDeployError {
    /// The error message to be returned externally
    message: String,
    /// Canisters created that need to be cleaned up
    canisters_to_delete: Option<SnsCanisterIds>,
    /// Subnet where canister_to_delete live (which is returned when cleanup fails)
    subnet: Option<SubnetId>,
    /// Dapp canisters that need to be restored to their original controllers
    dapp_canisters_to_restore: BTreeMap<Canister, Vec<PrincipalId>>,
}

/// Struct representing an error that can be partially cleaned up
struct PartiallyReversibleDeployError {
    /// The error message to be returned externally
    message: String,
    /// Canisters created that cannot be cleaned up (as they are no longer controlled by SNS-W)
    canisters_created: Option<SnsCanisterIds>,
    /// Subnet where canisters_created that cannot be cleaned up are deployed to
    subnet: Option<SubnetId>,
    /// Dapp canisters that need to be restored to their original controllers
    dapp_canisters_to_restore: BTreeMap<Canister, Vec<PrincipalId>>,
    /// Dapp canisters that are no longer under the control of NNS Root and therefore
    /// cannot be returned. This could be because they were never under control of the
    /// NNS Root canister, or have been transferred to the SNS.
    non_controlled_dapp_canisters: Vec<Canister>,
}

impl From<DeployError> for DeployNewSnsResponse {
    fn from(error: DeployError) -> Self {
        match error {
            DeployError::Validation(validation_error) => DeployNewSnsResponse {
                subnet_id: None,
                canisters: None,
                error: Some(SnsWasmError {
                    message: validation_error.message,
                }),
                dapp_canisters_transfer_result: None,
            },
            DeployError::Reversible(_) => {
                panic!(
                    "Do not try to use into() for DeployError::Reversible as this should be cleaned up"
                )
            }
            DeployError::PartiallyReversible(_) => {
                panic!(
                    "Do not try to use into() for DeployError::PartiallyReversible as this should be cleaned up"
                )
            }
        }
    }
}

impl<M: StableMemory + Clone + Default> SnsWasmCanister<M>
where
    SnsWasmCanister<M>: From<StableCanisterState>,
{
    pub fn new() -> Self {
        SnsWasmCanister::<M>::default()
    }

    pub fn set_sns_subnets(&mut self, subnet_ids: Vec<SubnetId>) {
        self.sns_subnet_ids = subnet_ids;
    }

    pub fn set_access_controls_enabled(&mut self, access_controls_enabled: bool) {
        self.access_controls_enabled = access_controls_enabled;
    }

    pub fn set_allowed_principals(&mut self, allowed_principals: Vec<PrincipalId>) {
        self.allowed_principals = allowed_principals;
    }

    /// Initialize stable memory. Should only be called on canister init.
    pub fn initialize_stable_memory(&self) {
        self.stable_memory
            .init()
            .expect("Failed to initialize stable memory")
    }

    /// Returns the amount of stable memory (in bytes) that SNS-WASM has used to store WASMs
    pub fn get_stable_memory_usage(&self) -> u32 {
        self.stable_memory
            .read_wasms_end_offset()
            .expect("Unable to get stable memory usage")
    }

    /// Returns an Option(SnsWasm) in the GetWasmResponse (a struct with wasm bytecode and the install target)
    pub fn get_wasm(&self, get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
        let hash = vec_to_hash(get_wasm_payload.hash).unwrap();
        GetWasmResponse {
            wasm: self.read_wasm(&hash),
        }
    }

    /// Returns an Option(ProposalId) in the GetProposalIdThatAddedWasmResponse (a struct with the proposal ID
    /// that blessed the given wasm hash)
    pub fn get_proposal_id_that_added_wasm(
        &self,
        payload: GetProposalIdThatAddedWasmRequest,
    ) -> GetProposalIdThatAddedWasmResponse {
        let hash = vec_to_hash(payload.hash).unwrap();
        GetProposalIdThatAddedWasmResponse {
            proposal_id: self
                .read_wasm(&hash)
                .and_then(|sns_wasm| sns_wasm.proposal_id),
        }
    }

    /// Read a WASM with the given hash from stable memory, if such a WASM exists.
    fn read_wasm(&self, hash: &[u8; 32]) -> Option<SnsWasm> {
        self.wasm_indexes
            .get(hash)
            .and_then(|index| self.stable_memory.read_wasm(index.offset, index.size).ok())
    }

    pub fn get_wasm_metadata(
        &self,
        get_wasm_metadata_payload: GetWasmMetadataRequestPb,
    ) -> GetWasmMetadataResponsePb {
        let get_wasm_metadata_impl = move || {
            let hash = <[u8; 32]>::try_from(get_wasm_metadata_payload)?;

            let Some(SnsWasmStableIndex { metadata, .. }) = self.wasm_indexes.get(&hash) else {
                return Err(format!("Cannot find WASM index for hash `{hash:?}`."));
            };
            let metadata = match metadata
                .iter()
                .cloned()
                .map(MetadataSection::try_from)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(metadata) => metadata,
                Err(err) => {
                    let err = format!(
                        "Inconsistent state detected in WASM metadata for hash `{hash:?}`: {err}"
                    );
                    println!("{}{}", LOG_PREFIX, err);
                    return Err(err);
                }
            };
            Ok(metadata)
        };
        let result = get_wasm_metadata_impl();
        GetWasmMetadataResponsePb::from(result)
    }

    /// Try reading the metadata sections of a WASM with the given hash from stable memory,
    /// if such a WASM exists.
    fn read_wasm_metadata_or_err(wasm: &SnsWasm) -> Result<Vec<MetadataSection>, String> {
        use ic_wasm::{metadata, utils};

        // We don't care for symbol names in the WASM module as we just want the custom sections
        // containing the metadata.
        let wasm_module = utils::parse_wasm(&wasm.wasm, false)
            .map_err(|err| format!("Cannot parse WASM: {err}"))?;

        let sections = metadata::list_metadata(&wasm_module);

        let sections = sections
            .into_iter()
            .filter_map(|section| {
                let mut section: Vec<&str> = section.split(' ').collect();
                if section.is_empty() {
                    // This cannot practically happen, as it would imply that all characters of
                    // the section are whitespaces.
                    return None;
                }
                // Save this section's visibility specification, e.g. "icp:public" or "icp:private".
                let visibility = section.remove(0).to_string();

                // The conjunction of the remaining parts are the section's name.
                let name = section.join(" ");

                // Read the actual contents of this section.
                let contents = metadata::get_metadata(&wasm_module, &name);

                // Represent the absence of contents as an empty byte vector.
                let contents = if let Some(contents) = contents {
                    contents.to_vec()
                } else {
                    vec![]
                };

                Some(MetadataSection {
                    visibility,
                    name,
                    contents,
                })
            })
            .collect();

        Ok(sections)
    }

    /// Adds a WASM to the canister's storage, validating that the expected hash matches that of the
    /// provided WASM bytecode.
    pub fn add_wasm(&mut self, add_wasm_payload: AddWasmRequest) -> AddWasmResponse {
        let AddWasmRequest {
            wasm,
            hash,
            skip_update_latest_version,
        } = add_wasm_payload;
        let wasm = wasm.expect("Wasm is required");

        let sns_canister_type = match wasm.checked_sns_canister_type() {
            Ok(canister_type) => canister_type,
            Err(message) => {
                println!(
                    "{}add_wasm invalid sns_canister_type: {}",
                    LOG_PREFIX, &message
                );

                return AddWasmResponse {
                    result: Some(add_wasm_response::Result::Error(SnsWasmError { message })),
                };
            }
        };

        let hash = vec_to_hash(hash).expect("Hash provided was not 32 bytes (i.e. [u8;32])");

        let skip_update_latest_version = skip_update_latest_version.unwrap_or(false);

        if hash != wasm.sha256_hash() {
            return AddWasmResponse {
                result: Some(add_wasm_response::Result::Error(SnsWasmError {
                    message: format!(
                        "Invalid Sha256 given for submitted WASM bytes. Provided hash was '{}' \
                         but calculated hash was '{}'",
                        hash_to_hex_string(&hash),
                        wasm.sha256_string()
                    ),
                })),
            };
        }

        let metadata = match Self::read_wasm_metadata_or_err(&wasm) {
            Ok(metadata) => metadata,
            Err(err) => {
                println!("err = {}, wasm = `{:?}`", err, wasm);
                return AddWasmResponse {
                    result: Some(add_wasm_response::Result::Error(SnsWasmError {
                        message: format!("Cannot read metadata sections from WASM: {err}"),
                    })),
                };
            }
        };

        let metadata = metadata
            .into_iter()
            .map(|metadata| {
                metadata
                    .validate()
                    .map(|_| MetadataSectionPb::from(metadata))
            })
            .collect::<Result<Vec<_>, _>>();

        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(err) => {
                return AddWasmResponse {
                    result: Some(add_wasm_response::Result::Error(SnsWasmError {
                        message: format!("Cannot validate metadata sections from WASM: {err}"),
                    })),
                };
            }
        };

        // Get the new latest version unless skip_update_latest_version is true.
        let new_latest_version = if skip_update_latest_version {
            None
        } else {
            // This function is fallible (as it checks for cycles in the upgrade path), but it has no side-effects.
            // So we want to try it first, and only if it succeeds, proceed to write the WASM to stable memory.
            let maybe_new_latest_version = self
                .upgrade_path
                .get_new_latest_version(sns_canister_type, &hash);

            match maybe_new_latest_version {
                Ok(new_latest_version) => Some(new_latest_version),
                Err(err) => {
                    return AddWasmResponse {
                        result: Some(add_wasm_response::Result::Error(SnsWasmError {
                            message: err,
                        })),
                    };
                }
            }
        };

        let result = match self.stable_memory.write_wasm(wasm) {
            Ok((offset, size)) => {
                self.wasm_indexes.insert(
                    hash,
                    SnsWasmStableIndex {
                        hash: hash.to_vec(),
                        offset,
                        size,
                        metadata,
                    },
                );

                if let Some(new_latest_version) = new_latest_version {
                    self.upgrade_path.add_wasm(new_latest_version);
                }

                add_wasm_response::Result::Hash(hash.to_vec())
            }
            Err(e) => {
                println!("{}add_wasm unable to persist WASM: {}", LOG_PREFIX, e);

                add_wasm_response::Result::Error(SnsWasmError {
                    message: format!("Unable to persist WASM: {e}"),
                })
            }
        };
        let result = Some(result);

        AddWasmResponse { result }
    }

    /// Insert upgrade path entries for the general path or for an SNS-specific path.
    pub fn insert_upgrade_path_entries(
        &mut self,
        request: InsertUpgradePathEntriesRequest,
    ) -> InsertUpgradePathEntriesResponse {
        let InsertUpgradePathEntriesRequest {
            upgrade_path,
            sns_governance_canister_id,
        } = request;

        let sns_governance_canister_id = match sns_governance_canister_id {
            None => None,
            Some(id) => match CanisterId::try_from(id) {
                Ok(canister_id) => Some(canister_id),
                Err(_) => {
                    return InsertUpgradePathEntriesResponse::error(format!(
                        "Request.sns_governance_canister_id ({id}) \
                        could not be converted to a canister ID"
                    ));
                }
            },
        };

        if upgrade_path.is_empty() {
            return InsertUpgradePathEntriesResponse::error(
                "No Upgrade Paths in request. No action taken.".to_string(),
            );
        }

        let mut versions_submitted = vec![];
        for upgrade_step in &upgrade_path {
            let SnsUpgrade {
                current_version,
                next_version,
            } = upgrade_step.clone();

            if current_version.is_none() || next_version.is_none() {
                return InsertUpgradePathEntriesResponse::error(
                    "A provided SnsUpgrade entry does not have a current_version or next_version"
                        .to_string(),
                );
            }
            versions_submitted.append(&mut current_version.unwrap().version_hashes());
            versions_submitted.append(&mut next_version.unwrap().version_hashes());
        }
        let versions_submitted: HashSet<Vec<u8>> = versions_submitted.into_iter().collect();

        // Ensure we have the WASMs in the submitted versions, otherwise the SNS could not execute
        // the upgrade request.
        for version in versions_submitted {
            let hash = match vec_to_hash(version) {
                Ok(h) => h,
                Err(e) => return InsertUpgradePathEntriesResponse::error(e),
            };
            if !self.wasm_indexes.contains_key(&hash) {
                return InsertUpgradePathEntriesResponse::error(
                    "Upgrade paths include WASM hashes that do not reference WASMs known by SNS-W"
                        .to_string(),
                );
            }
        }

        // Ensure the governance canister in the request belongs to a known SNS.
        if let Some(sns_governance_canister_id) = sns_governance_canister_id {
            // Note, if we ever get a substantial list here, we should make a data structure to
            // make this faster.
            if !self.deployed_sns_list.iter().any(|deployment| {
                deployment.governance_canister_id.is_some()
                    && deployment.governance_canister_id.unwrap()
                        == sns_governance_canister_id.into()
            }) {
                return InsertUpgradePathEntriesResponse::error(format!(
                    "Cannot add custom upgrade path for non-existent SNS.  Governance canister {sns_governance_canister_id} \
                     not found in list of deployed SNSes."
                ));
            }
        }

        if let Some(sns_governance_canister_id) = sns_governance_canister_id {
            for upgrade_step in upgrade_path {
                self.upgrade_path.insert_sns_specific_upgrade_path_entry(
                    upgrade_step.current_version.unwrap(),
                    upgrade_step.next_version.unwrap(),
                    sns_governance_canister_id,
                );
            }
        } else {
            for upgrade_step in upgrade_path {
                self.upgrade_path.insert_upgrade_path_entry(
                    upgrade_step.current_version.unwrap(),
                    upgrade_step.next_version.unwrap(),
                );
            }
        }

        InsertUpgradePathEntriesResponse { error: None }
    }

    /// List the upgrade steps in human-readable form from a given starting point
    /// If a canister is provided, interleave custom entries.  If not, use default only
    /// If a starting_at version is provided, do not list versions before the given version,
    /// otherwise, list all known versions
    pub fn list_upgrade_steps(&self, payload: ListUpgradeStepsRequest) -> ListUpgradeStepsResponse {
        let ListUpgradeStepsRequest {
            starting_at,
            sns_governance_canister_id,
            limit,
        } = payload;

        // TODO extract this constant
        let limit = if limit == 0 { 200 } else { limit };

        let sns_governance_canister_id =
            sns_governance_canister_id.unwrap_or_else(PrincipalId::new_anonymous);
        // Note, if we retire parts of the version path, we will need to
        // update this, or store it somewhere
        let mut current_version = starting_at.unwrap_or_else(|| SnsVersion {
            root_wasm_hash: vec![],
            governance_wasm_hash: vec![],
            ledger_wasm_hash: vec![],
            swap_wasm_hash: vec![],
            archive_wasm_hash: vec![],
            index_wasm_hash: vec![],
        });

        let mut versions = vec![current_version.clone()];

        for _ in 0..limit {
            let next_version = match self
                .upgrade_path
                .get_next_version(current_version, sns_governance_canister_id)
            {
                None => break,
                Some(v) => v,
            };

            versions.push(next_version.clone());
            current_version = next_version;
        }

        ListUpgradeStepsResponse {
            steps: versions
                .into_iter()
                .filter(|v| v.is_complete_version())
                .map(ListUpgradeStep::new)
                .collect(),
        }
    }

    /// Returns a list of Deployed SNS root CanisterId's and the subnet they were deployed to.
    pub fn list_deployed_snses(
        &self,
        _list_sns_payload: ListDeployedSnsesRequest,
    ) -> ListDeployedSnsesResponse {
        ListDeployedSnsesResponse {
            instances: self.deployed_sns_list.clone(),
        }
    }

    /// Returns a JSON string of the metrics service discovery for the deployed SNSes.
    pub fn get_metrics_service_discovery(&self) -> String {
        let mut canister_ids_by_type: BTreeMap<&'static str, Vec<PrincipalId>> = BTreeMap::new();

        let mut add_canister_id_to_map =
            |canister_type: &'static str, canister_id: Option<PrincipalId>| {
                if let Some(canister_id) = canister_id {
                    canister_ids_by_type
                        .entry(canister_type)
                        .or_default()
                        .push(canister_id);
                }
            };

        for sns in self.deployed_sns_list.iter() {
            add_canister_id_to_map("root", sns.root_canister_id);
            add_canister_id_to_map("governance", sns.governance_canister_id);
            add_canister_id_to_map("ledger", sns.ledger_canister_id);
            add_canister_id_to_map("swap", sns.swap_canister_id);
            add_canister_id_to_map("index", sns.index_canister_id);
            // We can't add the archive canisters as the SNS-WASM canister is not aware of them.
        }

        let targets_groups: Vec<_> = canister_ids_by_type
            .into_iter()
            .map(|(canister_type, canister_ids)| {
                let targets: Vec<_> = canister_ids
                    .into_iter()
                    .map(|canister_id| json!(format!("{canister_id}.raw.icp0.io")))
                    .collect();

                json! ({
                    "targets": JsonValue::Array(targets),
                    "labels": json! ({
                        "sns_canister_type": canister_type,
                        "__metrics_path__": "/metrics",
                    }),
                })
            })
            .collect();

        JsonValue::Array(targets_groups).to_string()
    }

    /// Deploys a new SNS based on the parameters of the payload
    ///
    /// Main actions that this performs:
    ///   1. Transfers control of the dapp_canisters to only NNS Root.
    ///   2. Creates the canisters.
    ///   3. Installs SNS root, SNS governance, SNS ledger and SNS index WASMs onto the created canisters.
    ///   4. Fund canisters with cycles
    ///   5. Sets the canisters' controllers:
    ///       * Root is controlled only by Governance.
    ///       * Governance is controlled only by Root.
    ///       * Ledger is controlled only by Root.
    ///       * Index is controlled only by Root.
    ///   6. Transfers control of the dapp_canisters from NNS Root to SNS Root.
    ///
    /// Step 3 requires installation parameters which come from the SnsInitPayload object
    /// included in DeployNewSnsRequest. This adds the created canister IDs to the payloads
    /// so that the SNS canisters know each other's Canister IDs at installation time, which is a
    /// requirement of the SNS deployment.
    ///
    /// In case any operations fail, we try our best to back out of previous changes,
    /// but that is not always possible. Further recovery by the caller may be required in case of failure.
    pub async fn deploy_new_sns(
        thread_safe_sns: &'static LocalKey<RefCell<SnsWasmCanister<M>>>,
        canister_api: &impl CanisterApi,
        nns_root_canister_client: &impl NnsRootCanisterClient,
        deploy_new_sns_payload: DeployNewSnsRequest,
        caller: PrincipalId,
    ) -> DeployNewSnsResponse {
        if caller != GOVERNANCE_CANISTER_ID.get() {
            return DeployNewSnsResponse::from(validation_deploy_error(
                "Only the NNS Governance may deploy a new SNS instance.".to_string(),
            ));
        }
        match Self::do_deploy_new_sns(
            thread_safe_sns,
            canister_api,
            nns_root_canister_client,
            deploy_new_sns_payload,
        )
        .await
        {
            Ok((subnet_id, canisters, dapp_canisters)) => DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(canisters),
                error: None,
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: dapp_canisters,
                }),
            },
            Err(DeployError::Reversible(reversible)) => {
                // Attempt to clean up after normal failures.
                Self::try_cleanup_reversible_deploy_error(
                    canister_api,
                    nns_root_canister_client,
                    reversible,
                )
                .await
            }
            Err(DeployError::PartiallyReversible(partially_reversible)) => {
                // Attempt to clean up after abnormal failures.
                Self::try_cleanup_partially_reversible_deploy_error(
                    nns_root_canister_client,
                    partially_reversible,
                )
                .await
            }
            // The rest are conversions as no additional processing is needed
            Err(e) => e.into(),
        }
    }

    async fn do_deploy_new_sns(
        thread_safe_sns: &'static LocalKey<RefCell<SnsWasmCanister<M>>>,
        canister_api: &impl CanisterApi,
        nns_root_canister_client: &impl NnsRootCanisterClient,
        deploy_new_sns_request: DeployNewSnsRequest,
    ) -> Result<(SubnetId, SnsCanisterIds, Vec<Canister>), DeployError> {
        let sns_init_payload = deploy_new_sns_request
            .get_and_validate_sns_init_payload()
            .map_err(validation_deploy_error)?;

        let dapp_canisters = &sns_init_payload
            .dapp_canisters
            .as_ref()
            .map(|dapp_canisters| dapp_canisters.canisters.as_slice())
            .unwrap_or_default();

        let subnet_id = thread_safe_sns
            .with(|sns_canister| sns_canister.borrow().get_available_sns_subnet())
            .map_err(validation_deploy_error)?;

        // Ensure we have WASMs available to install before proceeding (avoid unnecessary cleanup)
        let latest_wasms = thread_safe_sns
            .with(|sns_wasms| sns_wasms.borrow().get_latest_version_wasms())
            .map_err(validation_deploy_error)?;

        canister_api
            .this_canister_has_enough_cycles(SNS_CREATION_FEE)
            .map_err(validation_deploy_error)?;

        // Get the current controllers of each of the dapp_canisters in case of deployment errors.
        // The dapps will be returned to these controllers because it is not necessarily true
        // that fallback_controller_ids == dapp_canisters_original_controllers.
        let dapp_canisters_original_controllers: BTreeMap<Canister, Vec<PrincipalId>> =
            Self::get_original_dapp_controllers(nns_root_canister_client, dapp_canisters)
                .await
                .map_err(|err| {
                    DeployError::Reversible(ReversibleDeployError {
                        message: err,
                        canisters_to_delete: None,
                        subnet: None,
                        dapp_canisters_to_restore: btreemap! {}, // None to restore as no work was done
                    })
                })?;

        // Request that NNS Root claim sole control of all dapp_canisters. If there are any failures
        // the SNS creation process cannot continue. This may be due to dapp co-controllers backing
        // out of the terms of the decentralization process.
        let dapp_canister_to_new_controllers: BTreeMap<Canister, Vec<PrincipalId>> = dapp_canisters
            .iter()
            .map(|canister| (*canister, vec![ROOT_CANISTER_ID.get()]))
            .collect();
        Self::change_controllers_of_nns_root_owned_canisters(
            nns_root_canister_client,
            &dapp_canister_to_new_controllers,
        )
        .await
        // If any requests to change the controllers of the dapps fail, all dapp_canisters should
        // be returned to their original controllers.
        .map_err(|err| {
            DeployError::PartiallyReversible(PartiallyReversibleDeployError {
                message: "Could not change the controller of all dapp canisters to NNS Root."
                    .to_string(),
                canisters_created: None,
                subnet: None,
                dapp_canisters_to_restore: extract_keys(
                    &dapp_canisters_original_controllers,
                    &err.get_successful_canisters(),
                ),
                non_controlled_dapp_canisters: err.get_failed_canisters(),
            })
        })?;

        // After this step, we need to delete the canisters if things fail
        let sns_canisters =
            Self::create_sns_canisters(canister_api, subnet_id, INITIAL_CANISTER_CREATION_CYCLES)
                .await
                .map_err(|(message, canisters_to_delete)| {
                    DeployError::Reversible(ReversibleDeployError {
                        message,
                        canisters_to_delete,
                        subnet: Some(subnet_id),
                        dapp_canisters_to_restore: dapp_canisters_original_controllers.to_owned(),
                    })
                })?;

        // This step should never fail unless the step before it fails which would return
        // an error.
        let sns_init_canister_ids = sns_canisters.try_into().expect(
            "This should never happen. Failed to convert SnsCanisterIds into correct type.",
        );

        let latest_version = thread_safe_sns
            .with(|sns_wasms| sns_wasms.borrow().upgrade_path.latest_version.clone());
        // If that works, build the payloads
        let initial_payloads = sns_init_payload
            .build_canister_payloads(
                &sns_init_canister_ids,
                Some(Version {
                    root_wasm_hash: latest_version.root_wasm_hash,
                    governance_wasm_hash: latest_version.governance_wasm_hash,
                    ledger_wasm_hash: latest_version.ledger_wasm_hash,
                    swap_wasm_hash: latest_version.swap_wasm_hash,
                    archive_wasm_hash: latest_version.archive_wasm_hash,
                    index_wasm_hash: latest_version.index_wasm_hash,
                }),
                false,
            )
            // NOTE: This error path is not under test, because validate(), called above, should
            // ensure this can never be triggered where validate() would succeed.
            .map_err(|e| {
                DeployError::Reversible(ReversibleDeployError {
                    message: format!("build_canister_payloads failed: {e}"),
                    canisters_to_delete: Some(sns_canisters),
                    subnet: Some(subnet_id),
                    dapp_canisters_to_restore: dapp_canisters_original_controllers.to_owned(),
                })
            })?;

        // Install the wasms for the canisters.
        Self::install_wasms(canister_api, &sns_canisters, latest_wasms, initial_payloads)
            .await
            .map_err(|message| {
                DeployError::Reversible(ReversibleDeployError {
                    message,
                    canisters_to_delete: Some(sns_canisters),
                    subnet: Some(subnet_id),
                    dapp_canisters_to_restore: dapp_canisters_original_controllers.to_owned(),
                })
            })?;

        // Set up the expected control graph of the SNS while retaining control of the dapps.
        Self::add_sns_w_and_root_controllers(canister_api, &sns_canisters)
            .await
            .map_err(|message| {
                DeployError::Reversible(ReversibleDeployError {
                    message,
                    canisters_to_delete: Some(sns_canisters),
                    subnet: Some(subnet_id),
                    dapp_canisters_to_restore: dapp_canisters_original_controllers.to_owned(),
                })
            })?;

        // After this point, we cannot delete all the canisters necessarily, so we will have to fail
        // and allow some other mechanism to retry setting the correct ownership.

        // We record here because the remaining failures cannot be reversed, so it will be a deployed
        // SNS, but that needs cleanup or extra cycles
        thread_safe_sns.with(|sns_canister| {
            sns_canister
                .borrow_mut()
                .deployed_sns_list
                .push(DeployedSns::from(sns_canisters));

            // Get the index of the DeployedSns we just pushed
            let latest_deployed_sns_index = sns_canister.borrow().deployed_sns_list.len() - 1;

            // Record the index in `nns_proposal_to_deployed_sns`
            sns_canister
                .borrow_mut()
                .nns_proposal_to_deployed_sns
                .insert(
                    sns_init_payload.nns_proposal_id(),
                    latest_deployed_sns_index as u64,
                );
        });

        // We combine the errors of the last two steps because at this point they should both be done
        // even if one fails, since we can no longer back out
        join_errors_or_ok(vec![
            // Accept all remaining cycles and fund the canisters
            Self::fund_canisters(canister_api, &sns_canisters).await,
            // Remove self as the controller
            Self::remove_sns_w_as_controller(canister_api, &sns_canisters).await,
        ])
        // At this point, all the dapp canisters are still controlled by NNS Root and can
        // be restored.
        .map_err(|message| {
            DeployError::PartiallyReversible(PartiallyReversibleDeployError {
                message,
                canisters_created: Some(sns_canisters),
                subnet: Some(subnet_id),
                dapp_canisters_to_restore: dapp_canisters_original_controllers.to_owned(),
                non_controlled_dapp_canisters: vec![],
            })
        })?;
        // Request that NNS Root add the newly created SNS Root canister as a controller
        // of the dapp_canisters.
        // (NNS Root will be removed as a controller after the swap is done)
        let dapp_canister_to_new_controllers: BTreeMap<Canister, Vec<PrincipalId>> = dapp_canisters
            .iter()
            .map(|canister| {
                (
                    *canister,
                    vec![sns_init_canister_ids.root, ROOT_CANISTER_ID.get()],
                )
            })
            .collect();
        Self::change_controllers_of_nns_root_owned_canisters(
            nns_root_canister_client,
            &dapp_canister_to_new_controllers,
        )
        .await
        // In this error case, a partial failure means that some canisters are still under
        // the control of NNS Root, while others are under control of the SNS. Those that
        // are under control of the SNS are returned via a different path by the SNS.
        .map_err(|err| {
            DeployError::PartiallyReversible(PartiallyReversibleDeployError {
                message: "Could not change the controller of all dapp canisters to SNS Root."
                    .to_string(),
                canisters_created: Some(sns_canisters),
                subnet: Some(subnet_id),
                dapp_canisters_to_restore: extract_keys(
                    &dapp_canisters_original_controllers,
                    &err.get_failed_canisters(),
                ),
                non_controlled_dapp_canisters: err.get_successful_canisters(),
            })
        })?;

        Ok((subnet_id, sns_canisters, dapp_canisters.to_vec()))
    }

    /// Accept remaining cycles in the request, subtract the cycles we've already used, and distribute
    /// the remainder among the canisters
    async fn fund_canisters(
        canister_api: &impl CanisterApi,
        canisters: &SnsCanisterIds,
    ) -> Result<(), String> {
        // Accept the remaining cycles in the request we need to fund the canisters
        let remaining_unaccepted_cycles = SNS_CREATION_FEE.saturating_sub(
            INITIAL_CANISTER_CREATION_CYCLES.saturating_mul(SNS_CANISTER_COUNT_AT_INSTALL),
        );
        // We only collect the INITIAL_CANISTER_CREATION_CYCLES for the other 5 canisters because
        // archive will be created by the ledger post deploy.  In order to split whole allocation
        // evenly between all 6 canisters, we want to account for this.
        let uncollected_allocation_for_archive = INITIAL_CANISTER_CREATION_CYCLES;
        let cycles_per_canister = (remaining_unaccepted_cycles
            .saturating_sub(uncollected_allocation_for_archive))
        .saturating_div(SNS_CANISTER_TYPE_COUNT);

        let results = futures::future::join_all(canisters.into_named_tuples().into_iter().map(
            |(label, canister_id)| async move {
                // Ledger needs 2x as many because it will spawn an archive
                let cycles_to_provide = if label == "Ledger" {
                    // Give ledger the cycles archive would have gotten were it created the same
                    // as all of the other canisters.
                    cycles_per_canister * 2 + uncollected_allocation_for_archive
                } else {
                    cycles_per_canister
                };
                canister_api
                    .send_cycles_to_canister(canister_id, cycles_to_provide)
                    .await
                    .map_err(|e| format!("Could not fund {label} canister: {e}"))
            },
        ))
        .await;

        join_errors_or_ok(results)
    }

    /// Sets the controllers of the SNS framework canisters to SNS Root and SNS-W, with
    /// the exception of SNS Root itself, for which this function sets SNS Governance and SNS-W
    /// as controllers.
    ///
    /// WARNING: This function should be kept in sync with `remove_sns_w_as_controller`.
    async fn add_sns_w_and_root_controllers(
        canister_api: &impl CanisterApi,
        canisters: &SnsCanisterIds,
    ) -> Result<(), String> {
        let sns_w_canister_id = canister_api.local_canister_id().get();

        let set_controllers_results = vec![
            // Set Root as controller of Governance.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.governance.unwrap()),
                    vec![sns_w_canister_id, canisters.root.unwrap()],
                )
                .await
                .map_err(|err| {
                    format!("Unable to set SNS-W and Root as Governance canister controller: {err}")
                }),
            // Set Root as controller of Ledger.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.ledger.unwrap()),
                    vec![sns_w_canister_id, canisters.root.unwrap()],
                )
                .await
                .map_err(|err| {
                    format!("Unable to set SNS-W and Root as Ledger canister controller: {err}")
                }),
            // Set Root as controller of Index.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.index.unwrap()),
                    vec![sns_w_canister_id, canisters.root.unwrap()],
                )
                .await
                .map_err(|err| {
                    format!("Unable to set SNS-W and Root as Index canister controller: {err}")
                }),
            // Set Governance as controller of Root.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.root.unwrap()),
                    vec![sns_w_canister_id, canisters.governance.unwrap()],
                )
                .await
                .map_err(|err| {
                    format!("Unable to set SNS-W and Governance as Root canister controller: {err}")
                }),
            // Set Root as the controller of Swap.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.swap.unwrap()),
                    vec![sns_w_canister_id, canisters.root.unwrap()],
                )
                .await
                .map_err(|err| {
                    format!("Unable to set SNS-W and Root as Swap canister controller: {err}")
                }),
        ];

        join_errors_or_ok(set_controllers_results)
    }

    /// Remove the SNS-W canister as the controller of the SNS framework canisters.
    async fn remove_sns_w_as_controller(
        canister_api: &impl CanisterApi,
        canisters: &SnsCanisterIds,
    ) -> Result<(), String> {
        let set_controllers_results = vec![
            // Removing SNS-W, leaving SNS Root.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.governance.unwrap()),
                    vec![canisters.root.unwrap()],
                )
                .await
                .map_err(|err| format!("Unable to remove SNS-W as Governance's controller: {err}")),
            // Removing SNS-W, leaving SNS Root.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.ledger.unwrap()),
                    vec![canisters.root.unwrap()],
                )
                .await
                .map_err(|err| format!("Unable to remove SNS-W as Ledger's controller: {err}")),
            // Removing SNS-W, leaving SNS Governance.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.root.unwrap()),
                    vec![canisters.governance.unwrap()],
                )
                .await
                .map_err(|err| format!("Unable to remove SNS-W as Root's controller: {err}")),
            // Removing SNS-W, leaving SNS Root and NNS Root.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.swap.unwrap()),
                    vec![canisters.root.unwrap()],
                )
                .await
                .map_err(|err| format!("Unable to remove SNS-W as Swap's controller: {err}")),
            // Removing SNS-W, leaving Root.
            canister_api
                .set_controllers(
                    CanisterId::unchecked_from_principal(canisters.index.unwrap()),
                    vec![canisters.root.unwrap()],
                )
                .await
                .map_err(|err| format!("Unable to remove SNS-W as Index's controller: {err}")),
        ];

        join_errors_or_ok(set_controllers_results)
    }

    /// Install the SNS Wasms onto the canisters with the specified payloads
    async fn install_wasms(
        canister_api: &impl CanisterApi,
        canisters: &SnsCanisterIds,
        latest_wasms: SnsWasmsForDeploy,
        init_payloads: SnsCanisterInitPayloads,
    ) -> Result<(), String> {
        let results = zip(
            vec!["Root", "Governance", "Ledger", "Index", "Swap"],
            futures::future::join_all(vec![
                canister_api.install_wasm(
                    CanisterId::unchecked_from_principal(canisters.root.unwrap()),
                    latest_wasms.root,
                    Encode!(&init_payloads.root).unwrap(),
                ),
                canister_api.install_wasm(
                    CanisterId::unchecked_from_principal(canisters.governance.unwrap()),
                    latest_wasms.governance,
                    Encode!(&init_payloads.governance).unwrap(),
                ),
                canister_api.install_wasm(
                    CanisterId::unchecked_from_principal(canisters.ledger.unwrap()),
                    latest_wasms.ledger,
                    Encode!(&init_payloads.ledger).unwrap(),
                ),
                canister_api.install_wasm(
                    CanisterId::unchecked_from_principal(canisters.index.unwrap()),
                    latest_wasms.index,
                    Encode!(&init_payloads.index_ng).unwrap(),
                ),
                canister_api.install_wasm(
                    CanisterId::unchecked_from_principal(canisters.swap.unwrap()),
                    latest_wasms.swap,
                    Encode!(&init_payloads.swap).unwrap(),
                ),
            ])
            .await,
        )
        .map(|(label, result)| result.map_err(|e| format!("Error installing {label} WASM: {e}")))
        .collect();

        join_errors_or_ok(results)
    }

    /// Creates the Canisters for the SNS to be deployed, or returns a failure message and
    /// SnsCanisterIds to delete if any.
    async fn create_sns_canisters(
        canister_api: &impl CanisterApi,
        subnet_id: SubnetId,
        initial_cycles_per_canister: u64,
    ) -> Result<SnsCanisterIds, (String, Option<SnsCanisterIds>)> {
        let this_canister_id = canister_api.local_canister_id().get();
        let new_canister = |canister_type: SnsCanisterType| {
            canister_api.create_canister(
                subnet_id,
                this_canister_id,
                Cycles::new(initial_cycles_per_canister.into()),
                if canister_type == SnsCanisterType::Governance {
                    DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT
                } else {
                    DEFAULT_SNS_NON_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT
                },
            )
        };

        // Create these in order instead of join_all to get deterministic ordering for tests
        let root = new_canister(SnsCanisterType::Root).await;
        let governance = new_canister(SnsCanisterType::Governance).await;
        let ledger = new_canister(SnsCanisterType::Ledger).await;
        let swap = new_canister(SnsCanisterType::Swap).await;
        let index = new_canister(SnsCanisterType::Index).await;

        let (root, governance, ledger, swap, index) = match (root, governance, ledger, swap, index)
        {
            (Ok(root), Ok(governance), Ok(ledger), Ok(swap), Ok(index)) => {
                (root, governance, ledger, swap, index)
            }
            (root, governance, ledger, swap, index) => {
                let canisters_to_delete = SnsCanisterIds {
                    root: root.ok().map(|canister_id| canister_id.get()),
                    governance: governance.ok().map(|canister_id| canister_id.get()),
                    ledger: ledger.ok().map(|canister_id| canister_id.get()),
                    swap: swap.ok().map(|canister_id| canister_id.get()),
                    index: index.ok().map(|canister_id| canister_id.get()),
                };
                let problem_canisters = vec![
                    canisters_to_delete.root.is_none().then_some("Root"),
                    canisters_to_delete
                        .governance
                        .is_none()
                        .then_some("Governance"),
                    canisters_to_delete.ledger.is_none().then_some("Ledger"),
                    canisters_to_delete.swap.is_none().then_some("Swap"),
                    canisters_to_delete.index.is_none().then_some("Index"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
                return Err((
                    format!(
                        "Could not create some canisters: {}",
                        problem_canisters.join(", ")
                    ),
                    Some(canisters_to_delete),
                ));
            }
        };

        Ok(SnsCanisterIds {
            root: Some(root.get()),
            governance: Some(governance.get()),
            ledger: Some(ledger.get()),
            swap: Some(swap.get()),
            index: Some(index.get()),
        })
    }

    /// Attempt to clean up canisters that were created and return dapp canisters to their
    /// original owners.
    async fn try_cleanup_reversible_deploy_error(
        canister_api: &impl CanisterApi,
        nns_root_canister_client: &impl NnsRootCanisterClient,
        deploy_error: ReversibleDeployError,
    ) -> DeployNewSnsResponse {
        let dapp_canisters_to_restore = deploy_error.dapp_canisters_to_restore;
        let restore_dapp_canisters_result = Self::change_controllers_of_nns_root_owned_canisters(
            nns_root_canister_client,
            &dapp_canisters_to_restore,
        )
        .await;

        let (restored_dapp_canisters, nns_controlled_dapp_canisters) =
            match &restore_dapp_canisters_result {
                Ok(restored_dapp_canisters) => (restored_dapp_canisters.clone(), vec![]),
                Err(failed_change_canister_controllers_result) => (
                    failed_change_canister_controllers_result.get_successful_canisters(),
                    failed_change_canister_controllers_result.get_failed_canisters(),
                ),
            };

        let dapp_canisters_transfer_result = Some(DappCanistersTransferResult {
            restored_dapp_canisters,
            sns_controlled_dapp_canisters: vec![], // In the case of reversible deploy error, all dapps are under control of the NNS and can be restored
            nns_controlled_dapp_canisters,
        });

        let named_canister_tuples = match deploy_error.canisters_to_delete {
            None => vec![],
            Some(canisters) => canisters.into_named_tuples(),
        };

        let delete_canisters_results =
            futures::future::join_all(named_canister_tuples.into_iter().map(
                |(label, canister_id)| async move {
                    (label, canister_api.delete_canister(canister_id).await)
                },
            ))
            .await;

        // Map labels together with Option(Result)
        let delete_canisters_errors = delete_canisters_results
            .into_iter()
            .map(|(name, result)| {
                result.map_err(|e| format!("Could not delete {name} canister: {e}"))
            })
            .flat_map(|result| result.err())
            .collect::<Vec<_>>();

        let restore_dapp_canister_errors = match restore_dapp_canisters_result {
            Ok(_) => vec![],
            Err(f) => f
                .failed
                .iter()
                .map(|f| {
                    format!(
                        "Canister: {:?}. Failure Reason: {:?}.",
                        f.canister, f.reason
                    )
                })
                .collect::<Vec<_>>(),
        };

        let all_errors = [delete_canisters_errors, restore_dapp_canister_errors].concat();

        let error = if all_errors.is_empty() {
            Some(SnsWasmError {
                message: deploy_error.message,
            })
        } else {
            let message = format!(
                "Failure deploying, and could not finish cleanup. Some SNS canisters \
                 may not have been deleted or some dapp_canisters may not have \
                 been restored. Deployment failure was caused by: '{}' \n \
                 Cleanup failure was caused by: '{}'",
                deploy_error.message,
                all_errors.join("\n"),
            );
            Some(SnsWasmError { message })
        };

        DeployNewSnsResponse {
            subnet_id: deploy_error.subnet.map(|s| s.get()),
            canisters: deploy_error.canisters_to_delete,
            error,
            dapp_canisters_transfer_result,
        }
    }

    /// Attempt to clean up canisters that were created.
    async fn try_cleanup_partially_reversible_deploy_error(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        deploy_error: PartiallyReversibleDeployError,
    ) -> DeployNewSnsResponse {
        let dapp_canisters_to_restore = deploy_error.dapp_canisters_to_restore;
        let restore_dapp_canisters_result = Self::change_controllers_of_nns_root_owned_canisters(
            nns_root_canister_client,
            &dapp_canisters_to_restore,
        )
        .await;

        let (restored_dapp_canisters, nns_controlled_dapp_canisters) =
            match &restore_dapp_canisters_result {
                Ok(restored_dapp_canisters) => (restored_dapp_canisters.clone(), vec![]),
                Err(failed_change_canister_controllers_result) => (
                    failed_change_canister_controllers_result.get_successful_canisters(),
                    failed_change_canister_controllers_result.get_failed_canisters(),
                ),
            };

        let dapp_canisters_transfer_result = Some(DappCanistersTransferResult {
            restored_dapp_canisters,
            sns_controlled_dapp_canisters: deploy_error.non_controlled_dapp_canisters,
            nns_controlled_dapp_canisters,
        });

        let error = match restore_dapp_canisters_result {
            Ok(_) => Some(SnsWasmError {
                message: deploy_error.message,
            }),
            Err(failed_change_canister_controllers_result) => {
                let message = format!(
                    "Failure deploying, and could not finish cleanup. Some dapp_canisters \
                    may not have been restored or transferred. Deployment failure was caused by: '{}' \n \
                    Cleanup failure was caused by: '{}'",
                    deploy_error.message,
                    failed_change_canister_controllers_result.join_failed_reasons(),
                );
                Some(SnsWasmError { message })
            }
        };

        DeployNewSnsResponse {
            subnet_id: deploy_error.subnet.map(|s| s.get()),
            canisters: deploy_error.canisters_created,
            error,
            dapp_canisters_transfer_result,
        }
    }

    /// Get the original controllers of the target canisters. If any of the sets of controllers
    /// is empty, return an error.
    async fn get_original_dapp_controllers(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        target_canisters: &[Canister],
    ) -> Result<BTreeMap<Canister, Vec<PrincipalId>>, String> {
        let dapp_canisters_original_controllers: BTreeMap<Canister, Vec<PrincipalId>> =
            Self::get_controllers_of_nns_root_owned_canisters(
                nns_root_canister_client,
                target_canisters,
            )
            .await?;

        // Make sure that none of the dapp canisters will be black holed if a deployment error occurs.
        let canister_ids_with_empty_controller_sets = dapp_canisters_original_controllers
            .iter()
            .filter(|(_, controllers)| controllers.is_empty())
            .map(|(canister, _)| canister.id.unwrap_or_default().to_string())
            .collect::<Vec<_>>();

        if !canister_ids_with_empty_controller_sets.is_empty() {
            return Err(format!(
                "The following dapp canister(s) did not have any controllers, cannot transfer to an SNS. {:?}",
                canister_ids_with_empty_controller_sets.join("\n")
            ));
        }

        Ok(dapp_canisters_original_controllers)
    }

    /// Request NNS Root to change the controllers of the targeted canisters to the desired
    /// new controllers. This method attempts to transfer all target_canisters, and does not
    /// stop if one fails.
    async fn change_controllers_of_nns_root_owned_canisters(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        dapp_canisters_to_new_controllers: &BTreeMap<Canister, Vec<PrincipalId>>,
    ) -> Result<Vec<Canister>, FailedChangeCanisterControllersResult> {
        let mut result = FailedChangeCanisterControllersResult::new();

        // TODO: parallelize
        for (canister, new_controllers) in dapp_canisters_to_new_controllers {
            // This condition should never be reached due to prior validation, but in case the
            // new controllers is empty, do not change the controllers of the dapp canister.
            if new_controllers.is_empty() {
                result.failed.push(FailedChangeCanisterControllersRequest {
                    canister: *canister,
                    reason: "Tried to request NNS Root to set controllers to an empty set"
                        .to_string(),
                });
                continue;
            }

            match Self::change_controllers_of_nns_root_owned_canister(
                nns_root_canister_client,
                *canister,
                new_controllers.clone(),
            )
            .await
            {
                Ok(_) => result.successful.push(*canister),
                Err(reason) => result.failed.push(FailedChangeCanisterControllersRequest {
                    canister: *canister,
                    reason,
                }),
            };
        }

        if result.failed.is_empty() {
            Ok(dapp_canisters_to_new_controllers.keys().cloned().collect())
        } else {
            println!(
                "{}Failed to transfer control of dapp_canisters. Reason: {}",
                LOG_PREFIX,
                result.join_failed_reasons()
            );
            Err(result)
        }
    }

    /// Dispatch the the ChangeCanisterControllers call to NNS Root and handle error cases.
    async fn change_controllers_of_nns_root_owned_canister(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        target_canister: Canister,
        new_controllers: Vec<PrincipalId>,
    ) -> Result<(), String> {
        let target_canister_id = target_canister.id.ok_or_else(||
                // In practice, validation ensures that this is unreachable.
                format!(
                    "Could not change the controllers of {target_canister:?} due to no id field being present.",
                ))?;

        let request = ChangeCanisterControllersRequest {
            target_canister_id,
            new_controllers,
        };

        let call_response = nns_root_canister_client
            .change_canister_controllers(request)
            .await;

        let change_canister_controllers_response =
            call_response.map_err(|(code, description)| {
                format!(
                    "Could not change the controllers of {target_canister_id:?} \
                    due to an error from the replica. {code:?}:{description:?}"
                )
            })?;

        match change_canister_controllers_response.change_canister_controllers_result {
            ChangeCanisterControllersResult::Ok(_ok) => Ok(()),
            ChangeCanisterControllersResult::Err(err) => Err(format!(
                "Could not change the controllers of {target_canister_id:?} \
                due to an error from NNS Root: {err:?}"
            )),
        }
    }

    /// Request NNS Root to get the controllers of the targeted canisters. This method attempts to
    /// get all target_canisters controllers, and does not  stop if one fails so the response
    /// can have a conclusive set of errors.
    async fn get_controllers_of_nns_root_owned_canisters(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        target_canisters: &[Canister],
    ) -> Result<BTreeMap<Canister, Vec<PrincipalId>>, String> {
        let mut result = btreemap! {};
        let mut defects = vec![];
        for canister in target_canisters {
            match Self::get_controllers_of_nns_root_owned_canister(
                nns_root_canister_client,
                *canister,
            )
            .await
            {
                Ok(controllers) => {
                    // It is deliberate that NNS Root is kept in this list of original controllers
                    // for two reasons:
                    // 1. If developers remove themselves and leave NNS Root as the sole controller
                    //    we want to avoid black-holing the canister.
                    // 2. Other co-controllers can decide to remove NNS Root after a failed SNS
                    //    creation.
                    result.insert(*canister, controllers);
                }
                Err(failure_reason) => defects.push(failure_reason),
            };
        }

        if defects.is_empty() {
            Ok(result)
        } else {
            Err(format!(
                "Could not get the controllers of all dapp_canisters for the following reason(s):\n  -{}",
                defects.join("\n  -"),
            ))
        }
    }

    /// Dispatch the CanisterStatus call to NNS Root and handle error cases.
    async fn get_controllers_of_nns_root_owned_canister(
        nns_root_canister_client: &impl NnsRootCanisterClient,
        target_canister: Canister,
    ) -> Result<Vec<PrincipalId>, String> {
        let target_principal_id = target_canister.id.ok_or_else(||
            // In practice, validation ensures that this is unreachable.
            format!(
                "Could not get the controllers of {target_canister:?} due to no id field being present.",
            ))?;

        let target_canister_id = CanisterId::unchecked_from_principal(target_principal_id);

        let request = CanisterIdRecord {
            canister_id: target_canister_id,
        };

        let call_response = nns_root_canister_client.canister_status(request).await;

        let canister_status_result = call_response.map_err(|(code, description)| {
            format!(
                "Could not get the controllers of {target_canister_id:?} \
                    due to an error from the replica. {code:?}:{description:?}"
            )
        })?;

        Ok(canister_status_result.settings.controllers)
    }

    /// Get an available subnet to create canisters on
    fn get_available_sns_subnet(&self) -> Result<SubnetId, String> {
        // TODO We need a way to find "available" subnets based on SNS deployments (limiting numbers per Subnet)
        if !self.sns_subnet_ids.is_empty() {
            Ok(self.sns_subnet_ids[0])
        } else {
            Err("No SNS Subnet is available".to_string())
        }
    }

    /// Given the SnsVersion of an SNS instance, returns the SnsVersion that this SNS instance
    /// should upgrade to
    pub fn get_next_sns_version(
        &self,
        request: GetNextSnsVersionRequest,
        caller: PrincipalId,
    ) -> GetNextSnsVersionResponse {
        let GetNextSnsVersionRequest {
            governance_canister_id,
            current_version,
        } = request;

        let governance_canister_id = governance_canister_id.or(Some(caller));

        let next_version = current_version.and_then(|sns_version| {
            self.upgrade_path
                .get_next_version(sns_version, governance_canister_id.unwrap())
        });

        GetNextSnsVersionResponse { next_version }
    }

    /// Gets the latest/current SNS version in a human-readable format
    pub fn get_latest_sns_version_pretty(&self) -> HashMap<String, String> {
        let version = &self.upgrade_path.latest_version;

        let mut versions_str = HashMap::<String, String>::new();

        versions_str.insert("Root".into(), hex::encode(&version.root_wasm_hash));
        versions_str.insert(
            "Governance".into(),
            hex::encode(&version.governance_wasm_hash),
        );
        versions_str.insert("Ledger".into(), hex::encode(&version.ledger_wasm_hash));
        versions_str.insert("Swap".into(), hex::encode(&version.swap_wasm_hash));
        versions_str.insert(
            "Ledger Archive".into(),
            hex::encode(&version.archive_wasm_hash),
        );
        versions_str.insert("Ledger Index".into(), hex::encode(&version.index_wasm_hash));

        versions_str
    }

    /// Get the latest version of the WASMs based on the latest SnsVersion
    fn get_latest_version_wasms(&self) -> Result<SnsWasmsForDeploy, String> {
        let version = &self.upgrade_path.latest_version;

        let root = self
            .read_wasm(
                &vec_to_hash(version.root_wasm_hash.clone())
                    .map_err(|_| "No root wasm set for this version.".to_string())?,
            )
            .ok_or_else(|| "Root wasm for this version not found in storage.".to_string())?
            .wasm;

        let governance = self
            .read_wasm(
                &vec_to_hash(version.governance_wasm_hash.clone())
                    .map_err(|_| "No governance wasm set for this version.".to_string())?,
            )
            .ok_or_else(|| "Governance wasm for this version not found in storage.".to_string())?
            .wasm;

        let ledger = self
            .read_wasm(
                &vec_to_hash(version.ledger_wasm_hash.clone())
                    .map_err(|_| "No ledger wasm set for this version.".to_string())?,
            )
            .ok_or_else(|| "Ledger wasm for this version not found in storage.".to_string())?
            .wasm;

        let swap = self
            .read_wasm(
                &vec_to_hash(version.swap_wasm_hash.clone())
                    .map_err(|_| "No swap wasm set for this version.".to_string())?,
            )
            .ok_or_else(|| "Swap wasm for this version not found in storage.".to_string())?
            .wasm;

        let index = self
            .read_wasm(
                &vec_to_hash(version.index_wasm_hash.clone())
                    .map_err(|_| "No index wasm set for this version.".to_string())?,
            )
            .ok_or_else(|| "Index wasm for this version not found in storage.".to_string())?
            .wasm;

        // We do not need this to be set to install, but no upgrade path will be found by the installed
        // SNS if we do not have this as part of the version.
        self.read_wasm(
            &vec_to_hash(version.archive_wasm_hash.clone())
                .map_err(|_| "No archive wasm set for this version.".to_string())?,
        )
        .ok_or_else(|| "Archive wasm for this version not found in storage.".to_string())?;

        Ok(SnsWasmsForDeploy {
            root,
            governance,
            ledger,
            swap,
            index,
        })
    }

    /// Write canister state to stable memory
    pub fn write_state_to_stable_memory(&self) {
        self.stable_memory
            .write_canister_state(self.clone().into())
            .expect("Failed to write canister state from stable memory")
    }

    /// Read canister state from stable memory
    pub fn from_stable_memory() -> Self {
        SnsWasmStableMemory::<M>::default()
            .read_canister_state()
            .expect("Failed to read canister state from stable memory")
            .into()
    }

    /// Add or remove SNS subnet IDs from the list of subnet IDs that SNS instances will be
    /// deployed to
    pub fn update_sns_subnet_list(
        &mut self,
        request: UpdateSnsSubnetListRequest,
    ) -> UpdateSnsSubnetListResponse {
        for subnet_id_to_add in request.sns_subnet_ids_to_add {
            self.sns_subnet_ids.push(SubnetId::new(subnet_id_to_add));
        }

        for subnet_id_to_remove in request.sns_subnet_ids_to_remove {
            self.sns_subnet_ids
                .retain(|id| id != &SubnetId::new(subnet_id_to_remove));
        }

        UpdateSnsSubnetListResponse::ok()
    }

    /// Return the list of SNS subnet IDs that SNS-WASM will deploy SNS instances to
    pub fn get_sns_subnet_ids(&self) -> GetSnsSubnetIdsResponse {
        GetSnsSubnetIdsResponse {
            sns_subnet_ids: self
                .sns_subnet_ids
                .clone()
                .iter()
                .map(|id| id.get())
                .collect(),
        }
    }

    /// Returns the DeployedSns structure that maps from the proposal_id in the
    /// GetDeployedSnsByProposalIdRequest request. Return an error if the
    /// proposal_id is not tracked, or maps to missing data.
    pub fn get_deployed_sns_by_proposal_id(
        &self,
        request: GetDeployedSnsByProposalIdRequest,
    ) -> GetDeployedSnsByProposalIdResponse {
        match self.do_get_deployed_sns_by_proposal_id(request) {
            Ok(deployed_sns) => GetDeployedSnsByProposalIdResponse::ok(deployed_sns),
            Err(message) => GetDeployedSnsByProposalIdResponse::error(message),
        }
    }

    /// Returns the DeployedSns structure that maps from the proposal_id in the
    /// GetDeployedSnsByProposalIdRequest request. Return an error if the
    /// proposal_id is not tracked, or maps to missing data.
    pub fn do_get_deployed_sns_by_proposal_id(
        &self,
        request: GetDeployedSnsByProposalIdRequest,
    ) -> Result<DeployedSns, String> {
        let deployed_sns_index = self
            .nns_proposal_to_deployed_sns
            .get(&request.proposal_id)
            .ok_or_else(|| {
                format!(
                    "No DeployedSns matches provided proposal_id({})",
                    request.proposal_id
                )
            })?;
        self.deployed_sns_list
            .get(*deployed_sns_index as usize)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "Missing DeployedSns for provided proposal_id({})",
                    request.proposal_id
                )
            })
    }
}

/// Converts a vector of u8s to array of length 32 (the size of our sha256 hash)
/// or returns an error if wrong length is given
pub fn vec_to_hash(v: Vec<u8>) -> Result<[u8; 32], String> {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; 32]> = match boxed_slice.try_into() {
        Ok(hash) => hash,
        Err(original) => {
            return Err(format!(
                "Expected a hash of length {} but it was {}",
                32,
                original.len()
            ));
        }
    };
    Ok(*boxed_array)
}

/// Specifies the upgrade path for SNS instances
#[derive(Clone, Eq, PartialEq, Debug, Default, candid::CandidType, candid::Deserialize)]
pub struct UpgradePath {
    /// The latest SNS version. New SNS deployments will deploy the SNS canisters specified by
    /// this version.
    pub latest_version: SnsVersion,

    /// Maps SnsVersions to the SnsVersion that should be upgraded to.
    pub upgrade_path: HashMap<SnsVersion, SnsVersion>,

    /// Maps SnsVersions to SnsVersions for particular governance canisters to allow
    /// custom responses when a particular SNS becomes impossible to upgrade.
    /// These paths should tie back into the upgrade_path after the difficulty is resolved.
    pub sns_specific_upgrade_path: HashMap<CanisterId, HashMap<SnsVersion, SnsVersion>>,
}

impl UpgradePath {
    pub fn get_new_latest_version(
        &self,
        canister_type: SnsCanisterType,
        wasm_hash: &[u8; 32],
    ) -> Result<SnsVersion, String> {
        let mut new_latest_version = self.latest_version.clone();

        match canister_type {
            SnsCanisterType::Unspecified => panic!("SNS canister type must be non-zero"),
            SnsCanisterType::Root => new_latest_version.root_wasm_hash = wasm_hash.to_vec(),
            SnsCanisterType::Governance => {
                new_latest_version.governance_wasm_hash = wasm_hash.to_vec()
            }
            SnsCanisterType::Ledger => new_latest_version.ledger_wasm_hash = wasm_hash.to_vec(),
            SnsCanisterType::Swap => new_latest_version.swap_wasm_hash = wasm_hash.to_vec(),
            SnsCanisterType::Archive => new_latest_version.archive_wasm_hash = wasm_hash.to_vec(),
            SnsCanisterType::Index => new_latest_version.index_wasm_hash = wasm_hash.to_vec(),
        }

        if self.upgrade_path.contains_key(&new_latest_version) {
            return Err(format!(
                "Version {new_latest_version} already exists along the upgrade path - cannot add it again"
            ));
        }

        if self.latest_version == new_latest_version {
            return Err(format!(
                "Version {new_latest_version} is already the latest version"
            ));
        }

        Ok(new_latest_version)
    }

    pub fn add_wasm(&mut self, new_latest_version: SnsVersion) {
        self.upgrade_path
            .insert(self.latest_version.clone(), new_latest_version.clone());
        self.latest_version = new_latest_version;
    }

    pub fn get_next_version(
        &self,
        from_version: SnsVersion,
        caller: PrincipalId,
    ) -> Option<SnsVersion> {
        match CanisterId::try_from(caller) {
            // If not a canister id, just check normal path
            Err(_) => self.upgrade_path.get(&from_version).cloned(),
            // Check if special entry
            Ok(canister_id) => match self.sns_specific_upgrade_path.get(&canister_id) {
                // No special entry, use normal path map
                None => self.upgrade_path.get(&from_version).cloned(),
                // Special canister path map, but if no entry for version, fallback to regular path
                Some(emergency_paths) => emergency_paths
                    .get(&from_version)
                    .or_else(|| self.upgrade_path.get(&from_version))
                    .cloned(),
            },
        }
    }

    pub fn insert_sns_specific_upgrade_path_entry(
        &mut self,
        from: SnsVersion,
        to: SnsVersion,
        sns_governance_canister_id: CanisterId,
    ) {
        match self
            .sns_specific_upgrade_path
            .entry(sns_governance_canister_id)
            .or_default()
            .entry(from)
        {
            Entry::Occupied(occupied) => {
                println!(
                    "Special Entry for {}  from {:?} to {:?} is being overwritten with new value {:?}",
                    sns_governance_canister_id,
                    occupied.key(),
                    occupied.get(),
                    to
                );
            }
            Entry::Vacant(vacant) => {
                vacant.insert(to);
            }
        };
    }

    pub fn insert_upgrade_path_entry(&mut self, from: SnsVersion, to: SnsVersion) {
        match self.upgrade_path.entry(from) {
            Entry::Occupied(mut occupied) => {
                println!(
                    "Entry from {:?} to {:?} is being overwritten with new value {:?}",
                    occupied.key(),
                    occupied.get(),
                    to
                );
                occupied.insert(to);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(to);
            }
        };
        // self.upgrade_path.insert(from, to);
    }
}

impl DeployNewSnsRequest {
    /// Validates that the payload is valid w.r.t. the sender - the NNS
    /// governance canister can only create an SNS using the one-proposal flow,
    /// while other canisters can only create an SNS using the legacy flow.
    pub fn get_and_validate_sns_init_payload(&self) -> Result<SnsInitPayload, String> {
        let init_payload = self
            .sns_init_payload
            .as_ref()
            // Validate presence
            .ok_or("sns_init_payload is a required field")?
            .validate_post_execution()?;

        Ok(init_payload)
    }
}

pub fn assert_unique_canister_ids(sns_1: &SnsCanisterIds, sns_2: &SnsCanisterIds) {
    let mut canister_id_to_name = hashmap! {};
    for (name, canister_id) in [
        ("root 1", sns_1.root.unwrap()),
        ("ledger 1", sns_1.ledger.unwrap()),
        ("governance 1", sns_1.governance.unwrap()),
        ("swap 1", sns_1.swap.unwrap()),
        ("index 1", sns_1.index.unwrap()),
        ("root 2", sns_2.root.unwrap()),
        ("ledger 2", sns_2.ledger.unwrap()),
        ("governance 2", sns_2.governance.unwrap()),
        ("swap 2", sns_2.swap.unwrap()),
        ("index 2", sns_2.index.unwrap()),
    ] {
        match canister_id_to_name.entry(canister_id) {
            Entry::Vacant(entry) => {
                // Looking good so far (no panic).
                entry.insert(name);
                continue;
            }
            Entry::Occupied(entry) => {
                panic!(
                    "Canister ID {} not unique: {} vs. {}",
                    canister_id,
                    name,
                    entry.get()
                );
            }
        }
    }
}

impl From<DeployedSns> for SnsCanisterIds {
    fn from(value: DeployedSns) -> Self {
        let DeployedSns {
            root_canister_id: root,
            governance_canister_id: governance,
            ledger_canister_id: ledger,
            swap_canister_id: swap,
            index_canister_id: index,
        } = value;
        Self {
            root,
            ledger,
            governance,
            swap,
            index,
        }
    }
}

impl From<GetSnsCanistersSummaryResponse> for SnsCanisterIds {
    fn from(value: GetSnsCanistersSummaryResponse) -> Self {
        let GetSnsCanistersSummaryResponse {
            root,
            governance,
            ledger,
            swap,
            dapps: _,
            archives: _,
            index,
        } = value;

        Self {
            root: root.and_then(|c| c.canister_id),
            ledger: ledger.and_then(|c| c.canister_id),
            governance: governance.and_then(|c| c.canister_id),
            swap: swap.and_then(|c| c.canister_id),
            index: index.and_then(|c| c.canister_id),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{canister_stable_memory::TestCanisterStableMemory, pb::v1::SnsUpgrade};
    use async_trait::async_trait;
    use ic_base_types::PrincipalId;
    use ic_cdk::println;
    use ic_crypto_sha2::Sha256;
    use ic_nervous_system_common_test_utils::wasm_helpers;
    use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
    use ic_nns_handler_root_interface::client::{
        SpyNnsRootCanisterClient, SpyNnsRootCanisterClientCall, SpyNnsRootCanisterClientReply,
    };
    use ic_sns_init::pb::v1::{DappCanisters, SnsInitPayload};
    use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
    use pretty_assertions::assert_eq;
    use std::{
        sync::{Arc, Mutex},
        vec,
    };

    const CANISTER_CREATION_CYCLES: u64 = INITIAL_CANISTER_CREATION_CYCLES * 5;

    struct TestCanisterApi {
        canisters_created: Arc<Mutex<u64>>,
        /// Keep track of calls to our mocked methods.
        #[allow(clippy::type_complexity)]
        pub install_wasm_calls: Arc<Mutex<Vec<(CanisterId, Vec<u8>, Vec<u8>)>>>,
        #[allow(clippy::type_complexity)]
        pub set_controllers_calls: Arc<Mutex<Vec<(CanisterId, Vec<PrincipalId>)>>>,
        pub cycles_accepted: Arc<Mutex<Vec<u64>>>,
        #[allow(clippy::type_complexity)]
        pub cycles_sent: Arc<Mutex<Vec<(CanisterId, u64)>>>,
        pub canisters_deleted: Arc<Mutex<Vec<CanisterId>>>,
        /// How many cycles the canister has.
        pub canister_cycles_balance: Arc<Mutex<u64>>,
        /// How many cycles does the pretend request contain.
        pub cycles_found_in_request: Arc<Mutex<u64>>,
        /// Errors that can be thrown at some nth function call.
        pub errors_on_create_canister: Arc<Mutex<Vec<Option<String>>>>,
        pub errors_on_set_controller: Arc<Mutex<Vec<Option<String>>>>,
        pub errors_on_delete_canister: Arc<Mutex<Vec<Option<String>>>>,
        pub errors_on_install_wasms: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[async_trait]
    impl CanisterApi for TestCanisterApi {
        fn local_canister_id(&self) -> CanisterId {
            canister_test_id(0)
        }

        async fn create_canister(
            &self,
            _target_subnet: SubnetId,
            _controller_id: PrincipalId,
            _cycles: Cycles,
            _wasm_memory_limit: u64,
        ) -> Result<CanisterId, String> {
            let mut errors = self.errors_on_create_canister.lock().unwrap();
            if !errors.is_empty()
                && let Some(message) = errors.remove(0)
            {
                return Err(message);
            }

            let mut data = self.canisters_created.lock().unwrap();
            *data += 1;
            let canister_id = canister_test_id(*data);
            Ok(canister_id)
        }

        async fn delete_canister(&self, canister: CanisterId) -> Result<(), String> {
            self.canisters_deleted.lock().unwrap().push(canister);

            let mut errors = self.errors_on_delete_canister.lock().unwrap();
            if !errors.is_empty()
                && let Some(message) = errors.remove(0)
            {
                return Err(message);
            }

            Ok(())
        }

        async fn install_wasm(
            &self,
            target_canister: CanisterId,
            wasm: Vec<u8>,
            init_payload: Vec<u8>,
        ) -> Result<(), String> {
            self.install_wasm_calls
                .lock()
                .unwrap()
                .push((target_canister, wasm, init_payload));

            let mut errors = self.errors_on_install_wasms.lock().unwrap();
            if !errors.is_empty()
                && let Some(message) = errors.remove(0)
            {
                return Err(message);
            }

            Ok(())
        }

        async fn set_controllers(
            &self,
            canister: CanisterId,
            controllers: Vec<PrincipalId>,
        ) -> Result<(), String> {
            self.set_controllers_calls
                .lock()
                .unwrap()
                .push((canister, controllers));

            let mut errors = self.errors_on_set_controller.lock().unwrap();
            if !errors.is_empty()
                && let Some(message) = errors.remove(0)
            {
                return Err(message);
            }

            Ok(())
        }

        fn this_canister_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
            let amount = *self.canister_cycles_balance.lock().unwrap();
            if amount < required_cycles {
                return Err(format!(
                    "Not enough cycles in canister.  Required: {required_cycles}. Found: {amount}"
                ));
            }
            Ok(amount)
        }

        fn message_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
            let amount = *self.cycles_found_in_request.lock().unwrap();
            if amount < required_cycles {
                return Err(format!(
                    "Not enough cycles in request.  Required: {required_cycles}. Found: {amount}"
                ));
            }
            Ok(amount)
        }

        fn accept_message_cycles(&self, cycles: Option<u64>) -> Result<u64, String> {
            let cycles = cycles.unwrap_or_else(|| *self.cycles_found_in_request.lock().unwrap());
            self.message_has_enough_cycles(cycles)?;
            self.cycles_accepted.lock().unwrap().push(cycles);

            *self.cycles_found_in_request.lock().unwrap() -= cycles;

            Ok(cycles)
        }

        async fn send_cycles_to_canister(
            &self,
            target_canister: CanisterId,
            cycles: u64,
        ) -> Result<(), String> {
            self.cycles_sent
                .lock()
                .unwrap()
                .push((target_canister, cycles));
            Ok(())
        }
    }

    fn new_canister_api() -> TestCanisterApi {
        TestCanisterApi {
            canisters_created: Arc::new(Mutex::new(0)),
            install_wasm_calls: Arc::new(Mutex::new(vec![])),
            set_controllers_calls: Arc::new(Mutex::new(vec![])),
            cycles_accepted: Arc::new(Mutex::new(vec![])),
            cycles_sent: Arc::new(Mutex::new(vec![])),
            canisters_deleted: Arc::new(Mutex::new(vec![])),
            canister_cycles_balance: Arc::new(Mutex::new(SNS_CREATION_FEE)),
            cycles_found_in_request: Arc::new(Mutex::new(SNS_CREATION_FEE)),
            errors_on_create_canister: Arc::new(Mutex::new(vec![])),
            errors_on_set_controller: Arc::new(Mutex::new(vec![])),
            errors_on_delete_canister: Arc::new(Mutex::new(vec![])),
            errors_on_install_wasms: Arc::new(Mutex::new(vec![])),
        }
    }

    /// Provides a small wasm
    fn smallest_valid_wasm() -> SnsWasm {
        SnsWasm {
            wasm: wasm_helpers::SMALLEST_VALID_WASM_BYTES.to_vec(),
            canister_type: i32::from(SnsCanisterType::Governance),
            proposal_id: Some(2),
        }
    }

    fn new_wasm_canister() -> SnsWasmCanister<TestCanisterStableMemory> {
        let state = SnsWasmCanister::new();
        state.initialize_stable_memory();
        state
    }

    // Adds section "icp:[public|private] $name$contents" to `wasm`, returning `wasm`'s new hash.
    fn annotate_wasm_with_metadata_and_return_new_hash(
        wasm: &mut SnsWasm,
        is_public: bool,
        name: &str,
        contents: Vec<u8>,
    ) -> Vec<u8> {
        wasm.wasm =
            wasm_helpers::annotate_wasm_with_metadata(&wasm.wasm[..], is_public, name, contents);
        Sha256::hash(&wasm.wasm).to_vec()
    }

    fn small_valid_wasm_with_id<T>(wasm_id: T) -> SnsWasm
    where
        T: ToString,
    {
        let mut wasm = smallest_valid_wasm();
        annotate_wasm_with_metadata_and_return_new_hash(
            &mut wasm,
            true,
            &wasm_id.to_string(),
            vec![],
        );
        wasm
    }

    /// Add some placeholder WASMs with different values so we can test that each value is installed
    /// into the correct spot. The optional argument `group_number` specifies which group of WASMs
    /// you are adding so that they will have different content and therefore different hashes;
    /// setting `group_number` to `None` is appropriate in tests that call this function just once.
    fn add_dummy_wasms(
        canister: &mut SnsWasmCanister<TestCanisterStableMemory>,
        group_number: Option<u8>,
    ) -> (
        SnsVersion,
        SnsVersion,
        SnsVersion,
        SnsVersion,
        SnsVersion,
        SnsVersion,
    ) {
        let current_version = canister.upgrade_path.latest_version.clone();
        let mut added_versions = vec![];

        let wasm_id = |label: &str| {
            if let Some(group_number) = group_number {
                format!("{label}_{group_number}")
            } else {
                label.to_string()
            }
        };

        let root = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Root),
            ..small_valid_wasm_with_id(wasm_id("Root"))
        };
        let root_wasm_hash = root.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(root),
            hash: root_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            root_wasm_hash,
            ..current_version
        });

        let governance = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Governance),
            ..small_valid_wasm_with_id(wasm_id("Governance"))
        };
        let governance_wasm_hash = governance.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(governance),
            hash: governance_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            governance_wasm_hash,
            ..added_versions.last().cloned().unwrap()
        });

        let ledger = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Ledger),
            ..small_valid_wasm_with_id(wasm_id("Ledger"))
        };
        let ledger_wasm_hash = ledger.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(ledger),
            hash: ledger_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            ledger_wasm_hash,
            ..added_versions.last().cloned().unwrap()
        });
        let swap = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Swap),
            ..small_valid_wasm_with_id(wasm_id("Swap"))
        };
        let swap_wasm_hash = swap.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(swap),
            hash: swap_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            swap_wasm_hash,
            ..added_versions.last().cloned().unwrap()
        });

        let archive = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Archive),
            ..small_valid_wasm_with_id(wasm_id("Archive"))
        };
        let archive_wasm_hash = archive.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(archive),
            hash: archive_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            archive_wasm_hash,
            ..added_versions.last().cloned().unwrap()
        });

        let index = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Index),
            ..small_valid_wasm_with_id(wasm_id("Index"))
        };
        let index_wasm_hash = index.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(index),
            hash: index_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        added_versions.push(SnsVersion {
            index_wasm_hash,
            ..added_versions.last().cloned().unwrap()
        });

        let mut iter = added_versions.into_iter();
        (
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        )
    }

    fn add_dapp_canisters(sns_init_payload: &mut SnsInitPayload, dapp_canisters: &[PrincipalId]) {
        let canisters = dapp_canisters
            .iter()
            .map(|canister_id| Canister {
                id: Some(*canister_id),
            })
            .collect();

        sns_init_payload.dapp_canisters = Some(DappCanisters { canisters })
    }

    #[test]
    fn test_update_sns_subnet_list() {
        let mut canister = new_wasm_canister();

        let principal1 = PrincipalId::new_user_test_id(1);
        let principal2 = PrincipalId::new_user_test_id(2);

        // Check that the list of SNS subnet IDs is initially empty
        let response1 = canister.get_sns_subnet_ids();
        assert!(response1.sns_subnet_ids.is_empty());

        // Add a subnet ID and check that it was added
        canister.update_sns_subnet_list(UpdateSnsSubnetListRequest {
            sns_subnet_ids_to_add: vec![principal1],
            sns_subnet_ids_to_remove: vec![],
        });

        let response2 = canister.get_sns_subnet_ids();
        assert_eq!(response2.sns_subnet_ids, vec![principal1]);

        // Remove the first subnet ID and add a new one, and assert that the new subnet ID is the
        // only subnet ID in the SNS subnet list
        canister.update_sns_subnet_list(UpdateSnsSubnetListRequest {
            sns_subnet_ids_to_add: vec![principal2],
            sns_subnet_ids_to_remove: vec![principal1],
        });

        let response3 = canister.get_sns_subnet_ids();
        assert_eq!(response3.sns_subnet_ids, vec![principal2]);
    }

    #[test]
    fn test_api_get_wasm_returns_right_response() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: expected_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let wasm_response = canister.get_wasm(GetWasmRequest {
            hash: bad_hash.to_vec(),
        });

        // When given non-existent hash, return None
        assert!(wasm_response.wasm.is_none());

        let wasm_response = canister.get_wasm(GetWasmRequest {
            hash: expected_hash.to_vec(),
        });
        // When given valid hash return correct SnsWasm
        assert_eq!(wasm_response.wasm.unwrap(), wasm);
    }

    #[test]
    fn test_api_get_proposal_id_that_added_wasm_returns_right_response() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        let expected_proposal_id = wasm.proposal_id.unwrap();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: expected_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // When given non-existent hash, return None
        let bad_hash = Sha256::hash("something_else".as_bytes());
        let proposal_id_response =
            canister.get_proposal_id_that_added_wasm(GetProposalIdThatAddedWasmRequest {
                hash: bad_hash.to_vec(),
            });
        assert!(proposal_id_response.proposal_id.is_none());

        // When given valid hash return correct proposal ID
        let proposal_id_response =
            canister.get_proposal_id_that_added_wasm(GetProposalIdThatAddedWasmRequest {
                hash: expected_hash.to_vec(),
            });
        assert_eq!(
            proposal_id_response.proposal_id.unwrap(),
            expected_proposal_id
        );
    }

    #[test]
    fn test_api_add_wasm_fails_on_duplicate_version() {
        let mut canister = new_wasm_canister();

        // Add first wasm
        let wasm = SnsWasm {
            canister_type: SnsCanisterType::Root.into(),
            ..small_valid_wasm_with_id("Root")
        };
        let wasm_hash = wasm.sha256_hash().to_vec();
        let response = canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });
        assert_eq!(
            response.result.unwrap(),
            add_wasm_response::Result::Hash(wasm_hash.clone())
        );

        // Try to add same wasm again - should fail
        let AddWasmResponse {
            result: Some(add_wasm_response::Result::Error(SnsWasmError { message: _ })),
        } = canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        })
        else {
            panic!("Expected to fail to add duplicate version");
        };

        // Try to add a different wasm - should succeed
        {
            let wasm = SnsWasm {
                canister_type: SnsCanisterType::Ledger.into(),
                ..small_valid_wasm_with_id("Ledger")
            };
            let wasm_hash = wasm.sha256_hash().to_vec();
            let response = canister.add_wasm(AddWasmRequest {
                wasm: Some(wasm),
                hash: wasm_hash.clone(),
                skip_update_latest_version: Some(false),
            });
            assert_eq!(
                response.result.unwrap(),
                add_wasm_response::Result::Hash(wasm_hash)
            );
        }

        // Re-add the first wasm - should still fail
        let AddWasmResponse {
            result: Some(add_wasm_response::Result::Error(SnsWasmError { message: _ })),
        } = canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        })
        else {
            panic!("Expected to fail to add duplicate version");
        };
    }

    #[test]
    fn test_api_add_wasm_fails_on_unspecified_canister_type() {
        let mut canister = new_wasm_canister();
        let unspecified_canister_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Unspecified),
            ..SnsWasm::default()
        };

        let response = canister.add_wasm(AddWasmRequest {
            wasm: Some(unspecified_canister_wasm.clone()),
            hash: unspecified_canister_wasm.sha256_hash().to_vec(),
            skip_update_latest_version: Some(false),
        });

        assert_eq!(
            response,
            AddWasmResponse {
                result: Some(add_wasm_response::Result::Error(SnsWasmError {
                    message: "SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string()
                }))
            }
        )
    }

    #[test]
    fn test_api_add_wasm_fails_on_unsupported_canister_type() {
        let mut canister = new_wasm_canister();
        let invalid_canister_type_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: 1000,
            ..SnsWasm::default()
        };

        let response = canister.add_wasm(AddWasmRequest {
            wasm: Some(invalid_canister_type_wasm.clone()),
            hash: invalid_canister_type_wasm.sha256_hash().to_vec(),
            skip_update_latest_version: Some(false),
        });

        assert_eq!(
            response,
            AddWasmResponse {
                result: Some(add_wasm_response::Result::Error(
                    SnsWasmError {
                        message: "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                            .to_string()}))
            } );
    }

    #[test]
    fn test_api_add_wasm_responses() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        let bad_hash = Sha256::hash("Something else".as_bytes());
        // First try with incorrect hash
        let failure = canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: bad_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });
        assert_eq!(
            failure.result.unwrap(),
            add_wasm_response::Result::Error(SnsWasmError {
                message: format!(
                    "Invalid Sha256 given for submitted WASM bytes. Provided hash was \
                '{}' but calculated hash was \
                '{}'",
                    hash_to_hex_string(&bad_hash),
                    hash_to_hex_string(&expected_hash),
                )
            })
        );

        let valid_hash = wasm.sha256_hash();
        let success = canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        assert_eq!(
            success,
            AddWasmResponse {
                result: Some(add_wasm_response::Result::Hash(valid_hash.to_vec()))
            }
        );
    }

    #[test]
    fn test_api_insert_upgrade_path_entries_validation() {
        let mut canister = new_wasm_canister();
        let initial_version = add_dummy_wasms(&mut canister, Some(0)).5;

        // 1. validate request not empty
        let response = canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![],
            sns_governance_canister_id: None,
        });
        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message: "No Upgrade Paths in request. No action taken.".to_string()
            })
        );

        // 1a. Validate all SnsVersion entries are Some()
        let response = canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![SnsUpgrade {
                current_version: None,
                next_version: None,
            }],
            sns_governance_canister_id: None,
        });
        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message:
                    "A provided SnsUpgrade entry does not have a current_version or next_version"
                        .to_string()
            })
        );

        // 2. validate that an upgrade path must have real SNS-Wasms in it
        let governance = SnsWasm {
            canister_type: SnsCanisterType::Governance.into(),
            ..small_valid_wasm_with_id("Governance")
        };
        let governance_wasm_hash = governance.sha256_hash().to_vec();

        let next_version = SnsVersion {
            governance_wasm_hash: governance_wasm_hash.clone(),
            ..initial_version.clone()
        };
        let upgrade = SnsUpgrade {
            current_version: Some(initial_version),
            next_version: Some(next_version),
        };
        let response = canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![upgrade.clone()],
            sns_governance_canister_id: None,
        });

        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message:
                    "Upgrade paths include WASM hashes that do not reference WASMs known by SNS-W"
                        .to_string()
            })
        );
        canister.add_wasm(AddWasmRequest {
            wasm: Some(governance),
            hash: governance_wasm_hash,
            skip_update_latest_version: Some(false),
        });

        // 3. Validate that the governance canister is known
        let response = canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![upgrade],
            sns_governance_canister_id: Some(CanisterId::from_u64(10).into()),
        });
        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message: format!(
                    "Cannot add custom upgrade path for non-existent SNS.  Governance canister {} not \
                found in list of deployed SNSes.",
                    CanisterId::from_u64(10)
                )
            })
        );
    }

    #[test]
    fn test_api_get_wasm_correctly_checks_caller_for_overrides() {
        let mut canister = new_wasm_canister();
        let initial_version = add_dummy_wasms(&mut canister, Some(0)).5;

        println!("initial_version = {:#?}", initial_version);

        let governance = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Governance),
            ..small_valid_wasm_with_id("Governance")
        };
        let governance_wasm_hash = governance.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(governance),
            hash: governance_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        let ledger = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Ledger),
            ..small_valid_wasm_with_id("Ledger")
        };
        let ledger_wasm_hash = ledger.sha256_hash().to_vec();

        assert_ne!(governance_wasm_hash, ledger_wasm_hash);

        canister.add_wasm(AddWasmRequest {
            wasm: Some(ledger),
            hash: ledger_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        let second_version = SnsVersion {
            governance_wasm_hash: governance_wasm_hash.clone(),
            ..initial_version.clone()
        };

        let third_version = SnsVersion {
            ledger_wasm_hash,
            ..second_version.clone()
        };

        let next_version_response = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(initial_version.clone()),
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
            },
            CanisterId::from_u64(999).into(),
        );

        assert_eq!(next_version_response, second_version.clone().into());

        let special_governance_canister_id = CanisterId::from_u64(1000).into();

        canister.deployed_sns_list.push(DeployedSns {
            root_canister_id: Some(CanisterId::from_u64(999).into()),
            governance_canister_id: Some(special_governance_canister_id),
            ledger_canister_id: Some(CanisterId::from_u64(1001).into()),
            swap_canister_id: Some(CanisterId::from_u64(1002).into()),
            index_canister_id: Some(CanisterId::from_u64(1003).into()),
        });
        let custom_version = SnsVersion {
            archive_wasm_hash: governance_wasm_hash,
            ..initial_version.clone()
        };

        // just needs to be different, we dont' care what it is
        canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![SnsUpgrade {
                current_version: Some(initial_version.clone()),
                next_version: Some(custom_version.clone()),
            }],
            sns_governance_canister_id: Some(special_governance_canister_id),
        });
        // Call it 2x to exercise the "occupied" code path
        canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![SnsUpgrade {
                current_version: Some(initial_version.clone()),
                next_version: Some(custom_version.clone()),
            }],
            sns_governance_canister_id: Some(special_governance_canister_id),
        });

        // For another governance, we should get default response, even if our special one is the caller
        let next_version_response = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(initial_version.clone()),
                governance_canister_id: Some(CanisterId::from_u64(999).into()),
            },
            special_governance_canister_id,
        );
        assert_eq!(next_version_response, second_version.clone().into());

        // For our governance with a special path added, we should get the new response
        let response_for_custom_governance = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(initial_version),
                governance_canister_id: None,
            },
            special_governance_canister_id,
        );

        assert_eq!(response_for_custom_governance, custom_version.into());

        // For our governance with special path, we should get normal response if no entry
        // exists for a particular query
        let response_to_custom_governance_no_entry = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(second_version.clone()),
                governance_canister_id: None,
            },
            special_governance_canister_id,
        );
        assert_eq!(
            response_to_custom_governance_no_entry,
            third_version.clone().into()
        );

        let response_to_other_governance = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(second_version),
                governance_canister_id: None,
            },
            CanisterId::from_u64(999).into(),
        );
        assert_eq!(response_to_other_governance, third_version.into());
    }

    #[test]
    fn test_insert_upgrade_path_works_for_non_sns_specific_paths() {
        let mut canister = new_wasm_canister();
        let initial_version = add_dummy_wasms(&mut canister, Some(0)).5;

        let governance = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Governance),
            ..small_valid_wasm_with_id("Governance")
        };
        let governance_wasm_hash = governance.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(governance),
            hash: governance_wasm_hash.clone(),
            skip_update_latest_version: Some(false),
        });

        let ledger = SnsWasm {
            canister_type: i32::from(SnsCanisterType::Ledger),
            ..small_valid_wasm_with_id("Ledger")
        };
        let ledger_wasm_hash = ledger.sha256_hash().to_vec();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(ledger),
            hash: ledger_wasm_hash,
            skip_update_latest_version: Some(false),
        });

        let second_version = SnsVersion {
            governance_wasm_hash: governance_wasm_hash.clone(),
            ..initial_version.clone()
        };

        let next_version_response = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(initial_version.clone()),
                governance_canister_id: None,
            },
            PrincipalId::new_user_test_id(1),
        );

        assert_eq!(next_version_response, second_version.into());

        let custom_version = SnsVersion {
            archive_wasm_hash: governance_wasm_hash.clone(),
            ..initial_version.clone()
        };

        let custom_version_2 = SnsVersion {
            ledger_wasm_hash: governance_wasm_hash,
            ..custom_version.clone()
        };

        // just needs to be different, we dont' care what it is
        canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![SnsUpgrade {
                current_version: Some(initial_version.clone()),
                next_version: Some(custom_version.clone()),
            }],
            sns_governance_canister_id: None,
        });

        let new_default_response = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(initial_version),
                governance_canister_id: None,
            },
            PrincipalId::new_user_test_id(1),
        );

        assert_eq!(new_default_response, custom_version.clone().into());

        // Now set one never set before
        canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![SnsUpgrade {
                current_version: Some(custom_version.clone()),
                next_version: Some(custom_version_2.clone()),
            }],
            sns_governance_canister_id: None,
        });

        let new_default_response = canister.get_next_sns_version(
            GetNextSnsVersionRequest {
                current_version: Some(custom_version),
                governance_canister_id: None,
            },
            PrincipalId::new_user_test_id(1),
        );

        assert_eq!(new_default_response, custom_version_2.into());
    }

    // This assumes we create the following scenario
    // Normal Path: A -> B  -> C -> D -> E -> F -> G
    //                   \         /
    // One SNS Path:      ->  C'->
    // A = initial_version
    // G = final_version
    #[test]
    fn test_list_upgrade_steps_parameters_work_for_normal_and_custom_paths() {
        let mut canister = new_wasm_canister();

        let a_version = add_dummy_wasms(&mut canister, None).5;
        let (b_version, c_version, d_version, e_version, f_version, g_version) =
            add_dummy_wasms(&mut canister, Some(1));

        let alt_c_version = SnsVersion {
            governance_wasm_hash: a_version.ledger_wasm_hash.clone(),
            ..b_version.clone()
        };

        let special_governance_canister_id = CanisterId::from_u64(1000).into();
        canister.deployed_sns_list.push(DeployedSns {
            root_canister_id: Some(CanisterId::from_u64(999).into()),
            governance_canister_id: Some(special_governance_canister_id),
            ledger_canister_id: Some(CanisterId::from_u64(1001).into()),
            swap_canister_id: Some(CanisterId::from_u64(1002).into()),
            index_canister_id: Some(CanisterId::from_u64(1003).into()),
        });

        let insert_response =
            canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
                upgrade_path: vec![
                    SnsUpgrade {
                        current_version: Some(b_version.clone()),
                        next_version: Some(alt_c_version.clone()),
                    },
                    SnsUpgrade {
                        current_version: Some(alt_c_version.clone()),
                        next_version: Some(d_version.clone()),
                    },
                ],
                sns_governance_canister_id: Some(special_governance_canister_id),
            });

        assert_eq!(insert_response.error, None);

        let list_normal_canister = canister.list_upgrade_steps(ListUpgradeStepsRequest {
            starting_at: None,
            sns_governance_canister_id: None,
            limit: 0,
        });

        assert_eq!(
            list_normal_canister,
            ListUpgradeStepsResponse {
                steps: vec![
                    ListUpgradeStep::new(a_version.clone()),
                    ListUpgradeStep::new(b_version.clone()),
                    ListUpgradeStep::new(c_version),
                    ListUpgradeStep::new(d_version.clone()),
                    ListUpgradeStep::new(e_version.clone()),
                    ListUpgradeStep::new(f_version.clone()),
                    ListUpgradeStep::new(g_version.clone()),
                ]
            }
        );

        let list_custom_canister = canister.list_upgrade_steps(ListUpgradeStepsRequest {
            starting_at: None,
            sns_governance_canister_id: Some(special_governance_canister_id),
            limit: 0,
        });

        assert_eq!(
            list_custom_canister,
            ListUpgradeStepsResponse {
                steps: vec![
                    ListUpgradeStep::new(a_version),
                    ListUpgradeStep::new(b_version.clone()),
                    ListUpgradeStep::new(alt_c_version.clone()),
                    ListUpgradeStep::new(d_version.clone()),
                    ListUpgradeStep::new(e_version.clone()),
                    ListUpgradeStep::new(f_version.clone()),
                    ListUpgradeStep::new(g_version.clone()),
                ]
            }
        );

        // Testing "starting_at" field for both cases.

        let list_normal_canister = canister.list_upgrade_steps(ListUpgradeStepsRequest {
            starting_at: Some(e_version.clone()),
            sns_governance_canister_id: None,
            limit: 0,
        });

        assert_eq!(
            list_normal_canister,
            ListUpgradeStepsResponse {
                steps: vec![
                    ListUpgradeStep::new(e_version.clone()),
                    ListUpgradeStep::new(f_version.clone()),
                    ListUpgradeStep::new(g_version.clone()),
                ]
            }
        );

        let list_custom_canister = canister.list_upgrade_steps(ListUpgradeStepsRequest {
            starting_at: Some(b_version.clone()),
            sns_governance_canister_id: Some(special_governance_canister_id),
            limit: 0,
        });

        assert_eq!(
            list_custom_canister,
            ListUpgradeStepsResponse {
                steps: vec![
                    ListUpgradeStep::new(b_version.clone()),
                    ListUpgradeStep::new(alt_c_version.clone()),
                    ListUpgradeStep::new(d_version),
                    ListUpgradeStep::new(e_version),
                    ListUpgradeStep::new(f_version),
                    ListUpgradeStep::new(g_version),
                ]
            }
        );

        let list_custom_canister = canister.list_upgrade_steps(ListUpgradeStepsRequest {
            starting_at: Some(b_version.clone()),
            sns_governance_canister_id: Some(special_governance_canister_id),
            limit: 1,
        });
        assert_eq!(
            list_custom_canister,
            ListUpgradeStepsResponse {
                steps: vec![
                    ListUpgradeStep::new(b_version),
                    ListUpgradeStep::new(alt_c_version),
                ]
            }
        );
    }

    /// Adds Governance and Ledger WASMs and asserts that the upgrade path is updated by
    /// these calls to add_wasm
    #[test]
    fn test_add_wasm_updates_upgrade_path() {
        let mut canister = new_wasm_canister();

        let some_principal = PrincipalId::new_user_test_id(1);
        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: None,
                    governance_canister_id: None
                },
                some_principal
            ),
            GetNextSnsVersionResponse::default()
        );

        let mut wasm = smallest_valid_wasm();

        // Add a Governance WASM
        wasm.canister_type = SnsCanisterType::Governance.into();

        let valid_hash = wasm.sha256_hash();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Add a Root WASM
        wasm.canister_type = SnsCanisterType::Root.into();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Add a Ledger WASM
        wasm.canister_type = SnsCanisterType::Ledger.into();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Add a Swap WASM
        wasm.canister_type = SnsCanisterType::Swap.into();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Add an Archive WASM
        wasm.canister_type = SnsCanisterType::Archive.into();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Add an Index WASM
        wasm.canister_type = SnsCanisterType::Index.into();

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm),
            hash: valid_hash.to_vec(),
            skip_update_latest_version: Some(false),
        });

        // Assert that the upgrade path was constructed as expected
        let expected_next_sns_version1 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version2 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version3 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ledger_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version4 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ledger_wasm_hash: valid_hash.to_vec(),
            swap_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version5 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ledger_wasm_hash: valid_hash.to_vec(),
            swap_wasm_hash: valid_hash.to_vec(),
            archive_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version6 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ledger_wasm_hash: valid_hash.to_vec(),
            swap_wasm_hash: valid_hash.to_vec(),
            archive_wasm_hash: valid_hash.to_vec(),
            index_wasm_hash: valid_hash.to_vec(),
        };

        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(Default::default()),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version1.clone().into()
        );

        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(expected_next_sns_version1),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version2.clone().into()
        );

        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(expected_next_sns_version2),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version3.clone().into()
        );

        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(expected_next_sns_version3),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version4.clone().into()
        );
        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(expected_next_sns_version4),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version5.clone().into()
        );
        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(expected_next_sns_version5),
                    governance_canister_id: None
                },
                some_principal
            ),
            expected_next_sns_version6.into()
        );
    }

    #[test]
    fn test_reconfigure_previous_upgrade_path_for_specific_sns() {
        // In this test, we use a combination of (1) add_wasm without updating latest version and
        // (2) insert_upgrade_path_entries to reconfigure a previous upgrade path for a specific SNS
        let mut canister = new_wasm_canister();
        let normal_governance_canister_id = CanisterId::from_u64(1);
        let special_governance_canister_id = CanisterId::from_u64(1000);
        // Prepare the deployed SNS list for the test, since inserting custom upgrade path entries
        // requires a deployed SNS.
        canister.deployed_sns_list.push(DeployedSns {
            root_canister_id: Some(CanisterId::from_u64(999).into()),
            governance_canister_id: Some(special_governance_canister_id.get()),
            ledger_canister_id: Some(CanisterId::from_u64(1001).into()),
            swap_canister_id: Some(CanisterId::from_u64(1002).into()),
            index_canister_id: Some(CanisterId::from_u64(1003).into()),
        });

        let mut add_wasm_and_return_hash =
            |sns_type: SnsCanisterType, id: u32, skip_update_latest_version: bool| {
                let wasm = SnsWasm {
                    canister_type: sns_type as i32,
                    ..small_valid_wasm_with_id(format!("{} {}", sns_type.as_str_name(), id))
                };
                let hash = wasm.sha256_hash();
                let response = canister.add_wasm(AddWasmRequest {
                    wasm: Some(wasm),
                    hash: hash.to_vec(),
                    skip_update_latest_version: Some(skip_update_latest_version),
                });

                assert_eq!(
                    response,
                    AddWasmResponse {
                        result: Some(add_wasm_response::Result::Hash(hash.to_vec())),
                    }
                );

                hash.to_vec()
            };

        // Below is the "normal" upgrade path
        let governance_1_hash = add_wasm_and_return_hash(SnsCanisterType::Governance, 1, false);
        let root_1_hash = add_wasm_and_return_hash(SnsCanisterType::Root, 1, false);
        let ledger_1_hash = add_wasm_and_return_hash(SnsCanisterType::Ledger, 1, false);
        let swap_1_hash = add_wasm_and_return_hash(SnsCanisterType::Swap, 1, false);
        let archive_1_hash = add_wasm_and_return_hash(SnsCanisterType::Archive, 1, false);
        let index_1_hash = add_wasm_and_return_hash(SnsCanisterType::Index, 1, false);
        let governance_2_hash = add_wasm_and_return_hash(SnsCanisterType::Governance, 2, false);

        let basic_version = SnsVersion {
            governance_wasm_hash: governance_1_hash,
            root_wasm_hash: root_1_hash,
            ledger_wasm_hash: ledger_1_hash,
            swap_wasm_hash: swap_1_hash,
            archive_wasm_hash: archive_1_hash,
            index_wasm_hash: index_1_hash,
        };
        // Add a "special" root wasm that is not in the normal upgrade path.
        let root_2_hash = add_wasm_and_return_hash(SnsCanisterType::Root, 2, true);

        // Assert that the upgrade path for the normal governance canister does not contain the
        // special wasm, even before the insert_upgrade_path_entries call.
        assert_eq!(
            canister.get_next_sns_version(
                GetNextSnsVersionRequest {
                    current_version: Some(SnsVersion {
                        governance_wasm_hash: governance_2_hash.clone(),
                        ..basic_version.clone()
                    }),
                    governance_canister_id: Some(normal_governance_canister_id.get()),
                },
                PrincipalId::new_user_test_id(1),
            ),
            GetNextSnsVersionResponse { next_version: None }
        );

        let response = canister.insert_upgrade_path_entries(InsertUpgradePathEntriesRequest {
            upgrade_path: vec![
                SnsUpgrade {
                    current_version: Some(basic_version.clone()),
                    next_version: Some(SnsVersion {
                        root_wasm_hash: root_2_hash.clone(),
                        ..basic_version.clone()
                    }),
                },
                SnsUpgrade {
                    current_version: Some(SnsVersion {
                        root_wasm_hash: root_2_hash.clone(),
                        ..basic_version.clone()
                    }),
                    next_version: Some(SnsVersion {
                        root_wasm_hash: root_2_hash.clone(),
                        governance_wasm_hash: governance_2_hash.clone(),
                        ..basic_version.clone()
                    }),
                },
            ],
            sns_governance_canister_id: Some(special_governance_canister_id.get()),
        });
        assert_eq!(response, InsertUpgradePathEntriesResponse { error: None });

        // Assert that the upgrade path for the normal governance canister.
        let normal_upgrade_steps = canister
            .list_upgrade_steps(ListUpgradeStepsRequest {
                starting_at: Some(basic_version.clone()),
                sns_governance_canister_id: Some(normal_governance_canister_id.get()),
                limit: 0,
            })
            .steps
            .into_iter()
            .map(|step| step.version.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            normal_upgrade_steps,
            vec![
                basic_version.clone(),
                SnsVersion {
                    governance_wasm_hash: governance_2_hash.clone(),
                    ..basic_version.clone()
                },
            ]
        );

        // Assert that the upgrade path for the special governance canister.
        let special_upgrade_steps = canister
            .list_upgrade_steps(ListUpgradeStepsRequest {
                starting_at: Some(basic_version.clone()),
                sns_governance_canister_id: Some(special_governance_canister_id.get()),
                limit: 0,
            })
            .steps
            .into_iter()
            .map(|step| step.version.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            special_upgrade_steps,
            vec![
                basic_version.clone(),
                SnsVersion {
                    root_wasm_hash: root_2_hash.clone(),
                    ..basic_version.clone()
                },
                SnsVersion {
                    root_wasm_hash: root_2_hash.clone(),
                    governance_wasm_hash: governance_2_hash.clone(),
                    ..basic_version.clone()
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_missing_init_payload() {
        let canister_api = new_canister_api();

        test_deploy_new_sns_request_one_proposal(
            None,
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                canisters: None,
                subnet_id: None,
                error: Some(SnsWasmError {
                    message: "sns_init_payload is a required field".to_string(),
                }),
                dapp_canisters_transfer_result: None,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_missing_available_subnet() {
        let canister_api = new_canister_api();

        test_deploy_new_sns_request_one_proposal(
            Some(SnsInitPayload::with_valid_values_for_testing_post_execution()),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            None,
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                canisters: None,
                subnet_id: None,
                error: Some(SnsWasmError {
                    message: "No SNS Subnet is available".to_string(),
                }),
                dapp_canisters_transfer_result: None,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_wasms_not_available() {
        let canister_api = new_canister_api();

        test_deploy_new_sns_request_one_proposal(
            Some(SnsInitPayload::with_valid_values_for_testing_post_execution()),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            false,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                canisters: None,
                subnet_id: None,
                error: Some(SnsWasmError {
                    message: "No root wasm set for this version.".to_string(),
                }),
                dapp_canisters_transfer_result: None,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_insufficient_cycles_in_request() {
        let mut canister_api = new_canister_api();
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(100000));

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: None,
                canisters: None,
                error: Some(SnsWasmError {
                    message: format!(
                        "Not enough cycles in canister.  Required: {}. Found: {}",
                        SNS_CREATION_FEE, 100000
                    ),
                }),
                dapp_canisters_transfer_result: None,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_failure_if_canisters_cannot_be_created() {
        let canister_api = new_canister_api();
        canister_api
            .errors_on_create_canister
            .lock()
            .unwrap()
            .push(Some("Canister Creation Failed from our test".to_string()));

        let subnet_id = subnet_test_id(1);

        let governance_id = canister_test_id(1);
        let ledger_id = canister_test_id(2);
        let swap_id = canister_test_id(3);
        let index_id = canister_test_id(4);

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![governance_id, ledger_id, swap_id, index_id],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                canisters: Some(SnsCanisterIds {
                    root: None,
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                subnet_id: Some(subnet_id.get()),
                error: Some(SnsWasmError {
                    message: "Could not create some canisters: Root".to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_install_wasms() {
        let canister_api = new_canister_api();
        // don't throw an error until 3rd call to API
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(None);
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(None);
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(None);
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(None);
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(Some("Test Failure".to_string()));

        let subnet_id = subnet_test_id(1);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message: "Error installing Swap WASM: Test Failure".to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_install_wasms_with_dapp_canisters() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));

        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .append(&mut vec![
                None,
                None,
                None,
                None,
                Some("Test Failure".to_string()),
            ]);

        let subnet_id = subnet_test_id(1);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let dapp_id = canister_test_id(1000).get();
        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &[dapp_id]);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            // The first call to get the controllers of the dapp_canister
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            // The second call to change the controllers of the dapp_canister to just NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
            // The third call to change the controllers of the dapp_canister to
            // the original controllers
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![],
            vec![
                (dapp_id, vec![ROOT_CANISTER_ID.get()]),
                (
                    dapp_id,
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
            ],
            vec![dapp_id],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message: "Error installing Swap WASM: Test Failure".to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![Canister::new(dapp_id)],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_add_sns_w_and_root_controllers() {
        let canister_api = new_canister_api();
        canister_api
            .errors_on_set_controller
            .lock()
            .unwrap()
            .push(None);
        canister_api
            .errors_on_set_controller
            .lock()
            .unwrap()
            .push(Some("Set controller fail".to_string()));

        let subnet_id = subnet_test_id(1);

        let this_id = canister_test_id(0);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (
                    swap_id,
                    vec![this_id.get(), root_id.get()],
                ),
            ],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message:
                        "Unable to set SNS-W and Root as Ledger canister controller: Set controller fail"
                            .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_add_sns_w_and_root_controllers_with_dapp_canisters() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api
            .errors_on_set_controller
            .lock()
            .unwrap()
            .append(&mut vec![None, Some("Set controller fail".to_string())]);

        let subnet_id = subnet_test_id(1);

        let this_id = canister_test_id(0);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let dapp_id = canister_test_id(1000).get();
        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            // The first call to get the controllers of the dapp_canister
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            // The second call to change the controllers of the dapp_canister to just NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
            // The third call to change the controllers of the dapp_canister to
            // the original controllers
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (
                    swap_id,
                    vec![this_id.get(), root_id.get()],
                ),
            ],
            vec![
                (dapp_id, vec![ROOT_CANISTER_ID.get()]),
                (
                    dapp_id,
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
            ],
            vec![dapp_id],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message:
                        "Unable to set SNS-W and Root as Ledger canister controller: Set controller fail"
                            .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![Canister::new(dapp_id)],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_remove_sns_w_as_controllers() {
        let canister_api = new_canister_api();
        let mut errors = vec![
            None,
            None,
            None,
            None,
            None,
            Some("Set controller fail".to_string()),
        ];
        canister_api
            .errors_on_set_controller
            .lock()
            .unwrap()
            .append(&mut errors);

        let this_id = canister_test_id(0);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        // The cycles sent to each canister after its creation is the whole fee minus what was
        // used to create them, minus the INITIAL_CANISTER_CREATION_CYCLES that is allocated for
        // archive.  Also see below, ledger is given a double share, plus INITIAL_CANISTER_CREATION_CYCLES
        // to account for archive
        let sent_cycles =
            (SNS_CREATION_FEE - CANISTER_CREATION_CYCLES - INITIAL_CANISTER_CREATION_CYCLES) / 6;

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![
                (root_id, sent_cycles),
                (governance_id, sent_cycles),
                (
                    ledger_id,
                    sent_cycles * 2 + INITIAL_CANISTER_CREATION_CYCLES,
                ),
                (swap_id, sent_cycles),
                (index_id, sent_cycles),
            ],
            vec![],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (swap_id, vec![this_id.get(), root_id.get()]),
                (governance_id, vec![root_id.get()]),
                (ledger_id, vec![root_id.get()]),
                (root_id, vec![governance_id.get()]),
                (swap_id, vec![root_id.get()]),
                (index_id, vec![root_id.get()]),
            ],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_test_id(1).get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),

                error: Some(SnsWasmError {
                    message:
                        "Unable to remove SNS-W as Governance's controller: Set controller fail"
                            .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_remove_sns_w_as_controllers_with_dapp_canisters() {
        let mut canister_api = new_canister_api();
        canister_api
            .errors_on_set_controller
            .lock()
            .unwrap()
            .append(&mut vec![
                None,
                None,
                None,
                None,
                None,
                Some("Set controller fail".to_string()),
            ]);
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let this_id = canister_test_id(0);

        let subnet_id = subnet_test_id(1);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let dapp_id = canister_test_id(1000).get();
        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        // The cycles sent to each canister after its creation is the whole fee minus what was
        // used to create them, minus the INITIAL_CANISTER_CREATION_CYCLES that is allocated for
        // archive.  Also see below, ledger is given a double share, plus INITIAL_CANISTER_CREATION_CYCLES
        // to account for archive
        let sent_cycles =
            (SNS_CREATION_FEE - CANISTER_CREATION_CYCLES - INITIAL_CANISTER_CREATION_CYCLES) / 6;

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &[dapp_id]);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            // The first call to get the controllers of the dapp_canister
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            // The second call to change the controllers of the dapp_canister to just NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
            // The third call to change the controllers of the dapp_canister to
            // the original controllers
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![
                (root_id, sent_cycles),
                (governance_id, sent_cycles),
                (
                    ledger_id,
                    sent_cycles * 2 + INITIAL_CANISTER_CREATION_CYCLES,
                ),
                (swap_id, sent_cycles),
                (index_id, sent_cycles),
            ],
            vec![],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (swap_id, vec![this_id.get(), root_id.get()]),
                (governance_id, vec![root_id.get()]),
                (ledger_id, vec![root_id.get()]),
                (root_id, vec![governance_id.get()]),
                (swap_id, vec![root_id.get()]),
                (index_id, vec![root_id.get()]),
            ],
            vec![
                (dapp_id, vec![ROOT_CANISTER_ID.get()]),
                (
                    dapp_id,
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
            ],
            vec![dapp_id],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_test_id(1).get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),

                error: Some(SnsWasmError {
                    message:
                        "Unable to remove SNS-W as Governance's controller: Set controller fail"
                            .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![Canister::new(dapp_id)],
                    sns_controlled_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_cleanup() {
        let canister_api = new_canister_api();
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(None);

        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(Some("Install WASM fail".to_string()));

        canister_api
            .errors_on_delete_canister
            .lock()
            .unwrap()
            .push(Some("Test Failure 1".to_string()));

        canister_api
            .errors_on_delete_canister
            .lock()
            .unwrap()
            .push(Some("Test Failure 2".to_string()));

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: Some(DappCanisters::default()),
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_test_id(1).get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message: "Failure deploying, and could not finish cleanup. Some SNS canisters \
                        may not have been deleted or some dapp_canisters may not have been restored. \
                        Deployment failure was caused by: 'Error installing Governance WASM: Install \
                        WASM fail' \n Cleanup failure was caused by: 'Could not delete Root canister: \
                        Test Failure 1\nCould not delete Governance canister: Test Failure 2'"
                        .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_governance_deploy_sends_cycles_but_not_from_request() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let this_id = canister_test_id(0);

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        // The cycles sent to each canister after its creation is the whole fee minus what was
        // used to create them, minus the INITIAL_CANISTER_CREATION_CYCLES that is allocated for
        // archive.  Also see below, ledger is given a double share, plus INITIAL_CANISTER_CREATION_CYCLES
        // to account for archive
        let sent_cycles =
            (SNS_CREATION_FEE - CANISTER_CREATION_CYCLES - INITIAL_CANISTER_CREATION_CYCLES) / 6;

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: Some(DappCanisters::default()),
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![
                (root_id, sent_cycles),
                (governance_id, sent_cycles),
                (
                    ledger_id,
                    sent_cycles * 2 + INITIAL_CANISTER_CREATION_CYCLES,
                ),
                (swap_id, sent_cycles),
                (index_id, sent_cycles),
            ],
            vec![],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (swap_id, vec![this_id.get(), root_id.get()]),
                (governance_id, vec![root_id.get()]),
                (ledger_id, vec![root_id.get()]),
                (root_id, vec![governance_id.get()]),
                (swap_id, vec![root_id.get()]),
                (index_id, vec![root_id.get()]),
            ],
            vec![],
            vec![],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_test_id(1).get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: None,
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    async fn test_deploy_new_sns_request_one_proposal(
        sns_init_payload: Option<SnsInitPayload>,
        canister_api: TestCanisterApi,
        nns_root_canister_client: &SpyNnsRootCanisterClient,
        available_subnet: Option<SubnetId>,
        wasm_available: bool,
        expected_accepted_cycles: Vec<u64>,
        expected_sent_cycles: Vec<(CanisterId, u64)>,
        expected_canisters_destroyed: Vec<CanisterId>,
        expected_set_controllers_calls: Vec<(CanisterId, Vec<PrincipalId>)>,
        expected_change_canister_controllers_calls: Vec<(PrincipalId, Vec<PrincipalId>)>,
        expected_canister_status_calls: Vec<PrincipalId>,
        expected_response: DeployNewSnsResponse,
    ) {
        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
        }

        let caller = GOVERNANCE_CANISTER_ID.get();

        test_deploy_new_sns_request(
            &CANISTER_WRAPPER,
            sns_init_payload,
            canister_api,
            nns_root_canister_client,
            available_subnet,
            wasm_available,
            caller,
            expected_accepted_cycles,
            expected_sent_cycles,
            expected_canisters_destroyed,
            expected_set_controllers_calls,
            expected_change_canister_controllers_calls,
            expected_canister_status_calls,
            expected_response,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn test_deploy_new_sns_request(
        canister_wrapper: &'static LocalKey<RefCell<SnsWasmCanister<TestCanisterStableMemory>>>,
        sns_init_payload: Option<SnsInitPayload>,
        canister_api: TestCanisterApi,
        nns_root_canister_client: &SpyNnsRootCanisterClient,
        available_subnet: Option<SubnetId>,
        wasm_available: bool,
        caller: PrincipalId,
        expected_accepted_cycles: Vec<u64>,
        expected_sent_cycles: Vec<(CanisterId, u64)>,
        expected_canisters_destroyed: Vec<CanisterId>,
        expected_set_controllers_calls: Vec<(CanisterId, Vec<PrincipalId>)>,
        expected_change_canister_controllers_calls: Vec<(PrincipalId, Vec<PrincipalId>)>,
        expected_canister_status_calls: Vec<PrincipalId>,
        expected_response: DeployNewSnsResponse,
    ) {
        canister_wrapper.with(|c| {
            if available_subnet.is_some() {
                c.borrow_mut()
                    .set_sns_subnets(vec![available_subnet.unwrap()]);
            }
            if wasm_available {
                add_dummy_wasms(&mut c.borrow_mut(), None);
            }
        });

        let response = SnsWasmCanister::deploy_new_sns(
            canister_wrapper,
            &canister_api,
            nns_root_canister_client,
            DeployNewSnsRequest { sns_init_payload },
            caller,
        )
        .await;

        assert_eq!(response, expected_response);

        // Assert that we accepted the cycles
        let cycles_accepted = &*canister_api.cycles_accepted.lock().unwrap();
        assert_eq!(&expected_accepted_cycles, cycles_accepted);

        let cycles_sent = &*canister_api.cycles_sent.lock().unwrap();
        assert_eq!(&expected_sent_cycles, cycles_sent);

        let canisters_destroyed = &*canister_api.canisters_deleted.lock().unwrap();
        assert_eq!(&expected_canisters_destroyed, canisters_destroyed);

        let set_controllers_calls = &*canister_api.set_controllers_calls.lock().unwrap();
        assert_eq!(&expected_set_controllers_calls, set_controllers_calls);

        assert_nns_root_calls(
            nns_root_canister_client,
            expected_change_canister_controllers_calls,
            expected_canister_status_calls,
        );
    }

    #[track_caller]
    fn assert_nns_root_calls(
        nns_root_canister_client: &SpyNnsRootCanisterClient,
        expected_change_canister_controllers_calls: Vec<(PrincipalId, Vec<PrincipalId>)>,
        expected_canister_status_calls: Vec<PrincipalId>,
    ) {
        let nns_root_canister_calls = nns_root_canister_client.get_calls_snapshot();
        let observed_change_canister_controller_calls: Vec<SpyNnsRootCanisterClientCall> =
            nns_root_canister_calls
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        SpyNnsRootCanisterClientCall::ChangeCanisterControllers(_)
                    )
                })
                .cloned()
                .collect();

        let expected_change_canister_controllers_calls: Vec<SpyNnsRootCanisterClientCall> =
            expected_change_canister_controllers_calls
                .into_iter()
                .map(|(target_canister_id, new_controllers)| {
                    SpyNnsRootCanisterClientCall::ChangeCanisterControllers(
                        ChangeCanisterControllersRequest {
                            target_canister_id,
                            new_controllers,
                        },
                    )
                })
                .collect();

        assert_eq!(
            expected_change_canister_controllers_calls,
            observed_change_canister_controller_calls
        );

        let observed_canister_status_calls: Vec<SpyNnsRootCanisterClientCall> =
            nns_root_canister_calls
                .iter()
                .filter(|call| matches!(call, SpyNnsRootCanisterClientCall::CanisterStatus(_)))
                .cloned()
                .collect();

        let expected_canister_status_calls: Vec<SpyNnsRootCanisterClientCall> =
            expected_canister_status_calls
                .into_iter()
                .map(|principal_id| {
                    SpyNnsRootCanisterClientCall::CanisterStatus(CanisterIdRecord {
                        canister_id: CanisterId::unchecked_from_principal(principal_id),
                    })
                })
                .collect();

        assert_eq!(
            expected_canister_status_calls,
            observed_canister_status_calls
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_records_root_canisters() {
        let test_id = subnet_test_id(1);
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(SNS_CREATION_FEE));

        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
            add_dummy_wasms(&mut c.borrow_mut(), None);
        });

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        let sns_1 = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            DeployNewSnsRequest {
                sns_init_payload: Some(sns_init_payload.clone()),
            },
            PrincipalId::from(GOVERNANCE_CANISTER_ID),
        )
        .await
        .canisters
        .unwrap();

        // Add more cycles so our second call works
        let sns_2 = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            DeployNewSnsRequest {
                sns_init_payload: Some(sns_init_payload),
            },
            PrincipalId::from(GOVERNANCE_CANISTER_ID),
        )
        .await
        .canisters
        .unwrap();

        assert_unique_canister_ids(&sns_1, &sns_2);

        let known_deployments_response = CANISTER_WRAPPER.with(|canister| {
            canister
                .borrow()
                .list_deployed_snses(ListDeployedSnsesRequest {})
        });

        assert_eq!(
            known_deployments_response,
            ListDeployedSnsesResponse {
                instances: vec![DeployedSns::from(sns_1), DeployedSns::from(sns_2),],
            },
        )
    }

    #[tokio::test]
    async fn test_deploy_new_sns_works_for_nns_governance() {
        let test_id = subnet_test_id(1);
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
            add_dummy_wasms(&mut c.borrow_mut(), None);
        });

        let original_dapp_controller = PrincipalId::new_user_test_id(10);
        let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let root_canister_calls = sns_init_payload
            .dapp_canisters
            .clone()
            .unwrap_or_default()
            .canisters
            .iter()
            .map(|_| {
                SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                    original_dapp_controller,
                    ROOT_CANISTER_ID.get(),
                ])
            })
            .chain(
                sns_init_payload
                    .dapp_canisters
                    .clone()
                    .unwrap_or_default()
                    .canisters
                    .iter()
                    .flat_map(|_| {
                        vec![
                            // Transfer to NNS root
                            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(
                            ),
                            // Transfer to SNS root
                            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(
                            ),
                        ]
                    }),
            )
            .collect();

        let response = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            &SpyNnsRootCanisterClient::new(root_canister_calls),
            DeployNewSnsRequest {
                sns_init_payload: Some(sns_init_payload),
            },
            GOVERNANCE_CANISTER_ID.get(),
        )
        .await;

        assert_eq!(response.error, None);

        let sns_1 = response.canisters.unwrap();

        let known_deployments_response = CANISTER_WRAPPER.with(|canister| {
            canister
                .borrow()
                .list_deployed_snses(ListDeployedSnsesRequest {})
        });

        assert_eq!(
            known_deployments_response,
            ListDeployedSnsesResponse {
                instances: vec![DeployedSns::from(sns_1)],
            },
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_fails_for_nns_governance_is_sns_w_low_on_cycles() {
        let test_id = subnet_test_id(1);
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE - 1));

        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
            add_dummy_wasms(&mut c.borrow_mut(), None);
        });

        let response = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            DeployNewSnsRequest {
                sns_init_payload: Some(
                    SnsInitPayload::with_valid_values_for_testing_post_execution(),
                ),
            },
            GOVERNANCE_CANISTER_ID.get(),
        )
        .await;

        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message: "Not enough cycles in canister.  \
                    Required: 180000000000000. Found: 179999999999999"
                    .to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_with_dapp_canisters_only_by_nns_governance() {
        let test_id = subnet_test_id(1);
        let principal = PrincipalId::new_user_test_id(1);

        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));

        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|sns_wasm| {
            let mut sns_wasm = sns_wasm.borrow_mut();
            sns_wasm.set_sns_subnets(vec![test_id]);
            add_dummy_wasms(&mut sns_wasm, None);
        });

        let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();

        let response = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            &SpyNnsRootCanisterClient::new(vec![]),
            DeployNewSnsRequest {
                sns_init_payload: Some(sns_init_payload),
            },
            principal,
        )
        .await;

        assert_eq!(
            response.error,
            Some(SnsWasmError {
                message: "Only the NNS Governance may deploy a new SNS instance.".to_string()
            })
        );
    }

    #[tokio::test]
    async fn fail_take_sole_control_of_dapps() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let dapp_ids = [
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];
        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let sns_init_payload = SnsInitPayload {
            dapp_canisters: Some(DappCanisters {
                canisters: dapp_ids
                    .iter()
                    .map(|id| Canister { id: Some(*id) })
                    .collect(),
            }),
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_root(
                None,
                "Only controllers of canisters can change canister controllers".to_string(),
            ),
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_replica(
                None,
                "Only controllers of canisters can change canister controllers".to_string(),
            ),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![
                (dapp_ids[0], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![ROOT_CANISTER_ID.get()]),
                (
                    dapp_ids[0],
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
            ],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: None,
                canisters: None,
                error: Some(SnsWasmError {
                    message: "Could not change the controller of all dapp canisters to NNS Root."
                        .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![Canister::new(dapp_ids[0])],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![
                        Canister::new(dapp_ids[1]),
                        Canister::new(dapp_ids[2]),
                    ],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_transfer_all_dapps_to_sns_root() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let this_id = canister_test_id(0);
        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let subnet_id = subnet_test_id(1);

        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let dapp_ids = vec![
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &dapp_ids);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 2 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 3 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to SNS Root
            // Failed transfer of dapp 2 to SNS Root
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_root(
                None,
                "Something went wrong".to_string(),
            ),
            // Failed transfer of dapp 3 to SNS Root
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_replica(
                None,
                "Something else went wrong".to_string(),
            ),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to original controller
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 2 to original controller
        ]);

        // The cycles sent to each canister after its creation is the whole fee minus what was
        // used to create them, minus the INITIAL_CANISTER_CREATION_CYCLES that is allocated for
        // archive.  Also see below, ledger is given a double share, plus INITIAL_CANISTER_CREATION_CYCLES
        // to account for archive
        let sent_cycles =
            (SNS_CREATION_FEE - CANISTER_CREATION_CYCLES - INITIAL_CANISTER_CREATION_CYCLES) / 6;

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![
                (root_id, sent_cycles),
                (governance_id, sent_cycles),
                (
                    ledger_id,
                    sent_cycles * 2 + INITIAL_CANISTER_CREATION_CYCLES,
                ),
                (swap_id, sent_cycles),
                (index_id, sent_cycles),
            ],
            vec![],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (swap_id, vec![this_id.get(), root_id.get()]),
                (governance_id, vec![root_id.get()]),
                (ledger_id, vec![root_id.get()]),
                (root_id, vec![governance_id.get()]),
                (swap_id, vec![root_id.get()]),
                (index_id, vec![root_id.get()]),
            ],
            vec![
                (dapp_ids[0], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[0], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (
                    dapp_ids[1],
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
                (
                    dapp_ids[2],
                    vec![original_dapp_controller, ROOT_CANISTER_ID.get()],
                ),
            ],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message: "Could not change the controller of all dapp canisters to SNS Root."
                        .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![
                        Canister::new(dapp_ids[1]),
                        Canister::new(dapp_ids[2]),
                    ],
                    sns_controlled_dapp_canisters: vec![Canister::new(dapp_ids[0])],
                    nns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_get_controllers_of_dapp_canisters() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let dapp_ids = vec![
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &dapp_ids);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::err_canister_status_from_replica(
                None,
                "Something went wrong".to_string(),
            ),
            SpyNnsRootCanisterClientReply::err_canister_status_from_replica(
                None,
                "Something else went wrong".to_string(),
            ),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: None,
                canisters: None,
                error: Some(SnsWasmError {
                    message: "Could not get the controllers of all dapp_canisters for the following reason(s):\n  \
                    -Could not get the controllers of CanisterId(heic2-yaaaa-aaaaa-aapuq-cai) due to an error from the replica. None:\"Something went wrong\"\n  \
                    -Could not get the controllers of CanisterId(hnljg-oiaaa-aaaaa-aapva-cai) due to an error from the replica. None:\"Something else went wrong\""
                    .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn get_controllers_of_dapp_canisters_returns_empty_set() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let dapp_ids = vec![
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &dapp_ids);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_test_id(1)),
            true,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: None,
                canisters: None,
                error: Some(SnsWasmError {
                    message: "The following dapp canister(s) did not have any controllers, cannot \
                        transfer to an SNS. \"heic2-yaaaa-aaaaa-aapuq-cai\""
                        .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_restore_dapp_canisters_reversible_deployment() {
        let mut canister_api = new_canister_api();
        canister_api
            .errors_on_install_wasms
            .lock()
            .unwrap()
            .push(Some("Install WASM fail".to_string()));
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let subnet_id = subnet_test_id(1);

        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let dapp_ids = vec![
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &dapp_ids);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 2 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 3 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to original controller
            // Failed transfer of dapp 2 to original controller
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_root(
                None,
                "Something went wrong".to_string(),
            ),
            // Failed transfer of dapp 3 to original controller
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_replica(
                None,
                "Something else went wrong".to_string(),
            ),
        ]);

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![],
            vec![root_id, governance_id, ledger_id, swap_id, index_id],
            vec![],
            vec![
                (dapp_ids[0], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[0], vec![original_dapp_controller, ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![original_dapp_controller, ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![original_dapp_controller, ROOT_CANISTER_ID.get()]),
            ],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_test_id(1).get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),

                error: Some(SnsWasmError {
                    message:
                        "Failure deploying, and could not finish cleanup. Some SNS canisters \
                        may not have been deleted or some dapp_canisters may not have been \
                        restored. Deployment failure was caused by: 'Error installing Root \
                        WASM: Install WASM fail' \n Cleanup failure was caused by: 'Canister: \
                        Canister { id: Some(heic2-yaaaa-aaaaa-aapuq-cai) }. Failure \
                        Reason: \"Could not change the controllers of heic2-yaaaa-aaaaa-aapuq-cai \
                        due to an error from NNS Root: ChangeCanisterControllersError { code: None, \
                        description: \\\"Something went wrong\\\" }\".\nCanister: Canister \
                        { id: Some(hnljg-oiaaa-aaaaa-aapva-cai) }. Failure Reason: \"Could not \
                        change the controllers of hnljg-oiaaa-aaaaa-aapva-cai due to an error from \
                        the replica. None:\\\"Something else went wrong\\\"\".'"
                        .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![
                        Canister::new(dapp_ids[0]),
                    ],
                    nns_controlled_dapp_canisters: vec![
                        Canister::new(dapp_ids[1]),
                        Canister::new(dapp_ids[2]),
                    ],
                    sns_controlled_dapp_canisters: vec![],
                }),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn fail_restore_dapp_canisters_partially_reversible_deployment() {
        let mut canister_api = new_canister_api();
        canister_api.cycles_found_in_request = Arc::new(Mutex::new(0));
        canister_api.canister_cycles_balance = Arc::new(Mutex::new(SNS_CREATION_FEE));

        let this_id = canister_test_id(0);
        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);
        let index_id = canister_test_id(5);

        let subnet_id = subnet_test_id(1);

        let original_dapp_controller = PrincipalId::new_user_test_id(10);

        let dapp_ids = vec![
            canister_test_id(1000).get(),
            canister_test_id(1001).get(),
            canister_test_id(1002).get(),
        ];

        let mut sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        add_dapp_canisters(&mut sns_init_payload, &dapp_ids);

        let spy_nns_root_client = SpyNnsRootCanisterClient::new(vec![
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_canister_status_from_root(vec![
                original_dapp_controller,
                ROOT_CANISTER_ID.get(),
            ]),
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 2 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 3 to NNS Root
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to SNS Root
            // Failed transfer of dapp 2 to SNS Root
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_root(
                None,
                "Something went wrong".to_string(),
            ),
            // Failed transfer of dapp 3 to SNS Root
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_replica(
                None,
                "Something else went wrong".to_string(),
            ),
            // Failed Transfer of dapp 2 to original controller
            SpyNnsRootCanisterClientReply::ok_change_canister_controllers_from_root(), // Transfer of dapp 1 to original controller
            SpyNnsRootCanisterClientReply::err_change_canister_controllers_from_replica(
                None,
                "Something else went wrong".to_string(),
            ),
        ]);

        // The cycles sent to each canister after its creation is the whole fee minus what was
        // used to create them, minus the INITIAL_CANISTER_CREATION_CYCLES that is allocated for
        // archive.  Also see below, ledger is given a double share, plus INITIAL_CANISTER_CREATION_CYCLES
        // to account for archive
        let sent_cycles =
            (SNS_CREATION_FEE - CANISTER_CREATION_CYCLES - INITIAL_CANISTER_CREATION_CYCLES) / 6;

        test_deploy_new_sns_request_one_proposal(
            Some(sns_init_payload),
            canister_api,
            &spy_nns_root_client,
            Some(subnet_id),
            true,
            vec![],
            vec![
                (root_id, sent_cycles),
                (governance_id, sent_cycles),
                (
                    ledger_id,
                    sent_cycles * 2 + INITIAL_CANISTER_CREATION_CYCLES,
                ),
                (swap_id, sent_cycles),
                (index_id, sent_cycles),
            ],
            vec![],
            vec![
                (governance_id, vec![this_id.get(), root_id.get()]),
                (ledger_id, vec![this_id.get(), root_id.get()]),
                (index_id, vec![this_id.get(), root_id.get()]),
                (root_id, vec![this_id.get(), governance_id.get()]),
                (swap_id, vec![this_id.get(), root_id.get()]),
                (governance_id, vec![root_id.get()]),
                (ledger_id, vec![root_id.get()]),
                (root_id, vec![governance_id.get()]),
                (swap_id, vec![root_id.get()]),
                (index_id, vec![root_id.get()]),
            ],
            vec![
                (dapp_ids[0], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![ROOT_CANISTER_ID.get()]),
                (dapp_ids[0], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![root_id.get(), ROOT_CANISTER_ID.get()]),
                (dapp_ids[1], vec![original_dapp_controller, ROOT_CANISTER_ID.get()]),
                (dapp_ids[2], vec![original_dapp_controller, ROOT_CANISTER_ID.get()]),
            ],
            vec![dapp_ids[0], dapp_ids[1], dapp_ids[2]],
            DeployNewSnsResponse {
                subnet_id: Some(subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    ledger: Some(ledger_id.get()),
                    governance: Some(governance_id.get()),
                    swap: Some(swap_id.get()),
                    index: Some(index_id.get()),
                }),
                error: Some(SnsWasmError {
                    message:
                        "Failure deploying, and could not finish cleanup. Some dapp_canisters \
                        may not have been restored or transferred. Deployment failure was caused by: \
                        'Could not change the controller of all dapp canisters to SNS Root.' \n \
                        Cleanup failure was caused by: 'Canister: Canister { id: \
                        Some(hnljg-oiaaa-aaaaa-aapva-cai) }. Failure Reason: \"Could not \
                        change the controllers of hnljg-oiaaa-aaaaa-aapva-cai due to an error \
                        from the replica. None:\\\"Something else went wrong\\\"\".'"
                            .to_string(),
                }),
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![Canister::new(dapp_ids[1])],
                    nns_controlled_dapp_canisters: vec![Canister::new(dapp_ids[2])],
                    sns_controlled_dapp_canisters: vec![Canister::new(dapp_ids[0])],
                }),
            },
        )
        .await;
    }

    #[test]
    fn test_get_metrics_service_discovery() {
        let mut canister = new_wasm_canister();

        canister.deployed_sns_list.push(DeployedSns {
            root_canister_id: Some(canister_test_id(1).get()),
            governance_canister_id: Some(canister_test_id(2).get()),
            ledger_canister_id: Some(canister_test_id(3).get()),
            swap_canister_id: Some(canister_test_id(4).get()),
            index_canister_id: Some(canister_test_id(5).get()),
        });
        canister.deployed_sns_list.push(DeployedSns {
            root_canister_id: Some(canister_test_id(6).get()),
            governance_canister_id: Some(canister_test_id(7).get()),
            ledger_canister_id: Some(canister_test_id(8).get()),
            swap_canister_id: Some(canister_test_id(9).get()),
            // This isn't realistic, but it verifies the robustness of the
            // `get_metrics_service_discovery`.
            index_canister_id: None,
        });

        let metrics = canister.get_metrics_service_discovery();
        let expected_json = json!([
            {
                "labels": {"__metrics_path__": "/metrics", "sns_canister_type": "governance"},
                "targets": ["ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io", "rdmx6-jaaaa-aaaaa-aaadq-cai.raw.icp0.io"]
            },
            {
                "labels": {"__metrics_path__": "/metrics", "sns_canister_type": "index"},
                "targets": ["rno2w-sqaaa-aaaaa-aaacq-cai.raw.icp0.io"]
            },
            {
                "labels": {"__metrics_path__": "/metrics", "sns_canister_type": "ledger"},
                "targets": ["r7inp-6aaaa-aaaaa-aaabq-cai.raw.icp0.io", "qoctq-giaaa-aaaaa-aaaea-cai.raw.icp0.io"]
            },
            {
                "labels": {"__metrics_path__": "/metrics", "sns_canister_type": "root"},
                "targets": ["rrkah-fqaaa-aaaaa-aaaaq-cai.raw.icp0.io", "renrk-eyaaa-aaaaa-aaada-cai.raw.icp0.io"]
            },
            {
                "labels": {"__metrics_path__": "/metrics", "sns_canister_type": "swap"},
                "targets": ["rkp4c-7iaaa-aaaaa-aaaca-cai.raw.icp0.io", "qjdve-lqaaa-aaaaa-aaaeq-cai.raw.icp0.io"]
            }
        ]);
        assert_eq!(metrics, expected_json.to_string());
    }

    mod get_wasm_metadata {
        use super::*;
        use crate::pb::v1::{
            GetWasmMetadataRequest as GetWasmMetadataRequestPb,
            GetWasmMetadataResponse as GetWasmMetadataResponsePb,
            MetadataSection as MetadataSectionPb, get_wasm_metadata_response,
        };
        use pretty_assertions::assert_eq;

        // Gzips a wasm, returning the hash of its compressed representation.
        fn gzip_wasm_and_return_new_hash(wasm: &mut SnsWasm) -> Vec<u8> {
            wasm.wasm = wasm_helpers::gzip_wasm(&wasm.wasm[..]);
            Sha256::hash(&wasm.wasm).to_vec()
        }

        #[test]
        fn test_read_metadata_no_sections() {
            let mut canister = new_wasm_canister();

            let wasm = smallest_valid_wasm();
            let hash = Sha256::hash(&wasm.wasm);
            canister.add_wasm(AddWasmRequest {
                wasm: Some(wasm.clone()),
                hash: hash.to_vec(),
                skip_update_latest_version: Some(false),
            });

            // Run code under test
            let response = canister.get_wasm_metadata(GetWasmMetadataRequestPb {
                hash: Some(hash.to_vec()),
            });

            use get_wasm_metadata_response::{Ok, Result};
            assert_eq!(
                response,
                GetWasmMetadataResponsePb {
                    result: Some(Result::Ok(Ok { sections: vec![] }))
                }
            );
        }

        #[test]
        fn test_read_metadata_invalid() {
            let mut canister = new_wasm_canister();

            let wasm = {
                let mut wasm = smallest_valid_wasm();
                // Make this wasm invalid by changing its last byte.
                let index = wasm.wasm.len() - 1;
                wasm.wasm[index] = 1;
                wasm
            };

            let hash = Sha256::hash(&wasm.wasm);

            // Run code 1st function under test.
            {
                let response = canister.add_wasm(AddWasmRequest {
                    wasm: Some(wasm.clone()),
                    hash: hash.to_vec(),
                    skip_update_latest_version: Some(false),
                });
                use add_wasm_response::Result;
                assert_eq!(response, AddWasmResponse {
                    result: Some(Result::Error(SnsWasmError {
                        message:
                            "Cannot read metadata sections from WASM: Cannot parse WASM: Could not \
                            parse the data as WASM module. unknown binary version:  0x1000001 \
                            (at offset 0x4)"
                                .to_string()
                    }))
                });
            }

            // Run code 2nd function under test.
            {
                let response = canister.get_wasm_metadata(GetWasmMetadataRequestPb {
                    hash: Some(hash.to_vec()),
                });
                use get_wasm_metadata_response::Result;
                assert_eq!(
                    response,
                    GetWasmMetadataResponsePb {
                        result: Some(Result::Error(SnsWasmError {
                            message: format!(
                                "Cannot find WASM index for hash `{:?}`.",
                                hash.to_vec()
                            )
                        }))
                    }
                );
            }
        }

        #[test]
        fn test_read_metadata_one_section() {
            let git_commit_id = "ABCDEFG".to_string();
            let git_commit_id = git_commit_id.as_bytes();

            let mut wasm = smallest_valid_wasm();
            let hash = annotate_wasm_with_metadata_and_return_new_hash(
                &mut wasm,
                true,
                "git_commit_id",
                git_commit_id.to_vec(),
            );

            let mut canister = new_wasm_canister();
            canister.add_wasm(AddWasmRequest {
                wasm: Some(wasm.clone()),
                hash: hash.clone(),
                skip_update_latest_version: Some(false),
            });

            // Run code under test
            let response =
                canister.get_wasm_metadata(GetWasmMetadataRequestPb { hash: Some(hash) });

            use get_wasm_metadata_response::{Ok, Result};
            assert_eq!(
                response,
                GetWasmMetadataResponsePb {
                    result: Some(Result::Ok(Ok {
                        sections: vec![MetadataSectionPb {
                            visibility: Some("icp:public".to_string()),
                            name: Some("git_commit_id".to_string()),
                            contents: Some(git_commit_id.to_vec()),
                        }],
                    }))
                }
            );
        }

        #[test]
        fn test_read_metadata_two_sections() {
            let git_commit_id = "ABCDEFG".to_string();
            let git_commit_id = git_commit_id.as_bytes();

            let other_contents = "123456".to_string();
            let other_contents = other_contents.as_bytes();

            let mut wasm = smallest_valid_wasm();

            let hash = {
                annotate_wasm_with_metadata_and_return_new_hash(
                    &mut wasm,
                    true,
                    "git_commit_id",
                    git_commit_id.to_vec(),
                );
                annotate_wasm_with_metadata_and_return_new_hash(
                    &mut wasm,
                    false,
                    "other_contents",
                    other_contents.to_vec(),
                )
            };

            let mut canister = new_wasm_canister();
            canister.add_wasm(AddWasmRequest {
                wasm: Some(wasm.clone()),
                hash: hash.clone(),
                skip_update_latest_version: Some(false),
            });

            // Run code under test
            let response =
                canister.get_wasm_metadata(GetWasmMetadataRequestPb { hash: Some(hash) });

            use get_wasm_metadata_response::{Ok, Result};
            assert_eq!(
                response,
                GetWasmMetadataResponsePb {
                    result: Some(Result::Ok(Ok {
                        sections: vec![
                            MetadataSectionPb {
                                visibility: Some("icp:public".to_string()),
                                name: Some("git_commit_id".to_string()),
                                contents: Some(git_commit_id.to_vec()),
                            },
                            MetadataSectionPb {
                                visibility: Some("icp:private".to_string()),
                                name: Some("other_contents".to_string()),
                                contents: Some(other_contents.to_vec()),
                            },
                        ],
                    }))
                }
            );
        }

        #[test]
        fn test_read_metadata_gzipped() {
            let git_commit_id = "ABCDEFG".to_string();
            let git_commit_id = git_commit_id.as_bytes();

            let mut wasm = smallest_valid_wasm();

            let hash = {
                annotate_wasm_with_metadata_and_return_new_hash(
                    &mut wasm,
                    true,
                    "git_commit_id",
                    git_commit_id.to_vec(),
                );
                gzip_wasm_and_return_new_hash(&mut wasm)
            };

            let mut canister = new_wasm_canister();
            canister.add_wasm(AddWasmRequest {
                wasm: Some(wasm.clone()),
                hash: hash.clone(),
                skip_update_latest_version: Some(false),
            });

            // Run code under test
            let response =
                canister.get_wasm_metadata(GetWasmMetadataRequestPb { hash: Some(hash) });

            use get_wasm_metadata_response::{Ok, Result};
            assert_eq!(
                response,
                GetWasmMetadataResponsePb {
                    result: Some(Result::Ok(Ok {
                        sections: vec![MetadataSectionPb {
                            visibility: Some("icp:public".to_string()),
                            name: Some("git_commit_id".to_string()),
                            contents: Some(git_commit_id.to_vec()),
                        }],
                    }))
                }
            );
        }
    }
}
