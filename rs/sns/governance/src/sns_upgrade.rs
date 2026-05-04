use crate::cached_upgrade_steps::CachedUpgradeSteps;
use crate::{pb::v1::governance::Version, proposal::render_version, types::Environment};
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::canister_status::CanisterStatusResultV2;
use ic_nns_constants::SNS_WASM_CANISTER_ID;

/// A struct to represent all the types of SNS canisters Governance knows about.
pub struct RunningSnsCanisters {
    pub root: Option<PrincipalId>,
    pub governance: Option<PrincipalId>,
    pub ledger: Option<PrincipalId>,
    pub swap: Option<PrincipalId>,
    pub dapps: Vec<PrincipalId>,
    pub archives: Vec<PrincipalId>,
    pub index: Option<PrincipalId>,
}

/// Upgrade parameters.
pub(crate) struct UpgradeSnsParams {
    pub next_version: Version,
    pub canister_type_to_upgrade: SnsCanisterType,
    pub new_wasm_hash: Vec<u8>,
    pub canister_ids_to_upgrade: Vec<CanisterId>,
}

pub(crate) async fn get_upgrade_params(
    env: &dyn Environment,
    root_canister_id: CanisterId,
    current_version: &Version,
) -> Result<UpgradeSnsParams, String> {
    let next_version = match get_next_version(env, &current_version.clone()).await {
        Some(next) => next,
        None => {
            return Err(format!(
                "There is no next version found for the current SNS version: {}",
                render_version(current_version)
            ));
        }
    };

    let (canister_type_to_upgrade, new_wasm_hash) =
        canister_type_and_wasm_hash_for_upgrade(current_version, &next_version)?;

    let canister_ids_to_upgrade =
        get_canisters_to_upgrade(env, root_canister_id, canister_type_to_upgrade).await?;

    Ok(UpgradeSnsParams {
        next_version,
        canister_type_to_upgrade,
        new_wasm_hash,
        canister_ids_to_upgrade,
    })
}

// TODO(NNS1-1590) make these methods pub instead of pub(crate) after we no longer are duplicating
// the type definitions.  They are only that way to avoid leaking the types as they are not intended
// to be exposed beyond our workaround implementation.

/// Fetches the wasm from SNS-WASM canister and checks it against expected SnsCanisterType.
pub(crate) async fn get_wasm(
    env: &dyn Environment,
    wasm_hash: Vec<u8>,
    expected_sns_canister_type: SnsCanisterType,
) -> Result<SnsWasm, String> {
    let response = env
        .call_canister(
            SNS_WASM_CANISTER_ID,
            "get_wasm",
            Encode!(&GetWasmRequest { hash: wasm_hash })
                .map_err(|e| format!("Could not encode GetWasmRequest: {e:?}"))?,
        )
        .await
        .map_err(|(code, message)| {
            format!(
                "Call to get_wasm failed: {} {}",
                code.unwrap_or_default(),
                message
            )
        })?;

    let response = Decode!(&response, GetWasmResponse)
        .map_err(|e| format!("Decoding GetWasmResponse failed: {e:?}"))?;
    let wasm = response
        .wasm
        .ok_or_else(|| "No WASM found using hash returned from SNS-WASM canister.".to_string())?;

    let returned_canister_type = SnsCanisterType::try_from(wasm.canister_type).map_err(|err| {
        format!("Could not convert response from SNS-WASM to valid SnsCanisterType: {err}")
    })?;

    if returned_canister_type != expected_sns_canister_type {
        return Err(format!(
            "WASM returned from SNS-WASM is not intended for the same canister type. \
            Expected: {expected_sns_canister_type:?}.  Received: {returned_canister_type:?}."
        ));
    }

    Ok(wasm)
}

pub(crate) async fn get_proposal_id_that_added_wasm(
    env: &dyn Environment,
    wasm_hash: Vec<u8>,
) -> Result<Option<u64>, String> {
    let response = env
        .call_canister(
            SNS_WASM_CANISTER_ID,
            "get_proposal_id_that_added_wasm",
            Encode!(&GetProposalIdThatAddedWasmRequest { hash: wasm_hash }).map_err(|e| {
                format!("Could not encode GetProposalIdThatAddedWasmRequest: {e:?}")
            })?,
        )
        .await
        .map_err(|(code, message)| {
            format!(
                "Call to get_proposal_id_that_added_wasm failed: {} {}",
                code.unwrap_or_default(),
                message
            )
        })?;

    let response = Decode!(&response, GetProposalIdThatAddedWasmResponse)
        .map_err(|e| format!("Decoding GetProposalIdThatAddedWasmResponse failed: {e:?}"))?;
    let proposal_id = response.proposal_id;

    Ok(proposal_id)
}

pub(crate) async fn get_canisters_to_upgrade(
    env: &dyn Environment,
    root_canister_id: CanisterId,
    canister_type: SnsCanisterType,
) -> Result<Vec<CanisterId>, String> {
    let running_canisters = get_all_sns_canisters(env, root_canister_id).await?;
    let (maybe_principals, label) = match canister_type {
        SnsCanisterType::Root => (vec![running_canisters.root], "Root"),
        SnsCanisterType::Governance => (vec![running_canisters.governance], "Governance"),
        SnsCanisterType::Ledger => (vec![running_canisters.ledger], "Ledger"),
        SnsCanisterType::Swap => (vec![running_canisters.swap], "Swap"),
        SnsCanisterType::Archive => (
            running_canisters
                .archives
                .iter()
                .map(|p| Some(*p))
                .collect(),
            "Ledger Archives",
        ),
        SnsCanisterType::Index => (vec![running_canisters.index], "Index"),
        SnsCanisterType::Unspecified => panic!("SnsCanisterType cannot be unspecified"),
    };
    maybe_principals
        .iter()
        .map(|maybe_principal| {
            maybe_principal
                .ok_or_else(|| {
                    format!("Did not receive {label} CanisterId from list_sns_canisters call")
                })
                .map(CanisterId::unchecked_from_principal)
        })
        .collect()
}

pub(crate) fn canister_type_and_wasm_hash_for_upgrade(
    current_version: &Version,
    next_version: &Version,
) -> Result<(SnsCanisterType, Vec<u8>), String> {
    let mut differences = current_version.changes_against(next_version);

    // This should be impossible due to upstream constraints.
    if differences.is_empty() {
        return Err(format!(
            "No difference was found between the current SNS version {current_version:?} and the next SNS version {next_version:?}"
        ));
    }

    // This should also be impossible due to upstream constraints.
    if differences.len() > 1 {
        return Err(
            "There is more than one upgrade possible for UpgradeSnsToNextVersion Action.  This is not currently supported.".to_string()
        );
    }

    Ok(differences.remove(0))
}

/// Get the current version of the SNS this SNS is using.  This may not include
/// the archive version (as there may not be a running archive).  It will reflect
/// the current state of Root's knowledge about which canisters exist.
pub(crate) async fn get_running_version(
    env: &dyn Environment,
    root_canister_id: CanisterId,
) -> Result<Version, String> {
    let response = sns_canisters_summary(env, root_canister_id).await?;

    let GetSnsCanistersSummaryResponse {
        root: Some(root),
        governance: Some(governance),
        ledger: Some(ledger),
        swap: Some(swap),
        dapps: _,
        archives,
        index: Some(index),
    } = response
    else {
        return Err(format!(
            "CanisterSummary could not be fetched for all canisters: {response:?}"
        ));
    };

    let get_hash = |canister_status: CanisterSummary, label: &str| {
        canister_status
            .status
            .ok_or_else(|| format!("{label} had no status"))
            .and_then(|status| {
                status
                    .module_hash
                    .ok_or_else(|| format!("{label} Status had no module hash"))
            })
    };

    // If the values are not all unique, we return vec![0, 0, 0], which will not
    // be interpreted as empty (i.e. no running archives) but won't match any archive hashes
    let archive_wasm_hash = archives
        .into_iter()
        .map(|canister_summary| get_hash(canister_summary, "Ledger Archive"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        // Make sure all returned versions are the same.
        .reduce(|x, y| if x == y { x } else { vec![0, 0, 0] })
        .unwrap_or_default();

    Ok(Version {
        root_wasm_hash: get_hash(root, "Root")?,
        governance_wasm_hash: get_hash(governance, "Governance")?,
        ledger_wasm_hash: get_hash(ledger, "Ledger")?,
        swap_wasm_hash: get_hash(swap, "Swap")?,
        archive_wasm_hash,
        index_wasm_hash: get_hash(index, "Index")?,
    })
}

/// Returns the current canister_summary, which will be up-to-date as of the response made.
async fn sns_canisters_summary(
    env: &dyn Environment,
    root_canister_id: CanisterId,
) -> Result<GetSnsCanistersSummaryResponse, String> {
    let arg = Encode!(&GetSnsCanistersSummaryRequest {
        update_canister_list: Some(true)
    })
    .map_err(|e| format!("Could not encode GetSnsCanistersSummaryRequest: {e:?}"))?;

    let response = env
        .call_canister(root_canister_id, "get_sns_canisters_summary", arg)
        .await
        .map_err(|e| format!("Request failed for get_sns_canisters_summary: {e:?}"))?;

    Decode!(&response, GetSnsCanistersSummaryResponse)
        .map_err(|e| format!("Failed to decode response: {e:?}"))
}

/// Get the next version of the SNS based on a given version.
async fn get_next_version(env: &dyn Environment, current_version: &Version) -> Option<Version> {
    let arg = Encode!(&GetNextSnsVersionRequest {
        current_version: Some(current_version.clone().into())
    })
    .unwrap();

    let response = env
        .call_canister(SNS_WASM_CANISTER_ID, "get_next_sns_version", arg)
        .await
        .expect("Request failed for get_next_sns_version");

    let response = Decode!(&response, GetNextSnsVersionResponse)
        .expect("Could not decode response to get_next_sns_version");

    response.next_version.map(|v| v.into())
}

pub(crate) async fn get_upgrade_steps(
    env: &dyn Environment,
    current_version: Version,
    sns_governance_canister_id: PrincipalId,
) -> Result<CachedUpgradeSteps, String> {
    let request = ListUpgradeStepsRequest {
        starting_at: Some(current_version.into()),
        sns_governance_canister_id: Some(sns_governance_canister_id),
        limit: 0,
    };
    let arg = Encode!(&request)
        .map_err(|err| format!("Could not encode ListUpgradeStepsRequest: {err:?}"))?;

    let requested_timestamp_seconds = env.now();

    let response = env
        .call_canister(SNS_WASM_CANISTER_ID, "list_upgrade_steps", arg)
        .await
        .map_err(|err| format!("Request failed for get_next_sns_version: {err:?}"))?;

    let response = Decode!(&response, ListUpgradeStepsResponse).map_err(|err| {
        format!("Could not decode the response from SnsW.list_upgrade_steps: {err}")
    })?;

    let response_timestamp_seconds = env.now();

    CachedUpgradeSteps::try_from_sns_w_response(
        response,
        requested_timestamp_seconds,
        response_timestamp_seconds,
    )
}

/// Returns all SNS canisters known by the Root canister.
pub(crate) async fn get_all_sns_canisters(
    env: &dyn Environment,
    root_canister_id: CanisterId,
) -> Result<RunningSnsCanisters, String> {
    let response = sns_canisters_summary(env, root_canister_id).await?;

    let root = response
        .root
        .map(|summary| summary.canister_id)
        .unwrap_or_default();
    let governance = response
        .governance
        .map(|summary| summary.canister_id)
        .unwrap_or_default();
    let ledger = response
        .ledger
        .map(|summary| summary.canister_id)
        .unwrap_or_default();
    let swap = response
        .swap
        .map(|summary| summary.canister_id)
        .unwrap_or_default();
    let dapps = response
        .dapps
        .iter()
        .map(|response| response.canister_id.unwrap())
        .collect();
    let archives = response
        .archives
        .iter()
        .map(|response| response.canister_id.unwrap())
        .collect();
    let index = response
        .index
        .map(|summary| summary.canister_id)
        .unwrap_or_default();

    Ok(RunningSnsCanisters {
        root,
        governance,
        ledger,
        swap,
        dapps,
        archives,
        index,
    })
}

impl Version {
    /// Get the new hashes from next_version as a list of (SnsCanisterType, wasm_hash)
    pub(crate) fn changes_against(
        &self,
        next_version: &Self,
    ) -> Vec<(SnsCanisterType, Vec<u8> /*wasm hash*/)> {
        let mut differences = vec![];
        if self.root_wasm_hash != next_version.root_wasm_hash {
            differences.push((SnsCanisterType::Root, next_version.root_wasm_hash.clone()));
        }
        if self.governance_wasm_hash != next_version.governance_wasm_hash {
            differences.push((
                SnsCanisterType::Governance,
                next_version.governance_wasm_hash.clone(),
            ));
        }
        if self.ledger_wasm_hash != next_version.ledger_wasm_hash {
            differences.push((
                SnsCanisterType::Ledger,
                next_version.ledger_wasm_hash.clone(),
            ));
        }
        if self.swap_wasm_hash != next_version.swap_wasm_hash {
            differences.push((SnsCanisterType::Swap, next_version.swap_wasm_hash.clone()));
        }
        if self.archive_wasm_hash != next_version.archive_wasm_hash {
            differences.push((
                SnsCanisterType::Archive,
                next_version.archive_wasm_hash.clone(),
            ));
        }
        if self.index_wasm_hash != next_version.index_wasm_hash {
            differences.push((SnsCanisterType::Index, next_version.index_wasm_hash.clone()));
        }

        differences
    }

    pub(crate) fn version_has_expected_hashes(
        &self,
        expected_hashes: &[(SnsCanisterType, Vec<u8> /* wasm hash*/)],
    ) -> Result<(), Vec<String>> {
        let results = expected_hashes
            .iter()
            .map(|(canister_type, expected_hash)| {
                let actual_hash = self.get_hash_for_type(canister_type);
                if &actual_hash == expected_hash {
                    Ok(())
                } else {
                    Err(format!(
                        "Expected hash for {:?} to be: '{}', but it was '{}'",
                        canister_type,
                        hex::encode(expected_hash),
                        hex::encode(actual_hash)
                    ))
                }
            })
            .collect::<Vec<Result<(), String>>>();

        if results.iter().any(|r| r.is_err()) {
            Err(results
                .into_iter()
                .flat_map(|result| result.err())
                .collect::<Vec<_>>())
        } else {
            Ok(())
        }
    }

    fn get_hash_for_type(&self, canister_type: &SnsCanisterType) -> Vec<u8> {
        match canister_type {
            // Unspecified should be impossible given we create the diff we are using,
            // but we must not panic in a heartbeat, so  we use a value that won't match a
            // real hash so downstream check will fail.
            SnsCanisterType::Unspecified => vec![0; 3],
            SnsCanisterType::Root => self.root_wasm_hash.clone(),
            SnsCanisterType::Governance => self.governance_wasm_hash.clone(),
            SnsCanisterType::Ledger => self.ledger_wasm_hash.clone(),
            SnsCanisterType::Swap => self.swap_wasm_hash.clone(),
            SnsCanisterType::Archive => self.archive_wasm_hash.clone(),
            SnsCanisterType::Index => self.index_wasm_hash.clone(),
        }
    }
}

impl From<Version> for SnsVersion {
    fn from(version: Version) -> Self {
        SnsVersion {
            root_wasm_hash: version.root_wasm_hash,
            governance_wasm_hash: version.governance_wasm_hash,
            ledger_wasm_hash: version.ledger_wasm_hash,
            swap_wasm_hash: version.swap_wasm_hash,
            archive_wasm_hash: version.archive_wasm_hash,
            index_wasm_hash: version.index_wasm_hash,
        }
    }
}

impl From<SnsVersion> for Version {
    fn from(version: SnsVersion) -> Self {
        Version {
            root_wasm_hash: version.root_wasm_hash,
            governance_wasm_hash: version.governance_wasm_hash,
            ledger_wasm_hash: version.ledger_wasm_hash,
            swap_wasm_hash: version.swap_wasm_hash,
            archive_wasm_hash: version.archive_wasm_hash,
            index_wasm_hash: version.index_wasm_hash,
        }
    }
}

// TODO(NNS1-1590) Remove following duplicate definitions and split the types into their own crates

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround
/// The request type accepted by the get_next_sns_version canister method
#[derive(Clone, PartialEq, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetNextSnsVersionRequest {
    #[prost(message, optional, tag = "1")]
    pub current_version: ::core::option::Option<SnsVersion>,
}

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround
/// The response type returned by the get_next_sns_version canister method
#[derive(Clone, PartialEq, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetNextSnsVersionResponse {
    #[prost(message, optional, tag = "1")]
    pub next_version: ::core::option::Option<SnsVersion>,
}

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround.
/// Avoid using outside of tests and the functions in this file.
/// Specifies the version of an SNS.
#[derive(Clone, Eq, PartialEq, Hash, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub struct SnsVersion {
    /// The hash of the Root canister WASM.
    #[prost(bytes = "vec", tag = "1")]
    pub root_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Governance canister WASM.
    #[prost(bytes = "vec", tag = "2")]
    pub governance_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Ledger canister WASM.
    #[prost(bytes = "vec", tag = "3")]
    pub ledger_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Swap canister WASM.
    #[prost(bytes = "vec", tag = "4")]
    pub swap_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Ledger Archive canister WASM.
    #[prost(bytes = "vec", tag = "5")]
    pub archive_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    // The hash of the Index canister WASM.
    #[prost(bytes = "vec", tag = "6")]
    pub index_wasm_hash: ::prost::alloc::vec::Vec<u8>,
}

/// Copied from ic-sns-root
#[derive(Eq, PartialEq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetSnsCanistersSummaryRequest {
    /// If set to true, root will update the list of canisters it owns before building the
    /// GetSnsCanistersSummaryResponse. This currently amounts to asking ledger about its archive
    /// canisters.
    /// Only the SNS governance canister can set this field to true currently.
    pub update_canister_list: Option<bool>,
}

#[derive(Clone, Eq, PartialEq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetSnsCanistersSummaryResponse {
    pub root: Option<CanisterSummary>,
    pub governance: Option<CanisterSummary>,
    pub ledger: Option<CanisterSummary>,
    pub swap: Option<CanisterSummary>,
    pub dapps: Vec<CanisterSummary>,
    pub archives: Vec<CanisterSummary>,
    pub index: Option<CanisterSummary>,
}

/// Copied from ic-sns-root
#[derive(Clone, Eq, PartialEq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct CanisterSummary {
    pub canister_id: Option<PrincipalId>,
    pub status: Option<CanisterStatusResultV2>,
}

///Copied from ic-sns-wasm.
/// The argument for get_wasm, which consists of the WASM hash to be retrieved.
#[derive(Clone, PartialEq, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetWasmRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// Copied from ic-sns-wasm.
/// The response for get_wasm, which returns a WASM if it is found, or None.
#[derive(Clone, PartialEq, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetWasmResponse {
    #[prost(message, optional, tag = "1")]
    pub wasm: ::core::option::Option<SnsWasm>,
}

/// Copied from ic-sns-wasm.
/// The representation of a WASM along with its target canister type
#[derive(Clone, PartialEq, ::prost::Message, candid::CandidType, candid::Deserialize)]
pub(crate) struct SnsWasm {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub wasm: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "SnsCanisterType", tag = "2")]
    pub canister_type: i32,
    #[prost(uint64, optional, tag = "3")]
    pub proposal_id: ::core::option::Option<u64>,
}
/// Copied from ic-sns-wasm
/// The type of canister a particular WASM is intended to be installed on.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    ::prost::Enumeration,
    candid::CandidType,
    candid::Deserialize,
)]
#[repr(i32)]
pub(crate) enum SnsCanisterType {
    Unspecified = 0,
    /// The type for the root canister
    Root = 1,
    /// The type for the governance canister
    Governance = 2,
    /// The type for the ledger canister
    Ledger = 3,
    /// The type for the swap canister
    Swap = 4,
    /// The type for the ledger archive canister
    Archive = 5,
    /// The type for the ledger index canister
    Index = 6,
}
/// Copied from ic-sns-wasm
/// Similar to GetWasmRequest, but only returns the NNS proposal ID that blessed the wasm.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposalIdThatAddedWasmRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// Copied from ic-sns-wasm
/// The NNS proposal ID that blessed the wasm, if it was recorded.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposalIdThatAddedWasmResponse {
    #[prost(uint64, optional, tag = "1")]
    pub proposal_id: ::core::option::Option<u64>,
}

#[derive(Clone, PartialEq, candid::CandidType, candid::Deserialize, Debug)]
pub struct ListUpgradeStepsRequest {
    /// If provided, limit response to only include entries for this version and later
    pub starting_at: ::core::option::Option<SnsVersion>,
    /// If provided, give responses that this canister would get back
    pub sns_governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Limit to number of entries (for paging)
    pub limit: u32,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct ListUpgradeStepsResponse {
    pub steps: ::prost::alloc::vec::Vec<ListUpgradeStep>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct ListUpgradeStep {
    pub version: ::core::option::Option<SnsVersion>,
}
