use crate::pb::v1::governance::Version;
use crate::proposal::render_version;
use crate::types::Environment;
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::CanisterStatusResultV2;
use ic_nns_constants::SNS_WASM_CANISTER_ID;

/// A struct to represent all the types of SNS canisters Governance knows about.
pub struct RunningSnsCanisters {
    pub root: Option<PrincipalId>,
    pub governance: Option<PrincipalId>,
    pub ledger: Option<PrincipalId>,
    pub swap: Option<PrincipalId>,
    pub dapps: Vec<PrincipalId>,
    pub archives: Vec<PrincipalId>,
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
            ))
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
            Encode!(&GetWasmRequest { hash: wasm_hash }).expect("Could not encode"),
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
        .map_err(|e| format!("Decoding GetWasmResponse failed: {:?}", e))?;
    let wasm = response
        .wasm
        .ok_or_else(|| "No WASM found using hash returned from SNS-WASM canister.".to_string())?;

    let returned_canister_type =
        SnsCanisterType::from_i32(wasm.canister_type).ok_or_else(|| {
            "Could not convert response from SNS-WASM to valid SnsCanisterType".to_string()
        })?;

    if returned_canister_type != expected_sns_canister_type {
        return Err(format!(
            "WASM returned from SNS-WASM is not intended for the same canister type. \
            Expected: {:?}.  Received: {:?}.",
            expected_sns_canister_type, returned_canister_type
        ));
    }

    Ok(wasm)
}

async fn get_canisters_to_upgrade(
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
        SnsCanisterType::Unspecified => panic!("SnsCanisterType cannot be unspecified"),
    };
    maybe_principals
        .iter()
        .map(|maybe_principal| {
            maybe_principal
                .ok_or_else(|| {
                    format!(
                        "Did not receive {} CanisterId from list_sns_canisters call",
                        label
                    )
                })
                .and_then(|principal| CanisterId::new(principal).map_err(|e| format!("{}", e)))
        })
        .collect()
}

fn canister_type_and_wasm_hash_for_upgrade(
    current_version: &Version,
    next_version: &Version,
) -> Result<(SnsCanisterType, Vec<u8>), String> {
    let mut differences = current_version.changes_against(next_version);

    // This should be impossible due to upstream constraints.
    if differences.is_empty() {
        return Err(
            "No difference was found between the current SNS version and the next SNS version"
                .to_string(),
        );
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

    let root = response.root.unwrap();
    let governance = response.governance.unwrap();
    let swap = response.swap.unwrap();
    let ledger = response.ledger.unwrap();
    let archives = response.archives;

    let get_hash = |canister_status: &CanisterSummary, label: &str| {
        canister_status
            .status
            .as_ref()
            .ok_or_else(|| format!("{} had no status", label))
            .and_then(|status| {
                status
                    .module_hash()
                    .ok_or_else(|| format!("{} Status had no module hash", label))
            })
    };

    // If the values are not all unique, we return vec![0, 0, 0], which will not
    // be interpreted as empty (i.e. no running archives) but won't match any archive hashes
    let archive_wasm_hash = archives
        .into_iter()
        .map(|canister_summary| get_hash(&canister_summary, "Ledger Archive").unwrap_or_default())
        // Make sure all returned versions are the same.
        .reduce(|x, y| if x == y { x } else { vec![0, 0, 0] })
        .unwrap_or_default();

    Ok(Version {
        root_wasm_hash: get_hash(&root, "Root")?,
        governance_wasm_hash: get_hash(&governance, "Governance")?,
        ledger_wasm_hash: get_hash(&ledger, "Ledger")?,
        swap_wasm_hash: get_hash(&swap, "Swap")?,
        archive_wasm_hash,
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
    .unwrap();

    let response = env
        .call_canister(root_canister_id, "get_sns_canisters_summary", arg)
        .await
        .map_err(|e| format!("Request failed for get_sns_canisters_summary: {:?}", e))?;

    Decode!(&response, GetSnsCanistersSummaryResponse)
        .map_err(|e| format!("Failed to decode response: {:?}", e))
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

    Ok(RunningSnsCanisters {
        root,
        governance,
        ledger,
        swap,
        dapps,
        archives,
    })
}

impl Version {
    /// Get the new hashes from next_version as a list of (SnsCanisterType, wasm_hash)
    fn changes_against(
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

        differences
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
        }
    }
}

// TODO(NNS1-1590) Remove following duplicate definitions and split the types into their own crates

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround
/// The request type accepted by the get_next_sns_version canister method
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub(crate) struct GetNextSnsVersionRequest {
    #[prost(message, optional, tag = "1")]
    pub current_version: ::core::option::Option<SnsVersion>,
}

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround
/// The response type returned by the get_next_sns_version canister method
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub(crate) struct GetNextSnsVersionResponse {
    #[prost(message, optional, tag = "1")]
    pub next_version: ::core::option::Option<SnsVersion>,
}

/// Duplicated from ic-sns-wasms to avoid circular dependency as a temporary workaround.
/// Avoid using outside of tests and the functions in this file.
/// Specifies the version of an SNS.
#[derive(candid::CandidType, candid::Deserialize, Eq, Hash, Clone, PartialEq, ::prost::Message)]
pub(crate) struct SnsVersion {
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
}

/// Copied from ic-sns-root
#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetSnsCanistersSummaryRequest {
    /// If set to true, root will update the list of canisters it owns before building the
    /// GetSnsCanistersSummaryResponse. This currently amounts to asking ledger about its archive
    /// canisters.
    /// Only the SNS governance canister can set this field to true currently.
    pub update_canister_list: Option<bool>,
}

/// Copied from ic-sns-root
#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct GetSnsCanistersSummaryResponse {
    pub root: Option<CanisterSummary>,
    pub governance: Option<CanisterSummary>,
    pub ledger: Option<CanisterSummary>,
    pub swap: Option<CanisterSummary>,
    pub dapps: Vec<CanisterSummary>,
    pub archives: Vec<CanisterSummary>,
}

/// Copied from ic-sns-root
#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub(crate) struct CanisterSummary {
    pub canister_id: Option<PrincipalId>,
    pub status: Option<CanisterStatusResultV2>,
}

///Copied from ic-sns-wasm.
/// The argument for get_wasm, which consists of the WASM hash to be retrieved.
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub(crate) struct GetWasmRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// Copied from ic-sns-wasm.
/// The response for get_wasm, which returns a WASM if it is found, or None.
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub(crate) struct GetWasmResponse {
    #[prost(message, optional, tag = "1")]
    pub wasm: ::core::option::Option<SnsWasm>,
}

/// Copied from ic-sns-wasm.
/// The representation of a WASM along with its target canister type
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub(crate) struct SnsWasm {
    #[prost(bytes = "vec", tag = "1")]
    pub wasm: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "SnsCanisterType", tag = "2")]
    pub canister_type: i32,
}
/// Copied from ic-sns-wasm
/// The type of canister a particular WASM is intended to be installed on.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
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
}
