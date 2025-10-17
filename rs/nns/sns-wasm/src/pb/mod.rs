#![allow(deprecated)]
use crate::{
    pb::v1::{
        AddWasmResponse, DeployedSns, GetDeployedSnsByProposalIdResponse,
        GetNextSnsVersionResponse, InsertUpgradePathEntriesResponse, ListUpgradeStep,
        PrettySnsVersion, SnsCanisterIds, SnsCanisterType, SnsSpecificSnsUpgrade, SnsUpgrade,
        SnsVersion, SnsWasm, SnsWasmError, StableCanisterState, UpdateSnsSubnetListResponse,
        UpgradePath as StableUpgradePath, UpgradePath as UpgradePathPb, add_wasm_response,
        get_deployed_sns_by_proposal_id_response,
    },
    sns_wasm::{SnsWasmCanister, UpgradePath, vec_to_hash},
    stable_memory::SnsWasmStableMemory,
};
use ic_base_types::CanisterId;
use ic_cdk::api::stable::StableMemory;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common::hash_to_hex_string;
use std::{collections::HashMap, convert::TryFrom, str::FromStr};

#[allow(clippy::all)]
#[path = "../gen/ic_sns_wasm.pb.v1.rs"]
pub mod v1;

impl AddWasmResponse {
    pub fn error(message: String) -> Self {
        Self {
            result: Some(add_wasm_response::Result::Error(SnsWasmError { message })),
        }
    }
}

impl InsertUpgradePathEntriesResponse {
    pub fn error(message: String) -> Self {
        Self {
            error: Some(SnsWasmError { message }),
        }
    }
}

impl UpdateSnsSubnetListResponse {
    pub fn error(message: &str) -> Self {
        Self {
            error: Some(SnsWasmError {
                message: message.into(),
            }),
        }
    }

    pub fn ok() -> Self {
        Self { error: None }
    }
}

impl GetDeployedSnsByProposalIdResponse {
    pub fn error(message: String) -> Self {
        Self {
            get_deployed_sns_by_proposal_id_result: Some(
                get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult::Error(
                    SnsWasmError { message },
                ),
            ),
        }
    }

    pub fn ok(deployed_sns: DeployedSns) -> Self {
        Self {
            get_deployed_sns_by_proposal_id_result: Some(
                get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult::DeployedSns(
                    deployed_sns
                )
            )
        }
    }
}

impl SnsWasm {
    /// Calculate the sha256 hash for the wasm.
    pub fn sha256_hash(&self) -> [u8; 32] {
        Sha256::hash(&self.wasm)
    }

    /// Provide string representation of the sha256 hash for the wasm.
    pub fn sha256_string(&self) -> String {
        let bytes = self.sha256_hash();
        hash_to_hex_string(&bytes)
    }

    /// Return the SnsCanisterType if it's valid, else return an error
    pub fn checked_sns_canister_type(&self) -> Result<SnsCanisterType, String> {
        match SnsCanisterType::try_from(self.canister_type).ok() {
            None => Err(
                "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                    .to_string(),
            ),
            Some(canister_type) => {
                if canister_type == SnsCanisterType::Unspecified {
                    Err("SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string())
                } else {
                    Ok(canister_type)
                }
            }
        }
    }
}

impl From<SnsVersion> for GetNextSnsVersionResponse {
    fn from(version: SnsVersion) -> GetNextSnsVersionResponse {
        GetNextSnsVersionResponse {
            next_version: Some(version),
        }
    }
}

impl std::fmt::Display for SnsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut versions_str = HashMap::<&str, String>::new();

        versions_str.insert("Root", hex::encode(&self.root_wasm_hash));
        versions_str.insert("Governance", hex::encode(&self.governance_wasm_hash));
        versions_str.insert("Ledger", hex::encode(&self.ledger_wasm_hash));
        versions_str.insert("Swap", hex::encode(&self.swap_wasm_hash));
        versions_str.insert("Archive", hex::encode(&self.archive_wasm_hash));

        let json = serde_json::to_string(&versions_str)
            .unwrap_or_else(|e| format!("Unable to serialize SnsVersion: {e}"));

        write!(f, "{json}")
    }
}

impl SnsCanisterIds {
    /// Get Root CanisterId
    pub fn root(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.root.unwrap())
    }
    /// Get Governance CanisterId
    pub fn governance(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.governance.unwrap())
    }
    /// Get Ledger CanisterId
    pub fn ledger(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.ledger.unwrap())
    }
    /// Get Swap CanisterId
    pub fn swap(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.swap.unwrap())
    }

    /// Get Index CanisterId
    pub fn index(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.index.unwrap())
    }
}

impl TryFrom<SnsCanisterIds> for ic_sns_init::SnsCanisterIds {
    type Error = String;

    fn try_from(ids: SnsCanisterIds) -> Result<Self, Self::Error> {
        Ok(ic_sns_init::SnsCanisterIds {
            root: ids.root.ok_or_else(|| "Root missing".to_string())?,
            governance: ids
                .governance
                .ok_or_else(|| "Governance missing".to_string())?,
            ledger: ids.ledger.ok_or_else(|| "Ledger missing".to_string())?,
            swap: ids.swap.ok_or_else(|| "Swap missing".to_string())?,
            index: ids.index.ok_or_else(|| "Index missing".to_string())?,
        })
    }
}

impl<M: StableMemory + Clone + Default> From<StableCanisterState> for SnsWasmCanister<M> {
    fn from(stable_canister_state: StableCanisterState) -> Self {
        let StableCanisterState {
            wasm_indexes,
            upgrade_path,
            sns_subnet_ids,
            deployed_sns_list,
            access_controls_enabled,
            allowed_principals,
            nns_proposal_to_deployed_sns,
        } = stable_canister_state;

        let wasm_indexes = wasm_indexes
            .into_iter()
            .map(|index| (vec_to_hash(index.hash.clone()).unwrap(), index))
            .collect();
        let stable_upgrade_path = upgrade_path.unwrap_or_default();
        let upgrade_path = UpgradePath::from(stable_upgrade_path);
        let sns_subnet_ids = sns_subnet_ids.into_iter().map(|id| id.into()).collect();
        let stable_memory = SnsWasmStableMemory::<M>::default();

        SnsWasmCanister {
            wasm_indexes,
            sns_subnet_ids,
            stable_memory,
            deployed_sns_list,
            upgrade_path,
            access_controls_enabled,
            allowed_principals,
            nns_proposal_to_deployed_sns,
        }
    }
}

impl<M: StableMemory + Clone + Default> From<SnsWasmCanister<M>> for StableCanisterState {
    fn from(state: SnsWasmCanister<M>) -> StableCanisterState {
        let SnsWasmCanister::<M> {
            wasm_indexes,
            sns_subnet_ids,
            deployed_sns_list,
            upgrade_path,
            access_controls_enabled,
            allowed_principals,
            nns_proposal_to_deployed_sns,
            stable_memory: _,
        } = state;

        let wasm_indexes = wasm_indexes.into_values().collect();
        let sns_subnet_ids = sns_subnet_ids.into_iter().map(|id| id.get()).collect();
        let upgrade_path = Some(UpgradePathPb::from(upgrade_path));

        StableCanisterState {
            wasm_indexes,
            sns_subnet_ids,
            deployed_sns_list,
            upgrade_path,
            access_controls_enabled,
            allowed_principals,
            nns_proposal_to_deployed_sns,
        }
    }
}

impl From<UpgradePath> for StableUpgradePath {
    fn from(path: UpgradePath) -> Self {
        Self {
            latest_version: Some(path.latest_version),
            upgrade_path: path
                .upgrade_path
                .into_iter()
                .map(|(current, next)| SnsUpgrade {
                    current_version: Some(current),
                    next_version: Some(next),
                })
                .collect(),
            sns_specific_upgrade_path: path
                .sns_specific_upgrade_path
                .into_iter()
                .map(|(canister_id, upgrade_path)| {
                    let upgrade_path_list = upgrade_path
                        .into_iter()
                        .map(|(current, next)| SnsUpgrade {
                            current_version: Some(current),
                            next_version: Some(next),
                        })
                        .collect();
                    SnsSpecificSnsUpgrade {
                        governance_canister_id: Some(canister_id.into()),
                        upgrade_path: upgrade_path_list,
                    }
                })
                .collect(),
        }
    }
}

impl From<StableUpgradePath> for UpgradePath {
    fn from(stable_upgrade_path: StableUpgradePath) -> Self {
        let upgrade_path_hashmap = stable_upgrade_path
            .upgrade_path
            .into_iter()
            .map(|upgrade| {
                (
                    upgrade.current_version.unwrap(),
                    upgrade.next_version.unwrap(),
                )
            })
            .collect();

        let emergency_path_hashmap = stable_upgrade_path
            .sns_specific_upgrade_path
            .into_iter()
            .map(|em_upgrade| {
                let upgrade_path_hashmap = em_upgrade
                    .upgrade_path
                    .into_iter()
                    .map(|upgrade| {
                        (
                            upgrade.current_version.unwrap(),
                            upgrade.next_version.unwrap(),
                        )
                    })
                    .collect();
                (
                    CanisterId::try_from(em_upgrade.governance_canister_id.unwrap()).unwrap(),
                    upgrade_path_hashmap,
                )
            })
            .collect();

        UpgradePath {
            latest_version: stable_upgrade_path.latest_version.unwrap_or_default(),
            upgrade_path: upgrade_path_hashmap,
            sns_specific_upgrade_path: emergency_path_hashmap,
        }
    }
}

impl SnsCanisterIds {
    /// Get a set of "Name, CanisterId" tuples, useful for repetitive operations that need
    /// per-canister error messages.  Does not return canisters without a principal.
    pub fn into_named_tuples(self) -> Vec<(String, CanisterId)> {
        vec![
            ("Root".to_string(), self.root),
            ("Governance".to_string(), self.governance),
            ("Ledger".to_string(), self.ledger),
            ("Swap".to_string(), self.swap),
            ("Index".to_string(), self.index),
        ]
        .into_iter()
        .flat_map(|(label, principal_id)| {
            principal_id
                .map(|principal_id| (label, CanisterId::unchecked_from_principal(principal_id)))
        })
        .collect()
    }
}

impl FromStr for SnsCanisterType {
    type Err = String;

    fn from_str(input: &str) -> Result<SnsCanisterType, Self::Err> {
        match input.to_lowercase().as_str() {
            "unspecified" => Ok(SnsCanisterType::Unspecified),
            "root" => Ok(SnsCanisterType::Root),
            "governance" => Ok(SnsCanisterType::Governance),
            "ledger" => Ok(SnsCanisterType::Ledger),
            "swap" => Ok(SnsCanisterType::Swap),
            "archive" => Ok(SnsCanisterType::Archive),
            "index" => Ok(SnsCanisterType::Index),
            _ => Err(format!(
                "from_str is not yet implemented or that is not a valid type: {input}"
            )),
        }
    }
}

impl SnsVersion {
    /// Get a set of tuples mapping SnsCanistertype to wasm hashes
    pub fn into_tuples(self) -> Vec<(SnsCanisterType, Vec<u8> /* wasm hash */)> {
        vec![
            (SnsCanisterType::Root, self.root_wasm_hash),
            (SnsCanisterType::Governance, self.governance_wasm_hash),
            (SnsCanisterType::Ledger, self.ledger_wasm_hash),
            (SnsCanisterType::Swap, self.swap_wasm_hash),
            (SnsCanisterType::Archive, self.archive_wasm_hash),
            (SnsCanisterType::Index, self.index_wasm_hash),
        ]
    }

    /// Get a list of all version hashes without respective canister types
    pub fn version_hashes(self) -> Vec<Vec<u8> /*wasm hash*/> {
        self.into_tuples()
            .into_iter()
            .map(|(_, hash)| hash)
            .collect()
    }

    /// If all hashes are non-empty, return true
    pub fn is_complete_version(&self) -> bool {
        let SnsVersion {
            root_wasm_hash,
            governance_wasm_hash,
            ledger_wasm_hash,
            swap_wasm_hash,
            archive_wasm_hash,
            index_wasm_hash,
        } = self;

        !root_wasm_hash.is_empty()
            && !governance_wasm_hash.is_empty()
            && !ledger_wasm_hash.is_empty()
            && !swap_wasm_hash.is_empty()
            && !archive_wasm_hash.is_empty()
            && !index_wasm_hash.is_empty()
    }
}

impl From<SnsVersion> for PrettySnsVersion {
    fn from(version: SnsVersion) -> Self {
        Self {
            root_wasm_hash: hex::encode(version.root_wasm_hash),
            governance_wasm_hash: hex::encode(version.governance_wasm_hash),
            ledger_wasm_hash: hex::encode(version.ledger_wasm_hash),
            swap_wasm_hash: hex::encode(version.swap_wasm_hash),
            archive_wasm_hash: hex::encode(version.archive_wasm_hash),
            index_wasm_hash: hex::encode(version.index_wasm_hash),
        }
    }
}

impl From<ic_sns_governance::pb::v1::governance::Version> for SnsVersion {
    fn from(version: ic_sns_governance::pb::v1::governance::Version) -> Self {
        Self {
            root_wasm_hash: version.root_wasm_hash,
            governance_wasm_hash: version.governance_wasm_hash,
            ledger_wasm_hash: version.ledger_wasm_hash,
            swap_wasm_hash: version.swap_wasm_hash,
            archive_wasm_hash: version.archive_wasm_hash,
            index_wasm_hash: version.index_wasm_hash,
        }
    }
}

impl From<SnsVersion> for ic_sns_governance::pb::v1::governance::Version {
    fn from(version: SnsVersion) -> Self {
        Self {
            root_wasm_hash: version.root_wasm_hash,
            governance_wasm_hash: version.governance_wasm_hash,
            ledger_wasm_hash: version.ledger_wasm_hash,
            swap_wasm_hash: version.swap_wasm_hash,
            archive_wasm_hash: version.archive_wasm_hash,
            index_wasm_hash: version.index_wasm_hash,
        }
    }
}

impl ListUpgradeStep {
    pub fn new(version: SnsVersion) -> Self {
        Self {
            version: Some(version.clone()),
            pretty_version: Some(version.into()),
        }
    }
}
