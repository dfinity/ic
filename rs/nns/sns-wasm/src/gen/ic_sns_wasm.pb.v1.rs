/// The SNS-WASM canister state that is persisted to stable memory on pre-upgrade and read on
/// post-upgrade.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StableCanisterState {
    #[prost(message, repeated, tag = "1")]
    pub wasm_indexes: ::prost::alloc::vec::Vec<SnsWasmStableIndex>,
    #[prost(message, repeated, tag = "2")]
    pub sns_subnet_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag = "3")]
    pub deployed_sns_list: ::prost::alloc::vec::Vec<DeployedSns>,
    #[prost(message, optional, tag = "4")]
    pub upgrade_path: ::core::option::Option<UpgradePath>,
    #[prost(bool, tag = "5")]
    pub access_controls_enabled: bool,
    #[prost(message, repeated, tag = "6")]
    pub allowed_principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(btree_map = "uint64, uint64", tag = "7")]
    pub nns_proposal_to_deployed_sns: ::prost::alloc::collections::BTreeMap<u64, u64>,
}
/// Details the offset and size of a WASM binary in stable memory and the hash of this binary.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasmStableIndex {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub offset: u32,
    #[prost(uint32, tag = "3")]
    pub size: u32,
    #[prost(message, repeated, tag = "4")]
    pub metadata: ::prost::alloc::vec::Vec<MetadataSection>,
}
/// Specifies the upgrade path for SNS instances.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpgradePath {
    /// The latest SNS version. New SNS deployments will deploy the SNS canisters specified by
    /// this version.
    #[prost(message, optional, tag = "1")]
    pub latest_version: ::core::option::Option<SnsVersion>,
    /// A sequence of allowed upgrades.
    #[prost(message, repeated, tag = "2")]
    pub upgrade_path: ::prost::alloc::vec::Vec<SnsUpgrade>,
    /// A non-standard sequence of allowed upgrades for particular SNS's.
    /// This provides an escape hatch for if a particular SNS somehow has a bug that prevents upgrading
    /// on the standard path.
    #[prost(message, repeated, tag = "3")]
    pub sns_specific_upgrade_path: ::prost::alloc::vec::Vec<SnsSpecificSnsUpgrade>,
}
/// An allowed upgrade step, from a current version to a next version.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsUpgrade {
    #[prost(message, optional, tag = "1")]
    pub current_version: ::core::option::Option<SnsVersion>,
    #[prost(message, optional, tag = "2")]
    pub next_version: ::core::option::Option<SnsVersion>,
}
/// An allowed upgrade step (like SnsUpgrade) for a particular SNS, identified by its
/// governance canister id.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsSpecificSnsUpgrade {
    /// An SNS Governance canister to be targeted.
    #[prost(message, optional, tag = "1")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Allowed upgrade steps.
    #[prost(message, repeated, tag = "2")]
    pub upgrade_path: ::prost::alloc::vec::Vec<SnsUpgrade>,
}
/// The representation of a WASM along with its target canister type.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasm {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub wasm: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "SnsCanisterType", tag = "2")]
    pub canister_type: i32,
    #[prost(uint64, optional, tag = "3")]
    pub proposal_id: ::core::option::Option<u64>,
}
/// The error response returned in response objects on failed or partially failed operations.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasmError {
    /// The message returned by the canister on errors.
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
}
/// The payload for the add_wasm endpoint, which takes an SnsWasm along with the hash of the wasm bytes.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddWasmRequest {
    #[prost(message, optional, tag = "1")]
    pub wasm: ::core::option::Option<SnsWasm>,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "serde_bytes")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// The response from add_wasm, which is either Ok or Error.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddWasmResponse {
    #[prost(oneof = "add_wasm_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<add_wasm_response::Result>,
}
/// Nested message and enum types in `AddWasmResponse`.
pub mod add_wasm_response {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// The hash of the wasm that was added.
        #[prost(bytes, tag = "1")]
        #[serde(with = "serde_bytes")]
        Hash(::prost::alloc::vec::Vec<u8>),
        /// Error when request fails.
        #[prost(message, tag = "2")]
        Error(super::SnsWasmError),
    }
}
/// The payload for the insert_upgrade_path_entries endpoint
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertUpgradePathEntriesRequest {
    /// The upgrade paths to add.  All versions hashes in these upgrade paths MUST have a corresponding WASM
    /// in SNS-W already, or the request will fail.
    #[prost(message, repeated, tag = "1")]
    pub upgrade_path: ::prost::alloc::vec::Vec<SnsUpgrade>,
    /// If provided, the SNS Governance canister to which these paths apply (otherwise they apply
    /// to the main upgrade path)
    #[prost(message, optional, tag = "2")]
    pub sns_governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// The response from insert_upgrade_path_entries requests
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertUpgradePathEntriesResponse {
    /// Optional error if request does not succeed
    #[prost(message, optional, tag = "1")]
    pub error: ::core::option::Option<SnsWasmError>,
}
/// A request to list upgrade steps (for list_upgrade_steps_pretty at present)
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListUpgradeStepsRequest {
    /// If provided, limit response to only include entries for this version and later
    #[prost(message, optional, tag = "1")]
    pub starting_at: ::core::option::Option<SnsVersion>,
    /// If provided, give responses that this canister would get back
    #[prost(message, optional, tag = "2")]
    pub sns_governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Limit to number of entries (for paging)
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}
/// A human readable list of upgrade steps in order.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListUpgradeStepsResponse {
    #[prost(message, repeated, tag = "1")]
    pub steps: ::prost::alloc::vec::Vec<ListUpgradeStep>,
}
/// A step in the upgrade path for human or programmatic consumption
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListUpgradeStep {
    /// A machine-readable version
    #[prost(message, optional, tag = "1")]
    pub version: ::core::option::Option<SnsVersion>,
    /// A human-readable SnsVersion
    #[prost(message, optional, tag = "2")]
    pub pretty_version: ::core::option::Option<PrettySnsVersion>,
}
/// The argument for get_wasm, which consists of the WASM hash to be retrieved.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmRequest {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// The response for get_wasm, which returns a WASM if it is found, or None.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmResponse {
    #[prost(message, optional, tag = "1")]
    pub wasm: ::core::option::Option<SnsWasm>,
}
/// Similar to GetWasmRequest, but only returns the NNS proposal ID that blessed the wasm.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposalIdThatAddedWasmRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// The NNS proposal ID that blessed the wasm, if it was recorded.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposalIdThatAddedWasmResponse {
    #[prost(uint64, optional, tag = "1")]
    pub proposal_id: ::core::option::Option<u64>,
}
/// Payload to deploy a new SNS.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployNewSnsRequest {
    /// The initial payload to initialize the SNS with.
    #[prost(message, optional, tag = "1")]
    pub sns_init_payload: ::core::option::Option<::ic_sns_init::pb::v1::SnsInitPayload>,
}
/// The response to creating a new SNS.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployNewSnsResponse {
    /// The subnet the SNS was deployed to.
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// CanisterIds of canisters created by deploy_new_sns.
    #[prost(message, optional, tag = "2")]
    pub canisters: ::core::option::Option<SnsCanisterIds>,
    /// Error when the request fails.
    #[prost(message, optional, tag = "3")]
    pub error: ::core::option::Option<SnsWasmError>,
    /// The status of the dapp canisters being transferred to an SNS.
    #[prost(message, optional, tag = "4")]
    pub dapp_canisters_transfer_result: ::core::option::Option<DappCanistersTransferResult>,
}
/// The CanisterIds of the SNS canisters that are created.
#[derive(Copy, candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsCanisterIds {
    /// PrincipalId of the root canister.
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the ledger canister.
    #[prost(message, optional, tag = "2")]
    pub ledger: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the governance canister.
    #[prost(message, optional, tag = "3")]
    pub governance: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the swap canister.
    #[prost(message, optional, tag = "4")]
    pub swap: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the index canister.
    #[prost(message, optional, tag = "5")]
    pub index: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// The status of the dapp canisters that are being transferred to an SNS.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DappCanistersTransferResult {
    /// Dapp canisters that were restored to their original controllers due to some error
    /// encountered in the SNS deployment process.
    #[prost(message, repeated, tag = "1")]
    pub restored_dapp_canisters:
        ::prost::alloc::vec::Vec<::ic_nervous_system_proto::pb::v1::Canister>,
    /// Dapp canisters that were transferred to an SNS. This can either be as a result of
    /// a completely successful SNS deployment where all dapps were transferred to the SNS,
    /// or a result of a partially failed SNS deployment, where only some of the dapps
    /// were fully transferred to the SNS, and can not be restored by the SNS-W canister.
    #[prost(message, repeated, tag = "2")]
    pub sns_controlled_dapp_canisters:
        ::prost::alloc::vec::Vec<::ic_nervous_system_proto::pb::v1::Canister>,
    /// Dapp canisters that are still under the control of the NNS. This is a result of an
    /// error when restoring dapps to their original controller and requires additional work
    /// to fully restore them.
    #[prost(message, repeated, tag = "3")]
    pub nns_controlled_dapp_canisters:
        ::prost::alloc::vec::Vec<::ic_nervous_system_proto::pb::v1::Canister>,
}
/// Message to list deployed sns instances.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnsesRequest {}
/// Response to list_deployed_snses.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnsesResponse {
    /// The deployed instances.
    #[prost(message, repeated, tag = "1")]
    pub instances: ::prost::alloc::vec::Vec<DeployedSns>,
}
/// An SNS deployed by this canister (i.e. the sns-wasm canister).
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployedSns {
    /// ID of the various canisters that were originally created in an SNS.
    #[prost(message, optional, tag = "1")]
    pub root_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "2")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "3")]
    pub ledger_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "4")]
    pub swap_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "5")]
    pub index_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// Specifies the version of an SNS.
#[derive(Eq, Hash, candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsVersion {
    /// The hash of the Root canister WASM.
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub root_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Governance canister WASM.
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "serde_bytes")]
    pub governance_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Ledger canister WASM.
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "serde_bytes")]
    pub ledger_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Swap canister WASM.
    #[prost(bytes = "vec", tag = "4")]
    #[serde(with = "serde_bytes")]
    pub swap_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Ledger Archive canister WASM.
    #[prost(bytes = "vec", tag = "5")]
    #[serde(with = "serde_bytes")]
    pub archive_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Index canister WASM.
    #[prost(bytes = "vec", tag = "6")]
    #[serde(with = "serde_bytes")]
    pub index_wasm_hash: ::prost::alloc::vec::Vec<u8>,
}
/// A human readable SnsVersion
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrettySnsVersion {
    #[prost(string, tag = "1")]
    pub root_wasm_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub governance_wasm_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub ledger_wasm_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub swap_wasm_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub archive_wasm_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub index_wasm_hash: ::prost::alloc::string::String,
}
/// The request type accepted by the get_next_sns_version canister method.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNextSnsVersionRequest {
    /// The current version recorded on the SNS (in Governance, the "deployed_version" field). This
    /// field is still required when governance_canister_id is provided.
    #[prost(message, optional, tag = "1")]
    pub current_version: ::core::option::Option<SnsVersion>,
    /// If supplied, will replace "caller" to allow verifying the response a particular
    /// SNS would receive
    #[prost(message, optional, tag = "2")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// The response type returned by the get_next_sns_version canister method.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNextSnsVersionResponse {
    #[prost(message, optional, tag = "1")]
    pub next_version: ::core::option::Option<SnsVersion>,
}
/// The request type accepted by update_allowed_principals.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateAllowedPrincipalsRequest {
    #[prost(message, repeated, tag = "1")]
    pub added_principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag = "2")]
    pub removed_principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// The response type returned by update_allowed_principals.
/// Returns the allowed principals after the update or an error.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateAllowedPrincipalsResponse {
    #[prost(
        oneof = "update_allowed_principals_response::UpdateAllowedPrincipalsResult",
        tags = "1, 2"
    )]
    pub update_allowed_principals_result:
        ::core::option::Option<update_allowed_principals_response::UpdateAllowedPrincipalsResult>,
}
/// Nested message and enum types in `UpdateAllowedPrincipalsResponse`.
pub mod update_allowed_principals_response {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AllowedPrincipals {
        #[prost(message, repeated, tag = "1")]
        pub allowed_principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum UpdateAllowedPrincipalsResult {
        #[prost(message, tag = "1")]
        Error(super::SnsWasmError),
        #[prost(message, tag = "2")]
        AllowedPrincipals(AllowedPrincipals),
    }
}
/// The request type for get_allowed_principals.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAllowedPrincipalsRequest {}
/// The response type for get_allowed_principals.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAllowedPrincipalsResponse {
    #[prost(message, repeated, tag = "1")]
    pub allowed_principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// The request type of update_sns_subnet_list, used to add or remove SNS subnet IDs (these are the subnets that
/// SNS instances will be deployed to)
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateSnsSubnetListRequest {
    #[prost(message, repeated, tag = "1")]
    pub sns_subnet_ids_to_add: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag = "2")]
    pub sns_subnet_ids_to_remove: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// The response type of update_sns_subnet_list
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateSnsSubnetListResponse {
    #[prost(message, optional, tag = "1")]
    pub error: ::core::option::Option<SnsWasmError>,
}
/// The request type of get_sns_subnet_ids. Used to request the list of SNS subnet IDs that SNS-WASM will deploy
/// SNS instances to.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnsSubnetIdsRequest {}
/// The response type of get_sns_subnet_ids. Used to request the list of SNS subnet IDs that SNS-WASM will deploy
/// SNS instances to.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnsSubnetIdsResponse {
    #[prost(message, repeated, tag = "1")]
    pub sns_subnet_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// The request type of get_deployed_sns_by_proposal_id. Used to get a `DeployedSns` by the ProposalId in the
/// NNS that created it.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetDeployedSnsByProposalIdRequest {
    #[prost(uint64, tag = "1")]
    pub proposal_id: u64,
}
/// The response type of get_deployed_sns_by_proposal_id. Used to get a `DeployedSns` by the ProposalId in the
/// NNS that created it.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetDeployedSnsByProposalIdResponse {
    #[prost(
        oneof = "get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult",
        tags = "1, 2"
    )]
    pub get_deployed_sns_by_proposal_id_result: ::core::option::Option<
        get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult,
    >,
}
/// Nested message and enum types in `GetDeployedSnsByProposalIdResponse`.
pub mod get_deployed_sns_by_proposal_id_response {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum GetDeployedSnsByProposalIdResult {
        #[prost(message, tag = "1")]
        Error(super::SnsWasmError),
        #[prost(message, tag = "2")]
        DeployedSns(super::DeployedSns),
    }
}
/// The request type for get_wasm_metadata, which returns the metadata for a given wasm
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmMetadataRequest {
    #[prost(bytes = "vec", optional, tag = "1")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetadataSection {
    /// First part of the section. Normally, this is either "icp:private" or "icp:public".
    #[prost(string, optional, tag = "1")]
    pub visibility: ::core::option::Option<::prost::alloc::string::String>,
    /// Second part of the section. For example, this might be "candid:service".
    #[prost(string, optional, tag = "2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    /// Last part of the section, containing its raw contents.
    #[prost(bytes = "vec", optional, tag = "3")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub contents: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// The response for get_wasm_metadata, which returns the metadata for a given wasm
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmMetadataResponse {
    #[prost(oneof = "get_wasm_metadata_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<get_wasm_metadata_response::Result>,
}
/// Nested message and enum types in `GetWasmMetadataResponse`.
pub mod get_wasm_metadata_response {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        #[prost(message, repeated, tag = "1")]
        pub sections: ::prost::alloc::vec::Vec<super::MetadataSection>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Ok(Ok),
        #[prost(message, tag = "2")]
        Error(super::SnsWasmError),
    }
}
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
    serde::Serialize,
)]
#[repr(i32)]
pub enum SnsCanisterType {
    Unspecified = 0,
    /// The type for the root canister.
    Root = 1,
    /// The type for the governance canister.
    Governance = 2,
    /// The type for the ledger canister.
    Ledger = 3,
    /// The type for the swap canister.
    Swap = 4,
    /// The type for the ledger archive canister.
    Archive = 5,
    /// The type for the index canister.
    Index = 6,
}
impl SnsCanisterType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            SnsCanisterType::Unspecified => "SNS_CANISTER_TYPE_UNSPECIFIED",
            SnsCanisterType::Root => "SNS_CANISTER_TYPE_ROOT",
            SnsCanisterType::Governance => "SNS_CANISTER_TYPE_GOVERNANCE",
            SnsCanisterType::Ledger => "SNS_CANISTER_TYPE_LEDGER",
            SnsCanisterType::Swap => "SNS_CANISTER_TYPE_SWAP",
            SnsCanisterType::Archive => "SNS_CANISTER_TYPE_ARCHIVE",
            SnsCanisterType::Index => "SNS_CANISTER_TYPE_INDEX",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SNS_CANISTER_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "SNS_CANISTER_TYPE_ROOT" => Some(Self::Root),
            "SNS_CANISTER_TYPE_GOVERNANCE" => Some(Self::Governance),
            "SNS_CANISTER_TYPE_LEDGER" => Some(Self::Ledger),
            "SNS_CANISTER_TYPE_SWAP" => Some(Self::Swap),
            "SNS_CANISTER_TYPE_ARCHIVE" => Some(Self::Archive),
            "SNS_CANISTER_TYPE_INDEX" => Some(Self::Index),
            _ => None,
        }
    }
}
