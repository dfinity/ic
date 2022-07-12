/// The SNS-WASM canister state that is persisted to stable memory on pre-upgrade and read on
/// post-upgrade.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StableCanisterState {
    #[prost(message, repeated, tag="1")]
    pub wasm_indexes: ::prost::alloc::vec::Vec<SnsWasmStableIndex>,
    #[prost(message, repeated, tag="2")]
    pub sns_subnet_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag="3")]
    pub deployed_sns_list: ::prost::alloc::vec::Vec<DeployedSns>,
    #[prost(message, optional, tag="4")]
    pub upgrade_path: ::core::option::Option<UpgradePath>,
}
/// Details the offset and size of a WASM binary in stable memory and the hash of this binary
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasmStableIndex {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub offset: u32,
    #[prost(uint32, tag="3")]
    pub size: u32,
}
/// Specifies the upgrade path for SNS instances
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpgradePath {
    /// The latest SNS version. New SNS deployments will deploy the SNS canisters specified by
    /// this version.
    #[prost(message, optional, tag="1")]
    pub latest_version: ::core::option::Option<SnsVersion>,
    /// Maps SnsVersions to the SnsVersion that it should be upgraded to.
    #[prost(message, repeated, tag="2")]
    pub upgrade_path: ::prost::alloc::vec::Vec<SnsUpgrade>,
}
/// Maps an SnsVersion to the SnsVersion that it should be upgraded to.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsUpgrade {
    #[prost(message, optional, tag="1")]
    pub current_version: ::core::option::Option<SnsVersion>,
    #[prost(message, optional, tag="2")]
    pub next_version: ::core::option::Option<SnsVersion>,
}
/// The representation of a WASM along with its target canister type
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasm {
    #[prost(bytes="vec", tag="1")]
    pub wasm: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="SnsCanisterType", tag="2")]
    pub canister_type: i32,
}
/// The error response returned in response objects on failed or partially failed operations
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasmError {
    /// The message returned by the canister on errors
    #[prost(string, tag="1")]
    pub message: ::prost::alloc::string::String,
}
/// The payload for the add_wasm endpoint, which takes an SnsWasm along with the hash of the wasm bytes
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddWasmRequest {
    #[prost(message, optional, tag="1")]
    pub wasm: ::core::option::Option<SnsWasm>,
    #[prost(bytes="vec", tag="2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// The response from add_wasm, which is either Ok or Error.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddWasmResponse {
    #[prost(oneof="add_wasm_response::Result", tags="1, 2")]
    pub result: ::core::option::Option<add_wasm_response::Result>,
}
/// Nested message and enum types in `AddWasmResponse`.
pub mod add_wasm_response {
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// The hash of the wasm that was added
        #[prost(bytes, tag="1")]
        Hash(::prost::alloc::vec::Vec<u8>),
        /// Error when request fails
        #[prost(message, tag="2")]
        Error(super::SnsWasmError),
    }
}
/// The argument for get_wasm, which consists of the WASM hash to be retrieved.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmRequest {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// The response for get_wasm, which returns a WASM if it is found, or None.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasmResponse {
    #[prost(message, optional, tag="1")]
    pub wasm: ::core::option::Option<SnsWasm>,
}
/// Payload to deploy a new SNS.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployNewSnsRequest {
    /// The initial payload to initialize the SNS with.
    #[prost(message, optional, tag="1")]
    pub sns_init_payload: ::core::option::Option<::ic_sns_init::pb::v1::SnsInitPayload>,
}
/// The response to creating a new SNS.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployNewSnsResponse {
    /// The subnet the SNS was deployed to.
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// CanisterIds of canisters created by deploy_new_sns.
    #[prost(message, optional, tag="2")]
    pub canisters: ::core::option::Option<SnsCanisterIds>,
    /// Error when the request fails.
    #[prost(message, optional, tag="3")]
    pub error: ::core::option::Option<SnsWasmError>,
}
/// The CanisterIds of the SNS canisters that are created
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsCanisterIds {
    /// PrincipalId of the root canister
    #[prost(message, optional, tag="1")]
    pub root: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the ledger canister
    #[prost(message, optional, tag="2")]
    pub ledger: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the governance canister
    #[prost(message, optional, tag="3")]
    pub governance: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// PrincipalId of the swap canister
    #[prost(message, optional, tag="4")]
    pub swap: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// Message to list deployed sns instances
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnsesRequest {
}
/// Response to list_deployed_snses
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnsesResponse {
    /// The deployed instances
    #[prost(message, repeated, tag="1")]
    pub instances: ::prost::alloc::vec::Vec<DeployedSns>,
}
/// A deployed SNS root_canister_id
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployedSns {
    /// PrincipalId of the root canister of the sns
    #[prost(message, optional, tag="1")]
    pub root_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// Specifies the version of an SNS
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsVersion {
    /// The hash of the Root canister WASM
    #[prost(bytes="vec", tag="1")]
    pub root_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Governance canister WASM
    #[prost(bytes="vec", tag="2")]
    pub governance_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the Ledger canister WASM
    #[prost(bytes="vec", tag="3")]
    pub ledger_wasm_hash: ::prost::alloc::vec::Vec<u8>,
}
/// The request type accepted by the get_next_sns_version canister method
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNextSnsVersionRequest {
    #[prost(message, optional, tag="1")]
    pub current_version: ::core::option::Option<SnsVersion>,
}
/// The response type returned by the get_next_sns_version canister method
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNextSnsVersionResponse {
    #[prost(message, optional, tag="1")]
    pub next_version: ::core::option::Option<SnsVersion>,
}
/// The type of canister a particular WASM is intended to be installed on
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SnsCanisterType {
    Unspecified = 0,
    /// The type for the root canister
    Root = 1,
    /// The type for the governance canister
    Governance = 2,
    /// The type for the ledger canister
    Ledger = 3,
}
