/// The representation of a WASM along with its target canister type
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsWasm {
    #[prost(bytes="vec", tag="1")]
    pub wasm: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="SnsCanisterType", tag="2")]
    pub canister_type: i32,
}
/// The payload for the add_wasm endpoint, which takes an SnsWasm along with the hash of the wasm bytes
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddWasm {
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
    /// The error provides a reason the wasm could not be added.
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AddWasmError {
        #[prost(string, tag="1")]
        pub error: ::prost::alloc::string::String,
    }
    /// The Ok response provides the hash of the added WASM.
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AddWasmOk {
        #[prost(bytes="vec", tag="1")]
        pub hash: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag="1")]
        Error(AddWasmError),
        #[prost(message, tag="2")]
        Ok(AddWasmOk),
    }
}
/// The argument for get_wasm, which consists of the WASM hash to be retrieved.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetWasm {
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
pub struct DeployNewSns {
}
/// The response to creating a new SNS.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeployNewSnsResponse {
    /// The subnet the SNS was deployed to
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// CanisterIds of canisters created by deploy_new_sns
    #[prost(message, optional, tag="2")]
    pub canisters: ::core::option::Option<SnsCanisterIds>,
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
}
/// Message to list deployed sns instances
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnses {
}
/// Response to list_deployed_snses
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDeployedSnsesResponse {
    /// the deployed instances
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
