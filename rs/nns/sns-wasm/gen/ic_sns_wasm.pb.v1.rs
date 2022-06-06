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
